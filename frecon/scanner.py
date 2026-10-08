"""Network checks used by FRECON. Scans one resolved address without exploit scripts."""

from __future__ import annotations

import ipaddress
import http.client
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Target:
    original: str
    host: str
    scheme: str
    port: int | None
    address: str | None = None
    family: int | None = None

    @property
    def web_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)

    @property
    def web_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = f":{self.web_port}" if self.port else ""
        return f"{self.scheme}://{host}{port}/"


def parse_target(value: str) -> Target:
    raw = value.strip()
    if not raw or any(character.isspace() for character in raw):
        raise ValueError("Enter one IP address, hostname, or http(s) URL.")

    try:
        literal = ipaddress.ip_address(raw)
    except ValueError:
        literal = None
    if isinstance(literal, ipaddress.IPv6Address):
        candidate = f"https://[{raw}]"
    else:
        candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http and https URLs are supported.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not supported.")
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid target: {error}") from error

    if not host:
        raise ValueError("The target must include a hostname or IP address.")

    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("The target hostname is invalid.") from error
        if len(host) > 253 or any(not label or len(label) > 63 for label in host.rstrip(".").split(".")):
            raise ValueError("The target hostname is invalid.")

    return Target(raw, host, parsed.scheme, port)


def resolve_target(target: Target) -> Target:
    try:
        records = socket.getaddrinfo(target.host, target.web_port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise RuntimeError(f"Could not resolve {target.host}: {error}") from error

    for family, _, _, _, sockaddr in records:
        if family in {socket.AF_INET, socket.AF_INET6}:
            return Target(
                original=target.original,
                host=target.host,
                scheme=target.scheme,
                port=target.port,
                address=sockaddr[0],
                family=family,
            )
    raise RuntimeError(f"No IPv4 or IPv6 address found for {target.host}.")


def scan_ports(target: Target, top_ports: int = 1000) -> list[dict[str, object]]:
    if not target.address or target.family is None:
        raise ValueError("Resolve the target before scanning ports.")
    if not 1 <= top_ports <= 1000:
        raise ValueError("top_ports must be between 1 and 1000.")

    command = [
        "nmap", "-Pn", "-sT", "-sV", "--version-light", "--top-ports", str(top_ports),
        "--max-retries", "1", "--host-timeout", "90s", "--reason", "-oX", "-",
    ]
    if target.family == socket.AF_INET6:
        command.append("-6")
    command.append(target.address)

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=110, check=False)
    except FileNotFoundError as error:
        raise RuntimeError("Nmap is required. Install it with: sudo apt install nmap") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Nmap exceeded its 110-second safety timeout.") from error

    if result.returncode not in {0, 1} or not result.stdout.strip():
        detail = result.stderr.strip() or f"Nmap exited with status {result.returncode}."
        raise RuntimeError(detail)

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as error:
        raise RuntimeError("Nmap returned an unreadable XML report.") from error

    open_ports: list[dict[str, object]] = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        open_ports.append({
            "port": int(port_node.get("portid", "0")),
            "protocol": port_node.get("protocol", "unknown"),
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "") if service is not None else "",
            "reason": state.get("reason", "")
        })
    return open_ports


def check_web(target: Target) -> dict[str, object]:
    report: dict[str, object] = {"url": target.web_url, "http": None, "tls": None}
    connection_type = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    tls_context = ssl.create_default_context() if target.scheme == "https" else None
    if tls_context:
        connection = connection_type(target.host, target.web_port, timeout=8, context=tls_context)
    else:
        connection = connection_type(target.host, target.web_port, timeout=8)

    def connect_to_resolved_address() -> None:
        connection.sock = socket.create_connection(
            (target.address or target.host, target.web_port), timeout=8
        )
        if tls_context:
            connection.sock = tls_context.wrap_socket(
                connection.sock, server_hostname=target.host
            )

    connection.connect = connect_to_resolved_address
    try:
        host_header = target.host
        if target.port:
            host_header = f"[{target.host}]" if ":" in target.host else target.host
            host_header = f"{host_header}:{target.web_port}"
        connection.request(
            "HEAD", "/", headers={
                "Host": host_header,
                "User-Agent": "FRECON/0.1 (authorized security assessment)",
            }
        )
        response = connection.getresponse()
        report["http"] = {"status": response.status, "headers": dict(response.getheaders())}
    except (http.client.HTTPException, OSError, ssl.SSLError, TimeoutError) as error:
        report["http_error"] = str(error)
    finally:
        connection.close()

    if target.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target.address or target.host, target.web_port), timeout=8) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=target.host) as secured_socket:
                    certificate = secured_socket.getpeercert()
            expires_at = certificate.get("notAfter")
            days_remaining = None
            if expires_at:
                expiry_timestamp = ssl.cert_time_to_seconds(expires_at)
                days_remaining = int((expiry_timestamp - datetime.now(timezone.utc).timestamp()) // 86400)
            report["tls"] = {
                "verified": True,
                "not_after": expires_at,
                "days_remaining": days_remaining,
                "version": secured_socket.version(),
            }
        except (OSError, ssl.SSLError, ValueError) as error:
            report["tls"] = {
                "verified": False,
                "certificate_error": isinstance(error, ssl.SSLCertVerificationError),
                "error": str(error),
            }
    return report


_RISKY_PORTS = {
    21: ("FTP service exposed", "high", "FTP may expose credentials or data without encryption."),
    23: ("Telnet service exposed", "high", "Telnet does not encrypt authentication or session traffic."),
    445: ("SMB service exposed", "high", "Restrict SMB to trusted networks and verify patching and access controls."),
    1433: ("Database service exposed", "high", "Restrict database access to trusted application or admin networks."),
    3306: ("Database service exposed", "high", "Restrict database access to trusted application or admin networks."),
    3389: ("Remote Desktop exposed", "high", "Restrict RDP and require strong authentication and appropriate network controls."),
    5432: ("Database service exposed", "high", "Restrict database access to trusted application or admin networks."),
    5900: ("VNC service exposed", "high", "Restrict remote desktop access and verify authentication and encryption."),
    6379: ("Redis service exposed", "high", "Redis should not be reachable by untrusted networks."),
    9200: ("Elasticsearch API exposed", "high", "Restrict the API and verify authentication and network access controls."),
    27017: ("MongoDB service exposed", "high", "Restrict database access to trusted application or admin networks."),
}


def build_findings(ports: list[dict[str, object]], web: dict[str, object]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for item in ports:
        port = int(item["port"])
        name, severity, recommendation = _RISKY_PORTS.get(
            port, ("Open network service", "info", "Confirm this service is required and appropriately restricted.")
        )
        service = str(item.get("service", "unknown"))
        findings.append({
            "severity": severity,
            "title": name,
            "evidence": f"TCP/{port} is open; service identified as {service}.",
            "recommendation": recommendation,
        })

    http = web.get("http")
    if isinstance(http, dict):
        headers = {str(key).lower(): str(value) for key, value in http.get("headers", {}).items()}
        checks = [
            ("content-security-policy", "Content Security Policy header missing", "medium", "Set a Content-Security-Policy appropriate to the application."),
            ("x-content-type-options", "X-Content-Type-Options header missing", "low", "Set X-Content-Type-Options: nosniff."),
            ("x-frame-options", "Clickjacking protection header missing", "low", "Set X-Frame-Options or a frame-ancestors CSP directive."),
            ("referrer-policy", "Referrer-Policy header missing", "low", "Set a Referrer-Policy suitable for the site."),
        ]
        if str(web.get("url", "")).startswith("https://"):
            checks.append(("strict-transport-security", "HSTS header missing", "medium", "Set Strict-Transport-Security after confirming HTTPS is enforced."))
        for key, title, severity, recommendation in checks:
            if key not in headers:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "evidence": "The HTTP HEAD response did not include this header.",
                    "recommendation": recommendation,
                })
        if "server" in headers:
            findings.append({
                "severity": "info",
                "title": "Web server banner disclosed",
                "evidence": f"Server: {headers['server']}",
                "recommendation": "Avoid disclosing unnecessary server implementation details.",
            })

    tls = web.get("tls")
    if isinstance(tls, dict) and tls.get("certificate_error"):
        findings.append({
            "severity": "high",
            "title": "TLS certificate validation failed",
            "evidence": str(tls.get("error", "The certificate could not be validated.")),
            "recommendation": "Deploy a trusted, hostname-matching certificate with a complete certificate chain.",
        })
    if isinstance(tls, dict) and tls.get("verified") and isinstance(tls.get("days_remaining"), int):
        days = int(tls["days_remaining"])
        if days <= 30:
            findings.append({
                "severity": "high" if days <= 0 else "medium",
                "title": "TLS certificate expired" if days <= 0 else "TLS certificate expires soon",
                "evidence": f"The certificate has {days} day(s) remaining.",
                "recommendation": "Renew and deploy a valid certificate before expiry.",
            })
    return findings


def create_report(target: Target, ports: list[dict[str, object]], web: dict[str, object]) -> dict[str, object]:
    findings = build_findings(ports, web)
    return {
        "tool": "FRECON",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "input": target.original,
            "hostname": target.host,
            "resolved_address": target.address,
            "address_family": "IPv6" if target.family == socket.AF_INET6 else "IPv4",
        },
        "scope": "One resolved IP; TCP connect scan of the selected top ports; non-invasive HTTP/TLS checks.",
        "ports": ports,
        "web": web,
        "findings": findings,
        "limitations": [
            "Findings are indicators for manual verification, not proof of exploitability or a CVE assessment.",
            "Only one resolved address and TCP ports are checked; UDP, subdomains, content crawling, and exploit tests are out of scope.",
            "HTTP checks use HEAD and may not represent every application route or user context.",
        ],
    }