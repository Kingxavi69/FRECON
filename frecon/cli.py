"""Command-line interface for FRECON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from frecon.scanner import create_report, parse_target, resolve_target, scan_ports, check_web


def _format_text(report: dict[str, object]) -> str:
    target = report["target"]
    assert isinstance(target, dict)
    lines = [
        f"FRECON report: {target['input']}",
        f"Resolved: {target['resolved_address']} ({target['address_family']})",
        "",
        "Open TCP ports:",
    ]
    ports = report["ports"]
    assert isinstance(ports, list)
    if ports:
        for item in ports:
            detail = " ".join(part for part in [str(item["product"]), str(item["version"])] if part)
            suffix = f" ({detail})" if detail else ""
            lines.append(f"  {item['port']}/tcp  {item['service']}{suffix}")
    else:
        lines.append("  No open ports found in the selected TCP port set.")

    findings = report["findings"]
    assert isinstance(findings, list)
    lines.extend(["", f"Potential security findings ({len(findings)}):"])
    if findings:
        for finding in findings:
            lines.append(f"  [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"    Evidence: {finding['evidence']}")
            lines.append(f"    Recommendation: {finding['recommendation']}")
    else:
        lines.append("  No indicators were identified by these checks.")
    lines.extend([
        "",
        "These are risk indicators, not confirmed vulnerabilities. Verify findings manually.",
    ])
    web = report["web"]
    assert isinstance(web, dict)
    if web.get("http_error"):
        lines.append(f"HTTP check: {web['http_error']}")
    tls = web.get("tls")
    if isinstance(tls, dict) and tls.get("error"):
        lines.append(f"TLS check: {tls['error']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="frecon",
        description="Run bounded reconnaissance against one host you are authorized to assess.",
    )
    parser.add_argument("target", help="One IPv4/IPv6 address, hostname, or http(s) URL")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own the target or have written permission to scan it")
    parser.add_argument("--top-ports", type=int, default=1000, help="Nmap common TCP ports to check (1-1000; default: 1000)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--output", type=Path, help="Write the report to this file")
    args = parser.parse_args()

    if not args.authorized:
        parser.error("scanning requires --authorized and permission from the target owner")
    if not 1 <= args.top_ports <= 1000:
        parser.error("--top-ports must be between 1 and 1000")

    try:
        target = resolve_target(parse_target(args.target))
        ports = scan_ports(target, args.top_ports)
        web = check_web(target)
        report = create_report(target, ports, web)
    except (RuntimeError, ValueError) as error:
        print(f"frecon: {error}", file=sys.stderr)
        return 1

    output = json.dumps(report, indent=2) if args.format == "json" else _format_text(report)
    if args.output:
        try:
            args.output.write_text(output + "\n", encoding="utf-8")
        except OSError as error:
            print(f"frecon: could not write report: {error}", file=sys.stderr)
            return 1
        print(f"Report written to {args.output}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())