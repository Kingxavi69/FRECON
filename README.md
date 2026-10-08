# FRECON

FRECON is a small command-line reconnaissance tool for a **single IP address, hostname, or website URL**. It checks one resolved address for common open TCP ports, performs lightweight service identification with Nmap, and inspects a website's HTTP response headers and (for HTTPS) certificate.

FRECON reports **potential exposure and configuration risks**, not verified vulnerabilities. It does not exploit services, run vulnerability scripts, crawl pages, or check UDP ports. Use it only on systems you own or have explicit permission to assess.

FRECON does not require a GitHub login, username, password, paid API key, or subscription. The `--authorized` option is only a local confirmation that you have permission to scan the target; it is not an account login.

## What it checks

- Nmap TCP connect scan (`-sT`) of up to 1,000 common ports, with lightweight service detection.
- A single HTTP `HEAD` request to the target origin; redirects are not followed.
- HTTPS certificate validation and expiry when the input uses HTTPS.
- Risk indicators for selected exposed services, missing common response headers, and certificates expiring within 30 days.
- Text or JSON reports, optionally saved to a file.

The target hostname is resolved once and only one resulting IP address is scanned. If the hostname has multiple addresses, run FRECON again with a specific address if you are authorized to check it. It does not perform CVE matching; service banners can be incomplete or inaccurate and findings need manual verification.

## Installation on Kali Linux

Open a terminal and install the system dependency and Python tooling:

```bash
sudo apt update
sudo apt install -y nmap python3 python3-venv python3-pip curl unzip
```

Download the public source archive (no GitHub account or Git installation needed), then create a virtual environment and install FRECON:

```bash
curl -L --fail https://github.com/Kingxavi69/FRECON/archive/refs/heads/main.zip -o FRECON.zip
unzip FRECON.zip
cd FRECON-main
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

The source archive is public and does not require GitHub credentials. Nmap's TCP connect scan does not require root privileges.

## Usage

Every scan requires an explicit authorization acknowledgement:

```bash
frecon --authorized 192.0.2.10
frecon --authorized https://example.org
frecon --authorized example.org --top-ports 100
```

Save a JSON report:

```bash
frecon --authorized https://example.org --format json --output report.json
```

To run from a source checkout without installing the package:

```bash
python -m frecon.cli --authorized https://example.org
```

View options with `frecon --help`.

## Development and tests

```bash
python -m unittest discover -s tests -v
```

## Responsible use

Only scan a target when you own it or have explicit written authorization. A scan can trigger monitoring and may be prohibited by hosting-provider policies. Start with a narrow port count and coordinate with the system owner. FRECON intentionally limits each run to one resolved IP, TCP connect checks, a 110-second Nmap timeout, and non-exploitative HTTP/TLS observations.