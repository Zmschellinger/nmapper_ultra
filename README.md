# `nmapper-ultra` – Advanced Nmap Automation & Reporting

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  

> **A powerful, resumable, parallel Nmap scanner with live HTML dashboards, state persistence, and automatic result organization — built for pentesters and security researchers.**

---

## Features

| Feature | Description |
|---------|-------------|
| **Parallel Scanning** | Scan hundreds of targets simultaneously (up to 64 threads) |
| **Resumable Scans** | `state.json` tracks completed hosts; skip already-scanned IPs |
| **Live HTML Dashboard** | Auto-refreshing `dashboard.html` with search, filters, and charts |
| **Web Server Detection** | Auto-collects HTTP/HTTPS URLs with clickable links |
| **Protocol-Specific Scans** | HTTP, HTTPS, SSH, SMB, RDP, WinRM, FTP, MySQL, PostgreSQL, VNC, or all ports |
| **UDP Retry Logic** | Exponential backoff for reliable UDP scans |
| **Parallel XML Parsing** | Fast processing using `lxml` + `ProcessPoolExecutor` |
| **CIDR & Range Support** | Supports `192.168.1.0/24`, `10.0.0.1-10.0.0.254`, etc. |
| **External Tools** | Optional `gowitness` screenshots and `nuclei` vuln scans (skips if tools missing) |
| **Modern CLI** | Powered by [Typer](https://typer.tiangolo.com/) with auto-completion |

---

## Output Structure

```text
results/
├── nmap_xml/                  # Raw Nmap XML files
├── ports/
│   ├── 80/                    # IPs with port 80 open
│   ├── 445/                   # IPs with SMB open
│   └── ...                    # One folder per open port
├── services/
│   ├── http/                  # IP:port for HTTP services
│   ├── ssh/                   # IP:port for SSH services
│   └── ...                    # One folder per service
├── versions/
│   └── Apache_2.4.41/         # IPs running specific versions
├── servicesWithPorts/
│   └── http_80/               # IPs with HTTP on port 80
├── webHTML/
│   ├── dashboard.html         # Live-updating table + charts
│   ├── parsedWebServers.html  # Clickable web links
│   ├── http.url.list          # List of HTTP URLs
│   └── https.url.list         # List of HTTPS URLs
├── screenshots/               # gowitness screenshots (if enabled)
├── all.ports.up.csv           # CSV: IP,hostname,port
├── all.up.csv                 # CSV: IP,hostname
├── ips.up.list                # List of up IPs
├── hostnames.up.list          # List of hostnames
└── state.json                 # Scan state for resuming
```

---

## Installation (Kali Linux)

### 1. Clone the Repository

```bash
git clone https://github.com/yourname/nmapper-ultra.git ~/tools/dev/nmapper_ultra
cd ~/tools/dev/nmapper_ultra
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv nmapper-env
source nmapper-env/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -e .
```

### 4. Install System Dependencies

```bash
sudo apt update
sudo apt install -y nmap python3-lxml
```

### 5. (Optional) Install External Tools

```bash
# gowitness (screenshots)
go install github.com/sensepost/gowitness@latest
sudo cp ~/go/bin/gowitness /usr/local/bin/

# nuclei (vulnerability scanning)
sudo apt install -y nuclei
nuclei -update-templates
```

---

### Basic Scans

```bash
nmapper-ultra --targets-file scope.txt --outputDir ./results
```

### Full Scan (All Ports)

```bash
nmapper-ultra 192.168.216.0/24 --parallel 16 --serve-dashboard
```

### Options

```text
Arguments:
  TARGETS           CIDR, IP, or range (e.g., 192.168.1.0/24, 10.0.0.1-10.0.0.254)

Options:
  -tf, --targets-file PATH  File with one target per line
  -o, --outputDir PATH      Output directory [default: pyDumpOutput]
  -t, --parallel INT        Parallel threads (1–64) [default: 8]
  -O, --include-os          Enable OS detection
  --extra-nmap-args LIST    Extra nmap args (e.g., "--script vuln")
  --screenshots             Take screenshots with gowitness
  --nuclei                  Run Nuclei on HTTP/HTTPS
  --serve-dashboard         Serve live dashboard at http://127.0.0.1:8000
```

---

## Example Output

```bash
$ nmapper-ultra 192.168.216.0/24 --screenshots --nuclei
Running: nmap -sV -sC -p 80,443,8080,8443 -oX results/nmap_xml/192.168.216.189.xml ...
Scan completed: 192.168.216.189
...
Scanning: 100%|██████████| 256/256 [02:15<00:00, 1.9host/s]
Parsing XML: 100%|██████████| 12/12 [00:02<00:00, 5.1file/s]
[green]Parsed 12 hosts[/green]
[green]Dashboard: http://127.0.0.1:8000/dashboard.html[/green]
```

---

## Live Dashboard

- **Auto-refreshes**: Every 10 seconds
- **Search & filter**: By IP, port, service, or OS
- **Doughnut chart**: Top services (HTTP, SSH, etc.)
- **Dark mode**: Matches system theme
- **Clickable links**: Open web servers in browser

---

## Development

### Install for Development

```bash
pip install -e .[test]
```

### Run Tests

```bash
pytest -v
```

### Format Code

```bash
pip install black ruff isort
black .
ruff check .
isort .
```

---

## Security & Legal

> **Only scan systems you own or have explicit permission to test.**

- **Safe defaults**: No aggressive scripts
- **Secure parsing**: Sanitized `--extra-nmap-args`
- **Redaction-ready**: No credentials stored in output

---

## License

[MIT License](LICENSE) – Free for commercial and personal use.

---

## Built With

- [Typer](https://typer.tiangolo.com/) – CLI framework
- [Rich](https://github.com/Textualize/rich) – Terminal output
- [Jinja2](https://jinja.palletsprojects.com/) – HTML templates
- [lxml](https://lxml.de/) – XML parsing
- [netaddr](https://github.com/netaddr/netaddr) – CIDR expansion
- [tqdm](https://github.com/tqdm/tqdm) – Progress bars

---

**Star this repo if it helped you!**

---
