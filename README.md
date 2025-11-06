# `nmap_ultra_enhanced.py` – Advanced Nmap Automation & Reporting

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A powerful, resumable, parallel Nmap scanner with rich HTML dashboards, state persistence, and optional screenshot/Nuclei integration.**

---

## Features

| Feature | Description |
|-------|-----------|
| **Staged Scanning** | Full-port discovery → targeted aggressive scans |
| **Parallel Execution** | Scan multiple targets simultaneously |
| **Incremental & Resumable** | `state.json` tracks progress; skip already-scanned hosts |
| **Rich HTML Dashboard** | Live-updating `dashboard.html` with host/port/service summary |
| **Web Server Aggregation** | Auto-collects HTTP/HTTPS URLs with clickable links |
| **CSV + TXT Outputs** | Per-port, per-service, per-version files |
| **UDP Retry Logic** | Exponential backoff for unreliable UDP scans |
| **Parallel XML Parsing** | Fast processing of large scan results |
| **Live HTTP Server** | `--serve-dashboard` to view results in browser |
| **Screenshots** | `--screenshots` → `gowitness` on discovered web servers |
| **Nuclei Integration** | `--nuclei` → run vulnerability scan on web URLs |
| **Scope Control** | `--scope-file` ensures you only scan authorized targets |
| **Legal Banner** | Reminds users of ethical use |
| **Type-Safe & Clean** | Full type hints, `mypy`-clean, `pathlib`, `rich` logging |

---

## Output Structure

```
pyDumpOutput/
├── nmap_xml/                  # Raw Nmap XML files
├── ports/
│   ├── 80                     # IPs with HTTP
│   └── 22                     # IPs with SSH
├── services/
│   ├── http                   # IP:port lines
│   └── ssh
├── versions/
│   └── Apache_2.4.41          # IPs running that version
├── servicesWithPorts/
│   └── http_80                # IPs with HTTP on port 80
├── webHTML/
│   ├── dashboard.html         # Summary table
│   ├── parsedWebServers.html  # Clickable web links
│   ├── http.url.list
│   ├── https.url.list
│   └── screenshots/           # gowitness output
├── nuclei/
│   └── results.txt            # Nuclei scan results
├── all.ports.up.csv           # IP,hostname,port
├── all.up.csv                 # IP,hostname
├── ips.up.list
├── hostnames.up.list
└── state.json                 # Persistent deduplication state
```

---

## Installation

### 1. Clone & Install Python Dependencies

```bash
git clone https://github.com/yourname/nmap-ultra-enhanced.git
cd nmap-ultra-enhanced
pip install rich tqdm
```

### 2. Install `nmap`

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Kali Linux
sudo apt install nmap
```

### 3. (Optional) Install `gowitness` for Screenshots

```bash
go install github.com/sensepost/gowitness@latest
# Or download prebuilt: https://github.com/sensepost/gowitness/releases
```

### 4. (Optional) Install `nuclei`

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates
```

---

## Usage

### Basic Scan

```bash
python3 nmap_ultra_enhanced.py \
  --targets-file targets.txt \
  --outputDir results \
  --parallel 8
```

### Discovery Only (Faster)

```bash
python3 nmap_ultra_enhanced.py \
  --targets 10.0.0.0/24 \
  --discovery-only
```

### With OS Detection + UDP Retries

```bash
python3 nmap_ultra_enhanced.py \
  --targets-file targets.txt \
  --include-os \
  --udp-retries 3 \
  --udp-backoff 3.0
```

### Skip Already-Scanned Hosts

```bash
python3 nmap_ultra_enhanced.py \
  --targets-file new_targets.txt \
  --skip-known-up
```

### Scope Enforcement

```bash
# scope.txt
10.10.10.0/24
192.168.1.100

python3 nmap_ultra_enhanced.py \
  --targets-file targets.txt \
  --scope-file scope.txt
```

### Full Recon Pipeline (Screenshots + Nuclei)

```bash
python3 nmap_ultra_enhanced.py \
  --targets-file targets.txt \
  --screenshots \
  --nuclei \
  --serve-dashboard
```

> Open browser: [http://localhost:8000/webHTML/dashboard.html](http://localhost:8000/webHTML/dashboard.html)

---

## CLI Options

| Option | Description |
|------|-------------|
| `--targets-file` | File with one target per line |
| `--targets` | Comma-separated targets |
| `--outputDir` | Output directory (default: `pyDumpOutput`) |
| `--parallel` | Number of parallel workers |
| `--discovery-only` | Skip aggressive/service scans |
| `--include-os` | Add `-O` to aggressive TCP scan |
| `--udp-delay/backoff/retries` | UDP retry behavior |
| `--skip-known-up` | Skip hosts already in `state.json` |
| `--scope-file` | File with allowed IPs/CIDRs |
| `--screenshots` | Run `gowitness` on web URLs |
| `--nuclei` | Run `nuclei` on web URLs |
| `--serve-dashboard` | Start HTTP server on port 8000 |
| `--rebuild` | Rebuild reports from existing XMLs |
| `--extra-nmap-args` | Pass extra args to nmap (quoted) |

---

## Example `targets.txt`

```text
10.10.10.0/24
192.168.1.1
example.com
scanme.nmap.org
```

---

## Rebuilding Reports

If you have old XMLs and want fresh reports:

```bash
python3 nmap_ultra_enhanced.py --outputDir results --rebuild
```

---

## Legal & Ethical Use

> **WARNING: Only scan systems you own or have explicit written permission to test.**

This tool includes:
- A **legal banner** on every run
- **Scope enforcement** via `--scope-file`
- No default stealth options

Unauthorized scanning may violate laws like the CFAA (US), Computer Misuse Act (UK), etc.

---

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit (`git commit -am 'Add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open a Pull Request

---

## License

[MIT License](LICENSE) – Free to use, modify, and distribute.

---

## Author

**Zachary Schellinger** – Security Researcher / Pentester

---

**Fast. Smart. Beautiful. Ethical.**

> *“Stay hungry, stay foolish.” -Steve Jobs*
