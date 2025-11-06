# nmapper_ultra/reporter.py
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from .utils import console, which
import subprocess
import shutil

def generate_reports(hosts, output_dir: Path, args):
    web_dir = output_dir / "webHTML"
    web_dir.mkdir(exist_ok=True)

    # Organize
    _organize_files(hosts, output_dir)
    _generate_web_lists(hosts, web_dir)
    _generate_html_dashboard(hosts, web_dir)
    _generate_csvs(hosts, output_dir)

    # FIXED: Use dict access
    if args.get("screenshots") and which("gowitness"):
        _run_gowitness(web_dir, output_dir)
    if args.get("nuclei") and which("nuclei"):
        _run_nuclei(web_dir, output_dir)
    if args.get("serve_dashboard"):
        _serve_dashboard(web_dir)

def _organize_files(hosts, output_dir):
    dirs = {
        "ports": output_dir / "ports",
        "services": output_dir / "services",
        "versions": output_dir / "versions",
        "servicesWithPorts": output_dir / "servicesWithPorts"
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    for host in hosts:
        ip = host["ip"]
        hn = host["hostname"]
        for p in host["ports"]:
            port, svc = p["port"], p["service"]
            version = f"{p['product']}_{p['version']}".strip("_")
            version = version.replace(" ", "_").replace("/", "_") or svc

            # ports/<port>/ips.list
            (dirs["ports"] / port).mkdir(exist_ok=True)
            (dirs["ports"] / port / "ips.list").open("a").write(f"{ip}\n")

            # services/<svc>/ip_ports.list
            (dirs["services"] / svc).mkdir(exist_ok=True)
            (dirs["services"] / svc / "ip_ports.list").open("a").write(f"{ip}:{port}\n")

            # versions/<ver>/ips.list
            if p["version"]:
                (dirs["versions"] / version).mkdir(exist_ok=True)
                (dirs["versions"] / version / "ips.list").open("a").write(f"{ip}\n")

            # servicesWithPorts/<svc>_<port>/ips.list
            sp_dir = dirs["servicesWithPorts"] / f"{svc}_{port}"
            sp_dir.mkdir(exist_ok=True)
            (sp_dir / "ips.list").open("a").write(f"{ip}\n")

def _generate_web_lists(hosts, web_dir):
    http_urls = []
    https_urls = []
    for h in hosts:
        for p in h["ports"]:
            if "http" in p["service"]:
                scheme = "https" if "ssl" in p["service"] or p["port"] == "443" else "http"
                url = f"{scheme}://{h['ip']}:{p['port']}"
                (http_urls if scheme == "http" else https_urls).append(url)

    (web_dir / "http.url.list").write_text("\n".join(http_urls) + "\n")
    (web_dir / "https.url.list").write_text("\n".join(https_urls) + "\n")

    # parsedWebServers.html
    html = "<html><head><title>Web Servers</title></head><body>"
    html += "<h1>HTTP</h1><ul>" + "".join(f"<li><a href='{u}'>{u}</a></li>" for u in http_urls) + "</ul>"
    html += "<h1>HTTPS</h1><ul>" + "".join(f"<li><a href='{u}'>{u}</a></li>" for u in https_urls) + "</ul>"
    html += "</body></html>"
    (web_dir / "parsedWebServers.html").write_text(html)

def _generate_html_dashboard(hosts, web_dir):
    env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")))
    template = env.get_template("dashboard.html.j2")
    html = template.render(hosts=sorted(hosts, key=lambda x: x["ip"]))
    (web_dir / "dashboard.html").write_text(html)

def _generate_csvs(hosts, output_dir):
    with open(output_dir / "all.up.csv", "w") as f:
        f.write("IP,Hostname\n")
        for h in hosts:
            f.write(f"{h['ip']},{h['hostname']}\n")

    with open(output_dir / "all.ports.up.csv", "w") as f:
        f.write("IP,Hostname,Port\n")
        for h in hosts:
            for p in h["ports"]:
                f.write(f"{h['ip']},{h['hostname']},{p['port']}\n")

    (output_dir / "ips.up.list").write_text("\n".join(h["ip"] for h in hosts) + "\n")
    (output_dir / "hostnames.up.list").write_text("\n".join(h["hostname"] for h in hosts if h["hostname"]) + "\n")

def _run_gowitness(web_dir, output_dir):
    urls_file = web_dir / "all.urls"
    urls_file.write_text((web_dir / "http.url.list").read_text() + (web_dir / "https.url.list").read_text())
    out = output_dir / "screenshots"
    out.mkdir(exist_ok=True)
    subprocess.run(["gowitness", "file", "-f", str(urls_file), "-P", str(out)], check=False)

def _run_nuclei(web_dir, output_dir):
    for scheme in ["http", "https"]:
        lst = web_dir / f"{scheme}.url.list"
        if lst.stat().st_size > 0:
            out = output_dir / f"nuclei_{scheme}.txt"
            subprocess.run(["nuclei", "-l", str(lst), "-o", str(out)], check=False)

def _serve_dashboard(web_dir):
    import http.server, socketserver, threading, webbrowser, time
    os.chdir(web_dir)
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}/dashboard.html"
        console.print(f"[green]Dashboard: {url}[/green]")
        webbrowser.open(url)
        httpd.serve_forever()
