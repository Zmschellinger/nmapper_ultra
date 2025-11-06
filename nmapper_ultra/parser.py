# nmapper_ultra/parser.py
from lxml import etree
from pathlib import Path
from typing import List, Dict
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed
from tqdm import tqdm
from .utils import console

def parse_xml_file(xml_path: Path) -> List[Dict]:
    try:
        if not xml_path.exists() or xml_path.stat().st_size == 0:
            console.print(f"[yellow]Empty or missing: {xml_path}[/yellow]")
            return []

        tree = etree.parse(str(xml_path))
        root = tree.getroot()
        hosts = []

        for host in root.findall(".//host"):
            # Skip down hosts
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            # IP
            addr = host.find("address")
            if addr is None:
                continue
            ip = addr.get("addr")

            # Hostname
            hostname_elem = host.find(".//hostname")
            hostname = hostname_elem.get("name") if hostname_elem is not None else ""

            # Ports
            ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                portid = port.get("portid")
                protocol = port.get("protocol")
                service = port.find("service")
                name = service.get("name") if service is not None else "unknown"
                product = service.get("product") or ""
                version = service.get("version") or ""

                ports.append({
                    "port": portid,
                    "protocol": protocol,
                    "service": name,
                    "product": product,
                    "version": version
                })

            # OS
            os_name = ""
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports,
                "os": os_name
            })

        return hosts

    except Exception as e:
        console.print(f"[red]CRITICAL: Failed to parse {xml_path}: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        return []

def parse_all(xml_dir: Path, workers: int) -> List[Dict]:
    xml_files = list(xml_dir.glob("*.xml"))
    if not xml_files:
        console.print(f"[yellow]No XML files found in {xml_dir}[/yellow]")
        return []

    results = {}
    console.print(f"[blue]Parsing {len(xml_files)} XML files...[/blue]")

    with ProcessPoolExecutor(max_workers=workers) as exec:
        futures = {exec.submit(parse_xml_file, f): f for f in xml_files}

        for future in tqdm(
            as_completed(futures),
            total=len(futures),
            desc="Parsing XML",
            unit="file",
        ):
            file_path = futures[future]
            try:
                hosts = future.result()
                for host in hosts:
                    ip = host["ip"]
                    if ip not in results:
                        results[ip] = host
                    else:
                        # Merge ports
                        results[ip]["ports"].extend(host["ports"])
                        if host["os"] and not results[ip]["os"]:
                            results[ip]["os"] = host["os"]
            except Exception as e:
                console.print(f"[red]Failed to parse {file_path.name}: {e}[/red]")
                import traceback
                console.print(traceback.format_exc())

    parsed_hosts = list(results.values())
    console.print(f"[green]Parsed {len(parsed_hosts)} hosts[/green]")
    return parsed_hosts
