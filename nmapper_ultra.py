#!/usr/bin/env python3
"""
nmapper_ultra.py
Usage examples:
  # Default (staged, aggressive included without -O):
  python3 nmapPyDumpPlus_with_scanner.py --targets-file targets.txt --outputDir ./pyDumpOutput

  # Discovery-only (skip aggressive/service follow-ups):
  python3 nmapPyDumpPlus_with_scanner.py --targets-file targets.txt --outputDir ./pyDumpOutput --discovery-only

  # Include OS detection in aggressive TCP scan (adds -O):
  python3 nmapPyDumpPlus_with_scanner.py --targets-file targets.txt --outputDir ./pyDumpOutput --include-os

  # Tweak UDP retry/backoff behavior (default: delay=0.5s, backoff=2.0x, retries=2):
  python3 nmapPyDumpPlus_with_scanner.py --targets-file targets.txt --outputDir ./pyDumpOutput --udp-delay 1.0 --udp-backoff 3.0 --udp-retries 3
"""

import argparse
import os
import subprocess
import sys
import datetime
import multiprocessing
import json
import threading
import time
import http.server
import socketserver
from pathlib import Path
import csv
import ipaddress
import xml.etree.ElementTree as ET
import html

includeTcpwrapped = False


def sanitize_filename(filename):
    return "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in filename)


class NmapHost:
    def __init__(self):
        self.address = None
        self.hostname = None
        self.ports = []
        self.services = []

    def set_address(self, address):
        self.address = address

    def set_hostname(self, hostname):
        self.hostname = hostname

    def add_port(self, port):
        self.ports.append(port)

    def add_service(self, service_info):
        self.services.append(service_info)


# ---------------------- Persistent state helpers ----------------------

def load_state(state_file):
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        'hosts': {},
        'ports_seen': {},
        'services_seen': {},
        'versions_seen': {},
        'services_with_ports_seen': {},
        'http_urls': [],
        'https_urls': [],
        'ips_listed': [],
        'hostnames_listed': [],
        'ports_csv_seen': {},
        'up_seen': []
    }


def save_state(state, state_file):
    out = _to_serializable(state)
    with open(state_file, 'w') as f:
        json.dump(out, f)


def _to_sets(state):
    state['http_urls'] = set(state.get('http_urls', []))
    state['https_urls'] = set(state.get('https_urls', []))
    state['ips_listed'] = set(state.get('ips_listed', []))
    state['hostnames_listed'] = set(state.get('hostnames_listed', []))
    for key in ('ports_seen', 'services_seen', 'versions_seen', 'services_with_ports_seen', 'ports_csv_seen'):
        state.setdefault(key, {})
        for k, v in list(state[key].items()):
            state[key][k] = set(v) if isinstance(v, list) else set(v)
    state['up_seen'] = set(state.get('up_seen', []))


def _to_serializable(state):
    s = dict(state)
    s['http_urls'] = list(s.get('http_urls', []))
    s['https_urls'] = list(s.get('https_urls', []))
    s['ips_listed'] = list(s.get('ips_listed', []))
    s['hostnames_listed'] = list(s.get('hostnames_listed', []))
    for key in ('ports_seen', 'services_seen', 'versions_seen', 'services_with_ports_seen', 'ports_csv_seen'):
        new = {}
        for k, v in s.get(key, {}).items():
            new[k] = list(v)
        s[key] = new
    s['up_seen'] = list(s.get('up_seen', []))
    return s


# ---------------------- XML parsing ----------------------

def parse_nmap_xml(files):
    nmap_host_list = []

    for file in files:
        if not file or not os.path.isfile(file):
            continue
        try:
            tree = ET.parse(file)
            root = tree.getroot()

            for host_elem in root.findall('host'):
                nmap_host = NmapHost()
                try:
                    address_elem = host_elem.find("address[@addrtype='ipv4']")
                    if address_elem is not None:
                        ip_address = address_elem.get("addr")
                        nmap_host.set_address(ip_address)

                    hostname_elem = host_elem.find("hostnames/hostname")
                    if hostname_elem is not None:
                        nmap_host.set_hostname(hostname_elem.get("name"))

                    for port_elem in host_elem.findall("ports/port"):
                        state_elem = port_elem.find("state")
                        if state_elem is not None and state_elem.get("state") == "open":
                            port_id = port_elem.get("portid")
                            service_elem = port_elem.find("service")

                            if not includeTcpwrapped and service_elem is not None and service_elem.get("name") == "tcpwrapped":
                                continue

                            nmap_host.add_port(port_id)

                            if service_elem is not None:
                                service_name = service_elem.get("name", "unknown")
                                product = service_elem.get("product", "")
                                version = service_elem.get("version", "")
                                tunnel = service_elem.get("tunnel", "")

                                if tunnel == "ssl" and service_name in ["http", "https"] and "80" not in str(port_id):
                                    service_name = "https"

                                if product or version:
                                    full_version = f"{service_name}_{product}_{version}".strip("_")
                                else:
                                    full_version = service_name

                                nmap_host.add_service((service_name, port_id, full_version))

                    if nmap_host.address:
                        nmap_host_list.append(nmap_host)

                except Exception as e:
                    print(f"Warning: Error processing host record in file {file}: {e}. Continuing.")

        except ET.ParseError as e:
            print(f"Warning: Error parsing XML file {file}: {e}. Skipping file.")

    nmap_host_list.sort(key=lambda host: (list(map(int, host.address.split('.'))), host.hostname or host.address))
    return nmap_host_list


# ---------------------- Append-only writers ----------------------

def append_to_file(path, lines):
    if not lines:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a') as f:
        for line in lines:
            f.write(f"{line}\n")


def append_ports_for_host(host, output_dir, state):
    ports_dir = os.path.join(output_dir, 'ports')
    os.makedirs(ports_dir, exist_ok=True)
    for port in host.ports:
        port_file = os.path.join(ports_dir, f"{port}")
        ips_for_port = state['ports_seen'].setdefault(port, set())
        if host.address not in ips_for_port:
            append_to_file(port_file, [host.address])
            ips_for_port.add(host.address)


def append_services_versions(host, output_dir, state):
    services_dir = os.path.join(output_dir, 'services')
    versions_dir = os.path.join(output_dir, 'versions')
    services_with_ports_dir = os.path.join(output_dir, 'servicesWithPorts')
    os.makedirs(services_dir, exist_ok=True)
    os.makedirs(versions_dir, exist_ok=True)
    os.makedirs(services_with_ports_dir, exist_ok=True)

    for service in host.services:
        service_name, port, full_version = service
        san_service = sanitize_filename(service_name)
        san_version = sanitize_filename(full_version)
        san_port = sanitize_filename(port)

        service_file = os.path.join(services_dir, san_service)
        sips = state['services_seen'].setdefault(san_service, set())
        if host.address not in sips:
            append_to_file(service_file, [f"{host.address}:{port}"])
            sips.add(host.address)

        version_file = os.path.join(versions_dir, san_version)
        vips = state['versions_seen'].setdefault(san_version, set())
        if host.address not in vips:
            append_to_file(version_file, [host.address])
            vips.add(host.address)

        swp_file = os.path.join(services_with_ports_dir, f"{san_service}_{san_port}")
        swp_ips = state['services_with_ports_seen'].setdefault(f"{san_service}_{san_port}", set())
        if host.address not in swp_ips:
            append_to_file(swp_file, [host.address])
            swp_ips.add(host.address)


def append_web_entries(host, output_dir, state):
    web_html_dir = os.path.join(output_dir, 'webHTML')
    os.makedirs(web_html_dir, exist_ok=True)
    parsed_web_servers_html = os.path.join(web_html_dir, 'parsedWebServers.html')
    http_url_list = os.path.join(web_html_dir, 'http.url.list')
    https_url_list = os.path.join(web_html_dir, 'https.url.list')
    total_url_hostname_list = os.path.join(web_html_dir, 'total.url.hostname.list')
    total_url_ip_list = os.path.join(web_html_dir, 'total.url.ip.list')

    if not os.path.exists(parsed_web_servers_html):
        with open(parsed_web_servers_html, 'w') as html_file:
            html_file.write("""<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px}</style></head><body><h2>Parsed Web Servers</h2><table><thead><tr><td>IP Address</td><td>Links</td><td>Port</td><td>Service Info</td></tr></thead><tbody>""")

    new_http = []
    new_https = []
    new_total_hostnames = []
    new_total_ips = []

    for service in host.services:
        service_name, port, full_version = service
        if service_name in ['https', 'https-alt']:
            url_prefix = 'https'
        elif service_name in ['http', 'http-alt']:
            url_prefix = 'http'
        else:
            continue

        url = f"{url_prefix}://{host.address}:{port}"
        urls_state = state['https_urls'] if url_prefix == 'https' else state['http_urls']
        if url not in urls_state:
            row = f"<tr><td>{html.escape(host.address)}</td><td><a href=\"{html.escape(url)}\" target=\"_blank\"> {url_prefix.upper()} </a></td><td>{port}</td><td>{html.escape(full_version)}</td></tr>"
            with open(parsed_web_servers_html, 'a') as hf:
                hf.write(row)
            urls_state.add(url)
            if url_prefix == 'https':
                new_https.append(url)
            else:
                new_http.append(url)
            if host.hostname:
                new_total_hostnames.append(f"{url_prefix}://{host.hostname.lower()}:{port}")
            new_total_ips.append(f"{url_prefix}://{host.address}:{port}")

    append_to_file(http_url_list, new_http)
    append_to_file(https_url_list, new_https)
    if new_total_hostnames:
        append_to_file(total_url_hostname_list, new_total_hostnames)
    if new_total_ips:
        append_to_file(total_url_ip_list, new_total_ips)


def finalize_html(parsed_web_servers_html):
    if not os.path.exists(parsed_web_servers_html):
        return
    with open(parsed_web_servers_html, 'rb') as f:
        content = f.read().decode(errors='ignore')
    if '</tbody>' not in content:
        with open(parsed_web_servers_html, 'a') as f:
            f.write('</tbody></table></body></html>')


def append_csvs_and_lists(host, output_dir, state):
    ports_csv = os.path.join(output_dir, 'all.ports.up.csv')
    up_csv = os.path.join(output_dir, 'all.up.csv')
    ips_up = os.path.join(output_dir, 'ips.up.list')
    hostnames_up = os.path.join(output_dir, 'hostnames.up.list')

    ports_entries = []
    for port in host.ports:
        ports_entries.append((host.address, (host.hostname or host.address).lower(), port))

    for ip, hostname, port in ports_entries:
        port_key = state['ports_csv_seen'].setdefault(port, set())
        rec = f"{ip},{hostname},{port}"
        if ip not in port_key:
            append_to_file(ports_csv, [rec])
            port_key.add(ip)

    has_open = bool(host.ports)
    if has_open:
        up_key = state.setdefault('up_seen', set())
        if host.address not in up_key:
            rec2 = f"{host.address},{(host.hostname or host.address).lower()}"
            append_to_file(up_csv, [rec2])
            append_to_file(ips_up, [host.address])
            if host.hostname:
                append_to_file(hostnames_up, [host.hostname.strip().lower()])
            up_key.add(host.address)


# ---------------------- Dashboard ----------------------

def write_dashboard(output_dir, state):
    web_html_dir = os.path.join(output_dir, 'webHTML')
    os.makedirs(web_html_dir, exist_ok=True)
    dashboard = os.path.join(web_html_dir, 'dashboard.html')

    total_hosts = len(state['hosts'])
    total_ports = sum(len(set(h.get('ports', []))) for h in state['hosts'].values())
    total_services = sum(len(h.get('services', [])) for h in state['hosts'].values())

    rows = []
    for ip, info in state['hosts'].items():
        rows.append(f"<tr><td>{html.escape(ip)}</td><td>{html.escape(info.get('hostname') or '')}</td><td>{len(set(info.get('ports', [])))}</td><td>{len(info.get('services', []))}</td></tr>")

    html_content = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset=\"utf-8\">
        <title>Nmap PyDumpPlus Dashboard</title>
        <style>
          body{{font-family: Arial, Helvetica, sans-serif; margin: 20px}}
          table{{border-collapse: collapse; width:100%}}
          td,th{{border:1px solid #ccc;padding:6px}}
          thead th{{background:#eee}}
        </style>
      </head>
      <body>
        <h1>Scan Dashboard</h1>
        <p>Hosts: {total_hosts} &nbsp; Open ports: {total_ports} &nbsp; Service records: {total_services}</p>
        <table>
          <thead><tr><th>IP</th><th>Hostname</th><th># Ports</th><th># Services</th></tr></thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        <p>Updated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>
      </body>
    </html>
    """

    with open(dashboard, 'w') as f:
        f.write(html_content)


# ---------------------- Nmap invocation helpers ----------------------

def run_nmap_subprocess(cmd, timeout=None):
    try:
        print('Running:', ' '.join(cmd))
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if completed.returncode != 0:
            print(f"nmap exited with code {completed.returncode}. stderr:\n{completed.stderr.decode(errors='ignore')}")
        return completed.returncode
    except subprocess.TimeoutExpired:
        print('nmap timed out for command:', ' '.join(cmd))
        return -1
    except FileNotFoundError:
        print('Error: nmap binary not found. Install nmap and ensure it is on your PATH.')
        sys.exit(1)


# ---------------------- Staged scan builders ----------------------

def build_tcp_discovery_cmd(target, xml_out, extra_args):
    base = ["nmap", "-oX", xml_out, "-p-", "-T4", "-sS"]
    base += extra_args or []
    if os.path.exists(target):
        base += ['-iL', target]
    else:
        base.append(target)
    return base


def build_tcp_aggressive_cmd(target, ports, xml_out, extra_args, include_os=False):
    # aggressive: -T4 -sC -sV -A plus -p <ports>
    base = ["nmap", "-oX", xml_out, "-T4", "-sC", "-sV", "-A", "-p", ports]
    if include_os:
        base.insert(4, '-O')  # insert -O after -T4 for readability; order not critical
    base += extra_args or []
    if os.path.exists(target):
        base += ['-iL', target]
    else:
        base.append(target)
    return base


def build_udp_discovery_cmd(target, xml_out, extra_args):
    base = ["nmap", "-oX", xml_out, "-sU", "-p-", "-T3"]
    base += extra_args or []
    if os.path.exists(target):
        base += ['-iL', target]
    else:
        base.append(target)
    return base


def build_udp_service_cmd(target, ports, xml_out, extra_args):
    base = ["nmap", "-oX", xml_out, "-sU", "-sV", "-p", ports, "-T3"]
    base += extra_args or []
    if os.path.exists(target):
        base += ['-iL', target]
    else:
        base.append(target)
    return base


# ---------------------- Staged scanning for a single target (with UDP backoff) ----------------------

def run_target_staged(target, output_dir, extra_args=None, discovery_only=False, udp_delay=0.5, udp_backoff=2.0, udp_retries=2, include_os=False):
    xml_out_dir = os.path.join(output_dir, 'nmap_xml')
    os.makedirs(xml_out_dir, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')

    created = []

    # 1) TCP discovery (full port) - always run
    tcp_disc_xml = os.path.join(xml_out_dir, f"nmap_{ts}_tcp_discovery.xml")
    cmd = build_tcp_discovery_cmd(target, tcp_disc_xml, extra_args)
    rc = run_nmap_subprocess(cmd)
    if rc == 0 and os.path.exists(tcp_disc_xml):
        created.append(tcp_disc_xml)
        hosts = parse_nmap_xml([tcp_disc_xml])
        discovered_tcp_ports = []
        for h in hosts:
            discovered_tcp_ports.extend(h.ports)
    else:
        discovered_tcp_ports = []

    # If discovery-only, skip follow-up
    if not discovery_only and discovered_tcp_ports:
        # 2) TCP aggressive/service scan on discovered ports
        ports_csv = ','.join(sorted(set(discovered_tcp_ports), key=lambda x: int(x)))
        tcp_aggr_xml = os.path.join(xml_out_dir, f"nmap_{ts}_tcp_aggressive.xml")
        cmd2 = build_tcp_aggressive_cmd(target, ports_csv, tcp_aggr_xml, extra_args, include_os=include_os)
        rc2 = run_nmap_subprocess(cmd2)
        if rc2 == 0 and os.path.exists(tcp_aggr_xml):
            created.append(tcp_aggr_xml)

    # 3) UDP discovery (full port) - always run
    udp_disc_xml = os.path.join(xml_out_dir, f"nmap_{ts}_udp_discovery.xml")
    cmd3 = build_udp_discovery_cmd(target, udp_disc_xml, extra_args)
    rc3 = run_nmap_subprocess(cmd3)
    discovered_udp_ports = []
    if rc3 == 0 and os.path.exists(udp_disc_xml):
        created.append(udp_disc_xml)
        hosts_u = parse_nmap_xml([udp_disc_xml])
        for h in hosts_u:
            discovered_udp_ports.extend(h.ports)

    # 4) UDP service/version scan on discovered UDP ports (if any)
    if not discovery_only and discovered_udp_ports:
        ports_csv_u = ','.join(sorted(set(discovered_udp_ports), key=lambda x: int(x)))
        udp_service_xml = os.path.join(xml_out_dir, f"nmap_{ts}_udp_service.xml")
        # attempt with retries/backoff to reduce false negatives
        attempt = 0
        delay = udp_delay
        success = False
        while attempt <= udp_retries and not success:
            cmd4 = build_udp_service_cmd(target, ports_csv_u, udp_service_xml, extra_args)
            rc4 = run_nmap_subprocess(cmd4)
            if rc4 == 0 and os.path.exists(udp_service_xml):
                created.append(udp_service_xml)
                success = True
                break
            attempt += 1
            if attempt <= udp_retries:
                print(f"UDP service scan attempt {attempt} failed or produced no result, sleeping {delay}s before retry")
                time.sleep(delay)
                delay *= udp_backoff

    return created


# ---------------------- Orchestration across targets ----------------------

def run_scans(targets_arg, output_dir, parallel=1, extra_args=None, serve_dashboard=False, discovery_only=False, udp_delay=0.5, udp_backoff=2.0, udp_retries=2, include_os=False):
    xml_out_dir = os.path.join(output_dir, 'nmap_xml')
    os.makedirs(xml_out_dir, exist_ok=True)

    if isinstance(targets_arg, str) and os.path.exists(targets_arg):
        with open(targets_arg, 'r') as f:
            targets_list = [l.strip() for l in f if l.strip()]
    elif isinstance(targets_arg, str) and ',' in targets_arg:
        targets_list = [t.strip() for t in targets_arg.split(',') if t.strip()]
    elif isinstance(targets_arg, (list, tuple)):
        targets_list = list(targets_arg)
    else:
        targets_list = [targets_arg]

    total_jobs = len(targets_list)
    completed_jobs = 0

    state_file = os.path.join(output_dir, 'state.json')
    state = load_state(state_file)
    _to_sets(state)

    server_thread = None
    if serve_dashboard:
        def serve():
            os.chdir(output_dir)
            Handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("0.0.0.0", 8000), Handler) as httpd:
                print("Serving output directory at http://0.0.0.0:8000/")
                httpd.serve_forever()
        server_thread = threading.Thread(target=serve, daemon=True)
        server_thread.start()

    def worker_target(t):
        nonlocal completed_jobs
        created_xmls = run_target_staged(t, output_dir, extra_args=extra_args, discovery_only=discovery_only, udp_delay=udp_delay, udp_backoff=udp_backoff, udp_retries=udp_retries, include_os=include_os)
        for xml in created_xmls:
            new_hosts = parse_nmap_xml([xml])
            for nh in new_hosts:
                existing = state['hosts'].get(nh.address)
                if not existing:
                    state['hosts'][nh.address] = {
                        'hostname': nh.hostname,
                        'ports': nh.ports[:],
                        'services': [list(s) for s in nh.services]
                    }
                    append_ports_for_host(nh, output_dir, state)
                    append_services_versions(nh, output_dir, state)
                    append_web_entries(nh, output_dir, state)
                    append_csvs_and_lists(nh, output_dir, state)
                else:
                    new_ports = [p for p in nh.ports if p not in existing.get('ports', [])]
                    if new_ports:
                        for p in new_ports:
                            existing.setdefault('ports', []).append(p)
                        append_ports_for_host(nh, output_dir, state)
                    existing_services = set(tuple(s) for s in existing.get('services', []))
                    added_services = [s for s in nh.services if tuple(s) not in existing_services]
                    if added_services:
                        existing.setdefault('services', []).extend([list(s) for s in added_services])
                        append_services_versions(nh, output_dir, state)
                        append_web_entries(nh, output_dir, state)
                        append_csvs_and_lists(nh, output_dir, state)

        state['ips_listed'].update([ip for ip in state['hosts'].keys()])
        save_state(state, state_file)
        write_dashboard(output_dir, state)

        completed_jobs += 1
        total_hosts = len(state['hosts'])
        total_ports = sum(len(set(h.get('ports', []))) for h in state['hosts'].values())
        total_services = sum(len(h.get('services', [])) for h in state['hosts'].values())
        progress_bar = ('#' * int((completed_jobs/total_jobs) * 40)).ljust(40)
        print(f"Job {completed_jobs}/{total_jobs} [{progress_bar}] hosts={total_hosts} ports={total_ports} services={total_services}")

    if parallel and parallel > 1:
        with multiprocessing.Pool(processes=parallel) as pool:
            pool.map(worker_target, targets_list)
    else:
        for t in targets_list:
            worker_target(t)

    finalize_html(os.path.join(output_dir, 'webHTML', 'parsedWebServers.html'))
    write_dashboard(output_dir, state)
    save_state(state, state_file)

    print(f"Scans complete. XML files in {os.path.join(output_dir, 'nmap_xml')}")


# ---------------------- Full rebuild ----------------------

def rebuild_from_xml(output_dir):
    xml_dir = os.path.join(output_dir, 'nmap_xml')
    if not os.path.isdir(xml_dir):
        print('No nmap_xml directory found for rebuild.')
        return
    xml_files = [os.path.join(xml_dir, f) for f in os.listdir(xml_dir) if f.endswith('.xml')]
    if not xml_files:
        print('No XML files to rebuild from.')
        return

    for d in ('ports', 'services', 'versions', 'servicesWithPorts', 'webHTML'):
        path = os.path.join(output_dir, d)
        if os.path.isdir(path):
            for f in os.listdir(path):
                try:
                    os.remove(os.path.join(path, f))
                except Exception:
                    pass

    hosts = parse_nmap_xml(xml_files)
    state = {
        'hosts': {},
        'ports_seen': {},
        'services_seen': {},
        'versions_seen': {},
        'services_with_ports_seen': {},
        'http_urls': [],
        'https_urls': [],
        'ips_listed': [],
        'hostnames_listed': [],
        'ports_csv_seen': {},
        'up_seen': []
    }
    _to_sets(state)

    for h in hosts:
        state['hosts'][h.address] = {
            'hostname': h.hostname,
            'ports': h.ports[:],
            'services': [list(s) for s in h.services]
        }
        append_ports_for_host(h, output_dir, state)
        append_services_versions(h, output_dir, state)
        append_web_entries(h, output_dir, state)
        append_csvs_and_lists(h, output_dir, state)

    finalize_html(os.path.join(output_dir, 'webHTML', 'parsedWebServers.html'))
    write_dashboard(output_dir, state)
    save_state(state, os.path.join(output_dir, 'state.json'))
    print('Rebuild complete.')


# ---------------------- CLI ----------------------

def create_directory_structure(output_dir):
    directories = ["ports", "services", "versions", "servicesWithPorts", "webHTML", 'nmap_xml']
    for directory in directories:
        path = os.path.join(output_dir, directory)
        os.makedirs(path, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description='nmapPyDumpPlus with staged scans (full-port discovery then targeted scans)')
    parser.add_argument('--targets-file', help='Path to file with targets (one per line) OR a single target string.')
    parser.add_argument('--targets', help='Comma-separated target list, e.g. 10.0.0.1,10.0.0.2')
    parser.add_argument('--outputDir', default='pyDumpOutput', help='Output directory')
    parser.add_argument('--parallel', type=int, default=1, help='Number of parallel target workers')
    parser.add_argument('--only-scan', action='store_true', help='Only run scans, do not build reports (still create XMLs)')
    parser.add_argument('--extra-nmap-args', help='Additional space-separated args for nmap (wrap in quotes)')
    parser.add_argument('--rebuild', action='store_true', help='Force full rebuild from all XMLs in outputDir/nmap_xml')
    parser.add_argument('--serve-dashboard', action='store_true', help='Serve the outputDir over HTTP on port 8000 for dashboard viewing')
    parser.add_argument('--discovery-only', action='store_true', help='Run discovery stages only (skip aggressive/service follow-ups)')
    parser.add_argument('--udp-delay', type=float, default=0.5, help='Initial delay (seconds) before retrying UDP service scan')
    parser.add_argument('--udp-backoff', type=float, default=2.0, help='Backoff multiplier for UDP retry delay')
    parser.add_argument('--udp-retries', type=int, default=2, help='Number of retries for UDP service scan on failure')
    parser.add_argument('--include-os', action='store_true', help='Include OS detection (-O) in aggressive TCP scan')

    args = parser.parse_args()

    output_dir = args.outputDir
    create_directory_structure(output_dir)

    extra_args = args.extra_nmap_args.split() if args.extra_nmap_args else []

    if args.rebuild:
        rebuild_from_xml(output_dir)
        return

    targets_arg = args.targets_file or args.targets
    if not targets_arg:
        print('No targets provided. Use --targets-file or --targets')
        sys.exit(1)

    run_scans(targets_arg,
              output_dir,
              parallel=args.parallel,
              extra_args=extra_args,
              serve_dashboard=args.serve_dashboard,
              discovery_only=args.discovery_only,
              udp_delay=args.udp_delay,
              udp_backoff=args.udp_backoff,
              udp_retries=args.udp_retries,
              include_os=args.include_os)

    if args.only_scan:
        print('Scan phase complete. XML outputs are in', os.path.join(output_dir, 'nmap_xml'))
        return

    print('Done. Dashboard is in', os.path.join(output_dir, 'webHTML', 'dashboard.html'))


if __name__ == '__main__':
    main()
