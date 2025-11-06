# nmapper_ultra/utils.py
import ipaddress
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List
from rich.console import Console

console = Console()

@contextmanager
def nmap_cmd(*args, **kwargs) -> Generator[str, None, None]:
    proc = subprocess.Popen(
        *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Nmap failed: {stderr.strip()}")
    yield stdout

def expand_targets(raw_targets: List[str]) -> List[str]:
    expanded = set()
    for t in raw_targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            expanded.update(str(ip) for ip in net.hosts())
        except ValueError:
            expanded.add(t.strip())
    return sorted(expanded)

def which(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0
