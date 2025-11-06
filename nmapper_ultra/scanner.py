# nmapper_ultra/scanner.py
import time
import subprocess
from pathlib import Path
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from .utils import nmap_cmd, console
from .state import ScanState

class NmapBuilder:
    def __init__(self, target: str, xml_path: Path):
        self.cmd = ["nmap", "-oX", str(xml_path), target]

    def aggressive(self):
        self.cmd[1:1] = ["-sCV", "-A"]
        return self

    def os_detect(self):
        self.cmd.insert(-2, "-O")
        return self

    def udp(self):
        self.cmd[1:1] = ["-sU", "--top-ports=100"]
        return self

    def discovery(self):
        self.cmd = ["nmap", "-sn", "-oX", str(self.cmd[-2]), self.cmd[-1]]
        return self

    def extra(self, args: List[str]):
        self.cmd[1:-2] += args
        return self

    def build(self) -> List[str]:
        return self.cmd

def scan_host(target: str, args, state: ScanState, output_dir: Path):
    try:
        # Skip known
        if args.get("skip_known_up") and state.is_completed(target):
            console.print(f"[yellow]Skipping already scanned: {target}[/yellow]")
            return

        xml_dir = output_dir / "nmap_xml"
        xml_dir.mkdir(parents=True, exist_ok=True)
        safe_target = target.replace('/', '_').replace('\\', '_')
        xml_file = xml_dir / f"{safe_target}.xml"

        # Build command
        builder = NmapBuilder(target, xml_file)
        if args.get("discovery_only"):
            builder.discovery()
        else:
            builder.aggressive()
            if args.get("include_os"):
                builder.os_detect()
            if args.get("extra_nmap_args"):
                builder.extra(args.get("extra_nmap_args", []))

        cmd = builder.build()
        console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")

        # Run nmap
        with nmap_cmd(cmd) as stdout:
            console.print(f"[green]Scan completed: {target}[/green]")

        # UDP retry
        if not args.get("discovery_only") and args.get("udp_retries", 0) > 0:
            udp_file = xml_dir / f"{safe_target}_udp.xml"
            for attempt in range(1, args.get("udp_retries", 1) + 1):
                delay = args.get("udp_delay", 1.0) * (args.get("udp_backoff", 2.0) ** (attempt - 1))
                if attempt > 1:
                    time.sleep(delay)
                udp_cmd = NmapBuilder(target, udp_file).udp().build()
                try:
                    with nmap_cmd(udp_cmd):
                        console.print(f"[green]UDP scan succeeded on attempt {attempt}[/green]")
                        break
                except Exception as e:
                    console.print(f"[yellow]UDP retry {attempt} failed: {e}[/yellow]")

        # Mark done
        state.mark_completed(target, str(xml_file))

    except Exception as e:
        console.print(f"[red]FATAL ERROR scanning {target}: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
