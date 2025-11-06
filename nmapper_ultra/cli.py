# nmapper_ultra/cli.py
import typer
from pathlib import Path
from typing import Optional, List

from .scanner import scan_host
from .parser import parse_all
from .reporter import generate_reports
from .state import ScanState
from .utils import expand_targets, console
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

app = typer.Typer(
    help="Advanced Nmap Automation & Reporting",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def main(
    # ────── Input ──────
    targets_file: Optional[Path] = typer.Option(
        None, "--targets-file", help="File with one target per line"
    ),
    targets: Optional[str] = typer.Option(
        None, "--targets", help="Comma‑separated targets or CIDRs"
    ),

    # ────── Output ──────
    output_dir: Path = typer.Option(
        "pyDumpOutput", "--outputDir", help="Output directory"
    ),

    # ────── Parallelism ──────
    parallel: int = typer.Option(8, "--parallel", min=1, max=64),

    # ────── Scan options ──────
    discovery_only: bool = typer.Option(False, "--discovery-only"),
    include_os: bool = typer.Option(False, "--include-os"),
    udp_delay: float = typer.Option(1.0, "--udp-delay"),
    udp_backoff: float = typer.Option(2.0, "--udp-backoff"),
    udp_retries: int = typer.Option(1, "--udp-retries"),
    skip_known_up: bool = typer.Option(False, "--skip-known-up"),
    extra_nmap_args: Optional[List[str]] = typer.Option(
        None, "--extra-nmap-args", help="Extra nmap args (quoted list)"
    ),

    # ────── Post‑processing ──────
    screenshots: bool = typer.Option(False, "--screenshots"),
    nuclei: bool = typer.Option(False, "--nuclei"),
    serve_dashboard: bool = typer.Option(False, "--serve-dashboard"),
):
    """
    Run a full Nmap scan with optional screenshots, Nuclei, and live dashboard.
    """

    # ────── 1. Validate input ──────
    if not targets_file and not targets:
        console.print("[red]Error: Provide --targets-file or --targets[/red]")
        raise typer.Exit(code=1)

    # ────── 2. Load targets ──────
    raw_targets: List[str] = []
    if targets_file:
        raw_targets.extend(
            line.strip()
            for line in targets_file.read_text().splitlines()
            if line.strip()
        )
    if targets:
        raw_targets.extend(t.strip() for t in targets.split(",") if t.strip())

    all_targets = expand_targets(raw_targets)

    # ────── 3. Prepare output & state ──────
    output_dir.mkdir(parents=True, exist_ok=True)
    state = ScanState(output_dir / "state.json")

    if skip_known_up:
        all_targets = [
            t for t in all_targets if not state.is_completed(t)
        ]

    if not all_targets:
        console.print("[green]All targets already scanned.[/green]")
        return

    # ────── 4. Build args dict for downstream functions ──────
    args = {
        "targets_file": targets_file,
        "targets": targets,
        "output_dir": output_dir,
        "parallel": parallel,
        "discovery_only": discovery_only,
        "include_os": include_os,
        "udp_delay": udp_delay,
        "udp_backoff": udp_backoff,
        "udp_retries": udp_retries,
        "skip_known_up": skip_known_up,
        "extra_nmap_args": extra_nmap_args or [],
        "screenshots": screenshots,
        "nuclei": nuclei,
        "serve_dashboard": serve_dashboard,
    }

    # ────── 5. Run scans in parallel ──────
    with ThreadPoolExecutor(max_workers=parallel) as executor:
        futures = [
            executor.submit(scan_host, target, args, state, output_dir)
            for target in all_targets
        ]
        for _ in tqdm(
            as_completed(futures),
            total=len(futures),
            desc="Scanning",
            unit="host",
        ):
            pass

        # ────── 6. Parse XML results ──────
    xml_dir = output_dir / "nmap_xml"
    console.print(f"[blue]Looking for XML in: {xml_dir.resolve()}[/blue]")
    xml_files = list(xml_dir.glob("*.xml"))
    console.print(f"[blue]Found {len(xml_files)} XML files[/blue]")

    if not xml_files:
        console.print("[red]No XML files found! Check nmap output.[/red]")
        hosts = []
    else:
        hosts = parse_all(xml_dir, parallel)

    # ────── 7. Generate reports ──────
    generate_reports(hosts, output_dir, args)


# ────── Optional: keep old `scan` sub‑command for backward compat ──────
@app.command(hidden=True)
def scan():
    """Legacy alias – use the default command instead."""
    console.print("[yellow]Warning: 'scan' subcommand is deprecated. Use: nmapper-ultra --targets ...[/yellow]")
    raise typer.Exit(code=1)
