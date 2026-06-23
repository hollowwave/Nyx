#!/usr/bin/env python3
"""
Nyx - Automated OSINT & Recon Pipeline
Dark. Fast. Modular.
"""

import argparse
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich import box

console = Console()

BANNER = """
[bold red]
  ▄▄▄    ▄▄▄▄  ▄▄▄    ▄▄▄    ▄▄▄    ▄▄▄  
   ▒▒▒    ░░▌   ░░▌  ▀ ▀█░  ░░▌ ▀  ▀█░ 
   ▐░░▌   ▐░    ▐▒░    ▐░▌   ▐▒░    ▐░▌ 
    ██▀▄  ▐█     ▓▒▒  ███     ▓▒▒  ███
    ░▌▀▀░░▐█       ▓▒░░         ▓▒░░    
    ▒▌  ▒▒░▌        ▓▒        ▒▓▒  ░▓▒  
   ▐▓▌   ▓▒▒        █▓       ▐▓▌    ▒▓▌ 
   ██▓    ▓▓▌      ▐██▌      ██ ▄   ▐█▓ 
  ▀▀▀▀▀    ▀▀      ▀▀▀▀       ▀▀ ▀   ▀▀▀[/bold red]"""

VERSION   = "0.6.0"
CODENAME  = "Erebus"
MODULES   = ["dns", "whois", "ports", "tech", "crtsh", "breach", "usernames"]
BUILT_IN  = ["dns", "whois", "ports", "tech", "crtsh", "breach"]


def print_banner():
    console.print(BANNER)
    console.print(
        f"  [dim]v{VERSION} [{CODENAME}][/dim]  "
        f"[dim]Automated OSINT & Recon Pipeline[/dim]\n"
    )


def print_target_info(args):
    """Clean target/module display before scan starts."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim cyan", justify="right")
    grid.add_column(style="white")

    grid.add_row("TARGET",  f"[bold green]{args.target}[/bold green]")
    grid.add_row("MODULES", f"[yellow]{' → '.join(args.modules)}[/yellow]")
    grid.add_row("OUTPUT",  f"[yellow]{args.output}[/yellow]")
    if getattr(args, "hibp_key", None):
        grid.add_row("HIBP KEY", "[green]provided[/green]")
    if args.wordlist:
        grid.add_row("WORDLIST", args.wordlist)

    console.print(Panel(grid, border_style="dim red", expand=False))
    console.print()


def print_summary(results: dict, elapsed: float):
    """Print a final summary table of what was found."""
    console.print()
    console.rule("[bold red]SCAN COMPLETE[/bold red]")
    console.print()

    t = Table(box=box.SIMPLE, header_style="bold magenta", show_header=True)
    t.add_column("Module",   style="cyan",  width=16)
    t.add_column("Status",   width=10)
    t.add_column("Findings", style="white")

    summaries = {
        "dns": lambda r: (
            f"{len(r.get('records', {}))} record types, "
            f"{len(r.get('subdomains', []))} subdomains"
        ),
        "whois": lambda r: (
            r.get("whois", {}).get("org", "N/A")
        ),
        "ports": lambda r: (
            f"{len(r.get('open_ports', []))} open / "
            f"{r.get('total_scanned', 0)} scanned"
        ),
        "tech": lambda r: (
            f"CMS: {', '.join(r.get('cms', [])) or 'none'} | "
            f"Tech: {', '.join(r.get('technology', [])[:3]) or 'none'}"
        ),
        "crtsh": lambda r: (
            f"{len(r.get('subdomains', []))} subdomains, "
            f"{len(r.get('alive', []))} alive"
        ),
        "breach": lambda r: (
            f"{r.get('total_breaches', 0)} breach(es), "
            f"{r.get('total_pastes', 0)} paste(s)"
        ),
    }

    for module, data in results.items():
        if isinstance(data, dict) and not data.get("error"):
            summary_fn = summaries.get(module)
            summary    = summary_fn(data) if summary_fn else "completed"
            t.add_row(module.upper(), "[bold green]✓ done[/bold green]", summary)
        else:
            t.add_row(module.upper(), "[bold red]✗ error[/bold red]", str(data.get("error", "unknown")))

    console.print(t)
    console.print(f"\n  [dim]Completed in {elapsed:.1f}s[/dim]")
    console.print()


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Nyx — Modular OSINT & Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )

    parser.add_argument("target", help="Domain, IP, email, or username")

    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=MODULES,
        default=["dns"],
        metavar="MODULE",
        help=(
            "Modules to run (default: dns)\n"
            "  dns       DNS enumeration + subdomain brute-force\n"
            "  whois     WHOIS, ASN, geolocation, CDN detection\n"
            "  ports     TCP port scan + banner grabbing\n"
            "  tech      Web fingerprinting, CMS, security headers\n"
            "  crtsh     Certificate transparency subdomain discovery\n"
            "  breach    Email/domain breach lookup (--hibp-key optional)\n"
            "  usernames Username search across platforms  [coming soon]"
        )
    )

    parser.add_argument("--output",   "-o",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument("--wordlist", "-w",  help="Custom subdomain wordlist")
    parser.add_argument("--hibp-key",        help="HaveIBeenPwned API key")
    parser.add_argument("--verbose",  "-v",  action="store_true", help="Verbose output")
    parser.add_argument("--no-resolve",      action="store_true",  help="Skip DNS resolution in crtsh")
    parser.add_argument("--help",     "-h",  action="help", help="Show this message and exit")

    args = parser.parse_args()

    print_target_info(args)

    results = {}
    start   = time.time()

    # ── DNS ──
    if "dns" in args.modules:
        from modules.dns_enum import DNSEnum
        results["dns"] = DNSEnum(
            args.target,
            verbose=args.verbose,
            wordlist=args.wordlist
        ).run()

    # ── WHOIS ──
    if "whois" in args.modules:
        from modules.whois_intel import WHOISIntel
        results["whois"] = WHOISIntel(
            args.target,
            verbose=args.verbose
        ).run()

    # ── PORTS ──
    if "ports" in args.modules:
        from modules.port_scanner import PortScanner
        results["ports"] = PortScanner(
            args.target,
            verbose=args.verbose,
            grab_banner=True
        ).run()

    # ── TECH ──
    if "tech" in args.modules:
        from modules.web_fingerprint import WebFingerprint
        results["tech"] = WebFingerprint(
            args.target,
            verbose=args.verbose
        ).run()

    # ── CRTSH ──
    if "crtsh" in args.modules:
        from modules.cert_transparency import CertTransparency
        results["crtsh"] = CertTransparency(
            args.target,
            verbose=args.verbose,
            resolve=not args.no_resolve
        ).run()

    # ── BREACH ──
    if "breach" in args.modules:
        from modules.breach_check import BreachCheck
        results["breach"] = BreachCheck(
            target=args.target,
            api_key=getattr(args, "hibp_key", None),
            verbose=args.verbose,
        ).run()

    # ── COMING SOON ──
    for module in args.modules:
        if module not in BUILT_IN:
            console.print(f"[dim yellow][!] '{module}' not yet implemented.[/dim yellow]")

    # ── OUTPUT ──
    if args.output == "json":
        import json, os
        os.makedirs("output", exist_ok=True)
        path = f"output/{args.target.replace('.', '_')}_nyx.json"
        with open(path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[bold green][+] JSON saved → {path}[/bold green]")

    elif args.output == "html":
        console.print("\n[dim yellow][!] HTML report coming soon — use -o json for now.[/dim yellow]")

    elapsed = time.time() - start
    print_summary(results, elapsed)


if __name__ == "__main__":
    main()
