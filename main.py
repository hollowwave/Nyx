#!/usr/bin/env python3
"""
ReconTool - Automated OSINT & Recon Pipeline
Built module by module. Start with DNS, grow from here.
"""

import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
  ▄▄▄    ▄▄▄▄  ▄▄▄    ▄▄▄    ▄  ▄▄    ▄▄▄  
   ▒▒▒    ░░▌   ░░▌  ▀ ▀█░   ░░▌  ▀ ▀█░ 
   ▐░░▌   ▐░    ▐▒░    ▐░▌   ▐▒░    ▐░▌ 
    ██▀▄  ▐█     ▓▒▒  ███     ▓▒▒  ███  
    ░▌▀▀░░▐█       ▓▒░░         ▓▒░░    
    ▒▌  ▒▒░▌        ▓▒        ▒▓▒  ░▓▒  
   ▐▓▌   ▓▒▒        █▓       ▐▓▌    ▒▓▌ 
   ██▓    ▓▓▌      ▐██▌      ██ ▄   ▐█▓ 
  ▀▀▀▀▀    ▀▀      ▀▀▀▀       ▀▀ ▀   ▀▀▀
"""

def main():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(Panel("[bold cyan]Automated Recon & OSINT Pipeline[/bold cyan] | [dim]v0.1 - DNS Module[/dim]", expand=False))
    print()

    parser = argparse.ArgumentParser(
        description="ReconTool - Modular OSINT Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("target", help="Target domain, IP, email, or username")

    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=["dns", "whois", "ports", "tech", "breach", "usernames"],
        default=["dns"],
        help=(
            "Modules to run (default: dns)\n"
            "  dns       - DNS enumeration & subdomain lookup\n"
            "  whois     - WHOIS & IP intelligence       [coming soon]\n"
            "  ports     - Port scanning                 [coming soon]\n"
            "  tech      - Technology fingerprinting     [coming soon]\n"
            "  breach    - Email breach check            [coming soon]\n"
            "  usernames - Username search across platforms [coming soon]"
        )
    )

    parser.add_argument("--output", "-o", choices=["terminal", "json", "html"], default="terminal",
                        help="Output format (default: terminal)")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist for subdomain brute-force")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    console.print(f"[bold white]Target:[/bold white] [bold green]{args.target}[/bold green]")
    console.print(f"[bold white]Modules:[/bold white] [yellow]{', '.join(args.modules)}[/yellow]")
    console.print(f"[bold white]Output:[/bold white] [yellow]{args.output}[/yellow]\n")

    results = {}

    # --- Run selected modules ---
    if "dns" in args.modules:
        from modules.dns_enum import DNSEnum
        dns = DNSEnum(args.target, verbose=args.verbose, wordlist=args.wordlist)
        results["dns"] = dns.run()

    if "whois" in args.modules:
        from modules.whois_intel import WHOISIntel
        w = WHOISIntel(args.target, verbose=args.verbose)
        results["whois"] = w.run()

    if "ports" in args.modules:
        from modules.port_scanner import PortScanner
        ps = PortScanner(args.target, verbose=args.verbose, grab_banner=True)
        results["ports"] = ps.run()

    # Placeholder hooks for future modules
    for module in args.modules:
        if module not in ["dns", "whois", "ports"]:
            console.print(f"[dim yellow][!] Module '{module}' not yet implemented — coming soon.[/dim yellow]")

    # Output
    if args.output == "json":
        import json
        output_path = f"output/{args.target.replace('.', '_')}_recon.json"
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[bold green][+] JSON report saved to {output_path}[/bold green]")
    elif args.output == "html":
        console.print("\n[dim yellow][!] HTML report coming in next module build.[/dim yellow]")
    
    console.print("\n[bold green][✓] Recon complete.[/bold green]")

if __name__ == "__main__":
    main()
