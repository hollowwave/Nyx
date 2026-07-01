#!/usr/bin/env python3
"""
Nyx - Automated OSINT & Recon Pipeline
Dark. Fast. Modular.
"""

import argparse
import sys
import time
import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

console = Console()

BANNER = """[bold red]
  ▄▄▄    ▄▄▄▄  ▄▄▄    ▄▄▄    ▄▄▄    ▄▄▄  
   ▒▒▒    ░░▌   ░░▌  ▀ ▀█░  ░░▌ ▀  ▀█░
   ▐░░▌   ▐░    ▐▒░    ▐░▌   ▐▒░    ▐░▌
    ██▀▄  ▐█     ▓▒▒  ███     ▓▒▒  ███
    ░▌▀▀░░▐█       ▓▒░░         ▓▒░░    
    ▒▌  ▒▒░▌        ▓▒        ▒▓▒  ░▓▒  
   ▐▓▌   ▓▒▒        █▓       ▐▓▌    ▒▓▌
   ██▓    ▓▓▌      ▐██▌      ██ ▄   ▐█▓ 
  ▀▀▀▀▀    ▀▀      ▀▀▀▀       ▀▀ ▀   ▀▀▀[/bold red]"""

VERSION  = "0.7.0"
CODENAME = "Erebus"
BUILT_IN = ["dns", "whois", "ports", "tech", "crtsh", "breach", "usernames", "waf", "email", "dorks", "shodan", "harvest"]

# Dark gothic style for questionary
NYX_STYLE = Style([
    ("qmark",        "fg:#ff0000 bold"),
    ("question",     "fg:#ffffff bold"),
    ("answer",       "fg:#00ff41 bold"),
    ("pointer",      "fg:#ff0000 bold"),
    ("highlighted",  "fg:#ff0000 bold"),
    ("selected",     "fg:#00ff41"),
    ("separator",    "fg:#444444"),
    ("instruction",  "fg:#444444"),
    ("text",         "fg:#ffffff"),
    ("disabled",     "fg:#444444 italic"),
])

MODULE_DESCRIPTIONS = {
    "dns":       "DNS records, zone transfer, subdomain brute-force",
    "whois":     "WHOIS, ASN, geolocation, CDN detection",
    "ports":     "TCP port scan + banner grabbing (top 100)",
    "tech":      "Web fingerprinting, CMS, security headers",
    "crtsh":     "Certificate transparency subdomain discovery",
    "breach":    "Email/domain breach lookup via HIBP",
    "usernames": "Username search across 21 platforms",
    "waf":       "WAF detection — passive + active payload probing",
    "email":     "SPF/DMARC/DKIM email security audit",
    "dorks":     "Google Dork query generator for reconnaissance",
    "shodan":    "Shodan IP lookup — find known vulnerabilities",
    "harvest":   "Email harvester using Hunter.io API",

}


def print_banner():
    console.print(BANNER)
    console.print(
        f"  [dim]v{VERSION} [{CODENAME}][/dim]  "
        f"[dim]Automated OSINT & Recon Pipeline[/dim]\n"
    )


def interactive_menu() -> argparse.Namespace:
    """
    Show interactive menu when no arguments are provided.
    Returns a namespace object identical to what argparse would return.
    """
    console.print(Rule("[dim red]CONFIGURE SCAN[/dim red]"))
    console.print()

    # Target input
    target = questionary.text(
        "Target (domain / IP / email / username):",
        style=NYX_STYLE,
        validate=lambda t: True if t.strip() else "Target cannot be empty"
    ).ask()

    if not target:
        console.print("[red]Aborted.[/red]")
        sys.exit(0)

    console.print()

    # Module selection — checkboxes
    module_choices = [
        questionary.Choice(
            title=f"{name:<12} {MODULE_DESCRIPTIONS[name]}",
            value=name,
            checked=name in ["dns", "whois"]  # default checked
        )
        for name in BUILT_IN
    ]

    selected_modules = questionary.checkbox(
        "Select modules to run:",
        choices=module_choices,
        style=NYX_STYLE,
        instruction="(Space to select, Enter to confirm)",
    ).ask()

    if not selected_modules:
        console.print("[red]No modules selected. Aborted.[/red]")
        sys.exit(0)

    console.print()

    # Output format
    output = questionary.select(
        "Output format:",
        choices=[
            questionary.Choice("terminal  — print to screen",  value="terminal"),
            questionary.Choice("json      — save to file",     value="json"),
            questionary.Choice("html      — save report",      value="html"),
        ],
        style=NYX_STYLE,
    ).ask()

    console.print()

    # HIBP key if breach module selected
    hibp_key = None
    if "breach" in selected_modules:
        hibp_key = questionary.text(
            "HaveIBeenPwned API key (leave blank for mock mode):",
            style=NYX_STYLE,
        ).ask()
        hibp_key = hibp_key.strip() if hibp_key else None
        console.print()

    # Wordlist if dns selected
    wordlist = None
    if "dns" in selected_modules:
        use_wordlist = questionary.confirm(
            "Use custom subdomain wordlist?",
            default=False,
            style=NYX_STYLE,
        ).ask()
        if use_wordlist:
            wordlist = questionary.text(
                "Wordlist path:",
                style=NYX_STYLE,
            ).ask()
        console.print()

    # Verbose
    verbose = questionary.confirm(
        "Verbose output?",
        default=False,
        style=NYX_STYLE,
    ).ask()

    console.print()

    # Confirm
    console.print(Panel(
        f"  [cyan]Target[/cyan]   {target}\n"
        f"  [cyan]Modules[/cyan]  {' → '.join(selected_modules)}\n"
        f"  [cyan]Output[/cyan]   {output}",
        border_style="dim red",
        title="[dim]Scan Config[/dim]",
        expand=False
    ))
    console.print()

    confirm = questionary.confirm(
        "Launch scan?",
        default=True,
        style=NYX_STYLE,
    ).ask()

    if not confirm:
        console.print("[red]Aborted.[/red]")
        sys.exit(0)

    console.print()

    # Return namespace matching argparse output
    args = argparse.Namespace(
        target=target.strip(),
        modules=selected_modules,
        output=output,
        hibp_key=hibp_key,
        wordlist=wordlist,
        verbose=verbose,
        no_resolve=False,
    )
    return args


def print_target_info(args):
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim cyan", justify="right")
    grid.add_column(style="white")

    grid.add_row("TARGET",  f"[bold green]{args.target}[/bold green]")
    grid.add_row("MODULES", f"[yellow]{' → '.join(args.modules)}[/yellow]")
    grid.add_row("OUTPUT",  f"[yellow]{args.output}[/yellow]")
    if getattr(args, "hibp_key", None):
        grid.add_row("HIBP KEY", "[green]provided[/green]")
    if getattr(args, "wordlist", None):
        grid.add_row("WORDLIST", args.wordlist)

    console.print(Panel(grid, border_style="dim red", expand=False))
    console.print()


def print_summary(results: dict, elapsed: float):
    console.print()
    console.rule("[bold red]SCAN COMPLETE[/bold red]")
    console.print()

    summaries = {
        "dns":       lambda r: f"{len(r.get('records', {}))} record types, {len(r.get('subdomains', []))} subdomains",
        "whois":     lambda r: r.get("whois", {}).get("org", "N/A"),
        "ports":     lambda r: f"{len(r.get('open_ports', []))} open / {r.get('total_scanned', 0)} scanned",
        "tech":      lambda r: f"CMS: {', '.join(r.get('cms', [])) or 'none'} | Tech: {', '.join(r.get('technology', [])[:3]) or 'none'}",
        "crtsh":     lambda r: f"{len(r.get('subdomains', []))} subdomains, {len(r.get('alive', []))} alive",
        "breach":    lambda r: f"{r.get('total_breaches', 0)} breach(es), {r.get('total_pastes', 0)} paste(s)",
        "usernames": lambda r: f"{r.get('total_found', 0)} accounts found / {len(r.get('not_found', []))} not found",
    }

    t = Table(box=box.SIMPLE, header_style="bold magenta")
    t.add_column("Module",   style="cyan",  width=16)
    t.add_column("Status",   width=10)
    t.add_column("Findings", style="white")

    for module, data in results.items():
        if isinstance(data, dict) and not data.get("error"):
            summary = summaries.get(module, lambda r: "completed")(data)
            t.add_row(module.upper(), "[bold green]✓ done[/bold green]", summary)
        else:
            t.add_row(module.upper(), "[bold red]✗ error[/bold red]", str(data.get("error", "unknown")))

    console.print(t)
    console.print(f"\n  [dim]Completed in {elapsed:.1f}s[/dim]\n")


def run_scan(args):
    """Run all selected modules."""
    results = {}
    start   = time.time()

    if "dns" in args.modules:
        from modules.dns_enum import DNSEnum
        results["dns"] = DNSEnum(
            args.target, verbose=args.verbose,
            wordlist=getattr(args, "wordlist", None)
        ).run()

    if "whois" in args.modules:
        from modules.whois_intel import WHOISIntel
        results["whois"] = WHOISIntel(args.target, verbose=args.verbose).run()

    if "ports" in args.modules:
        from modules.port_scanner import PortScanner
        results["ports"] = PortScanner(
            args.target, verbose=args.verbose, grab_banner=True
        ).run()

    if "tech" in args.modules:
        from modules.web_fingerprint import WebFingerprint
        results["tech"] = WebFingerprint(args.target, verbose=args.verbose).run()

    if "crtsh" in args.modules:
        from modules.cert_transparency import CertTransparency
        results["crtsh"] = CertTransparency(
            args.target, verbose=args.verbose,
            resolve=not getattr(args, "no_resolve", False)
        ).run()

    if "breach" in args.modules:
        from modules.breach_check import BreachCheck
        results["breach"] = BreachCheck(
            target=args.target,
            api_key=getattr(args, "hibp_key", None),
            verbose=args.verbose,
        ).run()

    if "waf" in args.modules:
        from modules.waf_detector import WAFDetector
        results["waf"] = WAFDetector(
            target=args.target,
            verbose=args.verbose,
        ).run()

    if "dorks" in args.modules:
        from modules.google_dorks import GoogleDorkGenerator
        results["dorks"] = GoogleDorkGenerator(
            domain=args.target, verbose=args.verbose
        ).run()

    if "shodan" in args.modules:
        from modules.shodan_lookup import ShodanLookup
        results["shodan"] = ShodanLookup(
            target=args.target,
            api_key=getattr(args, "shodan_key", None),
            verbose=args.verbose,
        ).run()

    if "harvest" in args.modules:
        from modules.email_harvester import EmailHarvester
        results["harvest"] = EmailHarvester(
            domain=args.target,
            api_key=getattr(args, "hunter_key", None),
            verbose=args.verbose,
        ).run()

    if "email" in args.modules:
        from modules.email_security import EmailSecurityChecker
        results["email"] = EmailSecurityChecker(
            domain=args.target,
            verbose=args.verbose,
        ).run()

    if "usernames" in args.modules:
        from modules.username_search import UsernameSearch
        results["usernames"] = UsernameSearch(
            username=args.target, verbose=args.verbose
        ).run()

    # Output
    if args.output == "json":
        import json, os
        os.makedirs("output", exist_ok=True)
        path = f"output/{args.target.replace('.', '_')}_nyx.json"
        with open(path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[bold green][+] JSON saved → {path}[/bold green]")
    elif args.output == "html":
        console.print("\n[dim yellow][!] HTML report coming soon.[/dim yellow]")

    elapsed = time.time() - start
    print_summary(results, elapsed)


def main():
    print_banner()

    # If arguments provided → classic CLI mode
    # If no arguments → interactive menu mode
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="Nyx — Modular OSINT & Recon Pipeline",
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
        )
        parser.add_argument("target")
        parser.add_argument("--modules", "-m", nargs="+", choices=BUILT_IN, default=["dns"], metavar="MODULE")
        parser.add_argument("--output",  "-o", choices=["terminal", "json", "html"], default="terminal")
        parser.add_argument("--wordlist","-w")
        parser.add_argument("--hibp-key")
        parser.add_argument("--verbose", "-v", action="store_true")
        parser.add_argument("--no-resolve", action="store_true")
        parser.add_argument("--help", "-h", action="help")
        args = parser.parse_args()
        print_target_info(args)
    else:
        # Interactive menu
        args = interactive_menu()
        console.rule("[dim red]RUNNING SCAN[/dim red]")
        console.print()

    run_scan(args)


if __name__ == "__main__":
    main()
