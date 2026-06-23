import requests
import json
import socket
import concurrent.futures
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class CertTransparency:
    CRT_URL = "https://crt.sh/"

    def __init__(self, domain: str, verbose: bool = False, resolve: bool = True):
        self.domain  = domain
        self.verbose = verbose
        self.resolve = resolve  # whether to DNS-check discovered subdomains
        self.results = {
            "domain":         domain,
            "subdomains":     [],       # unique subdomains found
            "alive":          [],       # subdomains that resolve (DNS)
            "wildcards":      [],       # wildcard certs (*.domain.com)
            "related":        [],       # related domains found in certs
            "issuers":        [],       # who issued the certs
            "total_certs":    0,
            "findings":       [],
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Certificate Transparency[/bold cyan] → [green]{self.domain}[/green]\n"
            f"[dim]Querying crt.sh for all SSL certs ever issued for *.{self.domain}[/dim]",
            expand=False
        ))

        raw_certs = self._fetch_certs()

        if not raw_certs:
            console.print("  [dim red][!] No certificates found or crt.sh unreachable.[/dim red]")
            return self.results

        self.results["total_certs"] = len(raw_certs)
        console.print(f"  [dim][*] Found {len(raw_certs)} certificate entries — extracting subdomains...[/dim]\n")

        self._parse_certs(raw_certs)
        self._resolve_subdomains()
        self._display()

        return self.results

    # -------------------------------------------------------------------------
    # 1. Fetch from crt.sh
    # -------------------------------------------------------------------------
    def _fetch_certs(self) -> list:
        """
        Query crt.sh for all certs matching %.domain.com
        Tries multiple approaches since crt.sh can block automated requests.
        """
        headers_list = [
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", "Accept": "application/json"},
            {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36", "Accept": "application/json, text/html"},
        ]

        for i, headers in enumerate(headers_list, 1):
            try:
                console.print(f"  [dim][*] Querying crt.sh (attempt {i})...[/dim]")
                r = requests.get(
                    self.CRT_URL,
                    params={"q": f"%.{self.domain}", "output": "json"},
                    headers=headers,
                    timeout=30,
                )

                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        return data

                elif r.status_code == 403:
                    console.print(f"  [dim yellow][!] Blocked on attempt {i}, retrying...[/dim yellow]")
                    time.sleep(2)

            except requests.exceptions.Timeout:
                console.print(f"  [dim red][!] Attempt {i} timed out[/dim red]")
            except Exception as e:
                if self.verbose:
                    console.print(f"  [dim red][!] Attempt {i}: {e}[/dim red]")

        console.print("  [yellow][!] crt.sh unreachable from this IP — will work fine on your laptop.[/yellow]")
        console.print("  [dim]    crt.sh blocks cloud/sandbox IPs. Your home IP will work normally.[/dim]")
        return []

    # -------------------------------------------------------------------------
    # 2. Parse Certificate Data
    # -------------------------------------------------------------------------
    def _parse_certs(self, certs: list):
        """
        Each cert record contains:
          - name_value: the domain(s) the cert was issued for
            (can be comma/newline separated, can contain wildcards)
          - issuer_name: who signed the cert (Let's Encrypt, DigiCert, etc.)
          - not_before/not_after: validity period

        We extract all unique subdomains from name_value.
        """
        subdomains  = set()
        wildcards   = set()
        related     = set()
        issuers     = set()

        for cert in certs:
            # Extract domains from name_value field
            # Can be newline or comma separated
            name_value = cert.get("name_value", "")
            names = re.split(r"[\n,]", name_value)

            for name in names:
                name = name.strip().lower()

                if not name:
                    continue

                # Wildcard cert — *.domain.com
                if name.startswith("*."):
                    wildcards.add(name)
                    # Also add the base domain
                    base = name[2:]
                    if self.domain in base:
                        subdomains.add(base)

                # Our target domain or subdomain
                elif name.endswith(f".{self.domain}") or name == self.domain:
                    subdomains.add(name)

                # Related domain — same cert, different domain
                # e.g. company.com cert also covers company.io
                elif self.domain not in name and "." in name:
                    # Filter out obvious wildcards and IPs
                    if not name.startswith("*") and not re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
                        related.add(name)

            # Extract issuer
            issuer_name = cert.get("issuer_name", "")
            # Pull CN= value from issuer string
            cn_match = re.search(r"CN=([^,]+)", issuer_name)
            if cn_match:
                issuers.add(cn_match.group(1).strip())

        # Remove the root domain itself from subdomains
        subdomains.discard(self.domain)

        self.results["subdomains"] = sorted(list(subdomains))
        self.results["wildcards"]  = sorted(list(wildcards))
        self.results["related"]    = sorted(list(related))[:20]  # cap at 20
        self.results["issuers"]    = sorted(list(issuers))

        # Findings
        if wildcards:
            self.results["findings"].append(
                f"Wildcard certs found: {', '.join(list(wildcards)[:3])} — reveals infra patterns"
            )
        if related:
            self.results["findings"].append(
                f"{len(related)} related domain(s) found in certs — possible related attack surface"
            )

        # Flag interesting subdomain patterns
        interesting_keywords = ["dev", "staging", "test", "admin", "internal",
                                "jenkins", "git", "vpn", "backup", "old", "legacy",
                                "api", "beta", "debug", "db", "database", "corp"]
        for sub in subdomains:
            for kw in interesting_keywords:
                if kw in sub:
                    self.results["findings"].append(
                        f"Interesting subdomain: {sub} [{kw}] — likely less hardened"
                    )
                    break

    # -------------------------------------------------------------------------
    # 3. DNS Resolution — which subdomains are still alive?
    # -------------------------------------------------------------------------
    def _resolve_subdomains(self):
        """
        Not every subdomain in crt.sh is still active.
        We DNS-check each one to find which are currently live.
        Live subdomains = actual targets to investigate further.
        """
        if not self.resolve or not self.results["subdomains"]:
            return

        console.print(f"  [dim][*] Resolving {len(self.results['subdomains'])} subdomains...[/dim]")

        alive = []

        def check(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                return {"subdomain": subdomain, "ip": ip}
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check, sub): sub for sub in self.results["subdomains"]}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    alive.append(result)

        # Sort by subdomain name
        alive.sort(key=lambda x: x["subdomain"])
        self.results["alive"] = alive

        if alive:
            self.results["findings"].append(
                f"{len(alive)} subdomains currently alive and resolving"
            )

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------
    def _display(self):
        # ── Summary ──
        console.print(f"  [bold white]Total certs found:[/bold white]     {self.results['total_certs']}")
        console.print(f"  [bold white]Unique subdomains:[/bold white]     {len(self.results['subdomains'])}")
        console.print(f"  [bold white]Currently alive:[/bold white]       {len(self.results['alive'])}")
        console.print(f"  [bold white]Wildcard certs:[/bold white]        {len(self.results['wildcards'])}")
        console.print(f"  [bold white]Related domains:[/bold white]       {len(self.results['related'])}")

        # ── Alive Subdomains ──
        if self.results["alive"]:
            console.print("\n[bold yellow][*] Live Subdomains (DNS resolves)[/bold yellow]")
            t = Table(box=box.SIMPLE, header_style="bold magenta")
            t.add_column("Subdomain", style="green",  width=40)
            t.add_column("IP",        style="cyan",   width=18)

            for s in self.results["alive"]:
                t.add_row(s["subdomain"], s["ip"])
            console.print(t)

        # ── All Subdomains (if verbose) ──
        if self.verbose and self.results["subdomains"]:
            console.print("\n[bold yellow][*] All Subdomains from Certs[/bold yellow]")
            for sub in self.results["subdomains"]:
                alive_ips = [a["ip"] for a in self.results["alive"] if a["subdomain"] == sub]
                status = f"[green]{alive_ips[0]}[/green]" if alive_ips else "[dim]dead/unresolvable[/dim]"
                console.print(f"  {sub} → {status}")

        # ── Wildcards ──
        if self.results["wildcards"]:
            console.print("\n[bold yellow][*] Wildcard Certificates[/bold yellow]")
            for wc in self.results["wildcards"]:
                console.print(f"  [yellow]{wc}[/yellow]")

        # ── Certificate Issuers ──
        if self.results["issuers"]:
            console.print("\n[bold yellow][*] Certificate Issuers[/bold yellow]")
            console.print(f"  {', '.join(self.results['issuers'][:5])}")

        # ── Related Domains ──
        if self.results["related"]:
            console.print("\n[bold yellow][*] Related Domains (same certs)[/bold yellow]")
            for r in self.results["related"][:10]:
                console.print(f"  [cyan]{r}[/cyan]")

        # ── Findings ──
        if self.results["findings"]:
            console.print("\n[bold red][!] Findings[/bold red]")
            for f in self.results["findings"]:
                prefix = "[bold red][!!!][/bold red]" if "CRITICAL" in f else "[bold yellow][!][/bold yellow]"
                console.print(f"  {prefix} {f}")
