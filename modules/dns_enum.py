import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
import concurrent.futures
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Default subdomain wordlist — small but covers the most common ones
# In real engagements you'd use SecLists (github.com/danielmiessler/SecLists)
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server",
    "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "dev",
    "staging", "api", "portal", "admin", "test", "beta", "git",
    "jenkins", "jira", "confluence", "gitlab", "dashboard", "app",
    "cdn", "static", "assets", "media", "images", "upload", "files",
    "backup", "db", "database", "mysql", "mongo", "redis", "internal",
    "intranet", "corp", "old", "legacy", "v1", "v2", "mobile"
]

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


class DNSEnum:
    def __init__(self, domain: str, verbose: bool = False, wordlist: str = None):
        self.domain = domain
        self.verbose = verbose
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

        # Load wordlist
        if wordlist and os.path.exists(wordlist):
            with open(wordlist) as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
            console.print(f"[dim][*] Loaded {len(self.wordlist)} words from {wordlist}[/dim]")
        else:
            self.wordlist = DEFAULT_WORDLIST

        self.results = {
            "domain": domain,
            "records": {},
            "zone_transfer": [],
            "subdomains": [],
            "reverse_dns": {}
        }

    def run(self) -> dict:
        console.print(Panel(f"[bold cyan]DNS Enumeration[/bold cyan] → [green]{self.domain}[/green]", expand=False))

        self._basic_records()
        self._zone_transfer()
        self._subdomain_bruteforce()

        # Reverse DNS on any A records found
        a_records = self.results["records"].get("A", [])
        if a_records:
            self._reverse_dns(a_records)

        return self.results

    # -------------------------------------------------------------------------
    # 1. Basic Record Lookup
    # -------------------------------------------------------------------------
    def _basic_records(self):
        console.print("\n[bold yellow][*] Basic DNS Records[/bold yellow]")

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Value", style="white")

        found_any = False

        for rtype in RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                values = []

                for rdata in answers:
                    val = str(rdata)
                    values.append(val)
                    table.add_row(rtype, val)

                self.results["records"][rtype] = values
                found_any = True

            except dns.resolver.NoAnswer:
                if self.verbose:
                    console.print(f"  [dim][-] {rtype}: No answer[/dim]")
            except dns.resolver.NXDOMAIN:
                console.print(f"[bold red][!] Domain {self.domain} does not exist (NXDOMAIN)[/bold red]")
                return
            except dns.exception.DNSException as e:
                if self.verbose:
                    console.print(f"  [dim red][-] {rtype}: {e}[/dim red]")

        if found_any:
            console.print(table)
        else:
            console.print("  [dim]No records found.[/dim]")

    # -------------------------------------------------------------------------
    # 2. Zone Transfer (AXFR)
    # Why: A misconfigured DNS server will dump ALL its records if you ask nicely.
    # This is a classic finding in pentests and still shows up in the wild.
    # -------------------------------------------------------------------------
    def _zone_transfer(self):
        console.print("\n[bold yellow][*] Zone Transfer Attempt (AXFR)[/bold yellow]")

        ns_records = self.results["records"].get("NS", [])
        if not ns_records:
            console.print("  [dim]No NS records found, skipping zone transfer.[/dim]")
            return

        success = False
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            try:
                console.print(f"  [dim][*] Trying {ns_host}...[/dim]")
                z = dns.zone.from_xfr(dns.query.xfr(ns_host, self.domain, timeout=5))
                names = [str(n) for n in z.nodes.keys()]
                self.results["zone_transfer"] = names
                console.print(f"  [bold red][!!!] ZONE TRANSFER SUCCEEDED on {ns_host}![/bold red]")
                console.print(f"  [red]Found {len(names)} records — saving to results.[/red]")
                for name in names[:20]:  # show first 20
                    console.print(f"    [red]{name}.{self.domain}[/red]")
                if len(names) > 20:
                    console.print(f"    [dim red]... and {len(names)-20} more[/dim red]")
                success = True
                break
            except Exception:
                console.print(f"  [dim green][-] {ns_host}: Zone transfer denied (expected)[/dim green]")

        if not success:
            console.print("  [green][+] Zone transfers denied on all nameservers (good config)[/green]")

    # -------------------------------------------------------------------------
    # 3. Subdomain Brute-Force
    # Why: Forgotten subdomains (dev.target.com, staging.target.com) are goldmines.
    # They often run older software, have weaker auth, or expose internal tools.
    # -------------------------------------------------------------------------
    def _subdomain_bruteforce(self):
        console.print(f"\n[bold yellow][*] Subdomain Brute-Force[/bold yellow] [dim]({len(self.wordlist)} words, threaded)[/dim]")

        found = []

        def check_subdomain(word):
            sub = f"{word}.{self.domain}"
            try:
                answers = self.resolver.resolve(sub, "A")
                ips = [str(r) for r in answers]
                return {"subdomain": sub, "ips": ips}
            except Exception:
                return None

        # Threaded for speed — DNS lookups are I/O bound, threading helps a lot
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in self.wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    console.print(f"  [bold green][+] Found:[/bold green] {result['subdomain']} → {', '.join(result['ips'])}")

        self.results["subdomains"] = found

        if not found:
            console.print("  [dim]No subdomains found with current wordlist.[/dim]")
        else:
            console.print(f"\n  [bold green][✓] {len(found)} subdomains discovered[/bold green]")

    # -------------------------------------------------------------------------
    # 4. Reverse DNS
    # Why: Turn IPs back into hostnames — reveals related infrastructure,
    # hosting providers, CDN usage, and sometimes internal naming conventions.
    # -------------------------------------------------------------------------
    def _reverse_dns(self, ip_list: list):
        console.print("\n[bold yellow][*] Reverse DNS Lookup[/bold yellow]")

        for ip in ip_list:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.results["reverse_dns"][ip] = hostname
                console.print(f"  [cyan]{ip}[/cyan] → [white]{hostname}[/white]")
            except socket.herror:
                console.print(f"  [dim]{ip} → No PTR record[/dim]")
