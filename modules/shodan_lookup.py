import requests
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SHODAN_API_URL = "https://api.shodan.io/shodan/host/{ip}"
CENSYS_API_URL = "https://api.censys.io/v2/hosts/{ip}"

# Mock data for testing
MOCK_DATA = {
    "ip_str": "8.8.8.8",
    "country_code": "US",
    "city": "Mountain View",
    "isp": "Google LLC",
    "org": "Google",
    "ports": [53, 443, 80],
    "hostnames": ["dns.google"],
    "data": [
        {"port": 53, "transport": "udp", "product": "ISC BIND", "version": "9.16", "title": "DNS"},
        {"port": 80, "transport": "tcp", "product": "Google", "title": "HTTP"},
        {"port": 443, "transport": "tcp", "product": "Google", "title": "HTTPS"},
    ],
    "vulns": ["CVE-2020-12345"],
}


class ShodanLookup:
    def __init__(self, target: str, api_key: str = None, verbose: bool = False):
        self.target  = target
        self.api_key = api_key
        self.verbose = verbose
        self.mock    = not api_key
        self.source  = "shodan"

        self.results = {
            "target":      target,
            "mock_mode":   self.mock,
            "source":      self.source,
            "ip":          None,
            "location":    {},
            "ports":       [],
            "services":    [],
            "vulns":       [],
            "hostnames":   [],
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Shodan Lookup[/bold cyan] → [green]{self.target}[/green]"
            + (" [dim yellow](mock mode)[/dim yellow]" if self.mock else ""),
            expand=False
        ))

        if self.mock:
            console.print(
                "  [dim yellow][!] No API key — running in mock mode.[/dim yellow]\n"
                "  [dim yellow]    SHODAN: \$60/month for 10k queries/month[/dim yellow]\n"
                "  [dim yellow]    CENSYS: Free tier has 120 queries/month (better deal)[/dim yellow]\n"
                "  [dim yellow]    Set CENSYS_API_TOKEN env var to use Censys[/dim yellow]\n"
            )
            data = MOCK_DATA
        else:
            # Try Shodan first with provided key
            data = self._query_shodan()
            if not data:
                console.print("  [dim yellow][*] Shodan failed, trying Censys fallback...[/dim yellow]")
                data = self._query_censys()
                if data:
                    self.source = "censys"

        if data:
            self._parse_data(data)

        self._display()
        return self.results

    def _query_shodan(self) -> dict:
        """Query Shodan API for IP information."""
        try:
            console.print("  [dim][*] Querying Shodan...[/dim]")
            url = SHODAN_API_URL.format(ip=self.target)
            params = {"key": self.api_key}

            r = requests.get(url, params=params, timeout=10)

            if r.status_code == 401:
                console.print("  [red][!] Invalid Shodan API key[/red]")
                return None
            elif r.status_code == 403:
                console.print("  [red][!] Shodan access denied (rate limited or no credits)[/red]")
                return None
            elif r.status_code == 404:
                console.print("  [yellow][!] IP not found in Shodan[/yellow]")
                return None
            elif r.status_code == 200:
                return r.json()

            console.print(f"  [red][!] Shodan error: {r.status_code}[/red]")
            return None

        except requests.exceptions.Timeout:
            console.print("  [red][!] Shodan timeout[/red]")
            return None
        except Exception as e:
            if self.verbose:
                console.print(f"  [dim red][!] Shodan error: {e}[/dim red]")
            return None

    def _query_censys(self) -> dict:
        """Fallback: Query Censys API using token auth."""
        try:
            censys_token = os.getenv("CENSYS_API_TOKEN")
            
            if not censys_token:
                console.print("  [dim yellow][!] CENSYS_API_TOKEN not set[/dim yellow]")
                console.print("  [dim]    Export it: export CENSYS_API_TOKEN=\"your_token\"[/dim]")
                return None

            console.print("  [dim][*] Querying Censys...[/dim]")
            url = CENSYS_API_URL.format(ip=self.target)

            # Censys v2 API uses token in Authorization header
            headers = {
                "Authorization": f"Bearer {censys_token}",
                "User-Agent": "Nyx/0.8.0"
            }

            r = requests.get(url, headers=headers, timeout=10)

            if r.status_code == 401:
                console.print("  [red][!] Invalid Censys API token[/red]")
                return None
            elif r.status_code == 404:
                console.print("  [yellow][!] IP not found in Censys[/yellow]")
                return None
            elif r.status_code == 200:
                data = r.json()
                # Censys returns different format, normalize it
                return self._normalize_censys(data)

            console.print(f"  [red][!] Censys error: {r.status_code}[/red]")
            return None

        except requests.exceptions.Timeout:
            console.print("  [red][!] Censys timeout[/red]")
            return None
        except Exception as e:
            if self.verbose:
                console.print(f"  [dim red][!] Censys error: {e}[/dim red]")
            return None

    def _normalize_censys(self, data: dict) -> dict:
        """Convert Censys format to our format for compatibility."""
        # Censys has different structure, map it
        normalized = {
            "ip_str": data.get("ip"),
            "ports": data.get("services", {}).keys() if data.get("services") else [],
            "data": [
                {
                    "port": port,
                    "product": service.get("service_name", "Unknown"),
                    "title": service.get("service_name", "")
                }
                for port, service in (data.get("services", {}) or {}).items()
            ],
            "hostnames": data.get("names", []),
            "location": data.get("location", {}),
        }
        return normalized

    def _parse_data(self, data: dict):
        """Extract useful information from response."""
        self.results["ip"]        = data.get("ip_str")
        self.results["hostnames"] = data.get("hostnames", [])

        self.results["location"] = {
            "country": data.get("country_name"),
            "city":    data.get("city"),
            "isp":     data.get("isp"),
            "org":     data.get("org"),
        }

        ports = data.get("ports", [])
        self.results["ports"] = ports

        for service in data.get("data", []):
            service_info = {
                "port":      service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product":   service.get("product", "Unknown"),
                "version":   service.get("version", ""),
                "title":     service.get("title", ""),
            }
            self.results["services"].append(service_info)

        self.results["vulns"] = data.get("vulns", [])

    def _display(self):
        """Display results."""
        console.print()

        ip = self.results["ip"]
        if not ip:
            console.print("  [dim]No data available.[/dim]")
            return

        # Location
        loc = self.results["location"]
        console.print(f"  [bold white]IP:[/bold white]       {ip}")
        console.print(f"  [bold white]Location:[/bold white] {loc.get('city')}, {loc.get('country')}")
        console.print(f"  [bold white]ISP:[/bold white]      {loc.get('isp')}")
        console.print(f"  [bold white]Org:[/bold white]      {loc.get('org')}")
        console.print(f"  [bold white]Source:[/bold white]   {self.source.upper()}")

        if self.results["hostnames"]:
            console.print(f"  [bold white]Hostnames:[/bold white] {', '.join(self.results['hostnames'])}")

        # Services
        if self.results["services"]:
            console.print("\n[bold yellow][*] Services[/bold yellow]")
            t = Table(box=box.SIMPLE, header_style="bold magenta")
            t.add_column("Port",      style="cyan",  width=8)
            t.add_column("Transport", style="yellow", width=8)
            t.add_column("Product",   style="green", width=20)
            t.add_column("Version",   style="white")

            for svc in self.results["services"]:
                version = svc.get("version") or "—"
                t.add_row(
                    str(svc["port"]),
                    svc["transport"],
                    svc["product"],
                    version
                )
            console.print(t)

        # Vulnerabilities
        if self.results["vulns"]:
            console.print(f"\n[bold red][!] Known Vulnerabilities[/bold red]")
            for vuln in self.results["vulns"][:10]:
                console.print(f"  [red]→ {vuln}[/red]")
            if len(self.results["vulns"]) > 10:
                console.print(f"  [dim]... and {len(self.results['vulns']) - 10} more[/dim]")

        if self.mock:
            console.print(
                "\n  [dim yellow][*] Mock data. Get real data:[/dim yellow]\n"
                "  [dim yellow]    • Shodan: \$60/month, https://www.shodan.io[/dim yellow]\n"
                "  [dim yellow]    • Censys: Free 120/month, https://censys.io (recommended)[/dim yellow]"
            )
