import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

HUNTER_API_URL = "https://api.hunter.io/v2/domain-search"

# Mock data for testing without API key
MOCK_HUNTER_DATA = {
    "domain": "example.com",
    "emails": [
        {
            "value": "john.smith@example.com",
            "type": "personal",
            "confidence": 95,
            "first_name": "John",
            "last_name": "Smith",
            "position": "Software Engineer",
        },
        {
            "value": "jane.doe@example.com",
            "type": "personal",
            "confidence": 92,
            "first_name": "Jane",
            "last_name": "Doe",
            "position": "Product Manager",
        },
        {
            "value": "admin@example.com",
            "type": "generic",
            "confidence": 88,
        },
        {
            "value": "hello@example.com",
            "type": "generic",
            "confidence": 85,
        },
    ],
    "pattern": "{first}.{last}",
}


class EmailHarvester:
    def __init__(self, domain: str, api_key: str = None, verbose: bool = False):
        self.domain  = domain.strip()
        self.api_key = api_key
        self.verbose = verbose
        self.mock    = not api_key  # mock mode if no API key

        self.results = {
            "domain":      domain,
            "mock_mode":   self.mock,
            "total":       0,
            "pattern":     None,
            "emails":      [],
            "verified":    [],
            "generic":     [],
            "high_conf":   [],  # confidence >= 90
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Email Harvester[/bold cyan] → [green]{self.domain}[/green]"
            + (" [dim yellow](mock mode)[/dim yellow]" if self.mock else ""),
            expand=False
        ))

        if self.mock:
            console.print(
                "  [dim yellow][!] No API key — running in mock mode.[/dim yellow]\n"
                "  [dim yellow]    Get a free key at: https://hunter.io/api[/dim yellow]\n"
                "  [dim yellow]    Then run with: --hunter-key YOUR_KEY[/dim yellow]\n"
            )
            data = MOCK_HUNTER_DATA
        else:
            data = self._query_hunter()

        if data:
            self._parse_data(data)

        self._display()
        return self.results

    def _query_hunter(self) -> dict:
        """Query Hunter.io API for domain emails."""
        try:
            console.print("  [dim][*] Querying Hunter.io...[/dim]")
            params = {
                "domain": self.domain,
                "api_key": self.api_key,
                "limit": 100,
            }

            r = requests.get(HUNTER_API_URL, params=params, timeout=10)

            if r.status_code == 400:
                console.print("  [red][!] Invalid domain[/red]")
                return None
            elif r.status_code == 401:
                console.print("  [red][!] Invalid Hunter.io API key[/red]")
                return None
            elif r.status_code == 429:
                console.print("  [red][!] Hunter.io rate limited[/red]")
                return None

            if r.status_code == 200:
                data = r.json()
                if data.get("data"):
                    return data["data"]
                return None

            console.print(f"  [red][!] Hunter.io error: {r.status_code}[/red]")
            return None

        except requests.exceptions.Timeout:
            console.print("  [red][!] Hunter.io request timed out[/red]")
            return None
        except Exception as e:
            console.print(f"  [red][!] Hunter.io error: {e}[/red]")
            return None

    def _parse_data(self, data: dict):
        """Extract emails and metadata from Hunter response."""
        self.results["pattern"] = data.get("pattern")

        emails = data.get("emails", [])
        self.results["total"] = len(emails)

        for email_obj in emails:
            email = email_obj.get("value")
            email_type = email_obj.get("type")
            confidence = email_obj.get("confidence", 0)
            first_name = email_obj.get("first_name", "")
            last_name = email_obj.get("last_name", "")
            position = email_obj.get("position", "")

            email_info = {
                "email": email,
                "type": email_type,
                "confidence": confidence,
                "name": f"{first_name} {last_name}".strip() or "N/A",
                "position": position or "N/A",
            }

            self.results["emails"].append(email_info)

            # Categorize
            if email_type == "generic":
                self.results["generic"].append(email_info)
            else:
                self.results["verified"].append(email_info)

            # High confidence (>= 90)
            if confidence >= 90:
                self.results["high_conf"].append(email_info)

    def _display(self):
        """Display harvested emails."""
        console.print()

        if not self.results["emails"]:
            console.print("  [dim]No emails found for this domain.[/dim]")
            if self.mock:
                console.print(
                    "\n  [dim yellow][*] Above results are mock data for UI testing.[/dim yellow]\n"
                    "  [dim yellow]    Add --hunter-key to get real data.[/dim yellow]"
                )
            return

        console.print(f"  [bold white]Total emails found:[/bold white] {self.results['total']}")
        if self.results["pattern"]:
            console.print(f"  [bold white]Email pattern:[/bold white] [cyan]{self.results['pattern']}[/cyan]")

        # High confidence emails (most likely valid)
        if self.results["high_conf"]:
            console.print(f"\n[bold yellow][*] High Confidence ({len(self.results['high_conf'])})[/bold yellow]")
            t = Table(box=box.SIMPLE, header_style="bold magenta")
            t.add_column("Email",      style="cyan",  width=30)
            t.add_column("Name",       style="green", width=20)
            t.add_column("Position",   style="white", width=25)
            t.add_column("Conf.",      style="yellow", width=6)

            for e in self.results["high_conf"][:20]:
                t.add_row(
                    e["email"],
                    e["name"],
                    e["position"][:20],
                    f"{e['confidence']}%"
                )
            console.print(t)

        # All verified (personal) emails
        if self.results["verified"] and len(self.results["verified"]) > len(self.results["high_conf"]):
            console.print(f"\n[bold yellow][*] All Verified Emails ({len(self.results['verified'])})[/bold yellow]")
            for e in self.results["verified"]:
                console.print(f"  [cyan]{e['email']}[/cyan] [dim]({e['confidence']}%)[/dim]")

        # Generic emails (shared mailboxes)
        if self.results["generic"]:
            console.print(f"\n[bold yellow][*] Generic Emails ({len(self.results['generic'])})[/bold yellow]")
            for e in self.results["generic"]:
                console.print(f"  [yellow]{e['email']}[/yellow] [dim](shared mailbox)[/dim]")

        if self.mock:
            console.print(
                "\n  [dim yellow][*] Above results are mock data for UI testing.[/dim yellow]\n"
                "  [dim yellow]    Add --hunter-key to get real data.[/dim yellow]"
            )

        # Legal reminder
        console.print("\n[bold yellow][!] Legal Reminder:[/bold yellow]")
        console.print("[dim yellow]    Use harvested emails only for authorized security testing.[/dim yellow]")
        console.print("[dim yellow]    Unsolicited phishing/spam is illegal.[/dim yellow]")
