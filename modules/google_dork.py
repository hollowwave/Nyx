from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Dork templates — placeholders filled with target domain
DORK_CATEGORIES = {
    "File Discovery": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:xlsx',
        'site:{domain} filetype:docx',
        'site:{domain} filetype:txt',
        'site:{domain} filetype:log',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:bak',
    ],
    "Admin Panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:phpmyadmin',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:management',
        'site:{domain} inurl:dashboard',
    ],
    "Sensitive Paths": [
        'site:{domain} inurl:config',
        'site:{domain} inurl:database',
        'site:{domain} inurl:backup',
        'site:{domain} inurl:cache',
        'site:{domain} inurl:upload',
        'site:{domain} inurl:.env',
        'site:{domain} inurl:private',
        'site:{domain} inurl:internal',
    ],
    "Server Info": [
        'site:{domain} "Apache" | "nginx" | "IIS"',
        'site:{domain} "powered by"',
        'site:{domain} "server:"',
        'site:{domain} "X-Powered-By"',
    ],
    "Error Pages": [
        'site:{domain} "error" "debug"',
        'site:{domain} "stack trace"',
        'site:{domain} "exception"',
        'site:{domain} "SQL syntax"',
    ],
    "Subdomains": [
        '"*.{domain}"',
        'site:*.{domain}',
    ],
    "Cached Content": [
        'cache:{domain}',
    ],
}


class GoogleDorkGenerator:
    def __init__(self, domain: str, verbose: bool = False):
        self.domain  = domain.strip()
        self.verbose = verbose
        self.results = {
            "domain": domain,
            "dorks":  {},
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Google Dork Generator[/bold cyan] → [green]{self.domain}[/green]\n"
            f"[dim]Educational OSINT — completely passive, no network probing[/dim]",
            expand=False
        ))

        self._generate_dorks()
        self._display()

        return self.results

    def _generate_dorks(self):
        """Generate all dorks for the domain."""
        for category, templates in DORK_CATEGORIES.items():
            self.results["dorks"][category] = [
                template.format(domain=self.domain)
                for template in templates
            ]

    def _display(self):
        """Display dorks by category."""
        console.print("\n[bold yellow][*] Generated Dorks[/bold yellow]")
        console.print("[dim]Copy these into Google Search (one per line)[/dim]\n")

        for category, dorks in self.results["dorks"].items():
            console.print(f"[bold cyan]{category}[/bold cyan]")
            for dork in dorks:
                console.print(f"  [white]{dork}[/white]")
            console.print()

        console.print("[bold yellow][*] How to use:[/bold yellow]")
        console.print("[dim]  1. Copy a dork into Google search[/dim]")
        console.print("[dim]  2. Review results for sensitive files/info[/dim]")
        console.print("[dim]  3. If found, verify before reporting[/dim]")
        console.print()
        console.print("[dim yellow][!] Legal Notice:[/dim yellow]")
        console.print("[dim yellow]    Only search targets you have permission to audit.[/dim yellow]")
        console.print("[dim yellow]    Finding exposed data is great for bug bounty reports.[/dim yellow]")
