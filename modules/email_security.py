import dns.resolver
import dns.exception
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Common DKIM selectors to probe
# Organizations use different selectors — we try the most common ones
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "email",
    "key1", "key2", "selector1", "selector2",
    "smtp", "mta", "k1", "s1", "s2",
    "sendgrid", "mailchimp", "mandrill", "postmark",
]


class EmailSecurityChecker:
    def __init__(self, domain: str, verbose: bool = False):
        self.domain  = domain
        self.verbose = verbose

        self.resolver          = dns.resolver.Resolver()
        self.resolver.timeout  = 3
        self.resolver.lifetime = 3

        self.results = {
            "domain":   domain,
            "spf":      {"record": None, "valid": False, "policy": None, "includes": []},
            "dmarc":    {"record": None, "valid": False, "policy": None, "pct": None, "rua": None},
            "dkim":     {"found": False, "selectors": []},
            "findings": [],
            "score":    0,   # 0-100 security score
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Email Security Check[/bold cyan] → [green]{self.domain}[/green]\n"
            f"[dim]SPF · DMARC · DKIM — passive DNS queries only[/dim]",
            expand=False
        ))

        self._check_spf()
        self._check_dmarc()
        self._check_dkim()
        self._calculate_score()
        self._display()

        return self.results

    # -------------------------------------------------------------------------
    # SPF Check
    # -------------------------------------------------------------------------
    def _check_spf(self):
        console.print("\n[bold yellow][*] SPF Record[/bold yellow]")

        try:
            answers = self.resolver.resolve(self.domain, "TXT")

            for rdata in answers:
                txt = str(rdata).strip('"')

                if txt.startswith("v=spf1"):
                    self.results["spf"]["record"] = txt
                    self.results["spf"]["valid"]  = True

                    # Parse the policy (the 'all' mechanism)
                    # -all = hard fail (reject)
                    # ~all = soft fail (accept but mark)
                    # +all = pass all (dangerous — allows anyone)
                    # ?all = neutral (no policy)
                    all_match = re.search(r"([+\-~?])all", txt)
                    if all_match:
                        qualifier = all_match.group(1)
                        policy_map = {
                            "-": "hard fail (strict)",
                            "~": "soft fail (lenient)",
                            "+": "pass all (DANGEROUS)",
                            "?": "neutral (no policy)",
                        }
                        self.results["spf"]["policy"] = policy_map.get(qualifier, "unknown")

                        if qualifier == "+":
                            self.results["findings"].append(
                                "CRITICAL: SPF +all allows anyone to send email as this domain"
                            )
                        elif qualifier == "~":
                            self.results["findings"].append(
                                "SPF uses ~all (soft fail) — spoofed emails may still be delivered"
                            )

                    # Extract include: mechanisms — reveals mail providers
                    includes = re.findall(r"include:([^\s]+)", txt)
                    self.results["spf"]["includes"] = includes

                    # Display
                    console.print(f"  [green][+] SPF found[/green]")
                    console.print(f"  [dim]{txt}[/dim]")

                    policy = self.results["spf"]["policy"]
                    color  = "green" if "strict" in (policy or "") else "yellow" if "lenient" in (policy or "") else "red"
                    console.print(f"  Policy: [{color}]{policy}[/{color}]")

                    if includes:
                        console.print(f"  Mail providers: [cyan]{', '.join(includes)}[/cyan]")

                    return

            # No SPF found
            console.print("  [bold red][-] No SPF record found[/bold red]")
            self.results["findings"].append(
                "CRITICAL: No SPF record — domain spoofing is possible"
            )

        except dns.resolver.NXDOMAIN:
            console.print("  [red][!] Domain does not exist[/red]")
        except dns.resolver.NoAnswer:
            console.print("  [bold red][-] No TXT records found — no SPF[/bold red]")
            self.results["findings"].append("CRITICAL: No SPF record — domain spoofing is possible")
        except Exception as e:
            console.print(f"  [dim red][!] SPF lookup failed: {e}[/dim red]")

    # -------------------------------------------------------------------------
    # DMARC Check
    # -------------------------------------------------------------------------
    def _check_dmarc(self):
        console.print("\n[bold yellow][*] DMARC Record[/bold yellow]")

        # DMARC lives at _dmarc.domain.com
        dmarc_domain = f"_dmarc.{self.domain}"

        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")

            for rdata in answers:
                txt = str(rdata).strip('"')

                if txt.startswith("v=DMARC1"):
                    self.results["dmarc"]["record"] = txt
                    self.results["dmarc"]["valid"]  = True

                    # Parse policy
                    policy_match = re.search(r"p=(\w+)", txt)
                    if policy_match:
                        policy = policy_match.group(1).lower()
                        self.results["dmarc"]["policy"] = policy

                        if policy == "none":
                            self.results["findings"].append(
                                "DMARC p=none — monitoring only, no enforcement. Spoofing emails still delivered"
                            )
                        elif policy == "quarantine":
                            pass  # acceptable
                        elif policy == "reject":
                            pass  # best policy

                    # Parse percentage
                    pct_match = re.search(r"pct=(\d+)", txt)
                    if pct_match:
                        pct = int(pct_match.group(1))
                        self.results["dmarc"]["pct"] = pct
                        if pct < 100:
                            self.results["findings"].append(
                                f"DMARC pct={pct} — policy only applies to {pct}% of emails"
                            )

                    # Parse reporting address
                    rua_match = re.search(r"rua=mailto:([^\s;]+)", txt)
                    if rua_match:
                        self.results["dmarc"]["rua"] = rua_match.group(1)

                    # Display
                    console.print(f"  [green][+] DMARC found[/green]")
                    console.print(f"  [dim]{txt[:120]}[/dim]")

                    policy = self.results["dmarc"]["policy"]
                    color  = {"reject": "green", "quarantine": "yellow", "none": "red"}.get(policy, "white")
                    console.print(f"  Policy: [{color}]p={policy}[/{color}]")

                    if self.results["dmarc"]["pct"]:
                        console.print(f"  Coverage: [yellow]{self.results['dmarc']['pct']}%[/yellow]")
                    if self.results["dmarc"]["rua"]:
                        console.print(f"  Reports → [cyan]{self.results['dmarc']['rua']}[/cyan]")

                    return

            console.print("  [bold red][-] No DMARC record found[/bold red]")
            self.results["findings"].append(
                "CRITICAL: No DMARC record — SPF/DKIM bypass via header spoofing possible"
            )

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            console.print("  [bold red][-] No DMARC record found[/bold red]")
            self.results["findings"].append(
                "CRITICAL: No DMARC record — SPF/DKIM bypass via header spoofing possible"
            )
        except Exception as e:
            console.print(f"  [dim red][!] DMARC lookup failed: {e}[/dim red]")

    # --------- )----------------------------------------------------------------
    # DKIM Check
    # -------------------------------------------------------------------------
    def _check_dkim(self):
        console.print("\n[bold yellow][*] DKIM Selectors[/bold yellow]")
        console.print(f"  [dim][*] Probing {len(DKIM_SELECTORS)} common selectors...[/dim]")

        found_selectors = []

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = self.resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "p=" in txt or "k=" in txt:  # valid DKIM record has public key
                        found_selectors.append({
                            "selector": selector,
                            "record":   txt[:80] + "..." if len(txt) > 80 else txt
                        })
                        console.print(f"  [green][+] DKIM selector found:[/green] [cyan]{selector}[/cyan]")
                        break
            except Exception:
                if self.verbose:
                    console.print(f"  [dim][-] {selector}: not found[/dim]")

        self.results["dkim"]["found"]     = len(found_selectors) > 0
        self.results["dkim"]["selectors"] = found_selectors

        if not found_selectors:
            console.print("  [dim yellow][-] No DKIM selectors found with common names[/dim yellow]")
            console.print("  [dim]    (May use custom selector — not necessarily misconfigured)[/dim]")
            self.results["findings"].append(
                "No DKIM selectors found — emails may not be cryptographically signed"
            )

    # -------------------------------------------------------------------------
    # Security Score
    # -------------------------------------------------------------------------
    def _calculate_score(self):
        """
        Simple 0-100 scoring based on email security config.
        Used to give a quick summary of how well the domain is protected.
        """
        score = 0

        # SPF (40 points)
        if self.results["spf"]["valid"]:
            score += 20
            policy = self.results["spf"]["policy"] or ""
            if "strict" in policy:
                score += 20
            elif "lenient" in policy:
                score += 10

        # DMARC (40 points)
        if self.results["dmarc"]["valid"]:
            score += 10
            policy = self.results["dmarc"]["policy"] or ""
            if policy == "reject":
                score += 30
            elif policy == "quarantine":
                score += 20
            elif policy == "none":
                score += 5

        # DKIM (20 points)
        if self.results["dkim"]["found"]:
            score += 20

        self.results["score"] = score

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------
    def _display(self):
        score = self.results["score"]
        color = "green" if score >= 70 else "yellow" if score >= 40 else "red"

        console.print(f"\n[bold yellow][*] Email Security Score[/bold yellow]")
        console.print(f"  [{color}]{score}/100[/{color}]", end="  ")

        if score >= 70:
            console.print("[green]Well configured[/green]")
        elif score >= 40:
            console.print("[yellow]Partially configured — room for improvement[/yellow]")
        else:
            console.print("[bold red]Poorly configured — spoofing likely possible[/bold red]")

        # Summary table
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Check", style="cyan",  width=8)
        t.add_column("Status", width=30)
        t.add_column("Detail", style="dim white")

        # SPF row
        spf = self.results["spf"]
        spf_status = f"[green]✓ {spf['policy']}[/green]" if spf["valid"] else "[red]✗ missing[/red]"
        t.add_row("SPF", spf_status, spf["record"][:50] + "..." if spf["record"] and len(spf["record"]) > 50 else spf["record"] or "")

        # DMARC row
        dmarc = self.results["dmarc"]
        dmarc_color = {"reject": "green", "quarantine": "yellow", "none": "red"}.get(dmarc.get("policy", ""), "red")
        dmarc_status = f"[{dmarc_color}]✓ p={dmarc['policy']}[/{dmarc_color}]" if dmarc["valid"] else "[red]✗ missing[/red]"
        t.add_row("DMARC", dmarc_status, "")

        # DKIM row
        dkim = self.results["dkim"]
        dkim_status = f"[green]✓ {len(dkim['selectors'])} selector(s) found[/green]" if dkim["found"] else "[yellow]? not found[/yellow]"
        selectors = ", ".join(s["selector"] for s in dkim["selectors"]) if dkim["selectors"] else ""
        t.add_row("DKIM", dkim_status, selectors)

        console.print()
        console.print(t)

        # Findings
        if self.results["findings"]:
            console.print("\n[bold red][!] Findings[/bold red]")
            for f in self.results["findings"]:
                prefix = "[bold red][!!!][/bold red]" if "CRITICAL" in f else "[bold yellow][!][/bold yellow]"
                console.print(f"  {prefix} {f}")

            # Spoofing verdict
            spf_missing   = not self.results["spf"]["valid"]
            dmarc_missing = not self.results["dmarc"]["valid"]
            dmarc_none    = self.results["dmarc"].get("policy") == "none"

            if spf_missing or dmarc_missing or dmarc_none:
                console.print(
                    f"\n  [bold red][!!!] SPOOFING VERDICT:[/bold red] "
                    f"[red]Email spoofing from @{self.domain} may be possible[/red]"
                )
                console.print(
                    f"  [dim red]    Verify with: https://emkei.cz (authorized testing only)[/dim red]"
               
