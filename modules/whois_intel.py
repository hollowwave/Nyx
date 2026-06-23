import whois
import requests
import socket
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime
from datetime import timezone

console = Console()

# Known CDN/proxy IP ranges (simplified - real tools use larger databases)
# If the IP resolves to these ASNs, the real server is hidden
CDN_ASNS = {
    "AS13335": "Cloudflare",
    "AS16509": "Amazon CloudFront",
    "AS15169": "Google Cloud CDN",
    "AS8075":  "Microsoft Azure CDN",
    "AS54113": "Fastly",
    "AS20940": "Akamai",
}

# Known CDN org name keywords (fallback detection)
CDN_KEYWORDS = ["cloudflare", "akamai cdn", "akamai techonologies cdn", "fastly", "cloudfront", "incapsula", "sucuri"]


class WHOISIntel:
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "domain": domain,
            "whois": {},
            "ip_intel": {},
            "cdn_detected": False,
            "cdn_provider": None
        }

    def run(self) -> dict:
        console.print(Panel(f"[bold cyan]WHOIS / IP Intelligence[/bold cyan] → [green]{self.domain}[/green]", expand=False))

        self._whois_lookup()
        self._ip_intel()

        return self.results

    # -------------------------------------------------------------------------
    # 1. Domain WHOIS Lookup
    # Why: Reveals who owns the domain, when it was created, when it expires.
    # Expiring domains are sometimes taken over by attackers — good intel.
    # Old creation dates = possibly neglected infrastructure.
    # -------------------------------------------------------------------------
    def _whois_lookup(self):
        console.print("\n[bold yellow][*] WHOIS Lookup[/bold yellow]")

        try:
            w = whois.whois(self.domain)

            # Some fields return lists (multiple registrars, dates, etc.)
            # We normalize them to single values for clean output
            def normalize(val):
                if isinstance(val, list):
                    return val[0]
                return val

            registrar     = normalize(w.registrar) or "N/A"
            creation_date = normalize(w.creation_date)
            expiry_date   = normalize(w.expiration_date)
            updated_date  = normalize(w.updated_date)
            org           = normalize(w.org) or normalize(w.registrant) or "N/A"
            country       = normalize(w.country) or "N/A"
            name_servers  = w.name_servers or []

            # Calculate domain age
            age_str = "N/A"
            if creation_date and isinstance(creation_date, datetime):
                now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
                age = (now - creation_date).days
                age_str = f"{age // 365} years, {(age % 365) // 30} months"

            # Calculate days until expiry — expired or expiring soon is interesting
            expiry_str = "N/A"
            expiry_warning = False
            if expiry_date and isinstance(expiry_date, datetime):
                now = datetime.now(timezone.utc) if expiry_date.tzinfo else datetime.now()
                days_left = (expiry_date - now).days
                expiry_str = f"{expiry_date.strftime('%Y-%m-%d')} ({days_left} days left)"
                if days_left < 90:
                    expiry_warning = True

            # Build results dict
            self.results["whois"] = {
                "registrar": registrar,
                "org": str(org),
                "country": str(country),
                "creation_date": str(creation_date),
                "expiry_date": str(expiry_date),
                "updated_date": str(updated_date),
                "name_servers": [str(ns).lower() for ns in name_servers],
                "domain_age": age_str
            }

            # Display table
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Field", style="cyan", width=20)
            table.add_column("Value", style="white")

            table.add_row("Registrar", registrar)
            table.add_row("Org / Registrant", str(org))
            table.add_row("Country", str(country))
            table.add_row("Domain Age", age_str)
            table.add_row("Created", str(creation_date)[:10] if creation_date else "N/A")
            table.add_row(
                "Expires",
                f"[bold red]{expiry_str}[/bold red]" if expiry_warning else expiry_str
            )
            table.add_row("Updated", str(updated_date)[:10] if updated_date else "N/A")

            if name_servers:
                table.add_row("Name Servers", "\n".join([str(ns).lower() for ns in name_servers[:4]]))

            console.print(table)

            # Warn if expiring soon — in real pentests this is a finding
            if expiry_warning:
                console.print("  [bold red][!] Domain expiring within 90 days — possible takeover risk[/bold red]")

        except Exception as e:
            console.print(f"  [red][!] WHOIS lookup failed: {e}[/red]")
            if self.verbose:
                import traceback
                traceback.print_exc()

    # -------------------------------------------------------------------------
    # 2. IP Intelligence (ASN + Geolocation + CDN Detection)
    # Why: Knowing the ASN tells you if the target is self-hosted or on a cloud
    # provider. Cloud providers have APIs, metadata endpoints, and misconfig risks
    # that self-hosted servers don't. CDN detection tells you if the IPs from DNS
    # are real or just proxy IPs — critical before you start port scanning.
    # -------------------------------------------------------------------------
    def _ip_intel(self):
        console.print("\n[bold yellow][*] IP Intelligence[/bold yellow]")

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(self.domain)
            console.print(f"  [dim][*] Resolved {self.domain} → {ip}[/dim]")
        except socket.gaierror as e:
            console.print(f"  [red][!] Could not resolve domain: {e}[/red]")
            return

        # --- ASN Lookup via ipwhois ---
        # ASN = Autonomous System Number, identifies who owns the IP block
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)

            asn         = rdap.get("asn", "N/A")
            asn_desc    = rdap.get("asn_description", "N/A")
            asn_cidr    = rdap.get("asn_cidr", "N/A")
            network     = rdap.get("network", {})
            net_name    = network.get("name", "N/A")
            net_country = network.get("country", "N/A")

            self.results["ip_intel"]["ip"]          = ip
            self.results["ip_intel"]["asn"]         = f"AS{asn}"
            self.results["ip_intel"]["asn_desc"]    = asn_desc
            self.results["ip_intel"]["asn_cidr"]    = asn_cidr
            self.results["ip_intel"]["net_name"]    = net_name
            self.results["ip_intel"]["net_country"] = net_country

            # CDN detection via ASN
            asn_key = f"AS{asn}"
            if asn_key in CDN_ASNS:
                self.results["cdn_detected"] = True
                self.results["cdn_provider"] = CDN_ASNS[asn_key]

            # CDN detection via org name keywords
            if not self.results["cdn_detected"]:
                desc_lower = asn_desc.lower()
                for keyword in CDN_KEYWORDS:
                    if keyword in desc_lower:
                        self.results["cdn_detected"] = True
                        self.results["cdn_provider"] = keyword.capitalize()
                        break

        except IPDefinedError:
            console.print(f"  [dim yellow][!] {ip} is a private/reserved IP — skipping ASN lookup[/dim yellow]")
        except Exception as e:
            if self.verbose:
                console.print(f"  [dim red][!] Primary ASN lookup failed: {e} — trying fallback[/dim red]")
            # Fallback: bgpview API
            try:
                r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=5)
                data = r.json()
                if data.get("status") == "ok":
                    prefixes = data["data"].get("prefixes", [])
                    if prefixes:
                        p = prefixes[0]
                        asn_info = p.get("asn", {})
                        self.results["ip_intel"]["asn"]      = f"AS{asn_info.get('asn', 'N/A')}"
                        self.results["ip_intel"]["asn_desc"] = asn_info.get("description", "N/A")
                        self.results["ip_intel"]["asn_cidr"] = p.get("prefix", "N/A")
                        self.results["ip_intel"]["net_name"] = asn_info.get("name", "N/A")
                        # CDN detection on fallback
                        desc_lower = self.results["ip_intel"]["asn_desc"].lower()
                        for keyword in CDN_KEYWORDS:
                            if keyword in desc_lower:
                                self.results["cdn_detected"] = True
                                self.results["cdn_provider"] = keyword.capitalize()
                                break
            except Exception as e2:
                console.print(f"  [red][!] ASN fallback also failed: {e2}[/red]")
            asn_desc = self.results["ip_intel"].get("asn_desc", "N/A")

        # --- Geolocation via ip-api.com (free, no key needed) ---
        # Rate limit: 45 requests/minute — fine for our use case
        try:
            geo_url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,lat,lon"
            response = requests.get(geo_url, timeout=5)
            geo = response.json()

            if geo.get("status") == "success":
                self.results["ip_intel"]["geo"] = {
                    "country":  geo.get("country", "N/A"),
                    "region":   geo.get("regionName", "N/A"),
                    "city":     geo.get("city", "N/A"),
                    "isp":      geo.get("isp", "N/A"),
                    "org":      geo.get("org", "N/A"),
                    "lat":      geo.get("lat"),
                    "lon":      geo.get("lon")
                }
            else:
                self.results["ip_intel"]["geo"] = {}

        except Exception as e:
            console.print(f"  [dim red][!] Geolocation failed: {e}[/dim red]")
            self.results["ip_intel"]["geo"] = {}

        # --- Display Results ---
        geo = self.results["ip_intel"].get("geo", {})

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")

        table.add_row("IP Address", ip)
        table.add_row("ASN", f"{self.results['ip_intel'].get('asn', 'N/A')} — {self.results['ip_intel'].get('asn_desc', 'N/A')}")
        table.add_row("Network", self.results['ip_intel'].get('net_name', 'N/A'))
        table.add_row("CIDR Block", self.results['ip_intel'].get('asn_cidr', 'N/A'))

        if geo:
            table.add_row("Location", f"{geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
            table.add_row("ISP", geo.get("isp", "N/A"))
            table.add_row("Org", geo.get("org", "N/A"))
            table.add_row("Coordinates", f"{geo.get('lat')}, {geo.get('lon')}")

        console.print(table)

        # CDN Warning — this is an important pentesting finding
        if self.results["cdn_detected"]:
            provider = self.results["cdn_provider"]
            console.print(f"\n  [bold yellow][!] CDN DETECTED: {provider}[/bold yellow]")
            console.print(f"  [yellow]    The IP {ip} belongs to {provider}, not the origin server.[/yellow]")
            console.print(f"  [yellow]    Port scanning this IP won't reveal the real server's services.[/yellow]")
            console.print(f"  [yellow]    Find the origin IP via: historical DNS, SSL certs, email headers.[/yellow]")
        else:
            console.print(f"\n  [bold green][+] No CDN detected — {ip} is likely the real server IP[/bold green]")
