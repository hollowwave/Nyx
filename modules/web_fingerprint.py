import requests
import socket
import ssl
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Disable SSL warnings for scanning (we're checking certs manually)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURES — the core of fingerprinting
# Each entry maps a technology to indicators we look for
# ─────────────────────────────────────────────────────────────────────────────

# CMS detection — check HTML body for these strings
CMS_HTML_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "wordpress"],
    "Joomla":     ["joomla", "/components/com_", "mosConfig"],
    "Drupal":     ["drupal-settings-json", "Drupal.settings", "/sites/default/files"],
    "Magento":    ["Mage.Cookies", "magento", "/skin/frontend/"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Wix":        ["wixstatic.com", "wix-bolt"],
    "Squarespace":["squarespace.com", "squarespace-cdn"],
    "Ghost":      ["ghost.io", "content/themes/casper"],
    "Laravel":    ["laravel_session", "__laravel_flash"],
    "Django":     ["csrfmiddlewaretoken", "django"],
}

# CMS detection via paths — if this path returns 200, CMS is confirmed
CMS_PATH_SIGNATURES = {
    "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-json/"],
    "Joomla":     ["/administrator/", "/components/"],
    "Drupal":     ["/user/login", "/core/misc/drupal.js"],
    "phpMyAdmin": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
}

# Technology detection from headers and HTML
TECH_SIGNATURES = {
    # From headers
    "headers": {
        "PHP":        ["X-Powered-By:php"],
        "ASP.NET":    ["X-Powered-By:asp.net", "X-AspNet-Version"],
        "Node.js":    ["X-Powered-By:express"],
        "Nginx":      ["Server:nginx"],
        "Apache":     ["Server:apache"],
        "IIS":        ["Server:microsoft-iis", "X-Powered-By:asp.net"],
        "Cloudflare": ["Server:cloudflare", "CF-Ray"],
        "AWS":        ["Server:awselb", "x-amz"],
    },
    # From HTML body
    "html": {
        "React":          ["react-dom", "__reactFiber", "data-reactroot"],
        "Vue.js":         ["vue.js", "__vue__", "data-v-"],
        "Angular":        ["ng-version", "angular.js", "ng-app"],
        "jQuery":         ["jquery.min.js", "jquery.js"],
        "Bootstrap":      ["bootstrap.min.css", "bootstrap.css"],
        "Tailwind":       ["tailwindcss", "tailwind.min.css"],
        "Next.js":        ["__NEXT_DATA__", "_next/static"],
        "Nuxt.js":        ["__nuxt", "__NUXT__"],
        "Laravel":        ["laravel_session", "csrf-token"],
        "Django":         ["csrfmiddlewaretoken"],
        "Ruby on Rails":  ["csrf-param", "authenticity_token"],
        "ASP.NET":        ["__VIEWSTATE", "__EVENTVALIDATION"],
        "Google Analytics": ["google-analytics.com/analytics.js", "gtag("],
        "Google Tag Manager": ["googletagmanager.com/gtm.js"],
    }
}

# Paths to probe — organized by severity
PROBE_PATHS = {
    "critical": [
        "/.git/HEAD",           # Exposed git repo — source code leak
        "/.git/config",         # Git config — remote URLs, credentials
        "/.env",                # Environment file — passwords, API keys
        "/.env.local",
        "/.env.production",
        "/config.php",          # PHP config — database credentials
        "/wp-config.php",       # WordPress config
        "/config/database.yml", # Rails database config
        "/.htpasswd",           # Apache password file
        "/id_rsa",              # Private SSH key (yes, people do this)
        "/server.key",          # SSL private key
    ],
    "interesting": [
        "/robots.txt",          # Disallowed paths often reveal hidden endpoints
        "/sitemap.xml",         # All URLs of the site
        "/crossdomain.xml",     # Flash cross-domain policy
        "/.well-known/security.txt", # Security contact info
        "/security.txt",
        "/readme.html",         # WordPress version leak
        "/readme.txt",
        "/CHANGELOG.txt",       # Version info
        "/LICENSE.txt",
        "/phpinfo.php",         # PHP info page — critical if exists
        "/info.php",
        "/test.php",
    ],
    "admin": [
        "/admin",
        "/admin/",
        "/admin/login",
        "/administrator/",
        "/wp-admin/",
        "/dashboard",
        "/manage",
        "/panel",
        "/cpanel",
        "/webmail",
        "/phpmyadmin/",
        "/pma/",
        "/jenkins/",
        "/grafana/",
    ]
}

# Security headers every server should have
# Missing = reportable finding, here's why each matters
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Prevents SSL stripping attacks",
    "Content-Security-Policy":   "Mitigates XSS and injection attacks",
    "X-Frame-Options":           "Prevents clickjacking attacks",
    "X-Content-Type-Options":    "Prevents MIME sniffing attacks",
    "Referrer-Policy":           "Controls referrer information leakage",
    "Permissions-Policy":        "Controls browser feature access",
    "X-XSS-Protection":          "Legacy XSS filter (older browsers)",
}


class WebFingerprint:
    def __init__(self, target: str, verbose: bool = False, probe_admin: bool = True):
        self.target = target
        self.verbose = verbose
        self.probe_admin = probe_admin
        self.base_url = self._make_url()
        self.session = requests.Session()
        self.session.headers.update({
            # Blend in as a normal browser — some servers block obvious scanners
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.results = {
            "target": target,
            "url": self.base_url,
            "headers": {},
            "technology": [],
            "cms": [],
            "paths": {"critical": [], "interesting": [], "admin": []},
            "security": {},
            "cookies": [],
            "ssl": {},
            "findings": []  # high-level summary of interesting things
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Web Fingerprinting[/bold cyan] → [green]{self.base_url}[/green]",
            expand=False
        ))

        # Fetch main page
        try:
            r = self.session.get(self.base_url, timeout=10, verify=False, allow_redirects=True)
            console.print(f"  [dim][*] {r.status_code} {r.url} ({len(r.content)} bytes)[/dim]\n")
        except requests.exceptions.ConnectionError:
            # Try HTTP if HTTPS failed
            if self.base_url.startswith("https://"):
                self.base_url = self.base_url.replace("https://", "http://")
                console.print(f"  [dim yellow][!] HTTPS failed, trying HTTP...[/dim yellow]")
                try:
                    r = self.session.get(self.base_url, timeout=10, verify=False, allow_redirects=True)
                except Exception as e:
                    console.print(f"  [bold red][!] Connection failed: {e}[/bold red]")
                    return self.results
            else:
                console.print(f"  [bold red][!] Connection failed[/bold red]")
                return self.results
        except Exception as e:
            console.print(f"  [bold red][!] Error: {e}[/bold red]")
            return self.results

        soup = BeautifulSoup(r.text, "html.parser")

        # Run all analysis
        self._analyze_headers(r.headers)
        self._analyze_html(r.text, soup)
        self._analyze_cookies(r.cookies)
        self._probe_paths()
        self._check_security_headers(r.headers)
        self._get_ssl_info()

        # Display everything
        self._display_results()

        return self.results

    # -------------------------------------------------------------------------
    # 1. Header Analysis
    # -------------------------------------------------------------------------
    def _analyze_headers(self, headers):
        # Extract interesting headers
        interesting = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
                      "X-Runtime", "X-Version", "Via", "CF-Ray", "X-Served-By"]

        for h in interesting:
            if h in headers:
                self.results["headers"][h] = headers[h]

        # Detect technology from headers
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for tech, signatures in TECH_SIGNATURES["headers"].items():
            for sig in signatures:
                if ":" in sig:
                    header_name, keyword = sig.split(":", 1)
                    if header_name.lower() in headers_lower and keyword in headers_lower.get(header_name.lower(), ""):
                        if tech not in self.results["technology"]:
                            self.results["technology"].append(tech)
                else:
                    if sig.lower() in headers_lower:
                        if tech not in self.results["technology"]:
                            self.results["technology"].append(tech)

        # Version extraction — if we get a version number, note it
        # Version info = directly searchable for CVEs
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")

        for val in [server, powered]:
            if "/" in val:
                # e.g. "Apache/2.4.49" or "PHP/8.1.0"
                self.results["findings"].append(f"Version disclosed: {val} — search for CVEs")

    # -------------------------------------------------------------------------
    # 2. HTML Body Analysis
    # -------------------------------------------------------------------------
    def _analyze_html(self, html: str, soup: BeautifulSoup):
        html_lower = html.lower()

        # CMS detection from HTML
        for cms, signatures in CMS_HTML_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in html_lower:
                    if cms not in self.results["cms"]:
                        self.results["cms"].append(cms)
                    break

        # Technology detection from HTML
        for tech, signatures in TECH_SIGNATURES["html"].items():
            for sig in signatures:
                if sig.lower() in html_lower:
                    if tech not in self.results["technology"]:
                        self.results["technology"].append(tech)
                    break

        # Meta generator tag — often leaks CMS and version
        # e.g. <meta name="generator" content="WordPress 6.1.1">
        generator = soup.find("meta", {"name": "generator"})
        if generator and generator.get("content"):
            gen_content = generator["content"]
            self.results["headers"]["X-Generator (meta)"] = gen_content
            self.results["findings"].append(f"Generator tag found: {gen_content} — check for known CVEs")

        # HTML comments — devs sometimes leave sensitive info in comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in str(text))
        sensitive_keywords = ["password", "todo", "hack", "fix", "bug", "credential", "secret", "key", "token"]
        for comment in soup.find_all(string=lambda t: hasattr(t, '__class__') and t.__class__.__name__ == 'Comment'):
            comment_lower = str(comment).lower()
            for kw in sensitive_keywords:
                if kw in comment_lower:
                    self.results["findings"].append(f"Sensitive keyword '{kw}' found in HTML comment")
                    break

        # JavaScript files — external scripts reveal tech stack
        scripts = soup.find_all("script", src=True)
        for script in scripts[:20]:  # limit to first 20
            src = script.get("src", "").lower()
            if "jquery" in src and "jQuery" not in self.results["technology"]:
                self.results["technology"].append("jQuery")

    # -------------------------------------------------------------------------
    # 3. Cookie Analysis
    # -------------------------------------------------------------------------
    def _analyze_cookies(self, cookies):
        """
        Cookie flags matter for security:
        - HttpOnly: cookie not accessible via JS → XSS can't steal it
        - Secure: cookie only sent over HTTPS → no plaintext leakage
        - SameSite: CSRF protection
        Missing flags = vulnerabilities
        """
        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "httponly": cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"),
                "secure": cookie.secure,
                "samesite": cookie.has_nonstandard_attr("samesite"),
            }
            self.results["cookies"].append(cookie_info)

            # Flag missing security flags
            if not cookie.secure:
                self.results["findings"].append(f"Cookie '{cookie.name}' missing Secure flag")
            if not cookie_info["httponly"]:
                self.results["findings"].append(f"Cookie '{cookie.name}' missing HttpOnly flag — XSS can steal it")

    # -------------------------------------------------------------------------
    # 4. Path Probing
    # -------------------------------------------------------------------------
    def _probe_paths(self):
        console.print("[bold yellow][*] Probing paths...[/bold yellow]")

        all_paths = []
        all_paths += [("critical", p) for p in PROBE_PATHS["critical"]]
        all_paths += [("interesting", p) for p in PROBE_PATHS["interesting"]]
        if self.probe_admin:
            all_paths += [("admin", p) for p in PROBE_PATHS["admin"]]

        def probe(category_path):
            category, path = category_path
            url = urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                exists = r.status_code < 400
                result = {"path": path, "status": r.status_code, "exists": exists}

                if exists:
                    # Critical path found = major finding
                    if category == "critical":
                        self.results["findings"].append(f"CRITICAL: {path} is accessible ({r.status_code})")
                        console.print(f"  [bold red][!!!] CRITICAL: {path} → {r.status_code}[/bold red]")
                    elif category == "admin":
                        self.results["findings"].append(f"Admin panel found: {path} ({r.status_code})")
                        console.print(f"  [bold yellow][!] Admin panel: {path} → {r.status_code}[/bold yellow]")
                    elif self.verbose:
                        console.print(f"  [green][+] {path} → {r.status_code}[/green]")

                    # CMS confirmation via path
                    for cms, paths in CMS_PATH_SIGNATURES.items():
                        if path in paths and cms not in self.results["cms"]:
                            self.results["cms"].append(cms)

                return category, result

            except Exception:
                return category, {"path": path, "status": None, "exists": False}

        # Thread the path probing — lots of HTTP requests, threading helps a lot
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(probe, cp) for cp in all_paths]
            for future in concurrent.futures.as_completed(futures):
                category, result = future.result()
                if result["exists"]:
                    self.results["paths"][category].append(result)

    # -------------------------------------------------------------------------
    # 5. Security Header Audit
    # -------------------------------------------------------------------------
    def _check_security_headers(self, headers):
        for header, reason in SECURITY_HEADERS.items():
            present = header in headers
            self.results["security"][header] = present
            if not present:
                self.results["findings"].append(f"Missing security header: {header} — {reason}")

    # -------------------------------------------------------------------------
    # 6. SSL/TLS Info
    # -------------------------------------------------------------------------
    def _get_ssl_info(self):
        """
        Check SSL certificate details.
        Expired certs = finding. Wildcard certs reveal subdomain patterns.
        Self-signed certs on prod = finding.
        """
        try:
            hostname = self.target.replace("https://", "").replace("http://", "").split("/")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()

            # Extract useful fields
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            expiry  = cert.get("notAfter", "")
            sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

            self.results["ssl"] = {
                "common_name": subject.get("commonName", "N/A"),
                "issuer": issuer.get("organizationName", "N/A"),
                "expiry": expiry,
                "san": sans[:10],  # first 10 SANs — reveals related domains
            }

            # Check expiry
            if expiry:
                try:
                    exp_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.utcnow()).days
                    self.results["ssl"]["days_until_expiry"] = days_left
                    if days_left < 30:
                        self.results["findings"].append(f"SSL cert expires in {days_left} days!")
                except Exception:
                    pass

            # SANs can reveal subdomains and related infrastructure
            if sans:
                self.results["findings"].append(f"SSL SANs reveal {len(sans)} domain(s): {', '.join(sans[:5])}")

        except Exception as e:
            if self.verbose:
                console.print(f"  [dim]SSL info unavailable: {e}[/dim]")

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------
    def _display_results(self):
        # Headers
        if self.results["headers"]:
            console.print("\n[bold yellow][*] HTTP Headers[/bold yellow]")
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("Header", style="cyan", width=25)
            t.add_column("Value", style="white")
            for k, v in self.results["headers"].items():
                t.add_row(k, v)
            console.print(t)

        # Technology stack
        if self.results["technology"] or self.results["cms"]:
            console.print("\n[bold yellow][*] Technology Stack[/bold yellow]")
            if self.results["cms"]:
                console.print(f"  [bold green]CMS:[/bold green] {', '.join(self.results['cms'])}")
            if self.results["technology"]:
                console.print(f"  [bold green]Tech:[/bold green] {', '.join(self.results['technology'])}")

        # SSL
        if self.results["ssl"]:
            console.print("\n[bold yellow][*] SSL Certificate[/bold yellow]")
            ssl = self.results["ssl"]
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("Field", style="cyan", width=20)
            t.add_column("Value", style="white")
            t.add_row("Common Name", ssl.get("common_name", "N/A"))
            t.add_row("Issuer", ssl.get("issuer", "N/A"))
            t.add_row("Expires", ssl.get("expiry", "N/A"))
            days = ssl.get("days_until_expiry")
            if days is not None:
                color = "red" if days < 30 else "green"
                t.add_row("Days Left", f"[{color}]{days}[/{color}]")
            if ssl.get("san"):
                t.add_row("SANs", "\n".join(ssl["san"][:5]))
            console.print(t)

        # Paths found
        found_paths = (
            self.results["paths"]["critical"] +
            self.results["paths"]["interesting"] +
            self.results["paths"]["admin"]
        )
        if found_paths:
            console.print("\n[bold yellow][*] Accessible Paths[/bold yellow]")
            t = Table(box=box.SIMPLE, header_style="bold magenta")
            t.add_column("Path", style="white", width=35)
            t.add_column("Status", style="cyan", width=8)
            t.add_column("Type", style="yellow")
            for category in ["critical", "interesting", "admin"]:
                for p in self.results["paths"][category]:
                    color = "red" if category == "critical" else "yellow" if category == "admin" else "green"
                    t.add_row(p["path"], str(p["status"]), f"[{color}]{category}[/{color}]")
            console.print(t)

        # Security headers
        console.print("\n[bold yellow][*] Security Headers[/bold yellow]")
        t = Table(box=box.SIMPLE, header_style="bold magenta")
        t.add_column("Header", style="cyan", width=35)
        t.add_column("Status", width=10)
        for header, present in self.results["security"].items():
            status = "[bold green]✓ Present[/bold green]" if present else "[bold red]✗ Missing[/bold red]"
            t.add_row(header, status)
        console.print(t)

        # Cookies
        if self.results["cookies"]:
            console.print("\n[bold yellow][*] Cookies[/bold yellow]")
            t = Table(box=box.SIMPLE, header_style="bold magenta")
            t.add_column("Name", style="cyan")
            t.add_column("HttpOnly", width=10)
            t.add_column("Secure", width=8)
            t.add_column("SameSite", width=10)
            for c in self.results["cookies"]:
                t.add_row(
                    c["name"],
                    "[green]✓[/green]" if c["httponly"] else "[red]✗[/red]",
                    "[green]✓[/green]" if c["secure"] else "[red]✗[/red]",
                    "[green]✓[/green]" if c["samesite"] else "[red]✗[/red]",
                )
            console.print(t)

        # Findings summary — the analyst layer
        if self.results["findings"]:
            console.print("\n[bold red][!] Findings Summary[/bold red]")
            for f in self.results["findings"]:
                prefix = "[bold red][!!!][/bold red]" if "CRITICAL" in f else "[bold yellow][!][/bold yellow]"
                console.print(f"  {prefix} {f}")

    def _make_url(self) -> str:
        if self.target.startswith(("http://", "https://")):
            return self.target
        return f"https://{self.target}"
