import socket
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Top 100 most common ports in pentesting
# Scanning all 65535 ports takes too long for recon — these cover 99% of findings
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119,
    135, 139, 143, 161, 194, 389, 443, 445, 465, 587,
    631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376,
    3000, 3306, 3389, 3690, 4000, 4443, 4444, 4848, 5000, 5432,
    5672, 5900, 5984, 6000, 6379, 6443, 6666, 7000, 7001, 7070,
    7443, 7777, 8000, 8001, 8008, 8080, 8081, 8082, 8083, 8086,
    8088, 8089, 8090, 8091, 8161, 8181, 8443, 8444, 8500, 8800,
    8880, 8888, 8983, 9000, 9001, 9090, 9091, 9200, 9300, 9418,
    9999, 10000, 10250, 10255, 11211, 27017, 27018, 28017, 50000, 50070
]

# Smart banner probes — different services need different nudges to respond
# Sending HTTP to an SSH port won't get a useful response
BANNER_PROBES = {
    21:   b"",                              # FTP sends banner automatically
    22:   b"",                              # SSH sends banner automatically
    23:   b"",                              # Telnet sends banner automatically
    25:   b"EHLO nyx\r\n",                 # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP
    110:  b"",                              # POP3 sends banner automatically
    119:  b"",                              # NNTP
    143:  b"",                              # IMAP sends banner automatically
    443:  b"HEAD / HTTP/1.0\r\n\r\n",      # HTTPS (won't work without TLS but worth trying)
    3306: b"",                              # MySQL sends banner automatically
    5432: b"",                              # PostgreSQL
    6379: b"PING\r\n",                     # Redis
    8080: b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP alt
    8443: b"HEAD / HTTP/1.0\r\n\r\n",      # HTTPS alt
    27017: b"",                             # MongoDB
}

# Port to service name map — fallback if socket.getservbyport() fails
# Covers ports that Python's built-in doesn't always know
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind", 119: "NNTP",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2181: "Zookeeper", 2375: "Docker", 2376: "Docker TLS", 3000: "Dev Server",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    9300: "Elasticsearch", 10250: "Kubelet", 11211: "Memcached",
    27017: "MongoDB", 50070: "Hadoop"
}


class PortScanner:
    def __init__(
        self,
        target: str,
        verbose: bool = False,
        ports: list = None,
        start_port: int = None,
        end_port: int = None,
        max_workers: int = 100,
        timeout: float = 1.0,
        grab_banner: bool = True,
    ):
        self.target = target
        self.verbose = verbose
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banner = grab_banner

        # Port selection logic:
        # 1. Custom list passed in → use that
        # 2. Start/end range passed in → use that range
        # 3. Default → scan TOP_100_PORTS
        if ports:
            self.ports = ports
        elif start_port and end_port:
            self.ports = list(range(start_port, end_port + 1))
        else:
            self.ports = TOP_100_PORTS

        self.results = {
            "target": target,
            "open_ports": [],
            "total_scanned": len(self.ports),
        }

    def run(self) -> dict:
        console.print(Panel(
            f"[bold cyan]Port Scanner[/bold cyan] → [green]{self.target}[/green] "
            f"[dim]({len(self.ports)} ports, {self.max_workers} threads)[/dim]",
            expand=False
        ))

        # Resolve hostname to IP first
        # Why: scanning a hostname means resolving it every connection = slow
        # Resolving once and reusing the IP is much faster
        try:
            self.ip = socket.gethostbyname(self.target)
            if self.ip != self.target:
                console.print(f"  [dim][*] Resolved to {self.ip}[/dim]")
        except socket.gaierror as e:
            console.print(f"  [bold red][!] Could not resolve {self.target}: {e}[/bold red]")
            return self.results

        console.print(f"  [dim][*] Scanning {len(self.ports)} ports...[/dim]\n")

        open_ports = []

        # ThreadPoolExecutor — same pattern as DNS module
        # max_workers=100 means 100 simultaneous connections
        # Port scanning is I/O bound (waiting for responses) so threading helps a lot
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result["open"]:
                    open_ports.append(result)

        # Sort by port number for clean output
        open_ports.sort(key=lambda x: x["port"])
        self.results["open_ports"] = open_ports

        self._display_results(open_ports)

        return self.results

    def _scan_port(self, port: int) -> dict:
        """
        Attempt a TCP connection to the target:port.
        connect_ex() returns 0 on success (port open), non-zero on failure (closed/filtered).
        This is a TCP SYN-like connect scan — not stealthy, but works without root.
        For stealth scanning (SYN scan) you'd need raw sockets + root/admin — that's nmap's -sS flag.
        """
        result = {
            "port": port,
            "open": False,
            "service": self._get_service(port),
            "banner": ""
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)

                # connect_ex returns error code, 0 = success = port is open
                if sock.connect_ex((self.ip, port)) == 0:
                    result["open"] = True

                    if self.verbose:
                        console.print(f"  [bold green][+] {port}/tcp open[/bold green] ({result['service']})")

                    # Banner grabbing
                    if self.grab_banner:
                        result["banner"] = self._grab_banner(sock, port)

        except Exception:
            pass

        return result

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Try to get the service banner.
        Some services send it automatically (SSH, FTP, Telnet).
        Others need a probe first (HTTP needs a request).
        We send the right probe per port, then read the response.
        """
        try:
            # Send appropriate probe for this port
            probe = BANNER_PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
            if probe:
                sock.send(probe)

            # Read response — first 1024 bytes is enough for a banner
            banner = sock.recv(1024).decode(errors="ignore").strip()

            # Clean it up — take only first line (rest is usually headers/noise)
            first_line = banner.split("\n")[0].strip()

            # Truncate if too long for display
            if len(first_line) > 80:
                first_line = first_line[:77] + "..."

            return first_line

        except Exception:
            return ""

    def _get_service(self, port: int) -> str:
        """
        Get service name for a port.
        Try Python's built-in first, fall back to our custom dict.
        """
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return COMMON_SERVICES.get(port, "unknown")

    def _display_results(self, open_ports: list):
        """Display results as a rich table."""

        if not open_ports:
            console.print("  [dim]No open ports found.[/dim]")
            return

        table = Table(box=box.SIMPLE, header_style="bold magenta", show_header=True)
        table.add_column("Port",    style="cyan",   width=8)
        table.add_column("State",   style="green",  width=8)
        table.add_column("Service", style="yellow", width=15)
        table.add_column("Banner",  style="white")

        for p in open_ports:
            banner = p.get("banner", "")

            # Highlight interesting banners — version info = potential CVE
            banner_display = f"[dim]{banner}[/dim]" if banner else "[dim]—[/dim]"

            table.add_row(
                str(p["port"]),
                "open",
                p.get("service", "unknown"),
                banner_display
            )

        console.print(table)
        console.print(f"\n  [bold green][✓] {len(open_ports)} open port(s) found out of {self.results['total_scanned']} scanned[/bold green]")

        # Flag interesting ports — these are high value targets in pentesting
        self._flag_interesting(open_ports)

    def _flag_interesting(self, open_ports: list):
        """
        Flag ports that are particularly interesting from a pentesting perspective.
        This is like a mini-analyst — not just reporting what's open, but WHY it matters.
        """
        interesting = {
            21:    "FTP — check for anonymous login",
            22:    "SSH — check for weak credentials or old version",
            23:    "Telnet — unencrypted, credentials sent in plaintext",
            25:    "SMTP — check for open relay",
            445:   "SMB — check for EternalBlue (MS17-010), null sessions",
            1433:  "MSSQL — check for default credentials (sa/blank)",
            1521:  "Oracle DB — check for default credentials",
            2375:  "Docker (unauthenticated) — critical, RCE possible",
            3306:  "MySQL — check for remote root login",
            3389:  "RDP — check for BlueKeep (CVE-2019-0708)",
            5432:  "PostgreSQL — check for default credentials",
            5900:  "VNC — check for no auth or weak password",
            5984:  "CouchDB — check for unauthenticated admin panel",
            6379:  "Redis — often unauthenticated, RCE possible",
            7001:  "WebLogic — multiple critical CVEs",
            8080:  "HTTP-Alt — check for admin panels, dev servers",
            8888:  "Jupyter — often no auth, direct code execution",
            9200:  "Elasticsearch — often unauthenticated, data exposure",
            10250: "Kubelet API — check for unauthenticated access",
            11211: "Memcached — often unauthenticated",
            27017: "MongoDB — often unauthenticated",
        }

        found_interesting = []
        for p in open_ports:
            port = p["port"]
            if port in interesting:
                found_interesting.append((port, interesting[port]))

        if found_interesting:
            console.print("\n  [bold red][!] Interesting ports — investigate these:[/bold red]")
            for port, note in found_interesting:
                console.print(f"    [red]→ {port}[/red] [white]{note}[/white]")
