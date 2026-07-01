# Nyx 

**Automated OSINT & Recon Pipeline**

---

## ⚠️ LEGAL DISCLAIMER

**Nyx is an educational cybersecurity tool designed for authorized security testing only.**

### You Must Have Permission
- Only use Nyx on systems and domains you **own** or have **explicit written permission** to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- This includes domains, IPs, email systems, and any connected infrastructure

### Legal Frameworks
- **United States**: Computer Fraud and Abuse Act (CFAA)
- **Europe**: GDPR, NIS Directive
- **Philippines**: Cybercrime Prevention Act of 2012 (RA 10175)
- **International**: Check your local laws

### Responsible Use
- Use only for authorized bug bounties, penetration testing, or personal research
- Disclose findings responsibly to affected organizations
- Do not use for:
  - Unauthorized access
  - Social engineering without permission
  - Phishing (even for testing without written authorization)
  - Data exfiltration
  - Any malicious purpose

**By using Nyx, you agree that you are solely responsible for your actions and comply with all applicable laws.**

---

## What is Nyx?

Nyx is a modular OSINT (Open Source Intelligence) and reconnaissance tool for cybersecurity professionals, bug bounty hunters, and authorized penetration testers.

It automates the first phase of security testing: **passive reconnaissance** — gathering information about a target without directly attacking it.

---

## Features

### 11 Modules

| Module | What It Does | Type |
|--------|-------------|------|
| **DNS Enumeration** | DNS records, zone transfers, subdomain brute-force | Passive |
| **WHOIS Intel** | Domain ownership, ASN, geolocation, CDN detection | Passive |
| **Port Scanner** | TCP port scanning, banner grabbing (top 100 ports) | Active |
| **Web Fingerprinting** | CMS detection, tech stack, security headers | Active |
| **Cert Transparency** | Find subdomains from SSL certificate logs | Passive |
| **Username Search** | Search 21 platforms for a username | Passive |
| **WAF Detection** | Detect Web Application Firewalls | Active |
| **Email Security** | SPF/DMARC/DKIM audit, spoofing risk | Passive |
| **Google Dorks** | Generate reconnaissance Google search queries | Passive |
| **Shodan Lookup** | Query Shodan for known vulnerabilities | Passive |
| **Email Harvester** | Find emails associated with a domain | Passive |

### Key Strengths

✅ **Modular** — Use individual modules or chain them together  
✅ **No API keys required** — Most modules work out of the box (mock mode when needed)  
✅ **Interactive menu** — Beginner-friendly; no complex CLI flags  
✅ **Rich output** — Clean, readable terminal output  
✅ **JSON export** — Save results for further analysis  
✅ **Educational** — Learn OSINT techniques through the code  

---

## Installation

### Requirements
- Python 3.8+
- pip (Python package manager)

### Setup

```bash
# Clone or download the repository
cd nyx

# Install dependencies
pip install -r requirements.txt

# Run Nyx
python main.py
```

### Dependencies
```
dnspython>=2.4.0
requests>=2.31.0
rich>=13.0.0
jinja2>=3.1.0
python-whois>=0.8.0
questionary>=2.0.0
```

---

## Usage

### Interactive Menu (Easiest)

Run with no arguments to get an interactive menu:

```bash
python main.py
```

You'll be prompted to:
1. Enter target (domain, IP, email, username)
2. Select modules to run
3. Choose output format
4. Enter API keys (if available)

### Command Line (Advanced)

```bash
# DNS only
python main.py example.com --modules dns

# Multiple modules
python main.py example.com --modules dns whois ports tech email

# Save to JSON
python main.py example.com --modules dns crtsh -o json

# Verbose output
python main.py example.com --modules ports -v

# Custom subdomain wordlist
python main.py example.com --modules dns -w /path/to/wordlist.txt

# With API keys
python main.py example.com --modules breach --hibp-key YOUR_KEY
python main.py example.com --modules shodan --shodan-key YOUR_KEY
python main.py example.com --modules harvest --hunter-key YOUR_KEY
```

### Module Help

See what each module does:

```bash
python main.py --help
```

---

## Module Details

### 1. DNS Enumeration
Queries all major DNS record types, attempts zone transfers, and brute-forces subdomains.

**Best for:** Finding all subdomains of a domain  
**Output:** A, AAAA, MX, TXT, NS records + found subdomains  
**Legal:** ✅ Completely passive, public DNS queries

### 2. WHOIS Intelligence
Retrieves domain registration, ASN, ISP, geolocation, and detects CDNs.

**Best for:** Understanding domain ownership and infrastructure  
**Output:** Registrar, ASN, geolocation, CDN status  
**Legal:** ✅ Public WHOIS records

### 3. Port Scanner
Scans top 100 TCP ports and attempts banner grabbing.

**Best for:** Finding open services  
**Output:** Open ports, service banners, versions  
**Legal:** ⚠️ **Active scanning** — ensure you have permission

### 4. Web Fingerprinting
Analyzes HTTP headers, CMS signatures, security configuration, SSL certificates.

**Best for:** Understanding what's running on a web server  
**Output:** CMS type, tech stack, SSL info, security headers  
**Legal:** ⚠️ **Makes HTTP requests** — confirm authorization

### 5. Certificate Transparency
Searches SSL certificate logs for subdomains (crt.sh).

**Best for:** Finding subdomains never found by DNS brute-force  
**Output:** Subdomains from SSL certs, DNS resolution status  
**Legal:** ✅ Querying public certificate database

### 6. Username Search
Searches 21 platforms (GitHub, Twitter, Reddit, etc.) for a username.

**Best for:** OSINT on individuals  
**Output:** Accounts found, profile URLs, high-value profiles flagged  
**Legal:** ✅ Public profile searches

### 7. WAF Detection
Detects Web Application Firewalls using passive signatures and active payload probing.

**Best for:** Understanding what protection is in place  
**Output:** WAF brand, confidence level, bypass hints  
**Legal:** ⚠️ **Active probing** — may trigger alerts, authorized testing only

### 8. Email Security Audit
Checks SPF, DMARC, DKIM configuration and calculates security score.

**Best for:** Finding email spoofing vulnerabilities  
**Output:** Email security score, SPF policy, DMARC enforcement  
**Legal:** ✅ Public DNS TXT records

### 9. Google Dorks
Generates targeted Google search queries to find exposed files, admin panels, etc.

**Best for:** Finding exposed data via search engines  
**Output:** Ready-to-use Google dork queries by category  
**Legal:** ✅ Just Google searches (you execute manually)

### 10. Shodan Lookup
Queries Shodan for known information about an IP. Falls back to Censys if Shodan unavailable.

**Pricing:**
- Shodan: $60/month for 10,000 queries (most pentesters use this)
- Censys: FREE tier with 120 queries/month (better for budget)

**Best for:** Finding vulnerabilities already indexed by internet scanners  
**Output:** Open ports, services, known CVEs  
**Legal:** ✅ Querying public data (sign up free at Censys or Shodan)

### 11. Email Harvester
Finds email addresses associated with a domain (requires free Hunter.io API key).

**Best for:** Building email lists for authorized phishing simulations  
**Output:** Verified emails, naming patterns, confidence scores  
**Legal:** ⚠️ Use for authorized testing only (no unsolicited spam/phishing)

---

## API Keys (Optional)

Nyx works in **mock mode** for most modules without API keys. For real data:

### HaveIBeenPwned (Breach Check)
```
Cost: $3.50/month
Sign up: https://haveibeenpwned.com/API/Key
```

### Shodan (IP Lookup)
```
Cost: Free tier = 1 query/month (very limited)
       Lite = $60/month for 10,000 queries/month
Sign up: https://www.shodan.io/
```

### Censys (Free Alternative)
```
Cost: Free tier = 120 queries/month (recommended)
Sign up: https://censys.io
Note: Nyx has automatic fallback to Censys if Shodan unavailable
```

### Hunter.io (Email Harvester)
```
Cost: Free tier (100/month), paid plans available
Sign up: https://hunter.io/api
```

---

## Output Formats

### Terminal (Default)
Rich formatted output with tables, colors, and findings summary.

```bash
python main.py example.com --modules dns -o terminal
```

### JSON
Machine-readable JSON export for further analysis or integration.

```bash
python main.py example.com --modules dns -o json
# Saves to: output/example_com_nyx.json
```

### HTML
Pretty HTML report (coming in future version).

---

## Common Workflows

### Bug Bounty Reconnaissance
```bash
python main.py target.com --modules dns crtsh ports tech email waf
```
Gives you: all subdomains, web services, security config, and WAF status.

### Employee OSINT
```bash
python main.py username --modules usernames
```
Find all online profiles for a username.

### Email Security Audit
```bash
python main.py company.com --modules email harvest
```
Assess email security and find employee contacts.

### Full Infrastructure Map
```bash
python main.py target.com --modules dns whois ports tech crtsh waf email
```
Complete picture of a domain's infrastructure.

---

## Building Your Own Modules

Nyx is designed to be extended. Each module follows the same pattern:

```python
class MyModule:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.results = {}

    def run(self) -> dict:
        # Do the work here
        self._analyze()
        self._display()
        return self.results

    def _analyze(self):
        # Logic goes here
        pass

    def _display(self):
        # Rich output goes here
        pass
```

Hook it into `main.py` and it's integrated into the interactive menu and CLI.

---

## Performance Tips

- **DNS brute-force is slow** — use a custom wordlist with only relevant subdomains
- **Port scanning is fastest with threading** — default is 100 workers
- **Shodan/Hunter queries count against your API quota** — batch them carefully
- **WAF detection with active probing** — may take 30+ seconds per target

---

## Troubleshooting

### "Module not found" error
Make sure all files are in the correct directory:
```
nyx/
├── main.py
├── requirements.txt
└── modules/
    ├── dns_enum.py
    ├── whois_intel.py
    ... (all other modules)
```

### DNS lookups timing out
Some networks block DNS queries. Try:
```bash
pip install dnspython[DNSSEC]
```

### Port scanning getting blocked
If you get connection resets:
- Slow down with smaller thread count: edit `PortScanner` max_workers
- Or skip port scanning if not needed: use `--modules dns tech email` instead

### API key not working
- Verify you're using the correct key type (HIBP ≠ Shodan ≠ Hunter)
- Check you haven't hit rate limits
- Confirm your key has API access enabled

---

## Contributing

Want to add a module? Pull requests welcome! Each module should:

1. Follow the `__init__` → `run()` → `_display()` pattern
2. Use `rich` for output (not plain `print`)
3. Include docstring explaining what it does
4. Support mock mode if API-dependent
5. Be fully commented for educational value

---

## Project Structure

```
nyx/
├── main.py                 # Entry point, CLI, interactive menu
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── modules/
    ├── dns_enum.py
    ├── whois_intel.py
    ├── port_scanner.py
    ├── web_fingerprint.py
    ├── cert_transparency.py
    ├── username_search.py
    ├── waf_detector.py
    ├── email_security.py
    ├── google_dorks.py
    ├── shodan_lookup.py
    └── email_harvester.py
```

---

## What's Next?

Potential future modules:
- Reverse IP lookup (find other domains on same server)
- SSL certificate history (track cert changes over time)
- GitHub code search (find exposed secrets in commits)
- Metasploit integration (automated exploitation)
- Custom reporting engine

---

## References

### Learning Resources
- [HackerOne](https://www.hackerone.com) — bug bounty platform
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free training
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — web vulnerabilities
- [MITRE ATT&CK](https://attack.mitre.org) — adversary tactics

### Tools Used By Nyx
- [dnspython](https://www.dnspython.org/) — DNS queries
- [requests](https://requests.readthedocs.io/) — HTTP requests
- [rich](https://rich.readthedocs.io/) — terminal output
- [crt.sh](https://crt.sh) — SSL certificate logs
- [Shodan](https://www.shodan.io) — internet-connected devices
- [Hunter.io](https://hunter.io) — email intelligence

---

## License

Educational use only. Respect applicable laws and always get authorization before testing.

---

## Support

Found a bug? Have a feature request?

- Check existing issues first
- Provide: OS, Python version, module name, error message
- Include: what you tried, what you expected

---

## Acknowledgments

Built by a college student learning cybersecurity. Inspired by real penetration testing workflows and bug bounty methodology.

Special thanks to:
- The open-source security community
- HackerOne and Bugcrowd for legitimate testing platforms
- PortSwigger for free security training
- Everyone who responsibly discloses vulnerabilities

---

## Final Thoughts

**Nyx is a tool for learning and authorized security testing.**

- Use it to understand how reconnaissance works
- Help organizations find vulnerabilities before attackers do
- Always get permission first
- Report findings responsibly


---

