#!/usr/bin/env python3
"""
ReconX — Advanced Network Reconnaissance Tool
==============================================
For authorized penetration testing ONLY.
Never scan systems without explicit written permission.
"""

import nmap
import socket
import sys
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Optional dependencies ──────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    RED     = Fore.RED
    GREEN   = Fore.GREEN
    YELLOW  = Fore.YELLOW
    CYAN    = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE   = Fore.WHITE
    RESET   = Style.RESET_ALL
    BOLD    = Style.BRIGHT
except ImportError:
    RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = BOLD = ""

try:
    import requests
    import urllib3
    urllib3.disable_warnings()  # Suppress SSL warnings for pentest use
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


# ── Helpers ────────────────────────────────────────────────────────────────────
def log(msg, level="info"):
    prefixes = {
        "info":    f"{CYAN}[*]{RESET}",
        "success": f"{GREEN}[+]{RESET}",
        "warning": f"{YELLOW}[!]{RESET}",
        "error":   f"{RED}[-]{RESET}",
        "data":    f"{MAGENTA}[>]{RESET}",
    }
    print(f"{prefixes.get(level, '[*]')} {msg}")


def separator(char="═", length=68, color=CYAN):
    print(f"{color}{char * length}{RESET}")


def resolve_host(target: str) -> str:
    """Resolve hostname → IP. Exit gracefully if unreachable."""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            log(f"Resolved {YELLOW}{target}{RESET} → {GREEN}{ip}{RESET}", "success")
        return ip
    except socket.gaierror:
        log(f"Cannot resolve: {target}", "error")
        sys.exit(1)


def print_banner():
    print(f"""{CYAN}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{RESET}{YELLOW}     Advanced Network Reconnaissance Tool  v1.0
{RED}  ⚠  FOR AUTHORIZED PENETRATION TESTING USE ONLY  ⚠{RESET}
""")


# ── Core Scanner ───────────────────────────────────────────────────────────────
class ReconX:
    """
    Nmap-powered scanner with multiple profiles.
    Supports service/version detection, OS fingerprinting,
    script scanning, and vulnerability detection.
    """

    SCAN_PROFILES = {
        "quick": {
            "args": "-T4 -F --open",
            "desc": "Fast scan — top 100 ports, no version detection"
        },
        "standard": {
            "args": "-T4 -p 1-10000 -sV --version-intensity 5 --open",
            "desc": "Standard — ports 1-10000 with service version detection"
        },
        "full": {
            "args": "-T4 -p- -sV -sC --version-intensity 9 -O --open",
            "desc": "Full — all 65535 ports, OS detect, default scripts"
        },
        "stealth": {
            "args": "-T2 -sS -p 1-65535 -sV --open",
            "desc": "Stealth SYN scan — slow, low noise (requires root)"
        },
        "vuln": {
            "args": "-T4 -p 1-10000 -sV --script=vuln --open",
            "desc": "Vulnerability scan — runs nmap vuln script library"
        },
        "aggressive": {
            "args": "-T4 -A -p- --open",
            "desc": "Aggressive — OS, version, scripts, traceroute"
        },
        "udp": {
            "args": "-sU -T4 --top-ports 200 --open",
            "desc": "UDP top-200 port scan (requires root)"
        },
        "smb": {
            "args": "-T4 -p 139,445 --script=smb-vuln*,smb-enum* --open",
            "desc": "SMB focused — enum shares, users, vuln checks"
        },
        "web": {
            "args": "-T4 -p 80,443,8080,8443,8888 -sV --script=http-title,http-headers,http-methods --open",
            "desc": "Web focused — HTTP title, headers, methods"
        },
    }

    def __init__(self, target: str, scan_type: str = "standard", output_file: str = None):
        self.target      = target
        self.ip          = resolve_host(target)
        self.scan_type   = scan_type
        self.output_file = output_file
        self.nm          = nmap.PortScanner()
        self.results     = {}
        self.start_time  = datetime.now()

    def run_scan(self):
        profile = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["standard"])

        separator()
        log(f"Target     : {YELLOW}{self.target}{RESET} ({self.ip})")
        log(f"Scan Type  : {BOLD}{self.scan_type.upper()}{RESET} — {profile['desc']}")
        log(f"Nmap Args  : {profile['args']}", "data")
        log(f"Started    : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        separator()

        try:
            self.nm.scan(hosts=self.ip, arguments=profile["args"])
        except nmap.PortScannerError as e:
            log(f"Nmap error: {e}", "error")
            log("Some scan types (stealth/UDP/OS) require root/administrator privileges.", "warning")
            sys.exit(1)

        self._parse_and_print()

        if self.output_file:
            self._save_json()

    def _parse_and_print(self):
        elapsed = round((datetime.now() - self.start_time).total_seconds(), 2)

        if not self.nm.all_hosts():
            log("No live hosts found — host may be down or blocking probes.", "warning")
            return

        for host in self.nm.all_hosts():
            data = {
                "ip":        host,
                "hostname":  self.nm[host].hostname() or "N/A",
                "state":     self.nm[host].state(),
                "os":        self._get_os(host),
                "protocols": {}
            }

            separator("─")
            print(f"\n  {CYAN}{BOLD}HOST :{RESET}  {WHITE}{BOLD}{data['ip']}{RESET}")
            print(f"  {CYAN}NAME :{RESET}  {data['hostname']}")
            print(f"  {CYAN}STATE:{RESET}  {GREEN}{BOLD}{data['state'].upper()}{RESET}\n")

            # ── OS Detection ───────────────────────────────────────────────
            if data["os"]:
                print(f"  {YELLOW}{BOLD}┌── OS DETECTION ─────────────────────────────────{RESET}")
                for match in data["os"]:
                    print(f"  {YELLOW}│{RESET}  {MAGENTA}►{RESET} {match['name']} "
                          f"{GREEN}({match['accuracy']}% confidence){RESET}")
                print(f"  {YELLOW}└─────────────────────────────────────────────────{RESET}\n")

            # ── Port Table ─────────────────────────────────────────────────
            for proto in self.nm[host].all_protocols():
                ports = sorted(self.nm[host][proto].keys())
                open_ports = [p for p in ports
                              if self.nm[host][proto][p].get("state") == "open"]

                if not open_ports:
                    continue

                print(f"  {YELLOW}{BOLD}┌── OPEN PORTS [{proto.upper()}] ────────────────────────────{RESET}")
                print(f"  {YELLOW}│{RESET}  {CYAN}{'PORT':<10} {'SERVICE':<16} {'PRODUCT & VERSION'}{RESET}")
                print(f"  {YELLOW}│{RESET}  {'─' * 60}")

                for port in open_ports:
                    info    = self.nm[host][proto][port]
                    service = info.get("name", "unknown")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    extra   = info.get("extrainfo", "")
                    cpe     = info.get("cpe", "")
                    scripts = info.get("script", {})

                    ver_string = " ".join(filter(None, [product, version, extra])).strip()

                    print(f"  {YELLOW}│{RESET}  {WHITE}{BOLD}{str(port)+'/'+proto:<10}{RESET}"
                          f"  {MAGENTA}{service:<16}{RESET}"
                          f"  {ver_string or '—'}")

                    if cpe:
                        print(f"  {YELLOW}│{RESET}  {'':10}  {CYAN}CPE:{RESET} {cpe}")

                    # Script / vuln output
                    if scripts:
                        for script_name, output in scripts.items():
                            severity_color = RED if "VULNERABLE" in str(output).upper() else YELLOW
                            print(f"\n  {YELLOW}│{RESET}    {severity_color}{BOLD}[{script_name}]{RESET}")
                            for line in str(output).splitlines():
                                if line.strip():
                                    print(f"  {YELLOW}│{RESET}      {line}")
                        print()

                    # Store for JSON output
                    data["protocols"].setdefault(proto, {})[port] = {
                        "state": "open", "service": service,
                        "product": product, "version": version,
                        "extrainfo": extra, "cpe": cpe,
                        "scripts": scripts
                    }

                print(f"  {YELLOW}└─────────────────────────────────────────────────{RESET}\n")

            self.results[host] = data

        separator()
        log(f"Scan complete — {len(self.nm.all_hosts())} host(s) in {elapsed}s", "success")

    def _get_os(self, host) -> list:
        matches = []
        try:
            for m in self.nm[host].get("osmatch", [])[:3]:
                matches.append({"name": m.get("name", ""), "accuracy": m.get("accuracy", "?")})
        except Exception:
            pass
        return matches

    def _save_json(self):
        path = self.output_file
        if not path.endswith(".json"):
            path += ".json"
        payload = {
            "tool":      "ReconX v1.0",
            "scan_time": self.start_time.isoformat(),
            "target":    self.target,
            "scan_type": self.scan_type,
            "results":   self.results
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        log(f"Results saved → {YELLOW}{path}{RESET}", "success")


# ── DNS Enumerator ─────────────────────────────────────────────────────────────
class DNSEnumerator:
    """
    DNS reconnaissance — queries multiple record types
    and optionally brute-forces subdomains.
    """

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "dev", "staging", "api", "portal",
        "vpn", "remote", "test", "blog", "shop", "app", "secure", "login",
        "webmail", "smtp", "pop", "imap", "ns1", "ns2", "cdn", "static",
        "assets", "media", "beta", "dashboard", "git", "gitlab", "jenkins",
        "jira", "confluence", "db", "database", "backup", "internal", "corp",
        "intranet", "docs", "support", "help", "monitor", "proxy", "gateway"
    ]

    def __init__(self, domain: str):
        self.domain = domain

    def enumerate_records(self):
        if not DNS_OK:
            log("Install dnspython: pip install dnspython", "warning")
            return

        separator()
        print(f"\n  {CYAN}{BOLD}[ DNS RECORDS — {self.domain} ]{RESET}\n")

        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                print(f"  {YELLOW}{BOLD}{rtype:<8}{RESET}", end="  ")
                values = [str(r) for r in answers]
                print(f"\n         ".join(f"{GREEN}{v}{RESET}" for v in values))
            except Exception:
                pass

        print()

    def bruteforce_subdomains(self, wordlist: list = None):
        if not DNS_OK:
            return

        words = wordlist or self.COMMON_SUBDOMAINS
        separator()
        print(f"\n  {CYAN}{BOLD}[ SUBDOMAIN BRUTE-FORCE — {self.domain} ]{RESET}")
        print(f"  {WHITE}Checking {len(words)} candidates...{RESET}\n")

        found = []

        def check(word):
            sub = f"{word}.{self.domain}"
            try:
                ip = socket.gethostbyname(sub)
                return (sub, ip)
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sub, ip = result
                    log(f"{GREEN}{sub:<45}{RESET} → {WHITE}{ip}{RESET}", "success")
                    found.append(result)

        print()
        if found:
            log(f"{len(found)} subdomain(s) discovered.", "success")
        else:
            log("No subdomains found from wordlist.", "warning")

        return found


# ── Banner Grabber ─────────────────────────────────────────────────────────────
class BannerGrabber:
    """
    Raw socket banner grabbing across multiple ports
    using a thread pool for speed.
    """

    HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
    GENERIC_PROBE = b"\r\n"

    def __init__(self, host: str, ports: list, timeout: float = 3.0):
        self.host    = host
        self.ports   = ports
        self.timeout = timeout

    def _grab(self, port: int) -> dict:
        result = {"port": port, "banner": None}
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout) as s:
                probe = self.HTTP_PROBE.replace(b"{host}", self.host.encode())
                s.sendall(probe)
                raw = s.recv(2048).decode("utf-8", errors="replace").strip()
                if raw:
                    result["banner"] = raw
                else:
                    # Try generic probe for non-HTTP services
                    s.sendall(self.GENERIC_PROBE)
                    raw = s.recv(1024).decode("utf-8", errors="replace").strip()
                    result["banner"] = raw or None
        except Exception:
            pass
        return result

    def run(self):
        separator()
        print(f"\n  {CYAN}{BOLD}[ BANNER GRABBING — {self.host} ]{RESET}\n")

        with ThreadPoolExecutor(max_workers=25) as ex:
            futures = {ex.submit(self._grab, p): p for p in self.ports}
            for future in as_completed(futures):
                res = future.result()
                if res["banner"]:
                    print(f"  {YELLOW}{BOLD}PORT {res['port']}{RESET}")
                    for line in res["banner"].splitlines()[:6]:
                        if line.strip():
                            print(f"    {WHITE}{line}{RESET}")
                    print()


# ── HTTP Prober ────────────────────────────────────────────────────────────────
class HTTPProber:
    """
    Probes web services for status, headers, server info,
    and detects common technologies (CMS, frameworks, etc.).
    """

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    CMS_SIGNATURES = {
        "WordPress":  ["wp-content", "wp-json", "wordpress"],
        "Joomla":     ["joomla", "/components/com_"],
        "Drupal":     ["drupal", "sites/default/files"],
        "Magento":    ["magento", "mage/"],
        "Laravel":    ["laravel", "csrf-token"],
        "Django":     ["csrfmiddlewaretoken", "django"],
        "React":      ["__NEXT_DATA__", "react-root", "_reactroot"],
        "Angular":    ["ng-version", "ng-app"],
        "Vue.js":     ["__vue__", "data-v-"],
    }

    def __init__(self, target: str, ports: list = None):
        self.target = target
        self.ports  = ports or [80, 443, 8080, 8443, 8888, 3000, 5000]

    def _probe(self, url: str) -> dict:
        result = {"url": url, "status": None, "headers": {},
                  "server": "", "tech": [], "missing_security": []}
        if not REQUESTS_OK:
            return result
        try:
            r = requests.get(
                url, timeout=6, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 ReconX/1.0 (Pentest)"}
            )
            result.update({
                "status":  r.status_code,
                "headers": dict(r.headers),
                "server":  r.headers.get("Server", ""),
                "powered": r.headers.get("X-Powered-By", ""),
                "final_url": r.url,
                "tech":    self._detect_tech(r),
                "missing_security": [
                    h for h in self.SECURITY_HEADERS
                    if h not in r.headers
                ]
            })
        except requests.exceptions.RequestException:
            pass
        return result

    def _detect_tech(self, resp) -> list:
        body = resp.text[:8000].lower()
        detected = []
        for name, sigs in self.CMS_SIGNATURES.items():
            if any(s.lower() in body for s in sigs):
                detected.append(name)
        return detected

    def run(self):
        separator()
        print(f"\n  {CYAN}{BOLD}[ HTTP SERVICE PROBING — {self.target} ]{RESET}\n")

        if not REQUESTS_OK:
            log("Install requests: pip install requests", "warning")
            return

        for port in self.ports:
            scheme = "https" if port in (443, 8443) else "http"
            url    = f"{scheme}://{self.target}:{port}"
            res    = self._probe(url)

            if not res["status"]:
                continue

            status_color = GREEN if res["status"] < 400 else (
                YELLOW if res["status"] < 500 else RED
            )

            print(f"  {CYAN}URL     :{RESET} {YELLOW}{url}{RESET}")

            if res.get("final_url") and res["final_url"] != url:
                print(f"  {CYAN}Redirect:{RESET} → {res['final_url']}")

            print(f"  {CYAN}Status  :{RESET} {status_color}{BOLD}{res['status']}{RESET}")
            print(f"  {CYAN}Server  :{RESET} {res['server'] or '—'}")

            if res.get("powered"):
                print(f"  {CYAN}Powered :{RESET} {res['powered']}")

            if res["tech"]:
                print(f"  {CYAN}Tech    :{RESET} {MAGENTA}{', '.join(res['tech'])}{RESET}")

            if res["missing_security"]:
                print(f"  {YELLOW}Missing Security Headers:{RESET}")
                for h in res["missing_security"]:
                    print(f"    {RED}✗{RESET} {h}")

            print()


# ── CLI ────────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Advanced Network Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  python reconx.py 192.168.1.1 -s full\n"
               "  python reconx.py example.com -s vuln --dns --http -o report\n"
               "  python reconx.py 10.0.0.0/24 -s quick --banners\n"
               "  python reconx.py example.com --full-recon -o full_report"
    )
    p.add_argument("target",
                   help="IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    p.add_argument("-s", "--scan", default="standard",
                   choices=ReconX.SCAN_PROFILES.keys(),
                   help="Scan profile (default: standard)\n" + "\n".join(
                       f"  {k:<14} {v['desc']}"
                       for k, v in ReconX.SCAN_PROFILES.items()
                   ))
    p.add_argument("--dns",          action="store_true",
                   help="DNS record enumeration")
    p.add_argument("--subdomains",   action="store_true",
                   help="Subdomain brute-force")
    p.add_argument("--banners",      action="store_true",
                   help="Raw banner grabbing via socket")
    p.add_argument("--http",         action="store_true",
                   help="HTTP/HTTPS service probing")
    p.add_argument("--full-recon",   action="store_true",
                   help="Run ALL modules (overrides --scan with 'full')")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Export results to JSON (e.g. -o report)")
    p.add_argument("--ports",
                   default="21,22,23,25,53,80,110,143,389,443,445,3306,3389,5432,8080,8443",
                   help="Ports for banner/HTTP modules (comma-separated)")
    return p


def main():
    print_banner()

    print(f"{RED}{BOLD}  DISCLAIMER:{RESET} {WHITE}Authorized use only. Scanning without permission")
    print(f"  is illegal. You accept all responsibility for your actions.{RESET}\n")

    parser = build_parser()
    args   = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]
    full  = args.full_recon

    # ── 1. Port / Service Scan ──────────────────────────────────────────────
    scan_type = "full" if full else args.scan
    scanner   = ReconX(args.target, scan_type=scan_type, output_file=args.output)
    scanner.run_scan()

    # ── 2. DNS Enumeration ──────────────────────────────────────────────────
    if full or args.dns or args.subdomains:
        dns_enum = DNSEnumerator(args.target)
        if full or args.dns:
            dns_enum.enumerate_records()
        if full or args.subdomains:
            dns_enum.bruteforce_subdomains()

    # ── 3. Banner Grabbing ──────────────────────────────────────────────────
    if full or args.banners:
        ip = resolve_host(args.target)
        BannerGrabber(ip, ports).run()

    # ── 4. HTTP Probing ─────────────────────────────────────────────────────
    if full or args.http:
        HTTPProber(args.target, ports).run()

    separator()
    log("ReconX finished.", "success")


if __name__ == "__main__":
    main()