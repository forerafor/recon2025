#!/usr/bin/env python3

import argparse
import json
import re
import socket
import ssl
import threading
import time
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin
import ipaddress
import base64

import requests
import dns.resolver
import dns.query
import dns.message

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()


@dataclass
class SSLInfo:
    subject: str
    issuer: str
    sans: List[str]
    not_after: str
    common_name: str


@dataclass
class WAFInfo:
    detected: bool
    name: str = ""
    confidence: str = "low"
    indicators: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    vuln_type: str
    severity: str
    url: str
    details: str


@dataclass
class Endpoint:
    url: str
    status_code: int
    title: str = ""
    tech_stack: List[str] = field(default_factory=list)
    interesting: bool = False
    reason: str = ""


@dataclass
class Result:
    ip: str
    subdomain: str = ""
    source: str = ""
    ports: List[int] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Optional[SSLInfo] = None
    banner: str = ""
    is_valid: bool = True
    confidence: str = "low"
    validation_info: Dict[str, any] = field(default_factory=dict)
    waf_info: Optional[WAFInfo] = None
    endpoints: List[Endpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


class Config:
    def __init__(self, domain: str, verbose: bool = False, timeout: int = 10,
                 max_workers: int = 100, output_json: bool = False,
                 check_ports: bool = False, check_ssl: bool = False,
                 check_subdomains: bool = False, deep: bool = False,
                 wordlist: str = None, spider: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.timeout = timeout
        self.max_workers = max_workers
        self.output_json = output_json
        self.check_ports = check_ports
        self.check_ssl = check_ssl
        self.check_subdomains = check_subdomains
        self.deep = deep
        self.wordlist = wordlist
        self.spider = spider


class BugBountyRecon:
    def __init__(self, config: Config):
        self.config = config
        self.results: List[Result] = []
        self.discovered_subdomains: Set[str] = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = config.timeout
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]

    def run_recon(self) -> List[Result]:
        print("""
╔══════════════════════════════════════════════════════════════╗
║        🎯 ADVANCED BUG BOUNTY RECON TOOL 🎯                 ║
║     Finding Hidden Subdomains, IPs & Admin Panels           ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            # Phase 1: Subdomain Discovery
            print("[*] Phase 1: Aggressive Subdomain Enumeration")
            futures.append(executor.submit(self.enumerate_subdomains_advanced))
            futures.append(executor.submit(self.check_certificate_transparency))
            futures.append(executor.submit(self.brute_force_subdomains))
            futures.append(executor.submit(self.check_dns_aggregators))
            
            if self.config.deep:
                futures.append(executor.submit(self.permutate_subdomains))
                futures.append(executor.submit(self.check_vhost_bruteforce))
            
            # Wait for subdomain discovery
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error in subdomain discovery: {e}")

        # Phase 2: IP Resolution & Validation
        print(f"\n[*] Phase 2: Resolving {len(self.discovered_subdomains)} subdomains to IPs")
        self.resolve_all_subdomains()

        # Phase 3: WAF Detection
        print(f"\n[*] Phase 3: WAF Detection on discovered targets")
        self.detect_wafs()

        # Phase 4: Interesting Endpoints Discovery
        print(f"\n[*] Phase 4: Hunting for Admin Panels & Login Pages")
        self.find_interesting_endpoints()

        # Phase 5: Port Scanning - ALWAYS ENABLED FOR BUG BOUNTY
        print(f"\n[*] Phase 5: Extended Port Scanning (Always Enabled)")
        self.scan_extended_ports()

        # Phase 6: Common Vulnerability Checks
        print(f"\n[*] Phase 6: Common Vulnerability Checks")
        self.check_common_vulnerabilities()

        # Phase 7: Critical Vulnerability Scanning
        print(f"\n[*] Phase 7: Critical Vulnerability Scanning")
        self.check_critical_vulnerabilities()

        # Validate and filter results
        print(f"\n[*] Phase 8: Validating Results")
        validated_results = self.validate_all_results()
        
        return self.deduplicate_results(validated_results)

    def enumerate_subdomains_advanced(self):
        """Advanced subdomain enumeration with multiple techniques"""
        common_subs = [
            "www", "mail", "ftp", "webmail", "admin", "administrator", "dev", "test", "staging",
            "api", "api-dev", "api-test", "api-staging", "api-prod", "api-v1", "api-v2",
            "blog", "shop", "store", "secure", "support", "help", "docs", "cdn",
            "static", "img", "images", "media", "assets", "files", "download", "uploads",
            "portal", "dashboard", "panel", "cpanel", "whm", "directadmin", "plesk",
            "autodiscover", "autoconfig", "mx", "mx1", "mx2", "smtp", "pop", "imap",
            "ns", "ns1", "ns2", "dns", "remote", "cloud", "git", "svn", "vpn",
            "mobile", "m", "beta", "demo", "old", "new", "backup", "db", "mysql",
            "login", "signin", "auth", "sso", "oauth", "account", "accounts",
            "user", "users", "client", "clients", "partner", "partners",
            "internal", "intranet", "extranet", "private", "public",
            "jenkins", "gitlab", "jira", "confluence", "redmine",
            "grafana", "kibana", "elasticsearch", "prometheus", "nagios",
            "phpmyadmin", "adminer", "pgadmin", "mongodb", "redis",
            "s3", "bucket", "storage", "backups", "archive",
            "uat", "qa", "preprod", "production", "prod",
            "app", "apps", "application", "applications",
            "web", "web1", "web2", "website", "webserver",
            "status", "health", "monitor", "monitoring", "metrics",
            "log", "logs", "logger", "logging", "syslog",
            "payment", "payments", "pay", "checkout", "billing",
            "invoice", "invoices", "order", "orders",
            "crm", "erp", "hr", "finance", "sales",
            "marketing", "analytics", "stats", "statistics",
            "report", "reports", "dashboard", "admin-panel",
        ]

        # Extended list for deep mode
        if self.config.deep:
            common_subs.extend([
                "admin1", "admin2", "admin123", "root", "adm", "administrator1",
                "webadmin", "sysadmin", "netadmin", "serveradmin",
                "manager", "management", "control", "controlpanel",
                "console", "backend", "backoffice", "office",
                "devops", "infra", "infrastructure", "ops",
                "test1", "test2", "dev1", "dev2", "stage", "stage1",
                "alpha", "beta", "gamma", "delta", "omega",
                "v1", "v2", "v3", "version1", "version2",
                "old-site", "new-site", "temp", "temporary",
                "legacy", "deprecated", "archive", "archived",
                "subdomain", "sub", "secret", "hidden", "private",
            ])

        for sub in common_subs:
            fqdn = f"{sub}.{self.config.domain}"
            self.discovered_subdomains.add(fqdn)

    def brute_force_subdomains(self):
        """Brute force subdomains with custom wordlist or default"""
        if self.config.wordlist:
            try:
                with open(self.config.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                    print(f"[+] Loaded {len(wordlist)} words from wordlist")
                    for word in wordlist:
                        fqdn = f"{word}.{self.config.domain}"
                        self.discovered_subdomains.add(fqdn)
            except Exception as e:
                print(f"[!] Error loading wordlist: {e}")

    def permutate_subdomains(self):
        """Generate subdomain permutations"""
        base_words = ["admin", "dev", "test", "api", "app", "web", "portal"]
        suffixes = ["1", "2", "3", "-prod", "-dev", "-test", "-old", "-new"]
        prefixes = ["new-", "old-", "beta-", "v1-", "v2-"]
        
        for word in base_words:
            for suffix in suffixes:
                self.discovered_subdomains.add(f"{word}{suffix}.{self.config.domain}")
            for prefix in prefixes:
                self.discovered_subdomains.add(f"{prefix}{word}.{self.config.domain}")

    def check_certificate_transparency(self):
        """Check certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.config.domain}&output=json"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for domain in name_value.split('\n'):
                            domain = domain.strip().lower()
                            if domain and not domain.startswith('*') and domain.endswith(self.config.domain):
                                self.discovered_subdomains.add(domain)
                    
                    print(f"[+] Found {len(self.discovered_subdomains)} subdomains from CT logs")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.config.verbose:
                print(f"[!] CT log check failed: {e}")

    def check_dns_aggregators(self):
        """Check DNS aggregators for subdomains"""
        # AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.config.domain}/passive_dns"
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '')
                    if hostname.endswith(self.config.domain):
                        self.discovered_subdomains.add(hostname)
        except:
            pass

    def check_vhost_bruteforce(self):
        """Virtual host brute forcing"""
        print("[*] Starting vhost bruteforce...")
        # This would test different host headers against known IPs

    def resolve_all_subdomains(self):
        """Resolve all discovered subdomains to IPs"""
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for subdomain in self.discovered_subdomains:
                futures.append(executor.submit(self.resolve_subdomain, subdomain))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def resolve_subdomain(self, subdomain: str):
        """Resolve single subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(subdomain, 'A')
            for rdata in answers:
                ip = str(rdata)
                if self.is_valid_public_ip(ip):
                    result = Result(
                        ip=ip,
                        subdomain=subdomain,
                        source=f"DNS-Resolution"
                    )
                    self.add_result(result)
                    
        except Exception:
            pass

    def detect_wafs(self):
        """Detect WAF on all discovered targets"""
        unique_targets = self.get_unique_targets()
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for target in unique_targets[:50]:  # Limit to avoid rate limiting
                futures.append(executor.submit(self.detect_waf, target))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def detect_waf(self, target: dict):
        """Detect WAF on specific target"""
        subdomain = target.get('subdomain', target.get('ip'))
        
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'akamai': ['akamai', 'akamaighost'],
            'incapsula': ['incap_ses', 'visid_incap', 'x-cdn: incapsula'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'aws-waf': ['x-amzn-trace-id', 'x-amz-'],
            'barracuda': ['barra_counter_session', 'barracuda'],
            'f5-bigip': ['bigipserver', 'f5-', 'bigip'],
            'fortiweb': ['fortigate', 'fortiweb'],
            'imperva': ['x-iinfo', 'incap_ses'],
            'modsecurity': ['mod_security', 'modsec'],
            'wordfence': ['wordfence'],
        }
        
        waf_info = WAFInfo(detected=False)
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}/"
                
                # Test with suspicious payload
                test_url = f"{url}?test=<script>alert(1)</script>"
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.get(test_url, headers=headers, timeout=5, allow_redirects=False)
                
                # Check headers for WAF indicators
                for waf_name, indicators in waf_signatures.items():
                    for indicator in indicators:
                        header_match = any(indicator.lower() in k.lower() or indicator.lower() in str(v).lower() 
                                         for k, v in response.headers.items())
                        body_match = indicator.lower() in response.text.lower()[:1000]
                        
                        if header_match or body_match:
                            waf_info.detected = True
                            waf_info.name = waf_name
                            waf_info.confidence = "high"
                            waf_info.indicators.append(indicator)
                            break
                    
                    if waf_info.detected:
                        break
                
                # Check status code patterns
                if response.status_code in [403, 406, 419, 429, 503]:
                    if not waf_info.detected:
                        waf_info.detected = True
                        waf_info.name = "Unknown WAF"
                        waf_info.confidence = "medium"
                        waf_info.indicators.append(f"Suspicious status: {response.status_code}")
                
                if waf_info.detected:
                    self.update_result_waf(target['ip'], waf_info)
                    if self.config.verbose:
                        print(f"[!] WAF Detected on {subdomain}: {waf_info.name}")
                    break
                    
            except Exception:
                continue

    def find_interesting_endpoints(self):
        """Find admin panels, login pages, and interesting endpoints"""
        
        # Interesting paths to check
        interesting_paths = [
            # Admin panels
            '/admin', '/admin/', '/admin/login', '/admin/dashboard', '/administrator',
            '/admin/index.php', '/admin/login.php', '/admin.php', '/admin/admin.php',
            '/admin/home.php', '/admin/controlpanel.php', '/admin/cp.php',
            '/administrator/index.php', '/administrator/login.php',
            '/adminpanel', '/admincp', '/admin_area', '/admin_login',
            '/sysadmin', '/system-admin', '/backend', '/backoffice',
            '/controlpanel', '/cp', '/panel', '/dashboard',
            
            # CMS specific
            '/wp-admin', '/wp-login.php', '/wp-admin/login.php',
            '/ghost/signin', '/ghost/signup',
            '/user/login', '/user/admin', '/login', '/signin',
            
            # cPanel/WHM
            '/cpanel', '/whm', '/webmail', '/cpanel/login',
            '/cpanel-login', '/whm/login', '/whm-login',
            '/plesk', '/plesk/login',
            
            # Database interfaces
            '/phpmyadmin', '/pma', '/phpMyAdmin', '/mysql',
            '/adminer', '/adminer.php', '/dbadmin',
            '/pgadmin', '/pgadmin4',
            
            # CI/CD & DevOps
            '/jenkins', '/jenkins/login', '/gitlab', '/gitlab/users/sign_in',
            '/jira', '/jira/login', '/confluence', '/confluence/login',
            '/drone', '/travis', '/circleci',
            
            # Monitoring & Logs
            '/grafana', '/grafana/login', '/kibana', '/kibana/app',
            '/prometheus', '/nagios', '/cacti',
            '/status', '/server-status', '/nginx_status',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/docs',
            '/api/swagger', '/swagger', '/swagger-ui',
            '/api/graphql', '/graphql',
            
            # Config & backup files
            '/.env', '/.git/config', '/config.php', '/configuration.php',
            '/wp-config.php', '/settings.php', '/config.json',
            '/backup', '/backups', '/backup.sql', '/dump.sql',
            
            # File managers
            '/filemanager', '/files', '/fm', '/file-manager',
            '/elfinder', '/tinymce/filemanager',
            
            # Auth endpoints
            '/login', '/signin', '/sign-in', '/login.php',
            '/auth', '/auth/login', '/oauth', '/sso',
            '/account', '/accounts', '/user', '/users',
            '/register', '/signup', '/sign-up',
            '/forgot', '/forgot-password', '/reset-password',
            
            # Misc interesting
            '/debug', '/console', '/shell', '/terminal',
            '/.git', '/.svn', '/.DS_Store',
            '/robots.txt', '/sitemap.xml', '/.well-known/',
            '/actuator', '/actuator/health', '/health',
            '/info.php', '/phpinfo.php', '/test.php',
        ]

        unique_targets = self.get_unique_targets()
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for target in unique_targets:
                subdomain = target.get('subdomain', target.get('ip'))
                futures.append(executor.submit(self.scan_endpoints, subdomain, interesting_paths))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def scan_endpoints(self, subdomain: str, paths: List[str]):
        """Scan endpoints on a subdomain"""
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{subdomain}"
            
            for path in paths:
                try:
                    url = urljoin(base_url, path)
                    headers = {
                        'User-Agent': random.choice(self.user_agents),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                    
                    response = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
                    
                    # Check if endpoint is interesting
                    if response.status_code in [200, 301, 302, 401, 403]:
                        is_interesting, reason = self.analyze_response(response, path)
                        
                        if is_interesting:
                            title = self.extract_title(response.text)
                            tech_stack = self.detect_technologies(response)
                            
                            endpoint = Endpoint(
                                url=url,
                                status_code=response.status_code,
                                title=title,
                                tech_stack=tech_stack,
                                interesting=True,
                                reason=reason
                            )
                            
                            self.add_endpoint_to_result(subdomain, endpoint)
                            
                            if self.config.verbose:
                                print(f"[+] Found: {url} [{response.status_code}] - {reason}")
                            
                            break  # Found working protocol
                            
                except Exception:
                    continue

    def analyze_response(self, response, path: str) -> tuple:
        """Analyze if response is interesting"""
        interesting_indicators = {
            'login': ['login', 'signin', 'sign in', 'username', 'password', 'log in'],
            'admin': ['admin', 'administrator', 'dashboard', 'control panel', 'management'],
            'auth': ['authentication', 'oauth', 'sso', 'token'],
            'database': ['phpmyadmin', 'adminer', 'database', 'mysql', 'postgresql'],
            'api': ['api', 'swagger', 'graphql', 'endpoint', 'rest'],
            'config': ['configuration', 'settings', 'environment'],
            'file_manager': ['file manager', 'upload', 'elfinder'],
            'devops': ['jenkins', 'gitlab', 'jira', 'ci/cd'],
        }
        
        status = response.status_code
        body_lower = response.text.lower()[:2000]
        
        # Status code checks
        if status == 200:
            for reason, keywords in interesting_indicators.items():
                if any(keyword in body_lower or keyword in path.lower() for keyword in keywords):
                    return True, f"{reason.replace('_', ' ').title()} Page"
        
        elif status == 401:
            return True, "Authentication Required"
        
        elif status == 403:
            if 'forbidden' in body_lower or 'access denied' in body_lower:
                return True, "Forbidden - Possible Protected Resource"
        
        elif status in [301, 302]:
            location = response.headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                return True, f"Redirects to Auth ({status})"
        
        return False, ""

    def extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:100]
        except:
            pass
        return ""

    def detect_technologies(self, response) -> List[str]:
        """Detect technologies used"""
        tech_stack = []
        
        tech_indicators = {
            'PHP': ['x-powered-by: php', '.php'],
            'ASP.NET': ['x-powered-by: asp.net', 'x-aspnet-version'],
            'Node.js': ['x-powered-by: express', 'x-powered-by: node'],
            'Python': ['x-powered-by: python', 'x-powered-by: django', 'x-powered-by: flask'],
            'Ruby': ['x-powered-by: ruby', 'x-powered-by: rails'],
            'Java': ['x-powered-by: servlet', 'jsessionid'],
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Laravel': ['laravel', 'x-frame-options: sameorigin'],
            'React': ['react', '__react'],
            'Vue': ['vue.js', '__vue'],
            'Angular': ['ng-', 'angular'],
        }
        
        headers_lower = ' '.join([f"{k}: {v}".lower() for k, v in response.headers.items()])
        body_lower = response.text.lower()[:1000]
        
        for tech, indicators in tech_indicators.items():
            if any(ind in headers_lower or ind in body_lower for ind in indicators):
                tech_stack.append(tech)
        
        return tech_stack

    def scan_extended_ports(self):
        """Extended port scanning for hidden services"""
        print("[*] Extended Port Scanning for Hidden Services")
        
        ips = self.get_unique_ips()
        
        # Extended ports for bug bounty
        extended_ports = [
            # Web Services
            80, 443, 8080, 8443, 8000, 3000, 5000, 9000,
            
            # Database Ports
            3306, 5432, 27017, 6379, 1433, 1521,
            
            # Remote Access
            22, 21, 23, 3389, 5900, 5901,
            
            # Mail Services
            25, 110, 143, 465, 587, 993, 995,
            
            # Development & Monitoring
            9200, 9300, 5601, 3000, 24224, 514,
            
            # Network Services
            53, 161, 389, 636, 873, 2049,
            
            # Special Services
            11211, 27017, 50000, 50030, 50070
        ]
        
        if self.config.deep:
            extended_ports.extend([
                # Additional deep scan ports
                2082, 2083, 2086, 2087, 2095, 2096,
                10000, 20000, 21000, 22222, 28017,
                4486, 4848, 7676, 8008, 8081, 8088,
                8181, 8282, 8383, 8484, 8585, 8686,
                8888, 8899, 9001, 9002, 9090, 9091,
                9200, 9300, 9400, 9500, 9600, 9700,
                9800, 9900, 9999
            ])

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for ip in ips[:50]:  # Limit IPs to scan
                for port in extended_ports:
                    futures.append(executor.submit(self.check_port_with_service_detection, ip, port))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def check_port_with_service_detection(self, ip: str, port: int):
        """Check port with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_info = self.detect_service(sock, port)
                banner = service_info.get('banner', '')
                service_name = service_info.get('service', 'Unknown')
                
                self.update_result_ports(ip, port, f"{service_name}: {banner}")
                
                # If service is interesting, add as vulnerability
                if service_name != 'Unknown' and service_name != 'HTTP':
                    vuln = Vulnerability(
                        vuln_type=f"Open Service - {service_name}",
                        severity="Medium",
                        url=f"{ip}:{port}",
                        details=f"Open {service_name} service on port {port}"
                    )
                    self.add_vulnerability_by_ip(ip, vuln)
                    
            sock.close()
            
        except Exception as e:
            if self.config.verbose:
                print(f"[!] Port check failed for {ip}:{port}: {e}")

    def detect_service(self, sock: socket.socket, port: int) -> dict:
        """Detect service type on port"""
        service_info = {'service': 'Unknown', 'banner': ''}
        
        try:
            sock.settimeout(5)
            
            if port in [80, 443, 8080, 8443, 8000, 3000]:
                # Web services
                service_info['service'] = 'HTTP/Web'
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner[:200]
                
            elif port == 22:
                # SSH
                service_info['service'] = 'SSH'
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                
            elif port == 21:
                # FTP
                service_info['service'] = 'FTP'
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                
            elif port in [3306, 5432, 27017]:
                # Databases
                if port == 3306:
                    service_info['service'] = 'MySQL'
                elif port == 5432:
                    service_info['service'] = 'PostgreSQL'
                elif port == 27017:
                    service_info['service'] = 'MongoDB'
                    
            elif port == 6379:
                service_info['service'] = 'Redis'
                
            elif port == 11211:
                service_info['service'] = 'Memcached'
                
        except:
            pass
            
        return service_info

    def check_common_vulnerabilities(self):
        """Quick check for common vulnerabilities"""
        print("[*] Checking for common vulnerabilities...")
        
        unique_targets = self.get_unique_targets()
        
        for target in unique_targets[:20]:  # Limit to avoid being too aggressive
            subdomain = target.get('subdomain', '')
            if subdomain:
                self.check_directory_listing(subdomain)
                self.check_sensitive_files(subdomain)
                self.check_config_files(subdomain)

    def check_directory_listing(self, subdomain: str):
        """Check for directory listing"""
        paths = ['/', '/images/', '/uploads/', '/files/', '/assets/', '/backup/']
        
        for protocol in ['https', 'http']:
            for path in paths:
                try:
                    url = f"{protocol}://{subdomain}{path}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        if 'index of' in response.text.lower() or 'parent directory' in response.text.lower():
                            vuln = Vulnerability(
                                vuln_type="Directory Listing",
                                severity="Low",
                                url=url,
                                details="Directory listing enabled"
                            )
                            self.add_vulnerability_to_result(subdomain, vuln)
                            break
                except:
                    continue

    def check_sensitive_files(self, subdomain: str):
        """Check for sensitive files"""
        sensitive_files = [
            '/.git/HEAD',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/.aws/credentials',
            '/id_rsa',
            '/id_rsa.pub',
        ]
        
        for protocol in ['https', 'http']:
            for file in sensitive_files:
                try:
                    url = f"{protocol}://{subdomain}{file}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        vuln = Vulnerability(
                            vuln_type="Sensitive File Exposed",
                            severity="High",
                            url=url,
                            details=f"Accessible sensitive file: {file}"
                        )
                        self.add_vulnerability_to_result(subdomain, vuln)
                        
                        if self.config.verbose:
                            print(f"[!!!] Sensitive file found: {url}")
                except:
                    continue

    def check_config_files(self, subdomain: str):
        """Check for exposed configuration files"""
        config_files = [
            '/.env', '/config/.env', '/app/.env', '/api/.env',
            '/.aws/credentials', '/.config/credentials',
            '/web.config', '/config.xml', '/settings.py',
            '/config/database.yml', '/application.properties',
            '/.gitignore', '/composer.json', '/package.json',
            '/.htaccess', '/nginx.conf', '/httpd.conf'
        ]
        
        for protocol in ['https', 'http']:
            for config_file in config_files:
                try:
                    url = f"{protocol}://{subdomain}{config_file}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for sensitive information in config files
                        sensitive_patterns = [
                            'password', 'secret', 'key', 'token', 'api',
                            'database', 'mysql', 'postgres', 'mongodb',
                            'aws', 's3', 'cloud', 'credential'
                        ]
                        
                        if any(pattern in content for pattern in sensitive_patterns):
                            vuln = Vulnerability(
                                vuln_type="Exposed Configuration File",
                                severity="High",
                                url=url,
                                details=f"Exposed config file with sensitive data: {config_file}"
                            )
                            self.add_vulnerability_to_result(subdomain, vuln)
                            
                except:
                    continue

    def check_critical_vulnerabilities(self):
        """Check for critical vulnerabilities"""
        print("[*] Checking for Critical Vulnerabilities...")
        
        unique_targets = self.get_unique_targets()
        
        for target in unique_targets[:30]:
            subdomain = target.get('subdomain', '')
            if subdomain:
                self.check_sql_injection(subdomain)
                self.check_xss_vulnerabilities(subdomain)
                self.check_file_inclusion(subdomain)

    def check_sql_injection(self, subdomain: str):
        """Check for SQL injection vulnerabilities"""
        sql_payloads = [
            "'", 
            "';", 
            "' OR '1'='1", 
            "' UNION SELECT 1,2,3--", 
            "'; DROP TABLE users--"
        ]
        
        test_params = ['id', 'user', 'product', 'category', 'page']
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{subdomain}"
            
            # Check URL parameters
            for param in test_params:
                for payload in sql_payloads:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        
                        response = self.session.get(test_url, headers=headers, timeout=5)
                        
                        # Check for SQL injection indicators
                        sql_errors = [
                            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft odbc',
                            'postgresql', 'sqlite', 'warning: mysql', 'unclosed quotation'
                        ]
                        
                        if any(error in response.text.lower() for error in sql_errors):
                            vuln = Vulnerability(
                                vuln_type="SQL Injection",
                                severity="Critical",
                                url=test_url,
                                details=f"Possible SQL Injection in parameter: {param}"
                            )
                            self.add_vulnerability_to_result(subdomain, vuln)
                            if self.config.verbose:
                                print(f"[!!!] Possible SQL Injection: {test_url}")
                            break
                                
                    except Exception:
                        continue

    def check_xss_vulnerabilities(self, subdomain: str):
        """Check for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'message']
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{subdomain}"
            
            for param in test_params:
                for payload in xss_payloads:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        
                        response = self.session.get(test_url, headers=headers, timeout=5)
                        
                        # Check if payload was executed
                        if payload in response.text and '<script>' in payload:
                            vuln = Vulnerability(
                                vuln_type="Cross-Site Scripting (XSS)",
                                severity="High",
                                url=test_url,
                                details=f"Possible XSS in parameter: {param}"
                            )
                            self.add_vulnerability_to_result(subdomain, vuln)
                            break
                                
                    except Exception:
                        continue

    def check_file_inclusion(self, subdomain: str):
        """Check for file inclusion vulnerabilities"""
        lfi_payloads = [
            '../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '../../../../windows/win.ini',
            'file:///etc/passwd'
        ]
        
        test_params = ['file', 'page', 'path', 'include', 'template']
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{subdomain}"
            
            for param in test_params:
                for payload in lfi_payloads:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        
                        response = self.session.get(test_url, headers=headers, timeout=5)
                        
                        # Check for successful file inclusion
                        if 'root:' in response.text or '[extensions]' in response.text:
                            vuln = Vulnerability(
                                vuln_type="Local File Inclusion (LFI)",
                                severity="Critical",
                                url=test_url,
                                details=f"Possible LFI in parameter: {param}"
                            )
                            self.add_vulnerability_to_result(subdomain, vuln)
                            if self.config.verbose:
                                print(f"[!!!] Possible LFI: {test_url}")
                            break
                                
                    except Exception:
                        continue

    def validate_all_results(self) -> List[Result]:
        """Validate all results"""
        validated_results = []
        for result in self.results:
            if self.validate_result(result):
                validated_results.append(result)
        return validated_results

    def deduplicate_results(self, results: List[Result]) -> List[Result]:
        """Remove duplicate results"""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.ip, result.subdomain)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results

    def is_valid_public_ip(self, ip: str) -> bool:
        """Check if IP is valid and public"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
        except:
            return False

    def validate_result(self, result: Result) -> bool:
        """Validate a single result"""
        if not result.ip or not self.is_valid_public_ip(result.ip):
            return False
        
        # Additional validation can be added here
        return True

    def get_unique_targets(self):
        """Get unique targets for scanning"""
        unique_targets = []
        seen = set()
        
        for result in self.results:
            if result.subdomain and result.subdomain not in seen:
                unique_targets.append({'subdomain': result.subdomain, 'ip': result.ip})
                seen.add(result.subdomain)
            elif result.ip and result.ip not in seen:
                unique_targets.append({'subdomain': result.ip, 'ip': result.ip})
                seen.add(result.ip)
        
        return unique_targets

    def get_unique_ips(self):
        """Get unique IP addresses"""
        unique_ips = set()
        for result in self.results:
            if result.ip and self.is_valid_public_ip(result.ip):
                unique_ips.add(result.ip)
        return list(unique_ips)

    def add_result(self, result: Result):
        """Add a result to the results list"""
        with self.lock:
            self.results.append(result)

    def update_result_waf(self, ip: str, waf_info: WAFInfo):
        """Update result with WAF information"""
        with self.lock:
            for result in self.results:
                if result.ip == ip:
                    result.waf_info = waf_info
                    break

    def update_result_ports(self, ip: str, port: int, banner: str = ""):
        """Update result with port information"""
        with self.lock:
            for result in self.results:
                if result.ip == ip:
                    if port not in result.ports:
                        result.ports.append(port)
                    if banner and not result.banner:
                        result.banner = banner
                    break

    def add_endpoint_to_result(self, subdomain: str, endpoint: Endpoint):
        """Add endpoint to result"""
        with self.lock:
            for result in self.results:
                if result.subdomain == subdomain:
                    result.endpoints.append(endpoint)
                    break

    def add_vulnerability_to_result(self, subdomain: str, vulnerability: Vulnerability):
        """Add vulnerability to result"""
        with self.lock:
            for result in self.results:
                if result.subdomain == subdomain:
                    result.vulnerabilities.append(vulnerability)
                    break

    def add_vulnerability_by_ip(self, ip: str, vulnerability: Vulnerability):
        """Add vulnerability by IP"""
        with self.lock:
            for result in self.results:
                if result.ip == ip:
                    result.vulnerabilities.append(vulnerability)
                    break

    def print_results(self, results: List[Result]):
        """Print results in a formatted way"""
        print(f"\n{'='*80}")
        print(f"🎯 RECONNAISSANCE RESULTS FOR: {self.config.domain}")
        print(f"{'='*80}")
        
        valid_results = [r for r in results if r.is_valid]
        
        print(f"\n📊 SUMMARY:")
        print(f"  • Valid Targets: {len(valid_results)}")
        print(f"  • Unique Subdomains: {len(set(r.subdomain for r in valid_results if r.subdomain))}")
        print(f"  • Unique IPs: {len(set(r.ip for r in valid_results))}")
        
        # Subdomains with IPs
        print(f"\n🌐 SUBDOMAINS & IPs:")
        for result in valid_results:
            if result.subdomain:
                print(f"  • {result.subdomain} → {result.ip}")
                if result.ports:
                    print(f"    📍 Open ports: {', '.join(map(str, sorted(result.ports)))}")
                if result.waf_info and result.waf_info.detected:
                    print(f"    🛡️  WAF: {result.waf_info.name} ({result.waf_info.confidence} confidence)")
        
        # Interesting endpoints
        interesting_endpoints = []
        for result in valid_results:
            interesting_endpoints.extend([e for e in result.endpoints if e.interesting])
        
        if interesting_endpoints:
            print(f"\n🚨 INTERESTING ENDPOINTS FOUND:")
            for endpoint in interesting_endpoints:
                print(f"  • {endpoint.url} [{endpoint.status_code}]")
                if endpoint.title:
                    print(f"    📝 Title: {endpoint.title}")
                if endpoint.tech_stack:
                    print(f"    🛠️  Tech: {', '.join(endpoint.tech_stack)}")
                print(f"    💡 Reason: {endpoint.reason}")
        
        # Vulnerabilities
        all_vulnerabilities = []
        for result in valid_results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        if all_vulnerabilities:
            print(f"\n⚠️  POTENTIAL VULNERABILITIES:")
            for vuln in all_vulnerabilities:
                print(f"  • [{vuln.severity.upper()}] {vuln.vuln_type}")
                print(f"    🔗 {vuln.url}")
                print(f"    📋 {vuln.details}")
        
        print(f"\n{'='*80}")
        print(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")

    def save_results_json(self, results: List[Result], filename: str):
        """Save results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json_data = []
                for result in results:
                    result_dict = asdict(result)
                    # Convert dataclasses to dict
                    if result.ssl_info:
                        result_dict['ssl_info'] = asdict(result.ssl_info)
                    if result.waf_info:
                        result_dict['waf_info'] = asdict(result.waf_info)
                    result_dict['endpoints'] = [asdict(e) for e in result.endpoints]
                    result_dict['vulnerabilities'] = [asdict(v) for v in result.vulnerabilities]
                    json_data.append(result_dict)
                
                json.dump(json_data, f, indent=2, default=str)
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")


def main():
    parser = argparse.ArgumentParser(description="Advanced Bug Bounty Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Maximum workers")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--check-ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--check-ssl", action="store_true", help="Enable SSL checks")
    parser.add_argument("--deep", action="store_true", help="Enable deep scanning")
    parser.add_argument("--wordlist", help="Custom subdomain wordlist")
    
    args = parser.parse_args()
    
    config = Config(
        domain=args.domain,
        verbose=args.verbose,
        timeout=args.timeout,
        max_workers=args.workers,
        output_json=bool(args.output),
        check_ports=args.check_ports,
        check_ssl=args.check_ssl,
        check_subdomains=True,
        deep=args.deep,
        wordlist=args.wordlist,
        spider=False
    )
    
    recon = BugBountyRecon(config)
    
    try:
        results = recon.run_recon()
        
        if not results:
            print("[-] No valid results found")
            return
        
        recon.print_results(results)
        
        if args.output:
            recon.save_results_json(results, args.output)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
