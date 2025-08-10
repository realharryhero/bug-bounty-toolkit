"""
Reconnaissance Controller - Manages reconnaissance modules
"""

import logging
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import ScanResults, Finding, Severity, ReportGenerator
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class ReconController:
    """Controls and coordinates reconnaissance operations."""
    
    def __init__(self, config_manager: ConfigManager, args):
        """
        Initialize the reconnaissance controller.
        
        Args:
            config_manager: Configuration manager instance
            args: Command line arguments
        """
        self.config = config_manager
        self.args = args
        self.report_generator = ReportGenerator()
        
        # Initialize recon modules (simplified for now)
        self.recon_modules = {
            'subdomain': self._subdomain_enumeration,
            'portscan': self._port_scan,
            'fingerprint': self._tech_fingerprinting,
            'urls': self._url_discovery,
        }
    
    def run_recon(self, recon_type: str) -> ScanResults:
        """
        Run the specified reconnaissance operation.
        
        Args:
            recon_type: Type of reconnaissance to run
            
        Returns:
            ScanResults containing findings and metadata
        """
        start_time = datetime.now()
        target = self.args.domain or self.args.target
        
        logger.info(f"Starting {recon_type} reconnaissance on {target}")
        security_logger.log_scan_start(f"recon_{recon_type}", target)
        
        try:
            if recon_type == "all":
                findings = self._run_all_recon()
            elif recon_type in self.recon_modules:
                if self.config.is_recon_enabled(recon_type):
                    findings = self.recon_modules[recon_type](target)
                else:
                    logger.warning(f"Reconnaissance module {recon_type} is disabled")
                    findings = []
            else:
                logger.error(f"Unknown reconnaissance type: {recon_type}")
                findings = []
            
            end_time = datetime.now()
            
            # Create scan results
            results = self.report_generator.create_scan_results(
                scan_type=f"reconnaissance_{recon_type}",
                target=target,
                start_time=start_time,
                end_time=end_time,
                findings=findings,
                recon_config=self.config.get('recon'),
                command_line_args=vars(self.args)
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {str(e)}")
            security_logger.log_error("RECON_FAILED", str(e), target)
            raise
    
    def _run_all_recon(self) -> List[Finding]:
        """Run all enabled reconnaissance modules."""
        all_findings = []
        target = self.args.domain or self.args.target
        
        enabled_modules = [name for name in self.recon_modules.keys() 
                          if self.config.is_recon_enabled(name)]
        
        for module_name in enabled_modules:
            try:
                module_func = self.recon_modules[module_name]
                findings = module_func(target)
                all_findings.extend(findings)
                logger.info(f"Completed {module_name} reconnaissance - {len(findings)} findings")
            except Exception as e:
                logger.error(f"Reconnaissance module {module_name} failed: {str(e)}")
        
        return all_findings
    
    def _subdomain_enumeration(self, domain: str) -> List[Finding]:
        """Perform subdomain enumeration with DNS queries."""
        logger.info(f"Performing subdomain enumeration for {domain}")
        findings = []
        
        # Expanded list of common subdomains
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'app', 'mobile', 'secure', 'ssl',
            'vpn', 'remote', 'portal', 'support', 'help', 'docs',
            'cdn', 'static', 'assets', 'media', 'images', 'files',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'git', 'svn', 'jenkins', 'ci', 'build', 'deploy',
            'beta', 'alpha', 'demo', 'preview', 'sandbox',
            'internal', 'intranet', 'private', 'corp', 'corporate'
        ]
        
        # Try DNS resolution for each subdomain
        import socket
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                # Try to resolve the subdomain
                ip_address = socket.gethostbyname(full_domain)
                
                # Try to make an HTTP request to check if it's a web service
                try:
                    import requests
                    response = requests.get(f"http://{full_domain}", 
                                          timeout=5, 
                                          allow_redirects=True)
                    
                    # Determine severity based on subdomain type
                    severity = Severity.INFO
                    if subdomain in ['admin', 'api', 'internal', 'private', 'dev', 'test']:
                        severity = Severity.MEDIUM
                    elif subdomain in ['git', 'svn', 'jenkins', 'database', 'db']:
                        severity = Severity.HIGH
                    
                    finding = Finding(
                        title=f"Active Subdomain Found: {full_domain}",
                        severity=severity,
                        confidence=0.9,
                        description=f"Active subdomain with web service: {full_domain} (IP: {ip_address})",
                        target=f"http://{full_domain}",
                        vulnerability_type="Information Disclosure",
                        evidence=f"HTTP response: {response.status_code}, IP: {ip_address}",
                        impact="Subdomain exposes additional attack surface and may contain sensitive functionality.",
                        remediation="Review subdomain for security issues and ensure proper access controls."
                    )
                    findings.append(finding)
                    
                except requests.exceptions.RequestException:
                    # DNS resolves but no web service
                    finding = Finding(
                        title=f"Subdomain Found (DNS only): {full_domain}",
                        severity=Severity.LOW,
                        confidence=0.7,
                        description=f"Subdomain resolves via DNS: {full_domain} (IP: {ip_address})",
                        target=full_domain,
                        vulnerability_type="Information Disclosure",
                        evidence=f"DNS resolution successful, IP: {ip_address}",
                        impact="Subdomain may expose internal infrastructure details.",
                        remediation="Review if subdomain should be publicly accessible."
                    )
                    findings.append(finding)
                    
            except socket.gaierror:
                # Subdomain doesn't resolve - this is normal, skip
                continue
            except Exception as e:
                logger.debug(f"Error checking subdomain {full_domain}: {str(e)}")
                continue
        
        # Try certificate transparency lookup (simplified)
        try:
            import requests
            ct_response = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=10
            )
            
            if ct_response.status_code == 200:
                import json
                try:
                    ct_data = ct_response.json()
                    if isinstance(ct_data, list):
                        # Extract unique subdomains from certificate data
                        cert_domains = set()
                        for cert in ct_data[:20]:  # Limit to first 20 results
                            name_value = cert.get('name_value', '')
                            for domain_name in name_value.split('\n'):
                                domain_name = domain_name.strip()
                                if domain_name.endswith(f".{domain}") and '*' not in domain_name:
                                    cert_domains.add(domain_name)
                        
                        if cert_domains:
                            finding = Finding(
                                title=f"Certificate Transparency Subdomains",
                                severity=Severity.INFO,
                                confidence=0.8,
                                description=f"Found {len(cert_domains)} subdomains in certificate transparency logs",
                                target=domain,
                                vulnerability_type="Information Disclosure",
                                evidence=f"Domains found: {', '.join(list(cert_domains)[:10])}{'...' if len(cert_domains) > 10 else ''}",
                                impact="Certificate transparency logs reveal additional subdomains.",
                                remediation="Review all discovered subdomains for security posture."
                            )
                            findings.append(finding)
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error checking certificate transparency: {str(e)}")
        
        return findings
    
    def _port_scan(self, target: str) -> List[Finding]:
        """Perform port scanning with actual connection attempts."""
        logger.info(f"Performing port scan on {target}")
        findings = []
        
        # Extended list of common ports
        common_ports = [
            (21, 'FTP'),
            (22, 'SSH'),
            (23, 'Telnet'),
            (25, 'SMTP'),
            (53, 'DNS'),
            (80, 'HTTP'),
            (110, 'POP3'),
            (143, 'IMAP'),
            (443, 'HTTPS'),
            (993, 'IMAPS'),
            (995, 'POP3S'),
            (1433, 'MSSQL'),
            (3306, 'MySQL'),
            (3389, 'RDP'),
            (5432, 'PostgreSQL'),
            (5900, 'VNC'),
            (6379, 'Redis'),
            (8080, 'HTTP-Alt'),
            (8443, 'HTTPS-Alt'),
            (9200, 'Elasticsearch'),
            (27017, 'MongoDB')
        ]
        
        import socket
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def check_port(target_host, port, service):
            """Check if a specific port is open."""
            try:
                # Extract hostname from URL if needed
                if target_host.startswith('http'):
                    from urllib.parse import urlparse
                    parsed = urlparse(target_host)
                    target_host = parsed.hostname or parsed.netloc
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # 3 second timeout
                result = sock.connect_ex((target_host, port))
                sock.close()
                
                if result == 0:
                    # Try to grab banner for service identification
                    banner = ""
                    try:
                        banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        banner_sock.settimeout(2)
                        banner_sock.connect((target_host, port))
                        banner = banner_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        banner_sock.close()
                    except:
                        pass
                    
                    return {
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'open': True
                    }
                    
            except Exception as e:
                logger.debug(f"Error checking port {port}: {str(e)}")
            
            return None
        
        # Use thread pool for concurrent port scanning
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all port checks
            future_to_port = {
                executor.submit(check_port, target, port, service): (port, service)
                for port, service in common_ports
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                result = future.result()
                if result and result['open']:
                    open_ports.append(result)
        
        # Create findings for open ports
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            banner = port_info['banner']
            
            # Determine severity based on service type
            severity = Severity.INFO
            if port in [23, 21]:  # Telnet, FTP (often insecure)
                severity = Severity.MEDIUM
            elif port in [3389, 5900]:  # RDP, VNC (remote access)
                severity = Severity.MEDIUM
            elif port in [1433, 3306, 5432, 6379, 27017]:  # Databases
                severity = Severity.HIGH
            
            evidence = f"Port {port} ({service}) is open"
            if banner:
                evidence += f". Banner: {banner[:100]}..."
            
            impact = f"Open {service} service may provide additional attack vectors."
            if port in [1433, 3306, 5432]:
                impact = "Database service exposed - may allow data access if misconfigured."
            elif port in [3389, 5900]:
                impact = "Remote access service exposed - may allow system compromise."
            elif port == 23:
                impact = "Telnet service exposed - communications are unencrypted."
            
            finding = Finding(
                title=f"Open Port: {port} ({service})",
                severity=severity,
                confidence=0.9,
                description=f"Port {port} ({service}) is accessible from external networks",
                target=f"{target}:{port}",
                vulnerability_type="Information Disclosure",
                evidence=evidence,
                impact=impact,
                remediation="Verify if port should be exposed and ensure proper security configuration."
            )
            findings.append(finding)
        
        return findings
    
    def _tech_fingerprinting(self, target: str) -> List[Finding]:
        """Perform comprehensive technology fingerprinting."""
        logger.info(f"Performing technology fingerprinting on {target}")
        findings = []
        
        try:
            import requests
            from bs4 import BeautifulSoup
            
            # Make requests to gather information
            response = requests.get(target, timeout=10, allow_redirects=True)
            
            technologies = []
            
            # Analyze HTTP headers
            headers = response.headers
            
            # Server header analysis
            server = headers.get('Server', '')
            if server:
                technologies.append(('Server', server))
                
            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies.append(('X-Powered-By', powered_by))
            
            # Other revealing headers
            framework_headers = {
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS/Framework',
                'X-Powered-CMS': 'CMS',
                'X-Pingback': 'WordPress',
            }
            
            for header, tech in framework_headers.items():
                if header in headers:
                    technologies.append((header, f"{tech}: {headers[header]}"))
            
            # Analyze response content
            content = response.text.lower()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for meta generators
            generator_meta = soup.find('meta', attrs={'name': 'generator'})
            if generator_meta and generator_meta.get('content'):
                technologies.append(('Meta Generator', generator_meta.get('content')))
            
            # JavaScript framework detection
            js_patterns = {
                'jQuery': r'jquery[-\.]?(\d+\.?\d*\.?\d*)',
                'Angular': r'angular[-\.]?(\d+\.?\d*\.?\d*)',
                'React': r'react[-\.]?(\d+\.?\d*\.?\d*)',
                'Vue.js': r'vue[-\.]?(\d+\.?\d*\.?\d*)',
                'Bootstrap': r'bootstrap[-\.]?(\d+\.?\d*\.?\d*)',
            }
            
            import re
            for tech, pattern in js_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    version = matches[0] if matches[0] else 'detected'
                    technologies.append(('JavaScript Library', f"{tech} {version}"))
            
            # CMS Detection
            cms_indicators = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
                'Drupal': ['/sites/default/', '/modules/', 'drupal.js'],
                'Joomla': ['/components/com_', '/modules/mod_', 'joomla'],
                'Magento': ['/js/mage/', '/skin/frontend/', 'magento'],
                'Shopify': ['cdn.shopify.com', 'shopify-theme'],
                'Django': ['csrfmiddlewaretoken', '__admin'],
                'Laravel': ['laravel_token', 'laravel_session'],
            }
            
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        technologies.append(('CMS', cms))
                        break
            
            # Database technology hints
            db_indicators = {
                'MySQL': ['mysql', 'phpmyadmin'],
                'PostgreSQL': ['postgresql', 'postgres'],
                'MongoDB': ['mongodb', 'mongo'],
                'Redis': ['redis'],
                'MSSQL': ['mssql', 'microsoft sql'],
            }
            
            for db, indicators in db_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        technologies.append(('Database', db))
                        break
            
            # Web server detection from response patterns
            if 'apache' in server.lower():
                technologies.append(('Web Server', 'Apache HTTP Server'))
            elif 'nginx' in server.lower():
                technologies.append(('Web Server', 'Nginx'))
            elif 'iis' in server.lower():
                technologies.append(('Web Server', 'Microsoft IIS'))
            
            # SSL/TLS information
            if target.startswith('https://'):
                try:
                    import ssl
                    import socket
                    from urllib.parse import urlparse
                    
                    parsed_url = urlparse(target)
                    hostname = parsed_url.hostname
                    port = parsed_url.port or 443
                    
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            version = ssock.version()
                            
                            if version:
                                technologies.append(('TLS Version', version))
                            if cipher:
                                technologies.append(('Cipher Suite', f"{cipher[0]} ({cipher[1]} bits)"))
                                
                except Exception as e:
                    logger.debug(f"Error getting SSL info: {str(e)}")
            
            # Create findings
            if technologies:
                tech_list = []
                for category, value in technologies[:15]:  # Limit to first 15
                    tech_list.append(f"{category}: {value}")
                
                finding = Finding(
                    title="Technology Stack Information",
                    severity=Severity.INFO,
                    confidence=0.8,
                    description=f"Identified {len(technologies)} technology components",
                    target=target,
                    vulnerability_type="Information Disclosure",
                    evidence="; ".join(tech_list),
                    impact="Technology information may help attackers plan targeted attacks.",
                    remediation="Consider hiding server signatures and technology indicators where possible."
                )
                findings.append(finding)
                
                # Check for outdated or vulnerable technologies
                vulnerable_indicators = [
                    'php/4.', 'php/5.', 'apache/1.', 'apache/2.0', 'apache/2.2',
                    'iis/6.', 'iis/7.', 'nginx/0.', 'nginx/1.0', 'nginx/1.2'
                ]
                
                tech_string = " ".join([value.lower() for _, value in technologies])
                for indicator in vulnerable_indicators:
                    if indicator in tech_string:
                        finding = Finding(
                            title="Potentially Outdated Technology Detected",
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            description=f"Potentially outdated technology version detected: {indicator}",
                            target=target,
                            vulnerability_type="Outdated Software",
                            evidence=f"Detected version: {indicator}",
                            impact="Outdated software may contain known security vulnerabilities.",
                            remediation="Update software to the latest stable version."
                        )
                        findings.append(finding)
                        break
            
        except Exception as e:
            logger.debug(f"Error in technology fingerprinting: {str(e)}")
            # Fallback basic finding
            finding = Finding(
                title="Technology Fingerprinting Completed",
                severity=Severity.INFO,
                confidence=0.3,
                description="Basic technology fingerprinting completed with limited results",
                target=target,
                vulnerability_type="Information Disclosure",
                evidence=f"Error occurred during detailed analysis: {str(e)}",
                impact="Limited technology information available.",
                remediation="Manual analysis may reveal additional details."
            )
            findings.append(finding)
        
        return findings
    
    def _url_discovery(self, target: str) -> List[Finding]:
        """Perform comprehensive URL/directory discovery."""
        logger.info(f"Performing URL discovery on {target}")
        findings = []
        
        try:
            import requests
            from urllib.parse import urljoin, urlparse
            
            # Extended directory/file wordlist
            common_paths = [
                # Admin/Management
                '/admin', '/administrator', '/admin.php', '/admin.html',
                '/manage', '/management', '/panel', '/control',
                '/wp-admin', '/wp-login.php', '/login', '/signin',
                
                # Configuration/Sensitive files
                '/config', '/configuration', '/config.php', '/config.xml',
                '/settings', '/env', '/.env', '/web.config',
                '/.htaccess', '/robots.txt', '/sitemap.xml',
                
                # Backup files
                '/backup', '/backups', '/bak', '/old', '/temp',
                '/backup.zip', '/backup.tar.gz', '/database.sql',
                '/dump.sql', '/backup.sql',
                
                # Development/Testing
                '/test', '/testing', '/dev', '/development',
                '/debug', '/staging', '/beta', '/demo',
                '/phpinfo.php', '/info.php', '/test.php',
                
                # API/Services
                '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
                '/services', '/webservice', '/soap', '/rpc',
                
                # Documentation
                '/docs', '/documentation', '/help', '/readme',
                '/manual', '/guide', '/api-docs',
                
                # File/Media directories  
                '/files', '/uploads', '/media', '/images',
                '/documents', '/download', '/downloads',
                '/assets', '/static', '/public',
                
                # Server/System
                '/server-status', '/server-info', '/status',
                '/health', '/metrics', '/monitoring',
                
                # Common applications
                '/phpmyadmin', '/adminer', '/mysql', '/database',
                '/git', '/.git', '/svn', '/.svn',
                '/jenkins', '/nagios', '/munin',
            ]
            
            discovered_paths = []
            
            # Use thread pool for concurrent requests
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            def check_path(base_url, path):
                """Check if a path exists and analyze response."""
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(
                        url, 
                        timeout=5,
                        allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner)'}
                    )
                    
                    # Determine if path is interesting
                    if response.status_code == 200:
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'size': len(response.text),
                            'content_type': response.headers.get('content-type', ''),
                            'title': self._extract_title(response.text),
                            'interesting': True
                        }
                    elif response.status_code in [301, 302, 307, 308]:
                        location = response.headers.get('location', '')
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'redirect': location,
                            'interesting': True
                        }
                    elif response.status_code == 403:
                        # Forbidden might indicate existing resource
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'interesting': True,
                            'note': 'Access forbidden - resource may exist'
                        }
                    elif response.status_code == 401:
                        # Unauthorized might indicate protected resource
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'interesting': True,
                            'note': 'Authentication required'
                        }
                        
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Error checking path {path}: {str(e)}")
                
                return None
            
            # Concurrent path discovery
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_path = {
                    executor.submit(check_path, target, path): path
                    for path in common_paths
                }
                
                for future in as_completed(future_to_path):
                    result = future.result()
                    if result and result['interesting']:
                        discovered_paths.append(result)
            
            # Create findings for discovered paths
            for path_info in discovered_paths:
                path = path_info['path']
                url = path_info['url']
                status = path_info['status']
                
                # Determine severity based on path type and status
                severity = Severity.INFO
                if any(sensitive in path.lower() for sensitive in [
                    'admin', 'config', 'backup', '.env', 'password', 'login'
                ]):
                    severity = Severity.MEDIUM
                elif any(critical in path.lower() for critical in [
                    'phpmyadmin', 'database', '.git', 'phpinfo'
                ]):
                    severity = Severity.HIGH
                
                # Build evidence string
                evidence = f"HTTP {status}"
                if 'size' in path_info:
                    evidence += f", Size: {path_info['size']} bytes"
                if 'content_type' in path_info:
                    evidence += f", Type: {path_info['content_type']}"
                if 'title' in path_info and path_info['title']:
                    evidence += f", Title: {path_info['title']}"
                if 'redirect' in path_info:
                    evidence += f", Redirects to: {path_info['redirect']}"
                if 'note' in path_info:
                    evidence += f", Note: {path_info['note']}"
                
                # Determine impact based on path type
                impact = "Directory/file may contain interesting information."
                if 'admin' in path.lower():
                    impact = "Administrative interface may allow unauthorized access."
                elif 'config' in path.lower() or '.env' in path:
                    impact = "Configuration file may contain sensitive information."
                elif 'backup' in path.lower():
                    impact = "Backup file may contain sensitive data or source code."
                elif '.git' in path or 'phpinfo' in path.lower():
                    impact = "Resource may expose sensitive system or application information."
                
                finding = Finding(
                    title=f"Directory/File Found: {path}",
                    severity=severity,
                    confidence=0.8,
                    description=f"Discovered accessible path: {path}",
                    target=url,
                    vulnerability_type="Information Disclosure",
                    evidence=evidence,
                    impact=impact,
                    remediation="Review discovered resource and restrict access if necessary."
                )
                findings.append(finding)
            
            # Check for common file extensions
            if discovered_paths:
                file_extensions = ['.txt', '.log', '.bak', '.old', '.zip', '.tar.gz']
                base_files = ['/index', '/default', '/home', '/main']
                
                extension_findings = []
                for base_file in base_files[:2]:  # Limit to avoid too many requests
                    for ext in file_extensions[:3]:  # Limit extensions
                        test_path = base_file + ext
                        result = check_path(target, test_path)
                        if result and result['interesting']:
                            extension_findings.append(result)
                
                if extension_findings:
                    finding = Finding(
                        title=f"Additional Files with Extensions Found",
                        severity=Severity.LOW,
                        confidence=0.6,
                        description=f"Found {len(extension_findings)} additional files with common extensions",
                        target=target,
                        vulnerability_type="Information Disclosure",
                        evidence=f"Files: {', '.join([f['path'] for f in extension_findings[:5]])}",
                        impact="Files with common extensions may contain backup or sensitive data.",
                        remediation="Review discovered files and remove unnecessary files from web root."
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error in URL discovery: {str(e)}")
            # Fallback basic finding
            finding = Finding(
                title="URL Discovery Completed",
                severity=Severity.INFO,
                confidence=0.3,
                description="Basic URL discovery completed with limited results",
                target=target,
                vulnerability_type="Information Disclosure",
                evidence=f"Error occurred during discovery: {str(e)}",
                impact="Limited directory/file information available.",
                remediation="Manual analysis may reveal additional paths."
            )
            findings.append(finding)
        
        return findings
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:100]  # Limit length
        except Exception:
            pass
        return ""