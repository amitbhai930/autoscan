import requests
import socket
import ssl
import json
import re
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import nmap
import whois
from bs4 import BeautifulSoup
import concurrent.futures

class VulnerabilityScanner:
    def __init__(self, target_url, scan_id=None, user_id=None):
        self.target_url = target_url
        self.scan_id = scan_id
        self.user_id = user_id
        self.results = {
            'target': target_url,
            'scan_date': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'information': {},
            'statistics': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'cve_matches': 0,
                'total_vulnerabilities': 0
            }
        }
        
    def run_scan(self, scan_type="full", options=None):
        """Main scanning method"""
        try:
            # Basic target validation
            parsed_url = urlparse(self.target_url)
            if not parsed_url.scheme:
                self.target_url = 'http://' + self.target_url
            
            # Gather basic information
            self.results['information'] = self.gather_information()
            
            # Run selected scans
            if scan_type in ["full", "quick"]:
                self.check_security_headers()
                self.check_ssl_tls()
                self.detect_technologies()
                self.check_common_vulnerabilities()
                
            if scan_type == "full" or (options and options.get('cve_check', False)):
                self.check_cve_vulnerabilities()
                
            if scan_type == "full" or (options and options.get('xss_check', False)):
                self.check_xss_vulnerabilities()
                
            if scan_type == "full" or (options and options.get('sql_check', False)):
                self.check_sql_injection()
                
            if scan_type == "full" or (options and options.get('csrf_check', False)):
                self.check_csrf()
                
            # Update statistics
            self.results['statistics']['total_vulnerabilities'] = len(self.results['vulnerabilities'])
            
            return self.results
            
        except Exception as e:
            print(f"Scan error: {e}")
            return {'error': str(e)}
    
    def gather_information(self):
        """Gather basic information about target"""
        info = {}
        try:
            parsed_url = urlparse(self.target_url)
            info['domain'] = parsed_url.netloc
            info['scheme'] = parsed_url.scheme
            info['path'] = parsed_url.path
            
            # Get IP address
            ip = socket.gethostbyname(parsed_url.netloc)
            info['ip_address'] = ip
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(parsed_url.netloc)
                info['whois'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date)
                }
            except:
                info['whois'] = 'Unable to retrieve'
            
            # Get server information
            try:
                response = requests.get(self.target_url, timeout=10, verify=False)
                info['server'] = response.headers.get('Server', 'Unknown')
                info['technologies'] = self.detect_technologies_from_headers(response.headers)
            except:
                pass
                
        except Exception as e:
            info['error'] = str(e)
            
        return info
    
    def detect_technologies(self):
        """Detect web technologies in use"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            # Check for common technology indicators
            technologies = []
            
            # Check server header
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
                
            # Check X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
                
            # Check cookies for framework indicators
            cookies = headers.get('Set-Cookie', '')
            if 'sessionid' in cookies.lower():
                technologies.append('Django')
            elif 'laravel_session' in cookies.lower():
                technologies.append('Laravel')
                
            self.results['information']['detected_technologies'] = technologies
            
            # Check for outdated versions
            self.check_outdated_technologies(technologies)
            
        except Exception as e:
            print(f"Technology detection error: {e}")
    
    def check_outdated_technologies(self, technologies):
        """Check for outdated technology versions"""
        # This is a simplified check. In production, you'd query CVE databases
        outdated_checks = {
            'PHP': [
                {'version': '7.4', 'status': 'critical', 'cve': 'Multiple CVEs'},
                {'version': '5.6', 'status': 'critical', 'cve': 'Multiple CVEs'}
            ],
            'WordPress': [
                {'version': '5.0', 'status': 'high', 'cve': 'CVE-2023-XXXX'}
            ]
        }
        
        for tech in technologies:
            if tech in outdated_checks:
                for check in outdated_checks[tech]:
                    self.add_vulnerability(
                        f"Outdated {tech} version",
                        check['status'],
                        f"Running potentially outdated version of {tech}",
                        "Update to latest stable version",
                        "CVE",
                        check.get('cve', '')
                    )
    
    def check_security_headers(self):
        """Check for security headers"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': 'medium',
                'X-Frame-Options': 'medium',
                'X-Content-Type-Options': 'low',
                'Strict-Transport-Security': 'high',
                'X-XSS-Protection': 'low'
            }
            
            for header, severity in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        f"Missing {header}",
                        severity,
                        f"Security header {header} is not set",
                        f"Configure {header} header",
                        "Security Headers"
                    )
                    
        except Exception as e:
            print(f"Header check error: {e}")
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        try:
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme != 'https':
                self.add_vulnerability(
                    "No HTTPS",
                    "high",
                    "Website does not use HTTPS",
                    "Implement HTTPS with proper SSL certificate",
                    "SSL/TLS"
                )
                return
                
            context = ssl.create_default_context()
            with socket.create_connection((parsed_url.netloc, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    import datetime as dt
                    expiry_date = dt.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - dt.datetime.utcnow()).days
                    
                    if days_remaining < 30:
                        self.add_vulnerability(
                            "SSL Certificate Expiring Soon",
                            "medium",
                            f"SSL certificate expires in {days_remaining} days",
                            "Renew SSL certificate",
                            "SSL/TLS"
                        )
                        
        except ssl.SSLError as e:
            self.add_vulnerability(
                "SSL/TLS Error",
                "high",
                f"SSL/TLS configuration issue: {str(e)}",
                "Fix SSL/TLS configuration",
                "SSL/TLS"
            )
        except Exception as e:
            print(f"SSL check error: {e}")
    
    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        try:
            # Check for exposed directories
            common_dirs = ['admin', 'wp-admin', 'backup', 'config', 'logs', 'phpinfo.php']
            
            for dir_path in common_dirs:
                test_url = f"{self.target_url.rstrip('/')}/{dir_path}"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        self.add_vulnerability(
                            f"Exposed Directory: {dir_path}",
                            "medium",
                            f"Exposed directory or file: {dir_path}",
                            f"Restrict access to {dir_path}",
                            "Information Disclosure"
                        )
                except:
                    continue
                    
            # Check for robots.txt
            robots_url = f"{self.target_url.rstrip('/')}/robots.txt"
            try:
                response = requests.get(robots_url, timeout=5, verify=False)
                if response.status_code == 200 and 'Disallow:' in response.text:
                    self.results['information']['robots_txt'] = response.text[:500]
            except:
                pass
                
        except Exception as e:
            print(f"Common vulnerabilities check error: {e}")
    
    def check_xss_vulnerabilities(self):
        """Check for Cross-Site Scripting vulnerabilities"""
        try:
            # Basic XSS check in parameters
            test_payloads = [
                "<script>alert('XSS')</script>",
                "\"onmouseover=\"alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ]
            
            # Get forms from the page
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:3]:  # Limit to first 3 forms
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                for payload in test_payloads:
                    # This is a simplified check. Real XSS testing requires more sophisticated approach
                    test_data = {}
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        if input_field.get('type') not in ['submit', 'button']:
                            test_data[input_field.get('name', 'test')] = payload
                    
                    # Skip if no inputs
                    if not test_data:
                        continue
                    
                    # Try to submit the form
                    try:
                        if form_method == 'post':
                            response = requests.post(self.target_url + form_action, 
                                                   data=test_data, 
                                                   timeout=5, 
                                                   verify=False)
                        else:
                            response = requests.get(self.target_url + form_action, 
                                                  params=test_data, 
                                                  timeout=5, 
                                                  verify=False)
                        
                        # Check if payload appears in response
                        if payload in response.text:
                            self.add_vulnerability(
                                "Potential XSS Vulnerability",
                                "high",
                                f"Potential XSS found in form submission",
                                "Implement input validation and output encoding",
                                "XSS"
                            )
                            break
                    except:
                        continue
                        
        except Exception as e:
            print(f"XSS check error: {e}")
    
    def check_sql_injection(self):
        """Check for SQL Injection vulnerabilities"""
        try:
            # Basic SQL injection test
            sql_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT null --",
                "'; DROP TABLE users --"
            ]
            
            # Test URL parameters
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                params = parsed_url.query.split('&')
                for param in params[:3]:  # Test first 3 parameters
                    if '=' in param:
                        key, value = param.split('=', 1)
                        
                        for payload in sql_payloads:
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{key}={value}{payload}"
                            try:
                                response = requests.get(test_url, timeout=5, verify=False)
                                
                                # Check for common SQL error messages
                                sql_errors = [
                                    'sql syntax',
                                    'mysql_fetch',
                                    'ora-',
                                    'postgresql',
                                    'sqlite',
                                    'sql server',
                                    'unclosed quotation',
                                    'undefined function'
                                ]
                                
                                for error in sql_errors:
                                    if error in response.text.lower():
                                        self.add_vulnerability(
                                            "Potential SQL Injection",
                                            "critical",
                                            f"SQL error detected with payload: {payload}",
                                            "Use parameterized queries and input validation",
                                            "SQL Injection"
                                        )
                                        return  # Found one, stop checking
                            except:
                                continue
                                
        except Exception as e:
            print(f"SQL injection check error: {e}")
    
    def check_csrf(self):
        """Check for Cross-Site Request Forgery vulnerabilities"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:3]:
                # Check for CSRF token
                csrf_elements = form.find_all(attrs={'name': re.compile(r'(csrf|token)', re.I)})
                if not csrf_elements:
                    # Check for hidden input that might be CSRF token
                    hidden_inputs = form.find_all('input', {'type': 'hidden'})
                    has_token = False
                    for hi in hidden_inputs:
                        if re.search(r'(csrf|token)', hi.get('name', ''), re.I):
                            has_token = True
                            break
                    
                    if not has_token:
                        self.add_vulnerability(
                            "Potential CSRF Vulnerability",
                            "medium",
                            "Form lacks CSRF protection token",
                            "Implement CSRF tokens for state-changing operations",
                            "CSRF"
                        )
                        
        except Exception as e:
            print(f"CSRF check error: {e}")
    
    def check_cve_vulnerabilities(self):
        """Check for known CVE vulnerabilities"""
        try:
            # This would normally query a CVE database or API
            # For demonstration, we'll simulate CVE checks
            
            cve_list = [
                {
                    'cve_id': 'CVE-2023-12345',
                    'severity': 'critical',
                    'description': 'Remote Code Execution in CMS',
                    'affected': 'WordPress < 6.2'
                },
                {
                    'cve_id': 'CVE-2023-54321',
                    'severity': 'high',
                    'description': 'SQL Injection in Plugin',
                    'affected': 'Contact Form 7 < 5.8'
                },
                {
                    'cve_id': 'CVE-2023-67890',
                    'severity': 'medium',
                    'description': 'Cross-Site Scripting',
                    'affected': 'jQuery < 3.6.0'
                }
            ]
            
            # Simulate CVE matching based on detected technologies
            technologies = self.results['information'].get('detected_technologies', [])
            
            for tech in technologies:
                for cve in cve_list:
                    if tech.lower() in cve['affected'].lower():
                        self.add_vulnerability(
                            cve['description'],
                            cve['severity'],
                            f"CVE ID: {cve['cve_id']} - {cve['description']}",
                            f"Update {tech} to latest version",
                            "CVE",
                            cve['cve_id']
                        )
                        self.results['statistics']['cve_matches'] += 1
                        
        except Exception as e:
            print(f"CVE check error: {e}")
    
    def add_vulnerability(self, title, severity, description, remediation, vuln_type, cve_id=None):
        """Add a vulnerability to results"""
        vuln = {
            'id': len(self.results['vulnerabilities']) + 1,
            'title': title,
            'severity': severity,
            'description': description,
            'remediation': remediation,
            'type': vuln_type,
            'cve_id': cve_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.results['vulnerabilities'].append(vuln)
        
        # Update statistics
        if severity == 'critical':
            self.results['statistics']['critical'] += 1
        elif severity == 'high':
            self.results['statistics']['high'] += 1
        elif severity == 'medium':
            self.results['statistics']['medium'] += 1
        elif severity == 'low':
            self.results['statistics']['low'] += 1
    
    def detect_technologies_from_headers(self, headers):
        """Extract technology information from headers"""
        tech_info = {}
        
        # Server info
        if 'Server' in headers:
            tech_info['server'] = headers['Server']
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            tech_info['powered_by'] = headers['X-Powered-By']
        
        # Framework indicators
        cookies = headers.get('Set-Cookie', '')
        if 'laravel_session' in cookies:
            tech_info['framework'] = 'Laravel'
        elif 'sessionid' in cookies:
            tech_info['framework'] = 'Django'
        
        return tech_info