#!/usr/bin/env python3
"""
Enhanced DNS Analyzer - A tool to analyze DNS information using the dnsdumpster API
with improved detection sensitivity and verbose reporting
"""

import argparse
import json
import requests
import sys
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from pprint import pprint

class DNSDumpsterAnalyzer:
    """Class to interact with the dnsdumpster API and analyze results with enhanced sensitivity"""
    
    def __init__(self, api_key: str, verbose: bool = False):
        """Initialize with API key and verbosity setting"""
        self.api_key = api_key
        self.base_url = "https://api.dnsdumpster.com/domain/"
        self.headers = {"X-API-Key": self.api_key}
        self.results = None
        self.verbose = verbose
    
    def query_domain(self, domain: str) -> Dict[str, Any]:
        """Query the dnsdumpster API for a domain"""
        url = f"{self.base_url}{domain}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            self.results = response.json()
            return self.results
        except requests.exceptions.RequestException as e:
            print(f"Error querying dnsdumpster API: {e}")
            sys.exit(1)
    
    def save_results(self, filename: str) -> None:
        """Save results to a JSON file"""
        if not self.results:
            print("No results to save")
            return
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"Results saved to {filename}")
    
    def analyze_exposed_services(self) -> List[Dict[str, str]]:
        """Analyze for potentially exposed services with enhanced sensitivity"""
        if not self.results:
            return []
        
        exposed_services = []
        
        # Enhanced list of sensitive keywords
        sensitive_keywords = [
            # Admin interfaces
            'admin', 'administrator', 'adm', 'manage', 'management', 'manager', 'console', 'portal',
            # Internal services
            'internal', 'intranet', 'corp', 'corporate', 'private', 'local', 'localhost',
            # Development/testing environments
            'staging', 'stage', 'test', 'testing', 'dev', 'development', 'uat', 'qa', 'demo', 'beta',
            'sandbox', 'preprod', 'pre-prod', 'preview',
            # Remote access
            'citrix', 'vpn', 'ssh', 'rdp', 'remote', 'gateway', 'access',
            # File transfer
            'ftp', 'sftp', 'ftps', 'upload', 'download',
            # Email
            'smtp', 'imap', 'pop3', 'mail', 'email', 'webmail', 'exchange',
            # Databases
            'database', 'db', 'sql', 'oracle', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb',
            'redis', 'memcache', 'cassandra', 'couchdb', 'mariadb',
            # DevOps tools
            'jenkins', 'jira', 'confluence', 'gitlab', 'github', 'bitbucket', 'bamboo', 'travis',
            'sonar', 'nexus', 'artifactory', 'docker', 'kubernetes', 'k8s', 'rancher', 'openshift',
            # Monitoring
            'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus', 'nagios', 'zabbix', 'splunk',
            'elasticsearch', 'logstash',
            # Authentication
            'auth', 'login', 'sso', 'saml', 'oauth', 'ldap', 'active-directory', 'ad',
            # APIs
            'api', 'rest', 'graphql', 'soap', 'ws', 'webservice', 'service',
            # Backup
            'backup', 'bak', 'old', 'archive', 'dump',
            # CMS
            'wp', 'wordpress', 'joomla', 'drupal', 'typo3', 'magento', 'shopify',
            # Cloud
            'aws', 'azure', 'gcp', 'cloud', 's3', 'bucket', 'storage',
            # Misc
            'secret', 'password', 'secure', 'config', 'configuration', 'setup', 'install'
        ]
        
        # Check A records
        for record in self.results.get('dns_records', {}).get('a', []):
            domain = record.get('domain', '')
            
            # Check for sensitive keywords in domain name
            for keyword in sensitive_keywords:
                if keyword in domain.lower():
                    exposed_services.append({
                        'type': 'A Record',
                        'domain': domain,
                        'ip': record.get('ip', ''),
                        'concern': f"Potentially sensitive service containing '{keyword}'",
                        'risk_level': 'Medium'
                    })
            
            # Always include in verbose mode
            if self.verbose and not any(service['domain'] == domain for service in exposed_services):
                exposed_services.append({
                    'type': 'A Record',
                    'domain': domain,
                    'ip': record.get('ip', ''),
                    'concern': "Standard A record",
                    'risk_level': 'Info'
                })
        
        # Check CNAME records
        for record in self.results.get('dns_records', {}).get('cname', []):
            domain = record.get('domain', '')
            target = record.get('target', '')
            
            # Check for sensitive keywords in domain or target
            for keyword in sensitive_keywords:
                if keyword in domain.lower() or keyword in target.lower():
                    exposed_services.append({
                        'type': 'CNAME Record',
                        'domain': domain,
                        'target': target,
                        'concern': f"Potentially sensitive service containing '{keyword}'",
                        'risk_level': 'Medium'
                    })
            
            # Always include in verbose mode
            if self.verbose and not any(service['domain'] == domain for service in exposed_services):
                exposed_services.append({
                    'type': 'CNAME Record',
                    'domain': domain,
                    'target': target,
                    'concern': "Standard CNAME record",
                    'risk_level': 'Info'
                })
        
        # Check for any services in the 'a' array
        for host_entry in self.results.get('a', []):
            domain = host_entry.get('host', '')
            
            # Check for sensitive keywords in domain name
            for keyword in sensitive_keywords:
                if keyword in domain.lower():
                    ip_info = []
                    for ip_entry in host_entry.get('ips', []):
                        ip_info.append(ip_entry.get('ip', ''))
                    
                    exposed_services.append({
                        'type': 'Host Record',
                        'domain': domain,
                        'ip': ', '.join(ip_info),
                        'concern': f"Potentially sensitive service containing '{keyword}'",
                        'risk_level': 'Medium'
                    })
            
            # Check for FTP banners
            for ip_entry in host_entry.get('ips', []):
                if 'banners' in ip_entry and 'ftp' in ip_entry['banners']:
                    exposed_services.append({
                        'type': 'FTP Service',
                        'domain': domain,
                        'ip': ip_entry.get('ip', ''),
                        'banner': ip_entry['banners']['ftp'].get('banner', ''),
                        'concern': "FTP service exposed - potential security risk if not properly secured",
                        'risk_level': 'High'
                    })
            
            # Always include in verbose mode
            if self.verbose and not any(service['domain'] == domain for service in exposed_services):
                ip_info = []
                for ip_entry in host_entry.get('ips', []):
                    ip_info.append(ip_entry.get('ip', ''))
                
                exposed_services.append({
                    'type': 'Host Record',
                    'domain': domain,
                    'ip': ', '.join(ip_info),
                    'concern': "Standard host record",
                    'risk_level': 'Info'
                })
        
        return exposed_services
    
    def analyze_service_versions(self) -> List[Dict[str, str]]:
        """Analyze for service versions that might be vulnerable with enhanced sensitivity"""
        if not self.results:
            return []
        
        service_versions = []
        version_pattern = re.compile(r'(\d+\.\d+(\.\d+)?)')
        
        # Check for version information in host information
        hosts = self.results.get('hosts', [])
        
        # Process 'a' records for service version information
        for host_entry in self.results.get('a', []):
            domain = host_entry.get('host', '')
            
            for ip_entry in host_entry.get('ips', []):
                if 'banners' in ip_entry:
                    banners = ip_entry['banners']
                    
                    # Check HTTP banner
                    if 'http' in banners:
                        http_info = banners['http']
                        
                        # Check server header
                        if 'server' in http_info:
                            server = http_info['server']
                            version_match = version_pattern.search(server)
                            
                            if version_match:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'Web Server',
                                    'version': server,
                                    'concern': 'Server version exposed in headers - potential for targeted exploits',
                                    'risk_level': 'High'
                                })
                            elif self.verbose:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'Web Server',
                                    'version': server,
                                    'concern': 'Server type exposed but no version number',
                                    'risk_level': 'Low'
                                })
                        
                        # Check for apps information
                        if 'apps' in http_info:
                            for app in http_info['apps']:
                                version_match = version_pattern.search(app)
                                
                                if version_match:
                                    service_versions.append({
                                        'host': domain,
                                        'service': 'Web Application',
                                        'version': app,
                                        'concern': 'Application version exposed - potential for targeted exploits',
                                        'risk_level': 'High'
                                    })
                                elif self.verbose:
                                    service_versions.append({
                                        'host': domain,
                                        'service': 'Web Application',
                                        'version': app,
                                        'concern': 'Application type exposed but no version number',
                                        'risk_level': 'Low'
                                    })
                    
                    # Check HTTPS banner
                    if 'https' in banners:
                        https_info = banners['https']
                        
                        # Check server header
                        if 'server' in https_info:
                            server = https_info['server']
                            version_match = version_pattern.search(server)
                            
                            if version_match:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'HTTPS Server',
                                    'version': server,
                                    'concern': 'HTTPS Server version exposed in headers - potential for targeted exploits',
                                    'risk_level': 'High'
                                })
                            elif self.verbose:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'HTTPS Server',
                                    'version': server,
                                    'concern': 'HTTPS Server type exposed but no version number',
                                    'risk_level': 'Low'
                                })
                        
                        # Check for apps information
                        if 'apps' in https_info:
                            for app in https_info['apps']:
                                version_match = version_pattern.search(app)
                                
                                if version_match:
                                    service_versions.append({
                                        'host': domain,
                                        'service': 'HTTPS Application',
                                        'version': app,
                                        'concern': 'HTTPS Application version exposed - potential for targeted exploits',
                                        'risk_level': 'High'
                                    })
                                elif self.verbose:
                                    service_versions.append({
                                        'host': domain,
                                        'service': 'HTTPS Application',
                                        'version': app,
                                        'concern': 'HTTPS Application type exposed but no version number',
                                        'risk_level': 'Low'
                                    })
                    
                    # Check FTP banner
                    if 'ftp' in banners:
                        ftp_info = banners['ftp']
                        
                        if 'banner' in ftp_info:
                            banner = ftp_info['banner']
                            version_match = version_pattern.search(banner)
                            
                            if version_match:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'FTP Server',
                                    'version': banner,
                                    'concern': 'FTP Server version exposed in banner - potential for targeted exploits',
                                    'risk_level': 'High'
                                })
                            elif self.verbose:
                                service_versions.append({
                                    'host': domain,
                                    'service': 'FTP Server',
                                    'version': banner,
                                    'concern': 'FTP Server banner exposed but no clear version number',
                                    'risk_level': 'Medium'
                                })
        
        # Check for any other service information in the raw data
        if self.verbose:
            # Recursively search for version strings in the entire results
            def search_versions(data, path=""):
                if isinstance(data, dict):
                    for key, value in data.items():
                        new_path = f"{path}.{key}" if path else key
                        
                        # Check if the key or value contains version information
                        if 'version' in key.lower() or 'ver' == key.lower():
                            if isinstance(value, str):
                                service_versions.append({
                                    'host': 'Unknown',
                                    'service': path,
                                    'version': value,
                                    'concern': f'Version information found at {new_path}',
                                    'risk_level': 'Medium'
                                })
                        
                        # Continue searching recursively
                        search_versions(value, new_path)
                elif isinstance(data, list):
                    for i, item in enumerate(data):
                        new_path = f"{path}[{i}]"
                        search_versions(item, new_path)
                elif isinstance(data, str):
                    # Check if the string contains version-like patterns
                    version_match = version_pattern.search(data)
                    if version_match and 'version' not in path.lower():
                        service_versions.append({
                            'host': 'Unknown',
                            'service': path,
                            'version': data,
                            'concern': f'Possible version string found at {path}',
                            'risk_level': 'Low'
                        })
            
            search_versions(self.results)
        
        return service_versions
    
    def analyze_subdomains(self) -> List[Dict[str, str]]:
        """Analyze subdomains for potential security risks with enhanced sensitivity"""
        if not self.results:
            return []
        
        subdomains = []
        
        # Enhanced list of risky keywords
        risky_keywords = [
            # Development/testing environments
            'test', 'testing', 'dev', 'development', 'stage', 'staging', 'uat', 'qa', 'demo',
            'beta', 'alpha', 'sandbox', 'preprod', 'pre-prod', 'preview',
            # Internal services
            'internal', 'intranet', 'corp', 'corporate', 'private', 'local', 'localhost',
            # Admin interfaces
            'admin', 'administrator', 'adm', 'manage', 'management', 'manager', 'console', 'portal',
            # Backup and old services
            'backup', 'bak', 'old', 'archive', 'dump', 'temp', 'temporary',
            # APIs and web services
            'api', 'rest', 'graphql', 'soap', 'ws', 'webservice', 'service',
            # Development tools
            'jenkins', 'jira', 'confluence', 'gitlab', 'github', 'bitbucket', 'bamboo', 'travis',
            'sonar', 'nexus', 'artifactory', 'docker', 'kubernetes', 'k8s', 'rancher', 'openshift',
            # Monitoring
            'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus', 'nagios', 'zabbix', 'splunk',
            'elasticsearch', 'logstash',
            # Authentication
            'auth', 'login', 'sso', 'saml', 'oauth', 'ldap', 'active-directory', 'ad',
            # Databases
            'db', 'sql', 'oracle', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb',
            'redis', 'memcache', 'cassandra', 'couchdb', 'mariadb',
            # File transfer
            'ftp', 'sftp', 'ftps', 'upload', 'download',
            # Email
            'mail', 'email', 'webmail', 'exchange', 'smtp', 'imap', 'pop3',
            # Remote access
            'vpn', 'ssh', 'rdp', 'remote', 'gateway', 'access',
            # Cloud
            'aws', 'azure', 'gcp', 'cloud', 's3', 'bucket', 'storage',
            # Misc
            'secret', 'password', 'secure', 'config', 'configuration', 'setup', 'install'
        ]
        
        # Collect all subdomains from various record types
        all_domains = set()
        
        # A records from dns_records
        for record in self.results.get('dns_records', {}).get('a', []):
            all_domains.add(record.get('domain', ''))
        
        # CNAME records from dns_records
        for record in self.results.get('dns_records', {}).get('cname', []):
            all_domains.add(record.get('domain', ''))
        
        # MX records from dns_records
        for record in self.results.get('dns_records', {}).get('mx', []):
            all_domains.add(record.get('domain', ''))
        
        # TXT records from dns_records
        for record in self.results.get('dns_records', {}).get('txt', []):
            all_domains.add(record.get('domain', ''))
        
        # A records from 'a' array
        for host_entry in self.results.get('a', []):
            all_domains.add(host_entry.get('host', ''))
        
        # MX records from 'mx' array
        for host_entry in self.results.get('mx', []):
            all_domains.add(host_entry.get('host', ''))
        
        # NS records from 'ns' array
        for host_entry in self.results.get('ns', []):
            all_domains.add(host_entry.get('host', ''))
        
        # Extract potential subdomains from TXT records
        for txt_record in self.results.get('txt', []):
            # Remove quotes
            txt_value = txt_record.strip('"\'')
            
            # Look for domain patterns in TXT records
            domain_pattern = re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}')
            matches = domain_pattern.findall(txt_value)
            
            for match in matches:
                all_domains.add(match)
        
        # Extract main domain to identify subdomains
        main_domain = None
        for domain in all_domains:
            if '.' in domain:
                parts = domain.split('.')
                if len(parts) >= 2:
                    potential_main = '.'.join(parts[-2:])
                    if main_domain is None or len(potential_main) < len(main_domain):
                        main_domain = potential_main
        
        # Analyze each domain
        for domain in all_domains:
            is_subdomain = main_domain and domain.endswith(main_domain) and domain != main_domain
            
            # Check for risky keywords
            for keyword in risky_keywords:
                if keyword in domain.lower():
                    risk_level = 'High' if is_subdomain else 'Medium'
                    subdomains.append({
                        'subdomain': domain,
                        'is_subdomain': is_subdomain,
                        'concern': f"Potentially sensitive {'subdomain' if is_subdomain else 'domain'} containing '{keyword}'",
                        'risk_level': risk_level
                    })
                    break
            
            # Always include in verbose mode
            if self.verbose and not any(sd['subdomain'] == domain for sd in subdomains):
                subdomains.append({
                    'subdomain': domain,
                    'is_subdomain': is_subdomain,
                    'concern': f"{'Subdomain' if is_subdomain else 'Domain'} without obvious security concerns",
                    'risk_level': 'Info'
                })
        
        return subdomains
    
    def analyze_open_ports(self) -> List[Dict[str, Any]]:
        """Analyze for open ports with enhanced sensitivity"""
        if not self.results:
            return []
        
        open_ports = []
        
        # Define high-risk ports
        high_risk_ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC/DCOM',
            137: 'NetBIOS Name',
            138: 'NetBIOS Datagram',
            139: 'NetBIOS Session',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            445: 'SMB',
            512: 'rexec',
            513: 'rlogin',
            514: 'rsyslog',
            1433: 'MS SQL',
            1521: 'Oracle',
            2049: 'NFS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'Alternative HTTP',
            8443: 'Alternative HTTPS',
            27017: 'MongoDB'
        }
        
        # Medium risk ports
        medium_risk_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            8000: 'Alternative HTTP',
            8008: 'Alternative HTTP',
            8081: 'Alternative HTTP',
            8888: 'Alternative HTTP',
            9000: 'Alternative HTTP'
        }
        
        # Check for port information in host information
        hosts = self.results.get('hosts', [])
        for host in hosts:
            domain = host.get('domain', '')
            ip = host.get('ip', '')
            
            if 'ports' in host and isinstance(host['ports'], list):
                for port_info in host['ports']:
                    port = port_info.get('port')
                    status = port_info.get('status', '').lower()
                    service = port_info.get('service', '')
                    
                    # Determine risk level based on port number and status
                    risk_level = 'Info'
                    concern = f"{status.capitalize()} port {port} ({service})"
                    
                    if status == 'open':
                        if port in high_risk_ports:
                            risk_level = 'High'
                            concern = f"Open high-risk port {port} ({service or high_risk_ports[port]}) - This is a sensitive service port that should be restricted"
                        elif port in medium_risk_ports:
                            risk_level = 'Medium'
                            concern = f"Open medium-risk port {port} ({service or medium_risk_ports[port]}) - Ensure this service is properly secured"
                        else:
                            risk_level = 'Low'
                            concern = f"Open port {port} ({service}) - Verify if this port needs to be exposed"
                    elif status == 'filtered' and self.verbose:
                        risk_level = 'Info'
                        concern = f"Filtered port {port} ({service}) - Port is protected by firewall"
                    
                    # Only include non-verbose entries if they have some risk or all entries in verbose mode
                    if risk_level != 'Info' or self.verbose:
                        open_ports.append({
                            'domain': domain,
                            'ip': ip,
                            'port': port,
                            'service': service,
                            'status': status,
                            'concern': concern,
                            'risk_level': risk_level
                        })
        
        # Check for port information in banners
        for host_entry in self.results.get('a', []):
            domain = host_entry.get('host', '')
            
            for ip_entry in host_entry.get('ips', []):
                ip = ip_entry.get('ip', '')
                
                if 'banners' in ip_entry:
                    # HTTP banner indicates port 80 is open
                    if 'http' in ip_entry['banners']:
                        risk_level = 'Medium' if 80 in medium_risk_ports else 'Low'
                        open_ports.append({
                            'domain': domain,
                            'ip': ip,
                            'port': 80,
                            'service': 'HTTP',
                            'status': 'open',
                            'concern': "Open HTTP port (80) - Ensure proper security headers and HTTPS redirection",
                            'risk_level': risk_level
                        })
                    
                    # HTTPS banner indicates port 443 is open
                    if 'https' in ip_entry['banners']:
                        risk_level = 'Medium' if 443 in medium_risk_ports else 'Low'
                        open_ports.append({
                            'domain': domain,
                            'ip': ip,
                            'port': 443,
                            'service': 'HTTPS',
                            'status': 'open',
                            'concern': "Open HTTPS port (443) - Verify TLS configuration and certificate validity",
                            'risk_level': risk_level
                        })
                    
                    # FTP banner indicates port 21 is open
                    if 'ftp' in ip_entry['banners']:
                        risk_level = 'High' if 21 in high_risk_ports else 'Medium'
                        open_ports.append({
                            'domain': domain,
                            'ip': ip,
                            'port': 21,
                            'service': 'FTP',
                            'status': 'open',
                            'concern': "Open FTP port (21) - High-risk service that should be restricted or secured",
                            'risk_level': risk_level
                        })
        
        return open_ports
    
    def analyze_http_headers(self) -> List[Dict[str, str]]:
        """Analyze HTTP headers for information leakage with enhanced sensitivity"""
        if not self.results:
            return []
        
        header_findings = []
        
        # Enhanced list of sensitive headers
        sensitive_headers = {
            'server': 'High',
            'x-powered-by': 'High',
            'x-aspnet-version': 'High',
            'x-asp-version': 'High',
            'x-generator': 'Medium',
            'x-drupal-cache': 'Medium',
            'x-varnish': 'Medium',
            'via': 'Low',
            'x-amz-cf-id': 'Low',
            'x-wordpress-site': 'Medium',
            'x-wix-request-id': 'Low',
            'x-shopify-stage': 'Medium',
            'x-magento-cache': 'Medium',
            'x-joomla-cache': 'Medium',
            'x-content-powered-by': 'Medium',
            'x-runtime': 'Low',
            'x-rack-cache': 'Low',
            'x-request-id': 'Low',
            'x-served-by': 'Low',
            'x-cache': 'Low',
            'x-cache-hits': 'Low',
            'x-timer': 'Low',
            'x-middleton-display': 'Low',
            'x-drupal-dynamic-cache': 'Medium',
            'x-pantheon-styx-hostname': 'Low',
            'x-accel-buffering': 'Low',
            'x-application': 'Medium',
            'x-application-context': 'Medium',
            'x-backend-server': 'Medium',
            'x-content-type-options': 'Low',
            'x-frame-options': 'Low',
            'x-xss-protection': 'Low',
            'strict-transport-security': 'Low',
            'content-security-policy': 'Low',
            'access-control-allow-origin': 'Low',
            'access-control-allow-methods': 'Low',
            'access-control-allow-headers': 'Low',
            'access-control-expose-headers': 'Low',
            'access-control-max-age': 'Low',
            'access-control-allow-credentials': 'Low',
            'timing-allow-origin': 'Low'
        }
        
        # Check for header information in host information
        hosts = self.results.get('hosts', [])
        for host in hosts:
            domain = host.get('domain', '')
            
            if 'info' in host and isinstance(host['info'], dict):
                info = host['info']
                
                # Check for sensitive headers
                for header, risk_level in sensitive_headers.items():
                    if header in info:
                        value = info[header]
                        
                        # Determine concern based on header and risk level
                        concern = f"Information leakage through {header} header"
                        
                        if header == 'server' and any(v in value.lower() for v in ['apache', 'nginx', 'iis', 'tomcat']):
                            concern = f"Web server software exposed: {value}"
                        elif header == 'x-powered-by':
                            concern = f"Backend technology exposed: {value}"
                        elif 'version' in header:
                            concern = f"Software version exposed: {value}"
                        
                        header_findings.append({
                            'domain': domain,
                            'header': header,
                            'value': value,
                            'concern': concern,
                            'risk_level': risk_level
                        })
        
        # Check for header information in banners
        for host_entry in self.results.get('a', []):
            domain = host_entry.get('host', '')
            
            for ip_entry in host_entry.get('ips', []):
                if 'banners' in ip_entry:
                    banners = ip_entry['banners']
                    
                    # Check HTTP banner
                    if 'http' in banners:
                        http_info = banners['http']
                        
                        # Check server header
                        if 'server' in http_info:
                            server = http_info['server']
                            risk_level = 'High' if any(v in server.lower() for v in ['apache', 'nginx', 'iis', 'tomcat']) else 'Medium'
                            
                            header_findings.append({
                                'domain': domain,
                                'header': 'server',
                                'value': server,
                                'concern': f"Web server software exposed in HTTP header: {server}",
                                'risk_level': risk_level
                            })
                        
                        # Check for title that might indicate technology
                        if 'title' in http_info and http_info['title']:
                            title = http_info['title']
                            
                            # Look for error messages or technology indicators in title
                            if any(err in title.lower() for err in ['error', 'not found', 'forbidden', 'unauthorized']):
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'title',
                                    'value': title,
                                    'concern': f"Error page title may reveal information: {title}",
                                    'risk_level': 'Medium'
                                })
                            elif self.verbose:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'title',
                                    'value': title,
                                    'concern': f"Page title: {title}",
                                    'risk_level': 'Info'
                                })
                        
                        # Check for redirect location
                        if 'redirect_location' in http_info:
                            redirect = http_info['redirect_location']
                            
                            header_findings.append({
                                'domain': domain,
                                'header': 'redirect_location',
                                'value': redirect,
                                'concern': f"HTTP redirect location: {redirect}",
                                'risk_level': 'Low'
                            })
                    
                    # Check HTTPS banner
                    if 'https' in banners:
                        https_info = banners['https']
                        
                        # Check server header
                        if 'server' in https_info:
                            server = https_info['server']
                            risk_level = 'High' if any(v in server.lower() for v in ['apache', 'nginx', 'iis', 'tomcat']) else 'Medium'
                            
                            header_findings.append({
                                'domain': domain,
                                'header': 'server',
                                'value': server,
                                'concern': f"Web server software exposed in HTTPS header: {server}",
                                'risk_level': risk_level
                            })
                        
                        # Check for title that might indicate technology
                        if 'title' in https_info and https_info['title']:
                            title = https_info['title']
                            
                            # Look for error messages or technology indicators in title
                            if any(err in title.lower() for err in ['error', 'not found', 'forbidden', 'unauthorized']):
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'title',
                                    'value': title,
                                    'concern': f"Error page title may reveal information: {title}",
                                    'risk_level': 'Medium'
                                })
                            elif self.verbose:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'title',
                                    'value': title,
                                    'concern': f"Page title: {title}",
                                    'risk_level': 'Info'
                                })
                        
                        # Check for redirect location
                        if 'redirect_location' in https_info:
                            redirect = https_info['redirect_location']
                            
                            header_findings.append({
                                'domain': domain,
                                'header': 'redirect_location',
                                'value': redirect,
                                'concern': f"HTTPS redirect location: {redirect}",
                                'risk_level': 'Low'
                            })
                        
                        # Check for certificate information
                        if 'cn' in https_info:
                            cn = https_info['cn']
                            
                            if domain != cn:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'certificate_cn',
                                    'value': cn,
                                    'concern': f"Certificate common name ({cn}) doesn't match domain ({domain})",
                                    'risk_level': 'Medium'
                                })
                            elif self.verbose:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'certificate_cn',
                                    'value': cn,
                                    'concern': f"Certificate common name: {cn}",
                                    'risk_level': 'Info'
                                })
                        
                        # Check for alternative names
                        if 'alt_n' in https_info and https_info['alt_n']:
                            alt_names = https_info['alt_n']
                            
                            # Look for interesting subdomains in alt names
                            risky_keywords = ['internal', 'admin', 'test', 'dev', 'stage', 'uat', 'qa']
                            risky_alt_names = []
                            
                            for alt_name in alt_names:
                                for keyword in risky_keywords:
                                    if keyword in alt_name.lower():
                                        risky_alt_names.append(alt_name)
                                        break
                            
                            if risky_alt_names:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'certificate_alt_names',
                                    'value': ', '.join(risky_alt_names),
                                    'concern': f"Certificate contains potentially sensitive alternative names",
                                    'risk_level': 'Medium'
                                })
                            elif self.verbose:
                                header_findings.append({
                                    'domain': domain,
                                    'header': 'certificate_alt_names',
                                    'value': ', '.join(alt_names[:5]) + (f" and {len(alt_names) - 5} more" if len(alt_names) > 5 else ""),
                                    'concern': f"Certificate contains {len(alt_names)} alternative names",
                                    'risk_level': 'Info'
                                })
        
        return header_findings
    
    def analyze_spf_records(self) -> List[Dict[str, str]]:
        """Analyze SPF records for potential security issues"""
        if not self.results:
            return []
        
        spf_findings = []
        
        # Check TXT records for SPF
        for txt_record in self.results.get('txt', []):
            # Remove quotes
            txt_value = txt_record.strip('"\'')
            
            # Check if it's an SPF record
            if txt_value.startswith('v=spf1'):
                # Check for potentially risky SPF configurations
                
                # Check for overly permissive settings
                if ' +all' in txt_value:
                    spf_findings.append({
                        'record_type': 'SPF',
                        'value': txt_value,
                        'concern': "Overly permissive SPF record with '+all' - allows any server to send mail as this domain",
                        'risk_level': 'High'
                    })
                elif ' ?all' in txt_value:
                    spf_findings.append({
                        'record_type': 'SPF',
                        'value': txt_value,
                        'concern': "Permissive SPF record with '?all' - neutral policy doesn't protect against spoofing",
                        'risk_level': 'Medium'
                    })
                elif ' ~all' in txt_value:
                    spf_findings.append({
                        'record_type': 'SPF',
                        'value': txt_value,
                        'concern': "Soft-fail SPF record with '~all' - better than neutral but doesn't fully protect against spoofing",
                        'risk_level': 'Low'
                    })
                elif ' -all' in txt_value:
                    if self.verbose:
                        spf_findings.append({
                            'record_type': 'SPF',
                            'value': txt_value,
                            'concern': "Properly configured SPF record with '-all' - rejects unauthorized senders",
                            'risk_level': 'Info'
                        })
                else:
                    spf_findings.append({
                        'record_type': 'SPF',
                        'value': txt_value,
                        'concern': "SPF record without an 'all' mechanism - may not properly restrict unauthorized senders",
                        'risk_level': 'Medium'
                    })
                
                # Check for include mechanisms that might be risky
                includes = re.findall(r'include:([^\s]+)', txt_value)
                for include in includes:
                    if include in ['spf.protection.outlook.com', 'sendgrid.net', 'mailchimp.com', '_spf.google.com']:
                        if self.verbose:
                            spf_findings.append({
                                'record_type': 'SPF Include',
                                'value': include,
                                'concern': f"SPF includes common mail provider: {include}",
                                'risk_level': 'Info'
                            })
                    else:
                        spf_findings.append({
                            'record_type': 'SPF Include',
                            'value': include,
                            'concern': f"SPF includes external domain: {include} - verify this is an authorized mail sender",
                            'risk_level': 'Low'
                        })
                
                # Check for IP4/IP6 mechanisms that might be risky
                ips = re.findall(r'ip[46]:([^\s]+)', txt_value)
                for ip in ips:
                    if '/' in ip and not ip.endswith('/32'):
                        # IP range that's not a single IP
                        spf_findings.append({
                            'record_type': 'SPF IP Range',
                            'value': ip,
                            'concern': f"SPF includes IP range: {ip} - verify all IPs in this range are authorized mail senders",
                            'risk_level': 'Medium'
                        })
                    elif self.verbose:
                        spf_findings.append({
                            'record_type': 'SPF IP',
                            'value': ip,
                            'concern': f"SPF includes IP: {ip}",
                            'risk_level': 'Info'
                        })
        
        return spf_findings
    
    def analyze_dmarc_records(self) -> List[Dict[str, str]]:
        """Analyze DMARC records for potential security issues"""
        if not self.results:
            return []
        
        dmarc_findings = []
        
        # Check TXT records for DMARC
        for txt_record in self.results.get('txt', []):
            # Remove quotes
            txt_value = txt_record.strip('"\'')
            
            # Check if it's a DMARC record
            if txt_value.startswith('v=DMARC1'):
                # Parse DMARC policy
                policy_match = re.search(r'p=([^\s;]+)', txt_value)
                policy = policy_match.group(1) if policy_match else None
                
                # Check policy strength
                if policy == 'none':
                    dmarc_findings.append({
                        'record_type': 'DMARC',
                        'value': txt_value,
                        'concern': "Weak DMARC policy 'none' - monitoring only, doesn't protect against spoofing",
                        'risk_level': 'Medium'
                    })
                elif policy == 'quarantine':
                    dmarc_findings.append({
                        'record_type': 'DMARC',
                        'value': txt_value,
                        'concern': "Moderate DMARC policy 'quarantine' - suspicious emails sent to spam folder",
                        'risk_level': 'Low'
                    })
                elif policy == 'reject':
                    if self.verbose:
                        dmarc_findings.append({
                            'record_type': 'DMARC',
                            'value': txt_value,
                            'concern': "Strong DMARC policy 'reject' - unauthorized emails are rejected",
                            'risk_level': 'Info'
                        })
                else:
                    dmarc_findings.append({
                        'record_type': 'DMARC',
                        'value': txt_value,
                        'concern': "DMARC record without clear policy - may not properly protect against spoofing",
                        'risk_level': 'Medium'
                    })
                
                # Check reporting configuration
                rua_match = re.search(r'rua=mailto:([^\s;]+)', txt_value)
                ruf_match = re.search(r'ruf=mailto:([^\s;]+)', txt_value)
                
                if not rua_match and not ruf_match:
                    dmarc_findings.append({
                        'record_type': 'DMARC Reporting',
                        'value': txt_value,
                        'concern': "DMARC record without reporting addresses - won't receive feedback on email authentication",
                        'risk_level': 'Low'
                    })
                elif self.verbose:
                    reporting = []
                    if rua_match:
                        reporting.append(f"Aggregate reports: {rua_match.group(1)}")
                    if ruf_match:
                        reporting.append(f"Forensic reports: {ruf_match.group(1)}")
                    
                    dmarc_findings.append({
                        'record_type': 'DMARC Reporting',
                        'value': ', '.join(reporting),
                        'concern': "DMARC reporting configured correctly",
                        'risk_level': 'Info'
                    })
        
        # Check if DMARC record is missing entirely
        if not any(finding['record_type'] == 'DMARC' for finding in dmarc_findings):
            dmarc_findings.append({
                'record_type': 'DMARC',
                'value': 'Missing',
                'concern': "No DMARC record found - domain is vulnerable to email spoofing",
                'risk_level': 'High'
            })
        
        return dmarc_findings
    
    def analyze_dns_sec(self) -> List[Dict[str, str]]:
        """Analyze DNSSEC configuration"""
        if not self.results:
            return []
        
        dnssec_findings = []
        
        # Check for DNSSEC records in TXT records
        has_dnssec = False
        for txt_record in self.results.get('txt', []):
            # Remove quotes
            txt_value = txt_record.strip('"\'')
            
            # Look for DNSSEC-related TXT records
            if 'DNSSEC' in txt_value:
                has_dnssec = True
                dnssec_findings.append({
                    'record_type': 'DNSSEC',
                    'value': txt_value,
                    'concern': "DNSSEC appears to be configured",
                    'risk_level': 'Info'
                })
        
        # If no explicit DNSSEC records found, check for DS or DNSKEY records
        if not has_dnssec:
            # Unfortunately, dnsdumpster API might not provide DS or DNSKEY records directly
            # We can only make a note that we couldn't confirm DNSSEC
            dnssec_findings.append({
                'record_type': 'DNSSEC',
                'value': 'Unknown',
                'concern': "DNSSEC status could not be confirmed - consider implementing DNSSEC for additional security",
                'risk_level': 'Low'
            })
        
        return dnssec_findings
    
    def generate_security_report(self) -> Dict[str, List]:
        """Generate a comprehensive security report with enhanced analysis"""
        if not self.results:
            return {}
        
        report = {
            'exposed_services': self.analyze_exposed_services(),
            'service_versions': self.analyze_service_versions(),
            'subdomains': self.analyze_subdomains(),
            'open_ports': self.analyze_open_ports(),
            'http_headers': self.analyze_http_headers(),
            'spf_records': self.analyze_spf_records(),
            'dmarc_records': self.analyze_dmarc_records(),
            'dnssec': self.analyze_dns_sec()
        }
        
        return report

def main():
    """Main function to run the DNS analyzer"""
    parser = argparse.ArgumentParser(description='Analyze DNS information using dnsdumpster API')
    parser.add_argument('domain', help='Domain to analyze')
    parser.add_argument('--api-key', required=True, help='dnsdumpster API key')
    parser.add_argument('--output', help='Output file for raw JSON results')
    parser.add_argument('--report', help='Output file for security report')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose mode to show all findings, not just security concerns')
    
    args = parser.parse_args()
    
    analyzer = DNSDumpsterAnalyzer(args.api_key, args.verbose)
    results = analyzer.query_domain(args.domain)
    
    if args.output:
        analyzer.save_results(args.output)
    
    # Generate and display security report
    report = analyzer.generate_security_report()
    
    print("\n=== DNS Security Analysis Report ===\n")
    
    print("\n--- Exposed Services ---")
    if report['exposed_services']:
        for service in report['exposed_services']:
            if args.verbose or service.get('risk_level', 'Info') != 'Info':
                print(f"• {service['type']}: {service['domain']}")
                print(f"  Risk Level: {service.get('risk_level', 'Unknown')}")
                print(f"  Concern: {service['concern']}")
                if 'ip' in service:
                    print(f"  IP: {service['ip']}")
                if 'target' in service:
                    print(f"  Target: {service['target']}")
                if 'banner' in service:
                    print(f"  Banner: {service['banner']}")
                print()
    else:
        print("No potentially exposed services identified.")
    
    print("\n--- Service Versions ---")
    if report['service_versions']:
        for service in report['service_versions']:
            if args.verbose or service.get('risk_level', 'Info') != 'Info':
                print(f"• Host: {service['host']}")
                print(f"  Service: {service['service']}")
                print(f"  Version: {service['version']}")
                print(f"  Risk Level: {service.get('risk_level', 'Unknown')}")
                print(f"  Concern: {service['concern']}")
                print()
    else:
        print("No service version information identified.")
    
    print("\n--- Subdomains ---")
    if report['subdomains']:
        for subdomain in report['subdomains']:
            if args.verbose or subdomain.get('risk_level', 'Info') != 'Info':
                print(f"• {'Subdomain' if subdomain.get('is_subdomain', False) else 'Domain'}: {subdomain['subdomain']}")
                print(f"  Risk Level: {subdomain.get('risk_level', 'Unknown')}")
                print(f"  Concern: {subdomain['concern']}")
                print()
    else:
        print("No potentially risky subdomains identified.")
    
    print("\n--- Open Ports ---")
    if report['open_ports']:
        for port in report['open_ports']:
            if args.verbose or port.get('risk_level', 'Info') != 'Info':
                print(f"• Domain: {port['domain']} ({port['ip']})")
                print(f"  Port: {port['port']} ({port['service']})")
                print(f"  Status: {port['status']}")
                print(f"  Risk Level: {port.get('risk_level', 'Unknown')}")
                print(f"  Concern: {port['concern']}")
                print()
    else:
        print("No open ports identified.")
    
    print("\n--- HTTP Headers ---")
    if report['http_headers']:
        for header in report['http_headers']:
            if args.verbose or header.get('risk_level', 'Info') != 'Info':
                print(f"• Domain: {header['domain']}")
                print(f"  Header: {header['header']}")
                print(f"  Value: {header['value']}")
                print(f"  Risk Level: {header.get('risk_level', 'Unknown')}")
                print(f"  Concern: {header['concern']}")
                print()
    else:
        print("No concerning HTTP headers identified.")
    
    print("\n--- Email Security (SPF) ---")
    if report['spf_records']:
        for finding in report['spf_records']:
            if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                print(f"• Record Type: {finding['record_type']}")
                print(f"  Value: {finding['value']}")
                print(f"  Risk Level: {finding.get('risk_level', 'Unknown')}")
                print(f"  Concern: {finding['concern']}")
                print()
    else:
        print("No SPF records found - domain may be vulnerable to email spoofing.")
    
    print("\n--- Email Security (DMARC) ---")
    if report['dmarc_records']:
        for finding in report['dmarc_records']:
            if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                print(f"• Record Type: {finding['record_type']}")
                print(f"  Value: {finding['value']}")
                print(f"  Risk Level: {finding.get('risk_level', 'Unknown')}")
                print(f"  Concern: {finding['concern']}")
                print()
    else:
        print("No DMARC records found - domain may be vulnerable to email spoofing.")
    
    print("\n--- DNSSEC ---")
    if report['dnssec']:
        for finding in report['dnssec']:
            if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                print(f"• Record Type: {finding['record_type']}")
                print(f"  Value: {finding['value']}")
                print(f"  Risk Level: {finding.get('risk_level', 'Unknown')}")
                print(f"  Concern: {finding['concern']}")
                print()
    else:
        print("No DNSSEC information found.")
    
    # Save report to file if requested
    if args.report:
        with open(args.report, 'w') as f:
            f.write("=== DNS Security Analysis Report ===\n\n")
            
            f.write("\n--- Exposed Services ---\n")
            if report['exposed_services']:
                for service in report['exposed_services']:
                    if args.verbose or service.get('risk_level', 'Info') != 'Info':
                        f.write(f"• {service['type']}: {service['domain']}\n")
                        f.write(f"  Risk Level: {service.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {service['concern']}\n")
                        if 'ip' in service:
                            f.write(f"  IP: {service['ip']}\n")
                        if 'target' in service:
                            f.write(f"  Target: {service['target']}\n")
                        if 'banner' in service:
                            f.write(f"  Banner: {service['banner']}\n")
                        f.write("\n")
            else:
                f.write("No potentially exposed services identified.\n")
            
            f.write("\n--- Service Versions ---\n")
            if report['service_versions']:
                for service in report['service_versions']:
                    if args.verbose or service.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Host: {service['host']}\n")
                        f.write(f"  Service: {service['service']}\n")
                        f.write(f"  Version: {service['version']}\n")
                        f.write(f"  Risk Level: {service.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {service['concern']}\n")
                        f.write("\n")
            else:
                f.write("No service version information identified.\n")
            
            f.write("\n--- Subdomains ---\n")
            if report['subdomains']:
                for subdomain in report['subdomains']:
                    if args.verbose or subdomain.get('risk_level', 'Info') != 'Info':
                        f.write(f"• {'Subdomain' if subdomain.get('is_subdomain', False) else 'Domain'}: {subdomain['subdomain']}\n")
                        f.write(f"  Risk Level: {subdomain.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {subdomain['concern']}\n")
                        f.write("\n")
            else:
                f.write("No potentially risky subdomains identified.\n")
            
            f.write("\n--- Open Ports ---\n")
            if report['open_ports']:
                for port in report['open_ports']:
                    if args.verbose or port.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Domain: {port['domain']} ({port['ip']})\n")
                        f.write(f"  Port: {port['port']} ({port['service']})\n")
                        f.write(f"  Status: {port['status']}\n")
                        f.write(f"  Risk Level: {port.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {port['concern']}\n")
                        f.write("\n")
            else:
                f.write("No open ports identified.\n")
            
            f.write("\n--- HTTP Headers ---\n")
            if report['http_headers']:
                for header in report['http_headers']:
                    if args.verbose or header.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Domain: {header['domain']}\n")
                        f.write(f"  Header: {header['header']}\n")
                        f.write(f"  Value: {header['value']}\n")
                        f.write(f"  Risk Level: {header.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {header['concern']}\n")
                        f.write("\n")
            else:
                f.write("No concerning HTTP headers identified.\n")
            
            f.write("\n--- Email Security (SPF) ---\n")
            if report['spf_records']:
                for finding in report['spf_records']:
                    if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Record Type: {finding['record_type']}\n")
                        f.write(f"  Value: {finding['value']}\n")
                        f.write(f"  Risk Level: {finding.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {finding['concern']}\n")
                        f.write("\n")
            else:
                f.write("No SPF records found - domain may be vulnerable to email spoofing.\n")
            
            f.write("\n--- Email Security (DMARC) ---\n")
            if report['dmarc_records']:
                for finding in report['dmarc_records']:
                    if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Record Type: {finding['record_type']}\n")
                        f.write(f"  Value: {finding['value']}\n")
                        f.write(f"  Risk Level: {finding.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {finding['concern']}\n")
                        f.write("\n")
            else:
                f.write("No DMARC records found - domain may be vulnerable to email spoofing.\n")
            
            f.write("\n--- DNSSEC ---\n")
            if report['dnssec']:
                for finding in report['dnssec']:
                    if args.verbose or finding.get('risk_level', 'Info') != 'Info':
                        f.write(f"• Record Type: {finding['record_type']}\n")
                        f.write(f"  Value: {finding['value']}\n")
                        f.write(f"  Risk Level: {finding.get('risk_level', 'Unknown')}\n")
                        f.write(f"  Concern: {finding['concern']}\n")
                        f.write("\n")
            else:
                f.write("No DNSSEC information found.\n")
            
            print(f"Security report saved to {args.report}")

if __name__ == "__main__":
    main()
