#!/usr/bin/env python3
"""
External Ingress NGINX Vulnerability Checker (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974)

This script checks if a Kubernetes cluster is potentially vulnerable to the Ingress NGINX Controller
vulnerabilities by performing non-invasive network checks against the public IP address.

This is a DETECTION-ONLY script. It does not attempt to exploit the vulnerabilities.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import requests
import urllib3
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Common ports to check
COMMON_PORTS = [80, 443, 8443, 8080, 6443]
ADMISSION_WEBHOOK_PORTS = [8443, 8444, 8445, 9443]

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0"

# Connection timeout
TIMEOUT = 3  # seconds

# Fixed versions that remediate the vulnerabilities
FIXED_VERSIONS = {
    "1.12": "1.12.1",
    "1.11": "1.11.5"
}

def check_port_open(ip: str, port: int) -> bool:
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_http_headers(url: str) -> Optional[Dict[str, str]]:
    """Get HTTP headers from a URL"""
    try:
        response = requests.head(
            url, 
            timeout=TIMEOUT, 
            verify=False, 
            headers={"User-Agent": USER_AGENT}
        )
        return dict(response.headers)
    except:
        return None

def get_http_response(url: str) -> Optional[Tuple[int, Dict[str, str], str]]:
    """Get HTTP response code, headers and body from a URL"""
    try:
        response = requests.get(
            url, 
            timeout=TIMEOUT, 
            verify=False, 
            headers={"User-Agent": USER_AGENT}
        )
        return (response.status_code, dict(response.headers), response.text)
    except:
        return None

def get_cert_info(hostname: str, port: int) -> Optional[Dict[str, Any]]:
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                return cert
    except:
        return None

def check_admission_webhook_endpoint(ip: str, port: int) -> bool:
    """
    Check if the endpoint looks like an admission webhook
    """
    # Try the default admission webhook path with proper payload
    try:
        # Standard AdmissionReview request format with v1 apiVersion
        admission_review_payload = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test",
                "operation": "CREATE"
            }
        }
        
        # Default validation webhook path
        url = f"https://{ip}:{port}/validate"
        response = requests.post(
            url, 
            timeout=TIMEOUT, 
            verify=False, 
            headers={
                "User-Agent": USER_AGENT, 
                "Content-Type": "application/json"
            },
            json=admission_review_payload
        )
        
        # Check for specific error messages or status codes that might indicate a webhook
        if response.status_code in [400, 415, 422, 500]:
            if "webhook" in response.text.lower() or "admission" in response.text.lower():
                return True
            
            # Look for JSON error responses related to admission
            try:
                json_response = response.json()
                if "kind" in json_response and json_response["kind"] == "Status":
                    if "message" in json_response and ("webhook" in json_response["message"].lower() or 
                                                    "admission" in json_response["message"].lower()):
                        return True
            except:
                pass
            
            # Check for specific ingress-nginx admission controller patterns
            if "ingress-nginx" in response.text.lower() or "validating" in response.text.lower():
                return True
    except:
        pass
    
    # Try alternative paths that might be used
    alternative_paths = ["/admission", "/admissionreview", "/validate-ingress"]
    for path in alternative_paths:
        try:
            url = f"https://{ip}:{port}{path}"
            response = requests.post(
                url, 
                timeout=TIMEOUT, 
                verify=False, 
                headers={
                    "User-Agent": USER_AGENT, 
                    "Content-Type": "application/json"
                },
                json=admission_review_payload
            )
            
            if response.status_code in [400, 415, 422, 500]:
                if "webhook" in response.text.lower() or "admission" in response.text.lower() or "ingress" in response.text.lower():
                    return True
        except:
            pass
    
    return False

def parse_nginx_version(server_header: str) -> Optional[str]:
    """
    Parse the version from nginx server header
    Examples:
    - "nginx/1.19.0"
    - "nginx/1.20.1"
    - "openresty/1.19.3.1"
    - "ingress-nginx/1.11.3"
    - "ingress-nginx/1.12.0"
    """
    # Specific pattern for ingress-nginx
    ingress_nginx_match = re.search(r'ingress-nginx/(\d+\.\d+\.\d+)', server_header)
    if ingress_nginx_match:
        return ingress_nginx_match.group(1)
    
    # Generic nginx pattern
    nginx_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header)
    if nginx_match:
        return nginx_match.group(1)
    
    return None

def is_version_vulnerable(version: str) -> Tuple[bool, str]:
    """
    Check if the detected version is vulnerable
    Returns a tuple of (is_vulnerable, reason)
    """
    if not version:
        return True, "Unknown version is considered potentially vulnerable"
    
    try:
        # Split version into parts
        parts = version.split('.')
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        
        # Check against known fixed versions
        if minor == 12:
            if patch < 1:
                return True, f"Version {version} is < 1.12.1 (vulnerable)"
            else:
                return False, f"Version {version} is >= 1.12.1 (patched)"
        elif minor == 11:
            if patch < 5:
                return True, f"Version {version} is < 1.11.5 (vulnerable)"
            else:
                return False, f"Version {version} is >= 1.11.5 (patched)"
        elif minor > 12:
            return False, f"Version {version} is > 1.12.1 (likely patched)"
        else:
            return True, f"Version {version} is older than fixed versions (1.11.5, 1.12.1)"
    except:
        return True, f"Cannot parse version {version}, assuming vulnerable"

def detect_ingress_nginx(ip: str) -> Dict[str, Any]:
    """
    Detect if the IP has Ingress NGINX exposed and gather information
    """
    results = {
        "open_ports": [],
        "http_servers": [],
        "potential_ingress": [],
        "potential_admission_endpoints": [],
        "version_info": []
    }
    
    # Check common ports
    print(f"{Colors.BLUE}Checking for open ports...{Colors.ENDC}")
    for port in COMMON_PORTS:
        if check_port_open(ip, port):
            results["open_ports"].append(port)
            print(f"  - Port {port} is open")
    
    if not results["open_ports"]:
        print(f"{Colors.YELLOW}No common ports are open{Colors.ENDC}")
        return results
    
    # Check for HTTP servers on open ports
    print(f"{Colors.BLUE}Checking for HTTP servers...{Colors.ENDC}")
    for port in results["open_ports"]:
        # Try HTTP
        http_url = f"http://{ip}:{port}"
        headers = get_http_headers(http_url)
        if headers:
            server = headers.get("Server", "")
            results["http_servers"].append({
                "port": port,
                "protocol": "http",
                "server": server,
                "headers": headers
            })
            print(f"  - HTTP server on port {port}: {server}")
            
            # Check if it's potentially Ingress NGINX
            if "nginx" in server.lower():
                version = parse_nginx_version(server)
                is_vulnerable, reason = is_version_vulnerable(version)
                
                ingress_info = {
                    "port": port,
                    "protocol": "http",
                    "server": server,
                    "version": version,
                    "is_vulnerable": is_vulnerable,
                    "reason": reason
                }
                
                results["potential_ingress"].append(ingress_info)
                results["version_info"].append(ingress_info)
                
                vulnerability_indicator = f"{Colors.RED}vulnerable{Colors.ENDC}" if is_vulnerable else f"{Colors.GREEN}patched{Colors.ENDC}"
                print(f"  - {Colors.YELLOW}Potential Ingress NGINX detected on port {port}{Colors.ENDC}")
                if version:
                    print(f"    Version: {version} ({vulnerability_indicator}) - {reason}")
        
        # Try HTTPS
        https_url = f"https://{ip}:{port}"
        headers = get_http_headers(https_url)
        if headers:
            server = headers.get("Server", "")
            results["http_servers"].append({
                "port": port,
                "protocol": "https",
                "server": server,
                "headers": headers
            })
            print(f"  - HTTPS server on port {port}: {server}")
            
            # Check if it's potentially Ingress NGINX
            if "nginx" in server.lower():
                version = parse_nginx_version(server)
                is_vulnerable, reason = is_version_vulnerable(version)
                
                ingress_info = {
                    "port": port,
                    "protocol": "https",
                    "server": server,
                    "version": version,
                    "is_vulnerable": is_vulnerable,
                    "reason": reason
                }
                
                results["potential_ingress"].append(ingress_info)
                results["version_info"].append(ingress_info)
                
                vulnerability_indicator = f"{Colors.RED}vulnerable{Colors.ENDC}" if is_vulnerable else f"{Colors.GREEN}patched{Colors.ENDC}"
                print(f"  - {Colors.YELLOW}Potential Ingress NGINX detected on port {port}{Colors.ENDC}")
                if version:
                    print(f"    Version: {version} ({vulnerability_indicator}) - {reason}")
            
            # Get SSL certificate info
            cert_info = get_cert_info(ip, port)
            if cert_info:
                # Check for common K8s cert names
                subject = cert_info.get("subject", [])
                for attr in subject:
                    for name, value in attr:
                        if name == "commonName" and ("kube" in value.lower() or "k8s" in value.lower()):
                            print(f"  - {Colors.YELLOW}SSL certificate with K8s common name: {value}{Colors.ENDC}")
    
    # Check specific admission webhook ports
    print(f"{Colors.BLUE}Checking for potential admission webhook endpoints...{Colors.ENDC}")
    for port in ADMISSION_WEBHOOK_PORTS:
        if port not in results["open_ports"] and check_port_open(ip, port):
            results["open_ports"].append(port)
            print(f"  - Port {port} is open")
        
        if port in results["open_ports"]:
            # Check if it responds like an admission webhook
            if check_admission_webhook_endpoint(ip, port):
                results["potential_admission_endpoints"].append(port)
                print(f"  - {Colors.RED}Potential admission webhook endpoint detected on port {port}{Colors.ENDC}")
    
    return results

def scan_ip(ip: str) -> None:
    """
    Main function to scan an IP for potential Ingress NGINX vulnerabilities
    """
    print(f"{Colors.HEADER}{Colors.BOLD}External Ingress NGINX Vulnerability Checker{Colors.ENDC}")
    print(f"{Colors.BLUE}Target: {ip}{Colors.ENDC}")
    print(f"{Colors.BLUE}Looking for potential CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974 vulnerability indicators...{Colors.ENDC}\n")
    
    # Validate IP address format
    try:
        socket.inet_aton(ip)
    except socket.error:
        # Check if it's a hostname
        try:
            ip = socket.gethostbyname(ip)
            print(f"{Colors.BLUE}Resolved hostname to IP: {ip}{Colors.ENDC}\n")
        except socket.gaierror:
            print(f"{Colors.RED}Error: Invalid IP address or hostname{Colors.ENDC}")
            sys.exit(1)
    
    # Detect Ingress NGINX
    results = detect_ingress_nginx(ip)
    
    # Print summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}Vulnerability Assessment Summary:{Colors.ENDC}")
    
    if results["potential_ingress"]:
        print(f"{Colors.YELLOW}Potential Ingress NGINX detected on {len(results['potential_ingress'])} port(s){Colors.ENDC}")
        for ingress in results["potential_ingress"]:
            version_info = f" (version: {ingress['version']})" if ingress.get('version') else ""
            print(f"  - {ingress['protocol'].upper()} on port {ingress['port']}: {ingress['server']}{version_info}")
            if ingress.get('version'):
                if ingress.get('is_vulnerable', True):
                    print(f"    {Colors.RED}⚠️ {ingress['reason']}{Colors.ENDC}")
                else:
                    print(f"    {Colors.GREEN}✅ {ingress['reason']}{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}No obvious Ingress NGINX signatures detected{Colors.ENDC}")
    
    if results["potential_admission_endpoints"]:
        print(f"\n{Colors.RED}{Colors.BOLD}POTENTIALLY VULNERABLE:{Colors.ENDC} {len(results['potential_admission_endpoints'])} potential admission webhook endpoint(s) detected")
        print(f"Potential admission webhook endpoints:")
        for port in results["potential_admission_endpoints"]:
            print(f"  - Port {port}")
        
        vulnerable_versions = [i for i in results.get("version_info", []) if i.get("is_vulnerable", True)]
        if vulnerable_versions:
            print(f"\n{Colors.RED}Found {len(vulnerable_versions)} potentially vulnerable Ingress NGINX version(s){Colors.ENDC}")
            print(f"{Colors.YELLOW}Vulnerabilities affect versions < 1.12.1 and < 1.11.5{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}Recommendation: The target may be vulnerable to the Ingress NGINX Controller vulnerabilities.{Colors.ENDC}")
        print(f"{Colors.YELLOW}Recommended actions:{Colors.ENDC}")
        print(f"  1. Update to Ingress NGINX >= 1.12.1 or >= 1.11.5")
        print(f"  2. Enforce strict network policies so only the Kubernetes API Server can access the admission controller")
        print(f"  3. Consider temporarily disabling the admission controller if immediate update is not possible")
        print(f"{Colors.YELLOW}For more details: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities{Colors.ENDC}")
    else:
        print(f"\n{Colors.GREEN}{Colors.BOLD}LOW RISK:{Colors.ENDC} No obvious admission webhook endpoints detected")
        
        vulnerable_versions = [i for i in results.get("version_info", []) if i.get("is_vulnerable", True)]
        if vulnerable_versions:
            print(f"\n{Colors.YELLOW}NOTE: Found {len(vulnerable_versions)} potentially vulnerable Ingress NGINX version(s),{Colors.ENDC}")
            print(f"{Colors.YELLOW}but no exposed admission webhook endpoints were detected.{Colors.ENDC}")
            print(f"{Colors.YELLOW}Consider updating to Ingress NGINX >= 1.12.1 or >= 1.11.5{Colors.ENDC}")
    
    print(f"\nNote: This external scan has limitations and may produce false negatives. Some factors to consider:")
    print(f"  - Admission webhook endpoints might be behind a firewall or other security measures")
    print(f"  - Server version detection can be misleading if headers are modified")
    print(f"  - Internal testing with kubectl access using ingress_nginx_vuln_checker.py is recommended when possible.")

def scan_multiple_ips(ips: List[str]) -> None:
    """
    Scan multiple IPs and provide a summary
    """
    results = {}
    
    for ip in ips:
        print(f"\n{Colors.HEADER}{Colors.BOLD}Scanning: {ip}{Colors.ENDC}")
        try:
            # Validate and resolve IP address
            try:
                socket.inet_aton(ip)
            except socket.error:
                try:
                    resolved_ip = socket.gethostbyname(ip)
                    print(f"{Colors.BLUE}Resolved hostname to IP: {resolved_ip}{Colors.ENDC}")
                    ip = resolved_ip
                except socket.gaierror:
                    print(f"{Colors.RED}Error: Invalid IP address or hostname: {ip}{Colors.ENDC}")
                    continue
            
            # Detect Ingress NGINX
            results[ip] = detect_ingress_nginx(ip)
        except Exception as e:
            print(f"{Colors.RED}Error scanning {ip}: {str(e)}{Colors.ENDC}")
            results[ip] = {"error": str(e)}
    
    # Print overall summary
    potentially_vulnerable_admission = []
    potentially_vulnerable_version = []
    
    for ip, result in results.items():
        if "potential_admission_endpoints" in result and result["potential_admission_endpoints"]:
            potentially_vulnerable_admission.append(ip)
        
        if "version_info" in result:
            for version_info in result["version_info"]:
                if version_info.get("is_vulnerable", True):
                    if ip not in potentially_vulnerable_version:
                        potentially_vulnerable_version.append(ip)
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Overall Vulnerability Assessment Summary:{Colors.ENDC}")
    print(f"Scanned {len(ips)} target(s)")
    
    if potentially_vulnerable_admission:
        print(f"{Colors.RED}{Colors.BOLD}POTENTIALLY VULNERABLE ADMISSION ENDPOINTS:{Colors.ENDC} {len(potentially_vulnerable_admission)} target(s)")
        for ip in potentially_vulnerable_admission:
            endpoints = results[ip]["potential_admission_endpoints"]
            print(f"  - {ip}: {len(endpoints)} potential admission webhook endpoint(s) on ports {', '.join(map(str, endpoints))}")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}LOW RISK:{Colors.ENDC} No obvious admission webhook endpoints detected")
    
    if potentially_vulnerable_version:
        print(f"{Colors.YELLOW}{Colors.BOLD}POTENTIALLY VULNERABLE VERSIONS:{Colors.ENDC} {len(potentially_vulnerable_version)} target(s)")
        for ip in potentially_vulnerable_version:
            vulnerable_versions = [v for v in results[ip]["version_info"] if v.get("is_vulnerable", True)]
            for v in vulnerable_versions:
                print(f"  - {ip}: {v['protocol'].upper()} on port {v['port']}: {v.get('version', 'unknown')} - {v.get('reason', 'unknown')}")
    
    print(f"\nNote: This external scan has limitations and may produce false negatives.")
    print(f"For more details: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Ingress NGINX Controller vulnerabilities externally")
    parser.add_argument("target", nargs="+", help="IP address(es) or hostname(s) to check")
    args = parser.parse_args()
    
    if len(args.target) == 1:
        scan_ip(args.target[0])
    else:
        scan_multiple_ips(args.target)