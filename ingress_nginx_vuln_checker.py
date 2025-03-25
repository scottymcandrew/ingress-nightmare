#!/usr/bin/env python3
"""
Ingress NGINX Vulnerability Checker (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974)

This script checks if a Kubernetes cluster is vulnerable to the recently discovered
Ingress NGINX Controller vulnerabilities that could lead to unauthenticated Remote Code Execution.

This is a DETECTION-ONLY script. It does not attempt to exploit the vulnerabilities.
"""

import argparse
import json
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple, Any

# ANSI colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Vulnerable version ranges
# Versions prior to 1.12.1 and 1.11.5 are vulnerable
SAFE_VERSIONS = ["1.12.1", "1.11.5"]
SAFE_VERSION_REGEX = r"^(1\.12\.[1-9][0-9]*|1\.12\.[1-9][0-9]+|1\.1[3-9]|[2-9]|1\.[1-9][0-9]+\.[0-9]+|[2-9]\.[0-9]+\.[0-9]+)$"
SAFE_VERSION_1_11_REGEX = r"^1\.11\.([5-9]|[1-9][0-9]+)$"

def run_command(command: List[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Run a command and return success status, stdout, and stderr
    """
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return (result.returncode == 0, result.stdout, result.stderr)
    except Exception as e:
        return (False, None, str(e))

def check_kubectl_access() -> bool:
    """
    Check if kubectl is available and can access the cluster
    """
    success, output, _ = run_command(["kubectl", "version", "--client", "--output=json"])
    if not success:
        print(f"{Colors.RED}Error: kubectl command not found or failed{Colors.ENDC}")
        return False
    
    success, _, _ = run_command(["kubectl", "get", "nodes"])
    if not success:
        print(f"{Colors.RED}Error: Cannot connect to Kubernetes cluster{Colors.ENDC}")
        return False
    
    return True

def get_ingress_nginx_pods() -> List[Dict[str, Any]]:
    """
    Find all ingress-nginx controller pods in the cluster
    """
    success, output, error = run_command([
        "kubectl", "get", "pods", 
        "--all-namespaces", 
        "--selector=app.kubernetes.io/name=ingress-nginx,app.kubernetes.io/component=controller",
        "-o", "json"
    ])
    
    if not success or not output:
        print(f"{Colors.YELLOW}No Ingress NGINX controller pods found with standard labels.{Colors.ENDC}")
        # Try alternative selector
        success, output, error = run_command([
            "kubectl", "get", "pods", 
            "--all-namespaces", 
            "--selector=app=ingress-nginx",
            "-o", "json"
        ])
        
        if not success or not output:
            print(f"{Colors.YELLOW}No Ingress NGINX controller pods found with alternative labels.{Colors.ENDC}")
            return []
    
    try:
        pods_data = json.loads(output)
        return pods_data.get("items", [])
    except json.JSONDecodeError:
        print(f"{Colors.RED}Error: Could not parse kubectl output{Colors.ENDC}")
        return []

def get_pod_version(namespace: str, pod_name: str) -> Optional[str]:
    """
    Extract the version of the ingress-nginx controller from pod logs
    """
    success, output, _ = run_command([
        "kubectl", "logs", 
        "-n", namespace, 
        pod_name, 
        "--tail", "100"
    ])
    
    if not success or not output:
        return None
    
    # Try to find version in the logs
    version_match = re.search(r"NGINX Ingress controller Version: ([\d\.]+)", output)
    if version_match:
        return version_match.group(1)
    
    # If not found in logs, try checking the image tag
    success, output, _ = run_command([
        "kubectl", "get", "pod", 
        "-n", namespace, 
        pod_name, 
        "-o", "jsonpath={.spec.containers[*].image}"
    ])
    
    if success and output:
        image_match = re.search(r":v?([\d\.]+)(?:-[a-zA-Z0-9]+)?$", output)
        if image_match:
            return image_match.group(1)
    
    return None

def is_version_vulnerable(version: str) -> bool:
    """
    Check if the version is vulnerable
    """
    if not version:
        return True  # Consider unknown versions as vulnerable
    
    # Check if it matches known safe version patterns
    if re.match(SAFE_VERSION_REGEX, version) or re.match(SAFE_VERSION_1_11_REGEX, version):
        return False
    
    # Check exact safe versions
    return version not in SAFE_VERSIONS

def check_admission_webhook_service(namespace: str) -> bool:
    """
    Check if the admission webhook service exists and is potentially exposed
    """
    success, output, _ = run_command([
        "kubectl", "get", "service", 
        "-n", namespace, 
        "-l", "app.kubernetes.io/name=ingress-nginx,app.kubernetes.io/component=controller",
        "-o", "json"
    ])
    
    if not success or not output:
        return False
    
    try:
        services = json.loads(output).get("items", [])
        for service in services:
            service_type = service.get("spec", {}).get("type", "")
            if service_type in ["LoadBalancer", "NodePort"]:
                return True
    except json.JSONDecodeError:
        pass
    
    return False

def check_webhook_configuration() -> bool:
    """
    Check if validating webhook configuration exists for ingress-nginx
    """
    success, output, _ = run_command([
        "kubectl", "get", "validatingwebhookconfigurations", 
        "-l", "app.kubernetes.io/name=ingress-nginx",
        "-o", "json"
    ])
    
    if success and output:
        try:
            webhooks = json.loads(output).get("items", [])
            return len(webhooks) > 0
        except json.JSONDecodeError:
            pass
    
    return False

def perform_vulnerability_check() -> None:
    """
    Main function to check for vulnerability
    """
    print(f"{Colors.HEADER}{Colors.BOLD}Ingress NGINX Vulnerability Checker{Colors.ENDC}")
    print(f"{Colors.BLUE}Checking for CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974{Colors.ENDC}\n")
    
    if not check_kubectl_access():
        sys.exit(1)
    
    print(f"{Colors.BLUE}Looking for Ingress NGINX controller pods...{Colors.ENDC}")
    pods = get_ingress_nginx_pods()
    
    if not pods:
        print(f"{Colors.GREEN}No Ingress NGINX controller pods found. Cluster appears not vulnerable.{Colors.ENDC}")
        sys.exit(0)
    
    print(f"{Colors.YELLOW}Found {len(pods)} Ingress NGINX controller pod(s){Colors.ENDC}")
    
    vulnerable_pods = []
    for pod in pods:
        namespace = pod.get("metadata", {}).get("namespace", "")
        pod_name = pod.get("metadata", {}).get("name", "")
        
        print(f"\n{Colors.BOLD}Checking pod: {pod_name} in namespace: {namespace}{Colors.ENDC}")
        
        # Get controller version
        version = get_pod_version(namespace, pod_name)
        if version:
            print(f"  - Version: {version}")
            if is_version_vulnerable(version):
                print(f"  - {Colors.RED}Version is vulnerable{Colors.ENDC}")
                vulnerable_pods.append((namespace, pod_name, version))
            else:
                print(f"  - {Colors.GREEN}Version is not vulnerable{Colors.ENDC}")
        else:
            print(f"  - {Colors.YELLOW}Could not determine version, considering potentially vulnerable{Colors.ENDC}")
            vulnerable_pods.append((namespace, pod_name, "unknown"))
        
        # Check if admission webhook service potentially exposed
        if check_admission_webhook_service(namespace):
            print(f"  - {Colors.RED}Admission webhook service potentially exposed{Colors.ENDC}")
        else:
            print(f"  - {Colors.GREEN}No exposed admission webhook service detected{Colors.ENDC}")
        
    # Check for webhook configuration
    if check_webhook_configuration():
        print(f"\n{Colors.YELLOW}ValidatingWebhookConfiguration for ingress-nginx is present{Colors.ENDC}")
    else:
        print(f"\n{Colors.BLUE}No ValidatingWebhookConfiguration found for ingress-nginx{Colors.ENDC}")
    
    # Print summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}Vulnerability Assessment Summary:{Colors.ENDC}")
    if vulnerable_pods:
        print(f"{Colors.RED}{Colors.BOLD}POTENTIALLY VULNERABLE:{Colors.ENDC} {len(vulnerable_pods)} Ingress NGINX controller(s) found with vulnerable versions")
        print("\nVulnerable controllers:")
        for namespace, pod_name, version in vulnerable_pods:
            print(f"  - {namespace}/{pod_name} (version: {version or 'unknown'})")
        
        print(f"\n{Colors.YELLOW}Recommendation: Update Ingress NGINX Controller to version 1.12.1+ or 1.11.5+{Colors.ENDC}")
        print(f"{Colors.YELLOW}For more details: https://github.com/kubernetes/ingress-nginx/releases{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}NOT VULNERABLE:{Colors.ENDC} No vulnerable Ingress NGINX controllers found")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Ingress NGINX Controller vulnerabilities")
    args = parser.parse_args()
    
    perform_vulnerability_check()