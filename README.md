<p align="center">
  <img src="images/ingress-nightmare.png" alt="Ingress Nightmare Vulnerability">
</p>

# Ingress NGINX Vulnerability Checker

Detection scripts for the Ingress NGINX Controller vulnerabilities (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974).

## Available Scripts

This repository contains two vulnerability detection scripts:

1. **Internal Cluster Assessment** (`ingress_nginx_vuln_checker.py`)
   - For users with kubectl access to their clusters
   - Provides detailed version information and precise vulnerability assessment

2. **External Network Assessment** (`ingress_nginx_external_checker.py`)
   - For checking clusters you don't have kubectl access to
   - Works with just a public IP address or hostname
   - No authentication required

## Internal Checker Usage

```bash
# Make the script executable
chmod +x ingress_nginx_vuln_checker.py

# Run the script against your current kubectl context
./ingress_nginx_vuln_checker.py
```

### Requirements

- Python 3
- kubectl configured with access to the cluster you want to check

## External Checker Usage

```bash
# Make the script executable
chmod +x ingress_nginx_external_checker.py

# Install required dependencies
pip install requests urllib3

# Check a single IP address or hostname
./ingress_nginx_external_checker.py 123.45.67.89

# Check multiple targets at once
./ingress_nginx_external_checker.py 123.45.67.89 cluster.example.com 98.76.54.32
```

### Requirements

- Python 3
- `requests` and `urllib3` Python packages

## Output

Both scripts provide clear vulnerability assessments:
- Highlight potentially vulnerable components
- Provide recommendations for remediation

The external checker looks for:
- Exposed NGINX servers
- Kubernetes admission webhook endpoints
- Signs of Ingress Controller exposure

## Disclaimer

These are DETECTION-ONLY scripts. They do not attempt to exploit any vulnerabilities and pose no risk to your clusters. The external checker performs only non-invasive network checks.