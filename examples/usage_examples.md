# Usage Examples

## Basic Usage

### Single Vulnerability Scan
```bash
# SQL injection scan
python main.py --scan sqli --target https://example.com

# XSS scan
python main.py --scan xss --target https://example.com

# CSRF scan
python main.py --scan csrf --target https://example.com
```

### Comprehensive Scanning
```bash
# Run all enabled scanners
python main.py --scan all --target https://example.com

# Run with custom threads and delay
python main.py --scan all --target https://example.com --threads 20 --delay 0.5
```

### Reconnaissance
```bash
# Subdomain enumeration
python main.py --recon subdomain --domain example.com

# Port scanning
python main.py --recon portscan --target example.com

# All reconnaissance modules
python main.py --recon all --domain example.com
```

## Advanced Usage

### Custom Configuration
```bash
# Use custom configuration file
python main.py --scan all --target https://example.com --config config/custom.yml

# Override default settings
python main.py --scan sqli --target https://example.com --timeout 60 --threads 5
```

### Output and Reporting
```bash
# Generate HTML report (default)
python main.py --scan all --target https://example.com --format html

# Generate JSON report
python main.py --scan all --target https://example.com --format json

# Custom output directory
python main.py --scan all --target https://example.com --output /path/to/reports
```

### Verbose Logging
```bash
# Increase verbosity
python main.py --scan sqli --target https://example.com -v

# Maximum verbosity
python main.py --scan sqli --target https://example.com -vvv

# Quiet mode (errors only)
python main.py --scan sqli --target https://example.com --quiet
```

## Authorized Testing Scenarios

### Penetration Testing
```bash
# Load authorized scope from file
python main.py --scan all --target https://client-site.com --scope-file authorized_scope.json

# Rate-limited scanning to avoid disruption
python main.py --scan all --target https://client-site.com --delay 2.0 --threads 3
```

### Bug Bounty Programs
```bash
# Comprehensive reconnaissance
python main.py --recon all --domain bugbounty-target.com --output reports/recon

# Targeted vulnerability scanning
python main.py --scan all --target https://api.bugbounty-target.com --output reports/vulns

# Generate combined report
python main.py --scan all --target https://bugbounty-target.com --format json --output reports/final
```

## Example Workflow

### Complete Assessment Workflow
```bash
# Step 1: Reconnaissance
python main.py --recon all --domain target.com --output reports/step1_recon

# Step 2: Vulnerability Scanning
python main.py --scan all --target https://target.com --output reports/step2_vulns

# Step 3: Targeted Testing (based on recon findings)
python main.py --scan sqli --target https://api.target.com --output reports/step3_api
python main.py --scan xss --target https://app.target.com --output reports/step3_app

# Step 4: Report Generation
python main.py --scan all --target https://target.com --format html --output reports/final_report
```

## Configuration Examples

### High-Intensity Scanning
```yaml
general:
  threads: 50
  timeout: 10
  delay: 0.1
  
scanners:
  sqli:
    enabled: true
    confidence_threshold: 0.5
```

### Conservative Scanning
```yaml
general:
  threads: 3
  timeout: 60
  delay: 3.0
  
scanners:
  sqli:
    enabled: true
    confidence_threshold: 0.8
```

## Best Practices

1. **Always obtain proper authorization** before scanning
2. **Start with reconnaissance** to understand the target
3. **Use rate limiting** to avoid overwhelming the target
4. **Review configurations** before running scans
5. **Document your testing** with detailed reports
6. **Follow responsible disclosure** for any findings