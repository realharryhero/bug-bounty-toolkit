# Virtual Browser Integration with Bug Bounty Toolkit

This document explains how to integrate and use the virtual browser environment with the bug bounty toolkit for enhanced security testing.

## Overview

The virtual browser provides an isolated environment for:
- Safe browsing of potentially malicious websites
- Manual verification of automated scan findings
- Client-side vulnerability testing
- Screenshot capture and evidence collection
- Running additional security tools

## Integration Workflow

### 1. Initial Setup

Start the virtual browser before beginning your bug bounty work:

```bash
# Start virtual browser
./start-virtual-browser.sh

# Or use make
make start

# Access at http://localhost:6080
```

### 2. Reconnaissance Phase

Use the toolkit to gather initial intelligence:

```bash
# Run subdomain enumeration
python main.py --recon subdomain --domain target.com

# Run port scanning
python main.py --recon portscan --target target.com

# Full reconnaissance
python main.py --recon all --domain target.com
```

### 3. Manual Verification in Virtual Browser

1. Open http://localhost:6080 in your host browser
2. Use Firefox/Chromium in the virtual environment to:
   - Manually browse discovered subdomains
   - Inspect web applications
   - Test functionality
   - Look for additional attack vectors

### 4. Automated Vulnerability Scanning

Based on manual findings, run targeted scans:

```bash
# XSS scanning
python main.py --scan xss --target https://webapp.target.com

# SQL injection testing
python main.py --scan sqli --target https://api.target.com

# Comprehensive scan
python main.py --scan all --target https://target.com
```

### 5. Client-Side Testing in Virtual Browser

Test client-side vulnerabilities safely:

```bash
# Run client-side XPath injection scan
python main.py --scan client_xpath --target https://target.com

# Run client-side JSON injection scan
python main.py --scan client_json --target https://target.com
```

Then verify in virtual browser:
1. Navigate to the target URL
2. Open browser developer tools (F12)
3. Test payloads manually
4. Observe behavior and capture evidence

## Use Cases

### Use Case 1: XSS Verification

**Automated Detection:**
```bash
python main.py --scan xss --target https://target.com/search?q=test
```

**Manual Verification:**
1. Open virtual browser (http://localhost:6080)
2. Navigate to the flagged endpoint
3. Test the XSS payload manually
4. Verify execution in console
5. Take screenshot for report

### Use Case 2: CSRF Testing

**Automated Detection:**
```bash
python main.py --scan csrf --target https://target.com/action
```

**Manual Verification:**
1. Open virtual browser
2. Create a test HTML page with CSRF PoC
3. Host it locally or use file:// protocol
4. Execute and observe behavior

### Use Case 3: Safe Investigation of Suspicious Sites

**Scenario:** Found a potentially malicious redirect

1. Never visit suspicious sites on your host machine
2. Open virtual browser instead
3. Navigate to the suspicious URL
4. Monitor behavior safely
5. Document findings

### Use Case 4: Screenshot Collection

Collect evidence for your bug bounty report:

1. Open virtual browser
2. Navigate to vulnerable endpoint
3. Trigger the vulnerability
4. Use screenshot tool (Applications → Accessories → Screenshot)
5. Save to shared volume for easy access

## Advanced Integration

### Installing Security Tools in Virtual Browser

Add tools to the virtual environment:

```bash
# Access virtual browser shell
make shell

# Or
docker exec -it virtual-browser bash

# Install tools
apt-get update
apt-get install -y burpsuite nmap wireshark-qt sqlmap

# Install Python tools
pip3 install wfuzz wapiti-scanner
```

### Persistent Tool Installation

For permanent tool installation, modify the Dockerfile:

```dockerfile
# Add to Dockerfile after line 24
RUN apt-get update && apt-get install -y \
    burpsuite \
    sqlmap \
    nmap \
    wireshark \
    && apt-get clean
```

Rebuild:
```bash
docker compose build
docker compose up -d
```

### Custom Browser Configuration

#### Configure Proxy for Burp Suite

1. Open Firefox in virtual browser
2. Preferences → Network Settings
3. Manual proxy configuration
4. HTTP Proxy: localhost, Port: 8080
5. Use this proxy for all protocols

#### Install Browser Extensions

In the virtual browser:
1. Open Firefox/Chromium
2. Install extensions:
   - FoxyProxy (proxy management)
   - Wappalyzer (technology detection)
   - Cookie-Editor (cookie manipulation)
   - User-Agent Switcher

### Data Persistence

Browser data persists across restarts in the `browser-data` volume.

**Export browser profile:**
```bash
docker cp virtual-browser:/root/.mozilla ./backup/
```

**Import browser profile:**
```bash
docker cp ./backup/.mozilla virtual-browser:/root/
```

## Workflow Examples

### Example 1: Complete Bug Bounty Workflow

```bash
# 1. Start virtual browser
./start-virtual-browser.sh

# 2. Run reconnaissance
python main.py --recon all --domain target.com --output reports/recon

# 3. Review findings in virtual browser
# - Open http://localhost:6080
# - Manually verify discovered endpoints

# 4. Run vulnerability scans
python main.py --scan all --target https://target.com --output reports/vulns

# 5. Manually verify findings in virtual browser
# - Test flagged vulnerabilities
# - Capture screenshots
# - Document behavior

# 6. Generate comprehensive report
python main.py --scan all --target https://target.com --format html

# 7. Stop virtual browser (optional)
make stop
```

### Example 2: Focused XSS Campaign

```bash
# Start browser
make start

# Scan for XSS
python main.py --scan xss --target https://target.com

# In virtual browser:
# 1. Open http://localhost:6080
# 2. Navigate to flagged endpoints
# 3. Test payloads manually
# 4. Try bypass techniques
# 5. Document successful exploits

# Clean up
make stop
```

### Example 3: API Testing

```bash
# Start browser with terminal access
make start

# Access terminal in virtual browser
# Install API testing tools:
apt-get install -y curl jq

# Use toolkit for initial API discovery
python main.py --recon all --domain api.target.com

# Test API endpoints in virtual browser terminal
curl -X GET https://api.target.com/endpoint
curl -X POST https://api.target.com/endpoint -d '{"key":"value"}'

# Run automated scans
python main.py --scan all --target https://api.target.com
```

## Security Best Practices

### Do's
✅ Always use virtual browser for suspicious URLs
✅ Keep virtual browser updated (rebuild regularly)
✅ Use virtual browser for malware analysis
✅ Capture screenshots within virtual environment
✅ Store sensitive data only in virtual browser

### Don'ts
❌ Don't share credentials between host and virtual browser
❌ Don't paste sensitive data from host into virtual browser
❌ Don't expose virtual browser to untrusted networks
❌ Don't run production tools in virtual browser
❌ Don't store reports in virtual browser volume

## Troubleshooting Integration

### Issue: Can't access virtual browser

**Solution:**
```bash
# Check if container is running
docker ps

# Check logs
docker compose logs

# Restart services
make restart
```

### Issue: Performance is slow

**Solution:**
```bash
# Increase resources in docker-compose.yml
shm_size: '4gb'

# Lower resolution
environment:
  - RESOLUTION=1280x720
```

### Issue: Lost data after restart

**Solution:**
Data in `/root` persists automatically. For additional persistence:

```yaml
volumes:
  - ./data:/home/data  # Mount host directory
```

## Tips and Tricks

1. **Multiple tabs**: Virtual browser supports multiple browser tabs
2. **Copy/Paste**: Use browser noVNC clipboard feature
3. **File transfer**: Use shared volumes or scp
4. **Network isolation**: Use Docker networks for isolation
5. **Snapshots**: Create volume backups before risky operations

## Resources

- [Virtual Browser Documentation](VIRTUAL_BROWSER.md)
- [Quick Start Guide](QUICKSTART.md)
- [Configuration Examples](VIRTUAL_BROWSER_CONFIG.md)
- [Main Toolkit Documentation](README.md)

## Support

For integration issues:
1. Check both toolkit and virtual browser logs
2. Verify Docker and Docker Compose versions
3. Ensure sufficient system resources
4. Review Docker networking setup
5. Create an issue on GitHub with details
