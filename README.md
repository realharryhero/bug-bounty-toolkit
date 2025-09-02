# Bug Bounty Automation Toolkit

A comprehensive, professional-grade bug bounty automation toolkit for ethical security research. This toolkit provides automated vulnerability detection capabilities while maintaining strict ethical safeguards and legal compliance.

## ⚠️ LEGAL DISCLAIMER

**THIS TOOLKIT IS FOR AUTHORIZED TESTING ONLY**

By using this software, you acknowledge and agree that:
- You may only use this toolkit against systems you own or have explicit written permission to test
- Testing systems without proper authorization is illegal and may result in criminal and civil liability
- You are responsible for ensuring all activities comply with applicable laws and regulations
- The authors are not responsible for any misuse, damage, or legal consequences

**ALWAYS OBTAIN EXPLICIT WRITTEN AUTHORIZATION BEFORE TESTING ANY SYSTEM**

## Features

### 🔍 Automated Vulnerability Scanners
- **SQL Injection**: Error-based, blind, time-based, and union-based detection
- **XSS Detection**: Reflected, stored, and DOM-based XSS testing
- **CSRF Testing**: Token validation and bypass detection
- **Authentication Bypass**: Session management and privilege escalation testing
- **Directory Traversal**: Path traversal with multiple encoding techniques
- **SSRF**: Server-Side Request Forgery with internal service enumeration
- **XXE**: XML External Entity vulnerability testing
- **Command Injection**: OS command injection detection
- **IDOR**: Insecure Direct Object Reference testing
- **Client-side XPath Injection**: DOM-based XPath injection detection (reflected, stored, and DOM-based)
- **Client-side JSON Injection**: DOM-based JSON injection including JSONP and prototype pollution
- **HTTP PUT Method Detection**: Checks if the PUT method is enabled on the server.

### 🕵️ Reconnaissance Automation
- **Subdomain Enumeration**: DNS brute-forcing and passive discovery
- **Port Scanning**: Service detection and banner grabbing
- **Technology Fingerprinting**: Stack identification
- **URL Discovery**: Endpoint and directory enumeration

### 🛡️ Ethical Safeguards
- **Authorization Framework**: Mandatory authorization checks
- **Scope Verification**: Built-in scope enforcement
- **Rate Limiting**: Configurable request throttling
- **Audit Logging**: Comprehensive activity logging
- **Legal Compliance**: Built-in legal disclaimers and warnings

### 📊 Professional Reporting
- **Multi-format Reports**: HTML, JSON, and PDF output
- **Detailed Findings**: Comprehensive vulnerability information
- **Executive Summaries**: High-level overview for management
- **False Positive Reduction**: Smart filtering and validation

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/realharryhero/bug-bounty-toolkit.git
   cd bug-bounty-toolkit
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python main.py --help
   ```

## Quick Start

### Basic Vulnerability Scan
```bash
# Single vulnerability scan
python main.py --scan sqli --target https://example.com

# Client-side injection testing
python main.py --scan client_xpath --target https://example.com
python main.py --scan client_json --target https://example.com

# Multiple vulnerability types
python main.py --scan all --target https://example.com

# With custom configuration
python main.py --scan xss --target https://example.com --config config/custom.yml
```

### Reconnaissance
```bash
# Subdomain enumeration
python main.py --recon subdomain --domain example.com

# Port scanning
python main.py --recon portscan --target 192.168.1.1

# Full reconnaissance
python main.py --recon all --domain example.com
```

### Report Generation
```bash
# HTML report (default)
python main.py --scan all --target https://example.com --format html

# JSON report
python main.py --scan all --target https://example.com --format json

# Custom output directory
python main.py --scan all --target https://example.com --output /path/to/reports
```

## Configuration

The toolkit uses YAML configuration files for customization. Copy and modify `config/default.yml`:

```yaml
general:
  threads: 10
  timeout: 30
  delay: 1.0
  rate_limit:
    requests_per_second: 5

scanners:
  sqli:
    enabled: true
    confidence_threshold: 0.7
  xss:
    enabled: true
    confidence_threshold: 0.8
```

## Usage Examples

### Authorized Penetration Testing
```bash
# Load authorized scope from file
python main.py --scan all --target https://testsite.com --scope-file scope.json

# Verbose output with detailed logging
python main.py --scan sqli --target https://testsite.com -vvv

# Rate-limited scanning
python main.py --scan all --target https://testsite.com --delay 2.0 --threads 5
```

### Bug Bounty Programs
```bash
# Comprehensive scan for bug bounty
python main.py --scan all --domain bugbounty-target.com --format json

# Reconnaissance first, then targeted scanning
python main.py --recon all --domain target.com
python main.py --scan all --target https://api.target.com
```

## Architecture

```
bug-bounty-toolkit/
├── core/                   # Framework components
│   ├── authorization/      # Authorization and scope management
│   ├── config/            # Configuration management
│   ├── reporting/         # Report generation
│   └── utils/             # Utilities and logging
├── scanners/              # Vulnerability scanners
│   ├── sqli/              # SQL injection scanner
│   ├── xss/               # XSS scanner
│   ├── csrf/              # CSRF scanner
│   ├── put/               # HTTP PUT method scanner
│   └── ...                # Additional scanners
├── recon/                 # Reconnaissance modules
├── payloads/              # Attack payloads and wordlists
├── config/                # Configuration files
├── templates/             # Report templates
├── reports/               # Generated reports
└── docs/                  # Documentation
```

## Available Scanners

| Scanner | Description | Status |
|---------|-------------|---------|
| SQL Injection | Error, blind, time-based, union detection | ✅ Implemented |
| XSS | Reflected, stored, DOM-based testing | ✅ Implemented |
| CSRF | Token validation and bypass detection | ✅ Implemented |
| Auth Bypass | Session and privilege escalation testing | 🚧 In Progress |
| Directory Traversal | Path traversal with encoding | ✅ Implemented |
| SSRF | Server-side request forgery | 🚧 In Progress |
| XXE | XML external entity vulnerabilities | 🚧 In Progress |
| Command Injection | OS command injection detection | 🚧 In Progress |
| IDOR | Insecure direct object references | 🚧 In Progress |
| Client-side XPath Injection | DOM-based XPath injection (reflected, stored, DOM-based) | ✅ Implemented |
| Client-side JSON Injection | DOM-based JSON injection including JSONP and prototype pollution | ✅ Implemented |
| HTTP PUT Enabled | Detects if the HTTP PUT method is enabled (CWE-650) | ✅ Implemented |

## Reconnaissance Modules

| Module | Description | Status |
|--------|-------------|---------|
| Subdomain Enum | DNS brute-force and passive discovery | 🚧 Basic Implementation |
| Port Scanning | Service detection and banner grabbing | 🚧 Basic Implementation |
| Tech Fingerprinting | Technology stack identification | 🚧 Basic Implementation |
| URL Discovery | Directory and file enumeration | 🚧 Basic Implementation |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This toolkit is designed for ethical security research and authorized testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Review the documentation in the `docs/` directory
- Follow responsible disclosure practices

---

**Remember: With great power comes great responsibility. Use this toolkit ethically and legally.**