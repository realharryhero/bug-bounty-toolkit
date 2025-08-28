#!/usr/bin/env python3
"""
Demo script for the Bug Bounty Toolkit
Demonstrates the toolkit functionality with safe, local testing
"""

import sys
import os
import time
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.config.config_manager import ConfigManager
from core.reporting.report_generator import ReportGenerator, Finding, Severity
from core.authorization.auth_manager import AuthorizationManager
from datetime import datetime

def demo_configuration():
    """Demonstrate configuration management."""
    print("🔧 Configuration Management Demo")
    print("-" * 40)
    
    # Load configuration
    config = ConfigManager("config/default.yml")
    
    print(f"Threads: {config.get('general.threads')}")
    print(f"Timeout: {config.get('general.timeout')}")
    print(f"SQL injection enabled: {config.is_scanner_enabled('sqli')}")
    print(f"XSS enabled: {config.is_scanner_enabled('xss')}")
    print()

def demo_authorization():
    """Demonstrate authorization framework."""
    print("🔐 Authorization Framework Demo")
    print("-" * 40)
    
    auth_manager = AuthorizationManager()
    
    # Test blacklisted domains
    test_domains = ["localhost", "google.com", "example.com"]
    
    for domain in test_domains:
        is_blacklisted = auth_manager._is_blacklisted(domain)
        status = "❌ BLACKLISTED" if is_blacklisted else "✅ Not blacklisted"
        print(f"{domain}: {status}")
    
    print()

def demo_reporting():
    """Demonstrate report generation."""
    print("📊 Reporting System Demo")
    print("-" * 40)
    
    # Create temporary report generator
    report_gen = ReportGenerator("reports")
    
    # Create sample findings
    findings = [
        report_gen.create_finding(
            title="SQL Injection in Login Form",
            severity=Severity.HIGH,
            confidence=0.9,
            description="Error-based SQL injection found in login parameter",
            target="https://demo.example.com/login?user=test",
            vulnerability_type="SQL Injection",
            payload="' OR 1=1--",
            evidence="MySQL error message returned",
            impact="Attacker could extract sensitive data from database",
            remediation="Use parameterized queries"
        ),
        report_gen.create_finding(
            title="Reflected XSS in Search",
            severity=Severity.MEDIUM,
            confidence=0.8,
            description="User input reflected without proper encoding",
            target="https://demo.example.com/search?q=<script>alert('xss')</script>",
            vulnerability_type="Cross-Site Scripting",
            payload="<script>alert('xss')</script>",
            evidence="Script tag reflected in response",
            impact="Attacker could execute malicious scripts",
            remediation="Implement proper input encoding"
        ),
        report_gen.create_finding(
            title="Missing CSRF Protection",
            severity=Severity.MEDIUM,
            confidence=0.7,
            description="Form lacks CSRF token protection",
            target="https://demo.example.com/profile/update",
            vulnerability_type="Cross-Site Request Forgery",
            evidence="No CSRF token found in form",
            impact="Attacker could perform unauthorized actions",
            remediation="Implement CSRF tokens"
        )
    ]
    
    # Create scan results
    start_time = datetime.now()
    end_time = datetime.now()
    
    scan_results = report_gen.create_scan_results(
        scan_type="demo_scan",
        target="https://demo.example.com",
        start_time=start_time,
        end_time=end_time,
        findings=findings,
        demo_mode=True,
        scan_duration=45.2
    )
    
    # Generate reports
    try:
        json_report = report_gen.generate_report(scan_results, "json")
        html_report = report_gen.generate_report(scan_results, "html")
        
        print(f"JSON report: {json_report}")
        print(f"HTML report: {html_report}")
        print(f"Total findings: {len(findings)}")
        print(f"Severity breakdown: {scan_results.statistics['severity_breakdown']}")
        
    except Exception as e:
        print(f"Report generation error: {e}")
    
    print()

def demo_payload_loading():
    """Demonstrate payload loading."""
    print("💣 Payload System Demo")
    print("-" * 40)
    
    payload_files = [
        "payloads/sqli_payloads.txt",
        "payloads/xss_payloads.txt",
        "payloads/traversal_payloads.txt",
        "payloads/ssrf_payloads.txt"
    ]
    
    for payload_file in payload_files:
        if os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{payload_file}: {len(payloads)} payloads loaded")
        else:
            print(f"{payload_file}: Not found")
    
    print()

def main():
    """Run the demo."""
    print("=" * 60)
    print("🚀 BUG BOUNTY TOOLKIT DEMO")
    print("=" * 60)
    print("This demo shows the toolkit's capabilities with safe, local testing.")
    print("No actual security testing is performed on external systems.")
    print()
    
    demos = [
        demo_configuration,
        demo_authorization,
        demo_payload_loading,
        demo_reporting
    ]
    
    for demo in demos:
        try:
            demo()
            time.sleep(1)  # Small pause between demos
        except Exception as e:
            print(f"Demo error: {e}")
            print()
    
    print("=" * 60)
    print("✅ DEMO COMPLETED")
    print("=" * 60)
    print("To perform actual security testing:")
    print("1. Ensure you have proper authorization")
    print("2. Run: python main.py --scan all --target https://your-authorized-target.com")
    print("3. Check the reports/ directory for results")
    print()
    print("⚠️  REMEMBER: Only test systems you own or have explicit permission to test!")

if __name__ == "__main__":
    main()