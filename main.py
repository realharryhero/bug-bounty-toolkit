#!/usr/bin/env python3
"""
Bug Bounty Automation Toolkit - Main CLI Interface
"""

import argparse
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.authorization.auth_manager import AuthorizationManager
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import ReportGenerator
from core.utils.logger import setup_logging
import __init__

def main():
    """Main entry point for the bug bounty toolkit."""
    
    # Show legal disclaimer
    __init__.show_disclaimer()
    
    # Ask for explicit authorization confirmation
    response = input("\nDo you have explicit written authorization to test the target(s)? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("\n❌ Authorization not confirmed. Exiting for legal compliance.")
        print("Only proceed if you have explicit written authorization to test the target systems.")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Bug Bounty Automation Toolkit - Ethical Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan sqli --target https://example.com --config config/default.yml
  python main.py --recon subdomain --domain example.com
  python main.py --scan all --target https://example.com --output reports/scan_results
  
For more information, see the documentation in the docs/ directory.
        """
    )
    
    # Main action groups
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--scan", choices=[
        "sqli", "xss", "csrf", "auth", "traversal", "ssrf", "xxe", "cmdi", "idor", "trace", "all"
    ], help="Run vulnerability scanners")
    action_group.add_argument("--recon", choices=[
        "subdomain", "portscan", "fingerprint", "urls", "all"
    ], help="Run reconnaissance modules")
    
    # Target specification
    parser.add_argument("--target", help="Target URL or IP address")
    parser.add_argument("--domain", help="Target domain for reconnaissance")
    parser.add_argument("--scope-file", help="File containing authorized scope (URLs/domains)")
    
    # Configuration
    parser.add_argument("--config", default="config/default.yml", 
                       help="Configuration file path (default: config/default.yml)")
    parser.add_argument("--output", default="reports", 
                       help="Output directory for reports (default: reports)")
    parser.add_argument("--format", choices=["html", "json", "pdf"], default="html",
                       help="Report format (default: html)")
    
    # Performance and behavior
    parser.add_argument("--threads", type=int, default=10, 
                       help="Number of concurrent threads (default: 10)")
    parser.add_argument("--delay", type=float, default=1.0,
                       help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Request timeout in seconds (default: 30)")
    
    # Verbosity and debugging
    parser.add_argument("--verbose", "-v", action="count", default=0,
                       help="Increase verbosity level (use -v, -vv, or -vvv)")
    parser.add_argument("--quiet", "-q", action="store_true",
                       help="Suppress output except errors")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "ERROR" if args.quiet else ["INFO", "DEBUG", "DEBUG", "DEBUG"][min(args.verbose, 3)]
    logger = setup_logging(log_level)
    
    # Initialize core components
    try:
        config_manager = ConfigManager(args.config)
        auth_manager = AuthorizationManager()
        
        # Verify target authorization
        if args.target:
            if not auth_manager.verify_target_authorization(args.target):
                logger.error("❌ Target not in authorized scope. Exiting.")
                sys.exit(1)
        elif args.domain:
            if not auth_manager.verify_domain_authorization(args.domain):
                logger.error("❌ Domain not in authorized scope. Exiting.")
                sys.exit(1)
        
        logger.info("✅ Authorization verified. Starting toolkit...")
        
        # Execute requested action
        if args.scan:
            from core.scanner_controller import ScannerController
            controller = ScannerController(config_manager, args)
            results = controller.run_scan(args.scan)
        elif args.recon:
            from core.recon_controller import ReconController
            controller = ReconController(config_manager, args)
            results = controller.run_recon(args.recon)
        
        # Generate report
        report_gen = ReportGenerator(args.output)
        report_path = report_gen.generate_report(results, args.format)
        logger.info(f"✅ Report generated: {report_path}")
        
    except KeyboardInterrupt:
        logger.info("\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()