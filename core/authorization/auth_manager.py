"""
Authorization Manager - Ensures all testing activities are properly authorized
"""

import os
import re
import json
import logging
from urllib.parse import urlparse
from typing import List, Set, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class AuthorizationManager:
    """
    Manages authorization checks and scope verification to ensure all testing
    activities are performed only on authorized targets.
    """
    
    def __init__(self, scope_file: str = None):
        """
        Initialize the authorization manager.
        
        Args:
            scope_file: Path to file containing authorized scope definitions
        """
        self.authorized_domains: Set[str] = set()
        self.authorized_ips: Set[str] = set()
        self.authorized_urls: Set[str] = set()
        self.authorized_patterns: List[re.Pattern] = []
        self.blacklisted_domains: Set[str] = set()
        
        # Load default blacklisted domains (critical infrastructure, etc.)
        self._load_default_blacklist()
        
        # Load scope file if provided
        if scope_file and os.path.exists(scope_file):
            self.load_scope_file(scope_file)
        else:
            logger.warning("No scope file provided. Manual authorization required for each target.")
    
    def _load_default_blacklist(self):
        """Load default blacklisted domains that should never be tested."""
        # Critical infrastructure and government domains
        default_blacklist = [
            "*.gov", "*.mil", "*.edu",
            "localhost", "127.0.0.1", "::1",
            "*.internal", "*.local", "*.corp",
            "facebook.com", "google.com", "microsoft.com",
            "amazon.com", "apple.com", "twitter.com",
            # Add more as needed
        ]
        
        for domain in default_blacklist:
            if domain.startswith("*."):
                # Convert wildcard to regex pattern
                pattern = re.escape(domain[2:]).replace(r'\*', r'.*')
                self.authorized_patterns.append(re.compile(f".*\\.{pattern}$"))
            else:
                self.blacklisted_domains.add(domain)
    
    def load_scope_file(self, scope_file: str):
        """
        Load authorized scope from a file.
        
        Expected format (JSON):
        {
            "domains": ["example.com", "*.example.com"],
            "urls": ["https://api.example.com/v1/*"],
            "ips": ["192.168.1.0/24"],
            "patterns": [".*\\.bug-bounty-program\\.com"]
        }
        """
        try:
            with open(scope_file, 'r') as f:
                scope_data = json.load(f)
            
            # Load domains
            for domain in scope_data.get('domains', []):
                if domain.startswith("*."):
                    pattern = re.escape(domain[2:]).replace(r'\*', r'.*')
                    self.authorized_patterns.append(re.compile(f".*\\.{pattern}$"))
                else:
                    self.authorized_domains.add(domain)
            
            # Load URLs
            self.authorized_urls.update(scope_data.get('urls', []))
            
            # Load IPs (simplified - would need proper CIDR handling in production)
            self.authorized_ips.update(scope_data.get('ips', []))
            
            # Load regex patterns
            for pattern in scope_data.get('patterns', []):
                self.authorized_patterns.append(re.compile(pattern))
            
            logger.info(f"Loaded scope from {scope_file}")
            
        except Exception as e:
            logger.error(f"Failed to load scope file {scope_file}: {str(e)}")
            raise
    
    def verify_target_authorization(self, target: str) -> bool:
        """
        Verify that a target URL is within authorized scope.
        
        Args:
            target: Target URL to verify
            
        Returns:
            True if target is authorized, False otherwise
        """
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            
            if not hostname:
                logger.error(f"Invalid target URL: {target}")
                return False
            
            # Check blacklist first
            if self._is_blacklisted(hostname):
                logger.error(f"Target {hostname} is blacklisted")
                return False
            
            # Check if we have explicit authorization
            if self._is_authorized(hostname, target):
                return True
            
            # If no explicit authorization, ask user
            return self._request_manual_authorization(target)
            
        except Exception as e:
            logger.error(f"Error verifying target authorization: {str(e)}")
            return False
    
    def verify_domain_authorization(self, domain: str) -> bool:
        """
        Verify that a domain is within authorized scope.
        
        Args:
            domain: Domain to verify
            
        Returns:
            True if domain is authorized, False otherwise
        """
        # Check blacklist first
        if self._is_blacklisted(domain):
            logger.error(f"Domain {domain} is blacklisted")
            return False
        
        # Check if we have explicit authorization
        if self._is_authorized(domain, f"https://{domain}"):
            return True
        
        # If no explicit authorization, ask user
        return self._request_manual_authorization(domain)
    
    def _is_blacklisted(self, hostname: str) -> bool:
        """Check if hostname is in the blacklist."""
        if hostname in self.blacklisted_domains:
            return True
        
        # Check against blacklist patterns
        for pattern in self.authorized_patterns:
            if pattern.match(hostname):
                return True
        
        return False
    
    def _is_authorized(self, hostname: str, target: str) -> bool:
        """Check if hostname/target is explicitly authorized."""
        # Check exact domain match
        if hostname in self.authorized_domains:
            return True
        
        # Check URL patterns
        for url_pattern in self.authorized_urls:
            if url_pattern.endswith("*"):
                if target.startswith(url_pattern[:-1]):
                    return True
            elif target == url_pattern:
                return True
        
        # Check regex patterns
        for pattern in self.authorized_patterns:
            if pattern.match(hostname):
                return True
        
        return False
    
    def _request_manual_authorization(self, target: str) -> bool:
        """Request manual authorization confirmation from user."""
        print(f"\n⚠️  TARGET AUTHORIZATION REQUIRED")
        print(f"Target: {target}")
        print(f"This target is not in your predefined authorized scope.")
        print(f"")
        print(f"IMPORTANT: Only proceed if you have explicit written authorization to test this target.")
        print(f"Unauthorized testing may be illegal and could result in criminal charges.")
        print(f"")
        
        response = input(f"Do you have explicit written authorization to test {target}? (yes/no): ").strip().lower()
        
        if response in ['yes', 'y']:
            # Ask for additional confirmation
            confirm = input("Are you absolutely certain? This action will be logged. (yes/no): ").strip().lower()
            if confirm in ['yes', 'y']:
                logger.warning(f"Manual authorization granted for target: {target}")
                return True
        
        logger.info(f"Authorization denied for target: {target}")
        return False
    
    def log_activity(self, activity: str, target: str, details: Dict[str, Any]):
        """Log security testing activity for audit purposes."""
        log_entry = {
            "timestamp": logger.handlers[0].formatter.formatTime(logging.LogRecord("", 0, "", 0, "", (), None)),
            "activity": activity,
            "target": target,
            "details": details,
            "user": os.getenv("USER", "unknown")
        }
        
        # In production, this would go to a secure audit log
        logger.info(f"AUDIT: {json.dumps(log_entry)}")
    
    def get_scope_summary(self) -> Dict[str, Any]:
        """Get a summary of the current authorized scope."""
        return {
            "authorized_domains": list(self.authorized_domains),
            "authorized_urls": list(self.authorized_urls),
            "authorized_ips": list(self.authorized_ips),
            "pattern_count": len(self.authorized_patterns),
            "blacklisted_domains": list(self.blacklisted_domains)
        }