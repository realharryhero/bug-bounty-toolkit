"""
Configuration Manager - Handles YAML-based configuration files
"""

import yaml
import os
import logging
import glob
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class ConfigManager:
    """
    Manages configuration loading and validation for the bug bounty toolkit.
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file or "config/default.yml"
        self.config: Dict[str, Any] = {}
        self.default_config = self._get_default_config()
        
        self.load_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "general": {
                "threads": 10,
                "timeout": 30,
                "delay": 1.0,
                "user_agent": "BugBountyToolkit/1.0 (Ethical Security Research)",
                "max_retries": 3,
                "rate_limit": {
                    "requests_per_second": 5,
                    "burst_limit": 20
                }
            },
            "scanners": {
                "sqli": {
                    "enabled": True,
                    "payload_file": "payloads/sqli_payloads.txt",
                    "test_types": ["error", "blind", "time", "union"],
                    "time_delay": 5,
                    "confidence_threshold": 0.7
                },
                "xss": {
                    "enabled": True,
                    "payload_file": "payloads/xss_payloads.txt",
                    "test_types": ["reflected", "stored", "dom"],
                    "confidence_threshold": 0.8
                },
                "csrf": {
                    "enabled": True,
                    "check_tokens": True,
                    "check_referrer": True,
                    "check_origin": True
                },
                "auth": {
                    "enabled": True,
                    "test_session_management": True,
                    "test_privilege_escalation": True,
                    "common_passwords": "payloads/common_passwords.txt"
                },
                "traversal": {
                    "enabled": True,
                    "payload_file": "payloads/traversal_payloads.txt",
                    "encodings": ["url", "double_url", "unicode"]
                },
                "ssrf": {
                    "enabled": True,
                    "payload_file": "payloads/ssrf_payloads.txt",
                    "test_internal_ips": True,
                    "test_cloud_metadata": True
                },
                "xxe": {
                    "enabled": True,
                    "payload_file": "payloads/xxe_payloads.txt",
                    "test_out_of_band": True
                },
                "cmdi": {
                    "enabled": True,
                    "payload_file": "payloads/cmdi_payloads.txt",
                    "test_types": ["direct", "blind", "time"]
                },
                "idor": {
                    "enabled": True,
                    "test_numeric_ids": True,
                    "test_uuid_ids": True,
                    "test_encoded_ids": True
                }
            },
            "recon": {
                "subdomain_enum": {
                    "enabled": True,
                    "wordlist": "payloads/subdomains.txt",
                    "dns_servers": ["8.8.8.8", "1.1.1.1"],
                    "check_certificate_transparency": True,
                    "brute_force": True
                },
                "port_scan": {
                    "enabled": True,
                    "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443],
                    "full_scan": False,
                    "banner_grab": True,
                    "service_detection": True
                },
                "tech_fingerprint": {
                    "enabled": True,
                    "check_headers": True,
                    "check_cookies": True,
                    "check_html_patterns": True,
                    "check_js_libraries": True
                },
                "url_discovery": {
                    "enabled": True,
                    "wordlist": "payloads/directories.txt",
                    "extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ".js"],
                    "check_robots_txt": True,
                    "check_sitemap_xml": True
                }
            },
            "reporting": {
                "include_screenshots": False,
                "include_payload_details": True,
                "confidence_filter": 0.5,
                "formats": {
                    "html": {
                        "template": "templates/report.html",
                        "include_css": True
                    },
                    "json": {
                        "pretty_print": True
                    },
                    "pdf": {
                        "template": "templates/report_pdf.html"
                    }
                }
            },
            "output": {
                "directory": "reports",
                "timestamp_format": "%Y%m%d_%H%M%S",
                "log_level": "INFO",
                "save_raw_responses": False
            }
        }
    
    def load_config(self):
        """Load configuration from file, falling back to defaults."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
                
                # Merge with defaults
                self.config = self._merge_configs(self.default_config, file_config)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self.config = self.default_config.copy()
                logger.warning(f"Configuration file {self.config_file} not found, using defaults")
            
            # Load individual scanner configurations
            self._load_scanner_configs()
                
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            logger.warning("Falling back to default configuration")
            self.config = self.default_config.copy()
    
    def _load_scanner_configs(self):
        """Load individual scanner configuration files from config/scanners/"""
        scanners_config_dir = Path(self.config_file).parent / 'scanners'
        
        if not scanners_config_dir.exists():
            logger.debug(f"Scanner config directory does not exist: {scanners_config_dir}")
            return
        
        logger.info(f"Loading scanner configurations from: {scanners_config_dir}")
        
        # Find all .yml files in the scanners config directory
        config_files = scanners_config_dir.glob('*.yml')
        
        for config_file in config_files:
            scanner_name = config_file.stem
            try:
                with open(config_file, 'r') as f:
                    scanner_config = yaml.safe_load(f) or {}
                
                # Merge with existing scanner config (if any)
                if 'scanners' not in self.config:
                    self.config['scanners'] = {}
                
                if scanner_name in self.config['scanners']:
                    self.config['scanners'][scanner_name] = self._merge_configs(
                        self.config['scanners'][scanner_name], scanner_config
                    )
                else:
                    self.config['scanners'][scanner_name] = scanner_config
                
                logger.debug(f"Loaded scanner config: {scanner_name}")
                
            except Exception as e:
                logger.warning(f"Error loading scanner config {config_file}: {str(e)}")

    def _merge_configs(self, default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        result = default.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'scanners.sqli.enabled')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'scanners.sqli.enabled')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, file_path: str = None):
        """
        Save current configuration to file.
        
        Args:
            file_path: Path to save configuration (defaults to current config file)
        """
        file_path = file_path or self.config_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=True)
            
            logger.info(f"Configuration saved to {file_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            raise
    
    def validate_config(self) -> bool:
        """
        Validate the current configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check required sections
            required_sections = ['general', 'scanners', 'recon', 'reporting', 'output']
            for section in required_sections:
                if section not in self.config:
                    logger.error(f"Missing required configuration section: {section}")
                    return False
            
            # Validate general settings
            general = self.config['general']
            if not isinstance(general.get('threads'), int) or general.get('threads') <= 0:
                logger.error("Invalid threads configuration")
                return False
            
            if not isinstance(general.get('timeout'), (int, float)) or general.get('timeout') <= 0:
                logger.error("Invalid timeout configuration")
                return False
            
            # Validate payload files exist (if specified)
            for scanner_name, scanner_config in self.config['scanners'].items():
                payload_file = scanner_config.get('payload_file')
                if payload_file and not os.path.exists(payload_file):
                    logger.warning(f"Payload file not found for {scanner_name}: {payload_file}")
            
            logger.info("Configuration validation successful")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {str(e)}")
            return False
    
    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """Get configuration for a specific scanner."""
        return self.config.get('scanners', {}).get(scanner_name, {})
    
    def get_recon_config(self, recon_name: str) -> Dict[str, Any]:
        """Get configuration for a specific reconnaissance module."""
        return self.config.get('recon', {}).get(recon_name, {})
    
    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled."""
        return self.get_scanner_config(scanner_name).get('enabled', False)
    
    def is_recon_enabled(self, recon_name: str) -> bool:
        """Check if a reconnaissance module is enabled."""
        return self.get_recon_config(recon_name).get('enabled', False)