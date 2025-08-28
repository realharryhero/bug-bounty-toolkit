"""
Logging utilities for the bug bounty toolkit
"""

import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup structured logging for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Create formatter
    formatter = logging.Formatter(log_format, datefmt=date_format)
    
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (always log to file for audit purposes)
    if not log_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"bug_bounty_toolkit_{timestamp}.log"
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # Always capture all details in file
    logger.addHandler(file_handler)
    
    # Audit handler (separate file for security-related events)
    audit_file = log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
    audit_handler = logging.FileHandler(audit_file)
    audit_formatter = logging.Formatter(
        "%(asctime)s - AUDIT - %(message)s", 
        datefmt=date_format
    )
    audit_handler.setFormatter(audit_formatter)
    audit_handler.setLevel(logging.INFO)
    
    # Create audit logger
    audit_logger = logging.getLogger("audit")
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    
    logger.info(f"Logging initialized - Level: {level}, File: {log_file}")
    
    return logger

def get_audit_logger() -> logging.Logger:
    """Get the audit logger for security events."""
    return logging.getLogger("audit")

class ColoredFormatter(logging.Formatter):
    """Colored console formatter for better readability."""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        """Format log record with colors."""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

def setup_colored_logging(level: str = "INFO") -> logging.Logger:
    """
    Setup colored console logging for development.
    
    Args:
        level: Logging level
        
    Returns:
        Configured logger with colored output
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    colored_formatter = ColoredFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(colored_formatter)
    logger.addHandler(console_handler)
    
    return logger

class SecurityLogger:
    """Special logger for security-related events and audit trails."""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
        self.audit_logger = get_audit_logger()
    
    def log_scan_start(self, scan_type: str, target: str, user: str = None):
        """Log the start of a security scan."""
        user = user or os.getenv("USER", "unknown")
        message = f"SCAN_START - Type: {scan_type}, Target: {target}, User: {user}"
        self.audit_logger.info(message)
        self.logger.info(f"Started {scan_type} scan on {target}")
    
    def log_scan_complete(self, scan_type: str, target: str, findings_count: int):
        """Log the completion of a security scan."""
        message = f"SCAN_COMPLETE - Type: {scan_type}, Target: {target}, Findings: {findings_count}"
        self.audit_logger.info(message)
        self.logger.info(f"Completed {scan_type} scan on {target} - {findings_count} findings")
    
    def log_vulnerability_found(self, vuln_type: str, target: str, severity: str, confidence: float):
        """Log discovery of a potential vulnerability."""
        message = f"VULNERABILITY - Type: {vuln_type}, Target: {target}, Severity: {severity}, Confidence: {confidence}"
        self.audit_logger.warning(message)
        self.logger.warning(f"Potential {vuln_type} vulnerability found on {target} (Confidence: {confidence})")
    
    def log_authorization_check(self, target: str, authorized: bool, method: str):
        """Log authorization verification attempts."""
        status = "GRANTED" if authorized else "DENIED"
        message = f"AUTHORIZATION_{status} - Target: {target}, Method: {method}"
        self.audit_logger.info(message)
        
        if authorized:
            self.logger.info(f"Authorization granted for {target}")
        else:
            self.logger.warning(f"Authorization denied for {target}")
    
    def log_rate_limit(self, target: str, requests_sent: int, delay: float):
        """Log rate limiting activities."""
        message = f"RATE_LIMIT - Target: {target}, Requests: {requests_sent}, Delay: {delay}s"
        self.audit_logger.debug(message)
    
    def log_error(self, error_type: str, message: str, target: str = None):
        """Log errors and exceptions."""
        log_message = f"ERROR - Type: {error_type}, Message: {message}"
        if target:
            log_message += f", Target: {target}"
        
        self.audit_logger.error(log_message)
        self.logger.error(f"{error_type}: {message}")

# Global security logger instance
security_logger = SecurityLogger()

def get_security_logger() -> SecurityLogger:
    """Get the global security logger instance."""
    return security_logger