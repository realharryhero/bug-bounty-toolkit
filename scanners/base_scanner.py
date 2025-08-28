"""
Base Scanner Architecture - Registry and base classes for plugin-based scanners
"""

import logging
import os
import importlib
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Type, Optional
from pathlib import Path
from core.reporting.report_generator import Finding

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Registry for managing scanner plugins."""
    
    _instance = None
    _scanners: Dict[str, Type['BaseScanner']] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScannerRegistry, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def register_scanner(cls, name: str, scanner_class: Type['BaseScanner']):
        """
        Register a scanner plugin.
        
        Args:
            name: Scanner identifier (e.g., 'xxe', 'xss')
            scanner_class: Scanner class that inherits from BaseScanner
        """
        if name in cls._scanners:
            logger.warning(f"Scanner '{name}' is already registered. Overriding.")
        
        cls._scanners[name] = scanner_class
        logger.debug(f"Registered scanner: {name}")
    
    @classmethod
    def get_scanner(cls, name: str) -> Optional[Type['BaseScanner']]:
        """Get a scanner class by name."""
        return cls._scanners.get(name)
    
    @classmethod
    def get_all_scanners(cls) -> Dict[str, Type['BaseScanner']]:
        """Get all registered scanners."""
        return cls._scanners.copy()
    
    @classmethod
    def get_scanner_names(cls) -> List[str]:
        """Get list of all registered scanner names."""
        return list(cls._scanners.keys())
    
    @classmethod
    def discover_scanners(cls, scanners_dir: str = None):
        """
        Discover and load scanner modules from filesystem.
        
        Args:
            scanners_dir: Directory containing scanner modules (defaults to scanners/)
        """
        if scanners_dir is None:
            scanners_dir = Path(__file__).parent
        else:
            scanners_dir = Path(scanners_dir)
        
        if not scanners_dir.exists():
            logger.warning(f"Scanners directory does not exist: {scanners_dir}")
            return
        
        logger.info(f"Discovering scanners in: {scanners_dir}")
        
        # Look for scanner modules in subdirectories
        for scanner_dir in scanners_dir.iterdir():
            if scanner_dir.is_dir() and not scanner_dir.name.startswith('__'):
                cls._load_scanner_from_directory(scanner_dir)
    
    @classmethod
    def _load_scanner_from_directory(cls, scanner_dir: Path):
        """Load scanner from a directory."""
        scanner_name = scanner_dir.name
        
        # Skip base_scanner directory
        if scanner_name == 'base_scanner':
            return
        
        # Look for scanner file with pattern *_scanner.py
        scanner_files = list(scanner_dir.glob('*_scanner.py'))
        
        if not scanner_files:
            logger.debug(f"No scanner file found in {scanner_dir}")
            return
        
        scanner_file = scanner_files[0]  # Use first match
        module_name = scanner_file.stem
        
        try:
            # Import the module
            module_path = f"scanners.{scanner_name}.{module_name}"
            importlib.import_module(module_path)
            logger.debug(f"Successfully loaded scanner module: {module_path}")
            
        except ImportError as e:
            logger.warning(f"Failed to import scanner module {module_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error loading scanner from {scanner_dir}: {str(e)}")


class BaseScanner(ABC):
    """
    Base class for all vulnerability scanners.
    
    All scanners should inherit from this class and implement the scan method.
    They should also register themselves using the register_as decorator or
    by calling ScannerRegistry.register_scanner().
    """
    
    def __init__(self, config_manager):
        """
        Initialize the base scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config_manager = config_manager
        self.config = self._load_scanner_config()
        self.general_config = config_manager.get('general', {})
    
    @abstractmethod
    def scan(self, target: str) -> List[Finding]:
        """
        Perform vulnerability scan on the target.
        
        Args:
            target: Target URL or endpoint to scan
            
        Returns:
            List of Finding objects representing discovered vulnerabilities
        """
        pass
    
    def _load_scanner_config(self) -> Dict[str, Any]:
        """Load scanner-specific configuration."""
        scanner_name = self.get_scanner_name()
        return self.config_manager.get_scanner_config(scanner_name)
    
    @classmethod
    def get_scanner_name(cls) -> str:
        """
        Get the scanner name for registration.
        
        Default implementation extracts name from class name by removing 'Scanner' suffix.
        Override this method if you need custom naming.
        """
        class_name = cls.__name__
        if class_name.endswith('Scanner'):
            scanner_name = class_name[:-7].lower()
        else:
            scanner_name = class_name.lower()
        
        return scanner_name
    
    def is_enabled(self) -> bool:
        """Check if this scanner is enabled in configuration."""
        return self.config.get('enabled', False)


def register_scanner(name: str = None):
    """
    Decorator to register a scanner class.
    
    Args:
        name: Optional scanner name (defaults to auto-generated from class name)
    
    Usage:
        @register_scanner()
        class MyScanner(BaseScanner):
            pass
        
        @register_scanner('custom_name')
        class MyScanner(BaseScanner):
            pass
    """
    def decorator(scanner_class: Type[BaseScanner]):
        scanner_name = name or scanner_class.get_scanner_name()
        ScannerRegistry.register_scanner(scanner_name, scanner_class)
        return scanner_class
    
    return decorator