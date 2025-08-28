#!/usr/bin/env python3
"""
Test the new plugin-based scanner architecture
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.config.config_manager import ConfigManager
from scanners.base_scanner import ScannerRegistry
from core.scanner_controller import ScannerController


def test_plugin_system():
    """Test that the plugin system loads scanners correctly."""
    print("Testing plugin-based scanner architecture...")
    
    try:
        # Initialize configuration
        config_manager = ConfigManager("config/default.yml")
        
        # Test registry discovery
        ScannerRegistry.discover_scanners()
        plugin_scanners = ScannerRegistry.get_scanner_names()
        
        print(f"✅ Discovered {len(plugin_scanners)} plugin scanners: {plugin_scanners}")
        
        # Test scanner controller with both legacy and plugin scanners
        class MockArgs:
            threads = 1
            target = "http://example.com"
        
        args = MockArgs()
        scanner_controller = ScannerController(config_manager, args)
        
        available_scanners = scanner_controller.get_available_scanners()
        print(f"✅ Scanner controller loaded {len(available_scanners)} total scanners")
        
        # Verify XXE scanner is available and is a plugin
        if 'xxe' in available_scanners:
            xxe_scanner = scanner_controller.scanners.get('xxe')
            if hasattr(xxe_scanner, 'config_manager') and hasattr(xxe_scanner, 'is_enabled'):
                print("✅ XXE scanner successfully loaded as plugin")
                return True
            else:
                print("❌ XXE scanner loaded but not as expected plugin instance")
                return False
        else:
            print("❌ XXE scanner not found in available scanners")
            return False
            
    except Exception as e:
        print(f"❌ Plugin system test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_modular_config():
    """Test that modular configuration loading works."""
    print("\nTesting modular configuration system...")
    
    try:
        config_manager = ConfigManager("config/default.yml")
        
        # Test that XXE config was loaded from scanners/xxe.yml
        xxe_config = config_manager.get_scanner_config('xxe')
        
        if xxe_config and xxe_config.get('enabled') and 'test_out_of_band' in xxe_config:
            print("✅ XXE modular configuration loaded successfully")
            print(f"   - Enabled: {xxe_config.get('enabled')}")
            print(f"   - Test OOB: {xxe_config.get('test_out_of_band')}")
            return True
        else:
            print("❌ XXE modular configuration not loaded correctly")
            print(f"   - Config: {xxe_config}")
            return False
            
    except Exception as e:
        print(f"❌ Modular config test failed: {str(e)}")
        return False


if __name__ == "__main__":
    print("="*60)
    print("Plugin Architecture Test Suite")
    print("="*60)
    
    tests = [
        test_plugin_system,
        test_modular_config,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("✅ All plugin architecture tests passed!")
        sys.exit(0)
    else:
        print("❌ Some plugin architecture tests failed!")
        sys.exit(1)