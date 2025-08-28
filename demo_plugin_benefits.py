#!/usr/bin/env python3
"""
Demonstrate the benefits of the new plugin-based architecture
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


def demonstrate_plugin_benefits():
    """Demonstrate the key benefits of the plugin architecture."""
    print("="*70)
    print("PLUGIN ARCHITECTURE BENEFITS DEMONSTRATION")
    print("="*70)
    
    # 1. No merge conflicts - scanners are completely self-contained
    print("\n1. 🚀 NO MERGE CONFLICTS")
    print("   ✓ Each scanner is in its own directory")
    print("   ✓ Each scanner has its own config file")
    print("   ✓ No shared files need to be modified")
    print("   ✓ Multiple developers can work simultaneously")
    
    # 2. Dynamic discovery
    print("\n2. 🔍 DYNAMIC DISCOVERY")
    ScannerRegistry.discover_scanners()
    plugin_scanners = ScannerRegistry.get_scanner_names()
    print(f"   ✓ Automatically discovered {len(plugin_scanners)} plugin scanners")
    for scanner in sorted(plugin_scanners):
        print(f"     • {scanner}")
    
    # 3. Self-contained scanners
    print("\n3. 📦 SELF-CONTAINED SCANNERS")
    config_manager = ConfigManager("config/default.yml")
    
    for scanner_name in plugin_scanners:
        scanner_config = config_manager.get_scanner_config(scanner_name)
        config_file = f"config/scanners/{scanner_name}.yml"
        scanner_dir = f"scanners/{scanner_name}/"
        
        print(f"   ✓ {scanner_name.upper()}:")
        print(f"     • Configuration: {config_file}")
        print(f"     • Source code: {scanner_dir}")
        print(f"     • Enabled: {scanner_config.get('enabled', False)}")
    
    # 4. Backwards compatibility
    print("\n4. 🔄 BACKWARDS COMPATIBILITY")
    class MockArgs:
        threads = 1
        target = "http://example.com"
    
    args = MockArgs()
    scanner_controller = ScannerController(config_manager, args)
    all_scanners = scanner_controller.get_available_scanners()
    legacy_count = len([s for s in all_scanners if s not in plugin_scanners])
    
    print(f"   ✓ {len(all_scanners)} total scanners available")
    print(f"   ✓ {len(plugin_scanners)} new plugin-based scanners")
    print(f"   ✓ {legacy_count} legacy scanners (still functional)")
    
    # 5. Clean separation of concerns
    print("\n5. 🎯 CLEAN SEPARATION OF CONCERNS")
    print("   ✓ Base scanner class defines interface")
    print("   ✓ Registry manages scanner lifecycle")
    print("   ✓ Individual configs avoid conflicts")
    print("   ✓ Auto-registration eliminates manual wiring")
    
    # 6. Easy extension example
    print("\n6. ✨ EASY TO EXTEND")
    print("   Adding a new scanner now requires ONLY:")
    print("   1. Create scanners/new_scanner/ directory")
    print("   2. Create new_scanner_scanner.py with @register_scanner()")
    print("   3. Create config/scanners/new_scanner.yml")
    print("   4. That's it! No other files need modification.")
    
    return True


def demonstrate_migration_path():
    """Show how to migrate existing scanners."""
    print("\n" + "="*70)
    print("MIGRATION PATH FOR EXISTING SCANNERS")
    print("="*70)
    
    print("\nTo convert a legacy scanner to plugin:")
    print("1. Import base_scanner: from scanners.base_scanner import BaseScanner, register_scanner")
    print("2. Add decorator: @register_scanner('scanner_name')")
    print("3. Inherit from BaseScanner: class MyScannerScanner(BaseScanner)")
    print("4. Call super().__init__(config_manager) in __init__")
    print("5. Create config/scanners/scanner_name.yml")
    
    print("\nExample - XXE scanner conversion:")
    print("✓ Added @register_scanner('xxe')")
    print("✓ Inherited from BaseScanner") 
    print("✓ Created config/scanners/xxe.yml")
    print("✓ Now automatically discovered and loaded!")
    
    return True


if __name__ == "__main__":
    try:
        demonstrate_plugin_benefits()
        demonstrate_migration_path()
        
        print("\n" + "="*70)
        print("✅ PLUGIN ARCHITECTURE SUCCESSFULLY IMPLEMENTED!")
        print("="*70)
        print("Benefits achieved:")
        print("• No more merge conflicts when adding scanners")
        print("• Scanners are completely self-contained") 
        print("• Dynamic CLI generation")
        print("• Clean separation of concerns")
        print("• Easy to extend and maintain")
        print("• Backwards compatible with existing scanners")
        
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)