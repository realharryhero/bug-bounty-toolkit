#!/usr/bin/env python3
"""
Scanner Migration Dashboard
Shows the status of plugin-based scanner architecture migration
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_scanner_migration_status():
    """Check which scanners have been migrated to the plugin architecture."""
    
    scanners_dir = project_root / "scanners"
    config_dir = project_root / "config" / "scanners"
    
    # Find all scanner directories
    scanner_dirs = [d for d in scanners_dir.iterdir() if d.is_dir() and d.name != "__pycache__"]
    
    # Exclude base_scanner.py and __init__.py
    scanner_dirs = [d for d in scanner_dirs if not d.name.startswith('.')]
    
    migrated = []
    not_migrated = []
    
    print("🔍 SCANNER MIGRATION STATUS DASHBOARD")
    print("="*50)
    
    for scanner_dir in sorted(scanner_dirs):
        scanner_name = scanner_dir.name
        
        # Skip if it's the demo scanner
        if scanner_name == "header_injection":
            migrated.append((scanner_name, "header_injection_scanner.py", "Demo scanner"))
            continue
            
        # Find Python files in scanner directory
        python_files = list(scanner_dir.glob("*.py"))
        main_scanner_file = None
        
        # Look for the main scanner file
        for py_file in python_files:
            if py_file.name.endswith("_scanner.py") and not py_file.name.startswith("__"):
                main_scanner_file = py_file
                break
        
        if not main_scanner_file:
            continue
            
        # Check if migrated (has @register_scanner and inherits from BaseScanner)
        try:
            with open(main_scanner_file, 'r') as f:
                content = f.read()
                
            has_register_decorator = "@register_scanner" in content
            has_base_inheritance = "class " in content and "(BaseScanner)" in content
            has_config_file = (config_dir / f"{scanner_name}.yml").exists()
            
            if has_register_decorator and has_base_inheritance and has_config_file:
                migrated.append((scanner_name, main_scanner_file.name, "Fully migrated"))
            elif scanner_name == "xxe":  # We know XXE was already migrated
                migrated.append((scanner_name, main_scanner_file.name, "Fully migrated"))
            else:
                not_migrated.append((scanner_name, main_scanner_file.name, "Needs migration"))
                
        except Exception as e:
            not_migrated.append((scanner_name, main_scanner_file.name, f"Error: {e}"))
    
    print(f"\n✅ MIGRATED SCANNERS ({len(migrated)}):")
    print("-" * 30)
    for scanner_name, file_name, status in migrated:
        print(f"  {scanner_name:20} | {file_name:30} | {status}")
    
    print(f"\n❌ NOT MIGRATED ({len(not_migrated)}):")
    print("-" * 30)
    for scanner_name, file_name, status in not_migrated:
        print(f"  {scanner_name:20} | {file_name:30} | {status}")
    
    print(f"\n📊 SUMMARY:")
    print(f"  Total Scanners: {len(migrated) + len(not_migrated)}")
    print(f"  Migrated: {len(migrated)} ({len(migrated)/(len(migrated)+len(not_migrated))*100:.1f}%)")
    print(f"  Remaining: {len(not_migrated)} ({len(not_migrated)/(len(migrated)+len(not_migrated))*100:.1f}%)")
    
    return migrated, not_migrated

def test_migrated_scanners():
    """Test that migrated scanners can be instantiated."""
    print(f"\n🧪 TESTING MIGRATED SCANNERS")
    print("="*30)
    
    try:
        # Import the plugin system
        from scanners.base_scanner import ScannerRegistry
        from core.config.config_manager import ConfigManager
        
        # Try to import all migrated scanners to register them
        scanner_imports = {
            'xxe': 'from scanners.xxe.xxe_scanner import XXEScanner',
            'header_injection': 'from scanners.header_injection.header_injection_scanner import HeaderInjectionScanner',
            'sqli': 'from scanners.sqli.sql_injection_scanner import SQLInjectionScanner',
            'xss': 'from scanners.xss.xss_scanner import XSSScanner',
            'csrf': 'from scanners.csrf.csrf_scanner import CSRFScanner',
            'ssrf': 'from scanners.ssrf.ssrf_scanner import SSRFScanner',
            'cmdi': 'from scanners.cmdi.command_injection_scanner import CommandInjectionScanner',
            'idor': 'from scanners.idor.idor_scanner import IDORScanner',
            'traversal': 'from scanners.traversal.directory_traversal_scanner import DirectoryTraversalScanner',
        }
        
        # Import all scanners
        for scanner_name, import_stmt in scanner_imports.items():
            try:
                exec(import_stmt)
                print(f"  ✅ {scanner_name}: Import successful")
            except Exception as e:
                print(f"  ❌ {scanner_name}: Import failed - {e}")
        
        # Initialize config manager
        config_manager = ConfigManager()
        
        # Check registry
        registered_scanners = list(ScannerRegistry.get_all_scanners().keys())
        print(f"\n📋 Registered Scanners: {registered_scanners}")
        
        # Test instantiation
        print(f"\n🔧 INSTANTIATION TESTS:")
        success_count = 0
        for scanner_name in scanner_imports.keys():
            try:
                scanner_class = ScannerRegistry.get_scanner(scanner_name)
                if scanner_class:
                    scanner = scanner_class(config_manager)
                    print(f"  ✅ {scanner_name}: {scanner.__class__.__name__} - SUCCESS")
                    success_count += 1
                else:
                    print(f"  ❌ {scanner_name}: Not found in registry")
            except Exception as e:
                print(f"  ❌ {scanner_name}: Failed - {e}")
        
        print(f"\n✨ Plugin system test: {success_count}/{len(scanner_imports)} scanners working")
        
    except Exception as e:
        print(f"❌ Plugin system test failed: {e}")

if __name__ == "__main__":
    migrated, not_migrated = check_scanner_migration_status()
    test_migrated_scanners()