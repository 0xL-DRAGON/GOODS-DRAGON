#!/usr/bin/env python3
"""Patch main.py to auto-install dependencies"""
import re

with open('main.py', 'r') as f:
    content = f.read()

# Add import for dependency checker
import_line = "from core.dependency_checker import check_module_dependencies\n"
if import_line not in content:
    # Add after last core import
    content = content.replace(
        "from core.logger import log_info, log_error, log_success, log_warning",
        "from core.logger import log_info, log_error, log_success, log_warning\nfrom core.dependency_checker import check_module_dependencies"
    )

# Add check before brute force
bruteforce_section = """        if args.bruteforce:
            from modules.scan.bruteforce import BruteForce"""
    
bruteforce_with_check = """        if args.bruteforce:
            if not check_module_dependencies("modules.scan.bruteforce"):
                log_error("Skipping brute force - missing dependencies")
            else:
                from modules.scan.bruteforce import BruteForce"""

if "check_module_dependencies" not in content.split("if args.bruteforce:")[1].split("\n")[0]:
    content = content.replace(bruteforce_section, bruteforce_with_check)

# Add check before browser emulator
browser_section = """        if args.browser_emulator:
            from modules.core.browser_emulator import BrowserEmulator"""
            
browser_with_check = """        if args.browser_emulator:
            if not check_module_dependencies("modules.core.browser_emulator"):
                log_error("Skipping browser emulator - missing dependencies")
            else:
                from modules.core.browser_emulator import BrowserEmulator"""

if "check_module_dependencies" not in content.split("if args.browser_emulator:")[1].split("\n")[0]:
    content = content.replace(browser_section, browser_with_check)

# Add check before stealth pro
stealth_section = """        if args.stealth_pro:
            from modules.core.stealth_pro import StealthPro"""
            
stealth_with_check = """        if args.stealth_pro:
            if not check_module_dependencies("modules.core.stealth_pro"):
                log_error("Skipping stealth pro - missing dependencies")
            else:
                from modules.core.stealth_pro import StealthPro"""

if "check_module_dependencies" not in content.split("if args.stealth_pro:")[1].split("\n")[0]:
    content = content.replace(stealth_section, stealth_with_check)

# Add --check-deps flag
if "'--check-deps'" not in content:
    # Add before --update check
    update_check = "if \"--update\" in sys.argv:"
    deps_check = """if \"--check-deps\" in sys.argv:
        from core.dependency_checker import print_dependency_status
        print_dependency_status()
        sys.exit(0)

"""
    content = content.replace(update_check, deps_check + update_check)

with open('main.py', 'w') as f:
    f.write(content)

print("✅ main.py patched with auto-dependency checker!")
print("New features:")
print("  - Dependencies auto-install when needed")
print("  - python main.py --check-deps (check status)")
print("  - No manual setup required!")
