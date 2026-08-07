"""Basic tests for GOODS-DRAGON"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_import_core():
    """Test that core modules can be imported"""
    from core.logger import log_info, log_error, log_success, log_warning
    from core.color_config import use_colors, set_color_mode
    from core.network import resolve_domain
    assert True

def test_import_modules():
    """Test that key modules can be imported"""
    from modules.recon.subdomain import SubdomainFinder
    from modules.web.sqli import SQLiScanner
    from modules.web.xss import XSSScanner
    from modules.scan.portscan import PortScanner
    assert True

def test_version_string():
    """Test that version is consistent"""
    with open("main.py", "r") as f:
        content = f.read()
    assert "v2.0.0" in content

def test_color_config():
    """Test color configuration"""
    from core.color_config import set_color_mode, use_colors
    set_color_mode("never")
    assert use_colors() == False
    set_color_mode("always")
    assert use_colors() == True
    set_color_mode("auto")
