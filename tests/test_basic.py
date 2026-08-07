def test_import():
    """Test that core modules can be imported"""
    from core.color_config import use_colors
    from core.logger import log_info

    assert True


def test_version():
    """Test version consistency"""
    import re

    with open("main.py") as f:
        content = f.read()
    assert "v2.0.0" in content
