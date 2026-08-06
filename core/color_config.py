# Global color mode: 'auto', 'always', 'never'
COLOR_MODE = "auto"


def use_colors():
    """Check if colors should be used based on current mode."""
    import sys

    if COLOR_MODE == "always":
        return True
    elif COLOR_MODE == "never":
        return False
    else:  # auto
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def set_color_mode(mode):
    global COLOR_MODE
    if mode in ("auto", "always", "never"):
        COLOR_MODE = mode
