#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GOODS-DRAGON - Sound Effects
"""

import os
import sys
import time


def beep(times=3, delay=0.2):
    """Simple system beep"""
    for _ in range(times):
        sys.stdout.write("\a")
        sys.stdout.flush()
        time.sleep(delay)


def alert_sound():
    """Alert sound when scan finishes"""
    try:
        # Try playsound
        import subprocess

        if os.name == "nt":
            import winsound

            winsound.Beep(1000, 500)
        else:
            # Linux/Termux
            beep(5, 0.15)
    except:
        beep(3, 0.2)


def scan_complete_sound():
    """Happy sound for successful scan"""
    alert_sound()


def error_sound():
    """Error alert sound"""
    beep(1, 0.5)
    beep(1, 0.5)
    beep(1, 0.5)
