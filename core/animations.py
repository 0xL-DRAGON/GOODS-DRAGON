#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GOODS-DRAGON - Terminal Animations & Progress System
"""

import sys
import time
import threading
import random
from core.color_config import use_colors

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'
DIM = '\033[90m'


def _c(color_code, text):
    if use_colors():
        return f"{color_code}{text}\033[0m"
    return text

class ProgressBar:
    """Animated progress bar for scan operations"""
    
    def __init__(self, total=100, prefix='Scanning', suffix='Complete', length=30):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.current = 0
        self.running = True
        self.thread = None
    
    def update(self, current):
        self.current = min(current, self.total)
        percent = int(100 * (self.current / self.total))
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '░' * (self.length - filled)
        
        if percent < 100:
            color = CYAN if use_colors() else ''
        else:
            color = GREEN if use_colors() else ''
        
        sys.stdout.write(f'\r{self.prefix:20} [{color}{bar}{_c(RESET, '') if not use_colors() else RESET}] {percent}%')
        sys.stdout.flush()
        
        if percent >= 100:
            print(f' {GREEN}✅{RESET}')
    
    def start_animation(self):
        """Simulate progress with random increments"""
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
    
    def _animate(self):
        symbols = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        i = 0
        while self.running and self.current < self.total:
            i = (i + 1) % len(symbols)
            if use_colors():
                sys.stdout.write(f'\r{CYAN}{symbols[i]}{RESET} {self.prefix}...')
            else:
                sys.stdout.write(f'\r{symbols[i]} {self.prefix}...')
            sys.stdout.flush()
            time.sleep(0.1)
    
    def stop(self, success=True):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
        if success:
            self.update(self.total)
        else:
            if use_colors():
                sys.stdout.write(f'\r{self.prefix:20} {RED}✕ Failed{RESET}\n')
            else:
                sys.stdout.write(f'\r{self.prefix:20} X Failed\n')
            sys.stdout.flush()

class HackerUI:
    """Main hacker-style interface for scan operations"""
    
    @staticmethod
    def scan_header(target, module_name):
        """Display scan start header"""
        print()
        if use_colors():
            print(f"{GREEN}╔{'═'*60}╗{RESET}")
            print(f"{GREEN}║{RESET} {BOLD}🐉 GOODS-DRAGON - {module_name}{RESET}")
            print(f"{GREEN}╠{'═'*60}╣{RESET}")
            print(f"{GREEN}║{RESET} {DIM}Target:{RESET} {CYAN}{target}{RESET}")
            print(f"{GREEN}╚{'═'*60}╝{RESET}")
        else:
            print(f"╔{'═'*60}╗")
            print(f"║ GOODS-DRAGON - {module_name}")
            print(f"╠{'═'*60}╣")
            print(f"║ Target: {target}")
            print(f"╚{'═'*60}╝")
        print()
    
    @staticmethod
    def scan_footer(results_file=None):
        """Display scan completion"""
        print()
        if use_colors():
            print(f"{GREEN}╔{'═'*60}╗{RESET}")
            print(f"{GREEN}║{RESET}  {BOLD}✅ Scan Complete!{RESET}")
            if results_file:
                print(f"{GREEN}║{RESET}  {DIM}📄 Results:{RESET} {CYAN}{results_file}{RESET}")
            print(f"{GREEN}╚{'═'*60}╝{RESET}")
        else:
            print(f"╔{'═'*60}╗")
            print(f"║  Scan Complete!")
            if results_file:
                print(f"║  Results: {results_file}")
            print(f"╚{'═'*60}╝")
        print()
    
    @staticmethod
    def matrix_effect(duration=2):
        """Display Matrix-style rain effect"""
        import random
        if not use_colors():
            return
        chars = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃ0123456789'
        width = 60
        end_time = time.time() + duration
        
        while time.time() < end_time:
            line = ''.join(random.choice(chars) if random.random() > 0.5 else ' ' for _ in range(width))
            sys.stdout.write(f'\r{DIM}{GREEN}{line}{RESET}')
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write('\r' + ' ' * width + '\r')
    
    @staticmethod
    def countdown(message, seconds=3):
        """Display countdown before scan"""
        if use_colors():
            for i in range(seconds, 0, -1):
                sys.stdout.write(f'\r{YELLOW}⏳ {message} in {i}...{RESET}')
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write(f'\r{GREEN}🚀 {message}...{RESET}\n')
        else:
            for i in range(seconds, 0, -1):
                sys.stdout.write(f'\r[*] {message} in {i}...')
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write(f'\r[+] {message}...\n')

