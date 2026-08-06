#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
from core.logger import log_info, log_success, log_error
from core.color_config import use_colors

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def show_main_menu():
    clear_screen()
    G = '\033[92m' if use_colors() else ''
    W = '\033[97m' if use_colors() else ''
    D = '\033[90m' if use_colors() else ''
    B = '\033[1m' if use_colors() else ''
    R = '\033[0m' if use_colors() else ''
    
    print(f"{G}┌─────────────────────────────────────────────────────┐{R}")
    print(f"{G}│{R}  {B}GOODS-DRAGON v2.0{R}                                    {G}│{R}")
    print(f"{G}│{R}  {D}Advanced Pentesting & Bug Bounty Framework{R}            {G}│{R}")
    print(f"{G}│{R}  {D}Owner: 0xL-DRAGON | Team: L-DRAGON{R}                    {G}│{R}")
    print(f"{G}├─────────────────────────────────────────────────────┤{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[1]{R}  {G}Reconnaissance{R}                                    {G}│{R}")
    print(f"{G}│{R}     {D}Subdomain, OSINT, Dark Web, Shodan...{R}              {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[2]{R}  {G}Web Vulnerability Scanner{R}                        {G}│{R}")
    print(f"{G}│{R}     {D}SQLi, XSS, CSRF, SSRF, LFI, RCE...{R}                 {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[3]{R}  {G}Network Scanner{R}                                   {G}│{R}")
    print(f"{G}│{R}     {D}Port, SSL, Brute Force, S3...{R}                       {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[4]{R}  {G}Reports & Payloads{R}                               {G}│{R}")
    print(f"{G}│{R}     {D}HTML, PDF, TXT, HackerOne, Payloads{R}                 {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[5]{R}  {G}Web Control Panel{R}                                {G}│{R}")
    print(f"{G}│{R}     {D}Browser Dashboard on localhost:5000{R}                  {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[6]{R}  {G}Update Tool{R}                                      {G}│{R}")
    print(f"{G}│{R}     {D}Check for latest version from GitHub{R}                 {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[7]{R}  {G}Help & Usage{R}                                     {G}│{R}")
    print(f"{G}│{R}     {D}Show full CLI commands and examples{R}                 {G}│{R}")
    print(f"{G}│{R}                                                     {G}│{R}")
    print(f"{G}│{R}  {B}[0]{R}  {G}Exit{R}                                             {G}│{R}")
    print(f"{G}└─────────────────────────────────────────────────────┘{R}")
    print()
    return input(f"{G}🐉 {W}Select option [0-7]: {R}").strip()

def get_target():
    t = input(f"  Target (domain/IP/URL): ").strip()
    if not t:
        log_error("Target required")
        return None
    return t

def get_threads():
    t = input(f"  Threads [30]: ").strip()
    return int(t) if t.isdigit() else 30

def run(cmd):
    print()
    os.system(cmd)
    input(f"\n  Press Enter for menu...")
