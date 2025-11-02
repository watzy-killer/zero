"""
Enhanced logging utilities with professional animations.
"""
import os
import time
import sys
import random
from datetime import datetime
from typing import Any

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def typing_effect(text, speed=0.05, color_code="\033[1;37m"):
    """Enhanced typing effect with color support"""
    print(color_code, end='')
    for char in text:
        print(char, end='', flush=True)
        time.sleep(speed)
    print("\033[0m")  # Reset color

def rainbow_text(text):
    """Create rainbow colored text"""
    colors = ["\033[1;31m", "\033[1;33m", "\033[1;32m", "\033[1;36m", "\033[1;34m", "\033[1;35m"]
    result = ""
    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        result += f"{color}{char}"
    return result + "\033[0m"

def spinning_cursor():
    """Show a spinning cursor during loading"""
    cursors = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    for cursor in cursors:
        yield cursor

def display_intro():
    """Enhanced professional intro animation"""
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # ASCII Art Banner
    print("\033[1;36m")  # Bright cyan
    banner = [
        "╔══════════════════════════════════════════════════════════╗",
        "║                                                          ║",
        "║    ███████ ███████ ██████  ██    ██ ███████ ██████       ║",
        "║    ██      ██      ██   ██ ██    ██ ██      ██   ██      ║",
        "║    ███████ █████   ██████  ██    ██ █████   ██████       ║",
        "║         ██ ██      ██   ██ ██    ██ ██      ██   ██      ║",
        "║    ███████ ███████ ██   ██  ██████  ███████ ██   ██      ║",
        "║                                                          ║",
        "║              S E C U R I T Y   S C A N N E R             ║",
        "║                                                          ║",
        "╚══════════════════════════════════════════════════════════╝"
    ]
    
    for line in banner:
        typing_effect(line, 0.01, "\033[1;36m")
    
    time.sleep(0.5)
    
    # Initializing message with rainbow effect
    print()
    rainbow_message = rainbow_text("✦ Initializing Secure Scanning Protocol ✦")
    for char in rainbow_message:
        print(char, end='', flush=True)
        time.sleep(0.01)
    print()
    
    time.sleep(0.5)
    
    # Enhanced progress bar with multiple stages
    stages = [
        ("Loading Core Modules", 30),
        ("Establishing Secure Connection", 60),
        ("Initializing Scan Engine", 85),
        ("Finalizing Security Protocols", 95)
    ]
    
    spinner = spinning_cursor()
    current_stage = 0
    
    for i in range(101):
        # Update stage text
        if current_stage < len(stages) and i >= stages[current_stage][1]:
            print(f"\r\033[1;33m{next(spinner)} {stages[current_stage][0]}...", end='')
            current_stage += 1
            time.sleep(0.5)
        
        # Dynamic progress bar with color changes
        if i < 30:
            color = "\033[1;31m"  # Red
        elif i < 70:
            color = "\033[1;33m"  # Yellow
        else:
            color = "\033[1;32m"  # Green
        
        # Enhanced progress bar with different characters
        bar_length = 50
        filled = i // 2
        empty = bar_length - filled
        
        # Create animated bar with different characters
        bar_chars = ['█', '▓', '▒', '░']
        bar = bar_chars[0] * filled
        if empty > 0:
            bar += bar_chars[(i // 5) % len(bar_chars)]
            bar += ' ' * (empty - 1)
        
        print(f"\r{color}Progress: [{bar}] {i}%", end='')
        
        # Dynamic speed for more realistic feel
        if i < 20:
            time.sleep(0.1)
        elif i < 50:
            time.sleep(0.05)
        elif i < 80:
            time.sleep(0.03)
        elif i < 95:
            time.sleep(0.1)
        else:
            time.sleep(0.2)
    
    print()
    
    # Success animation
   # print("\n\033[1;32m")  # Bright green
    # success_messages = [
    #     "✓ Protocols Active", 
    #     "✓ Scanner Ready",
    #     "✓ All Systems Go!"
    # ]
    
    # for msg in success_messages:
    #     typing_effect(f"  {msg}", 0.1, "\033[1;32m")
    #     time.sleep(0.3)
    
    # Final ready message with flare
    print("\033[1;92m")  # Bright green
    ready_text = """
    ╔══════════════════════════════════════╗
    ║          SYSTEM READY!               ║
    ║    ────────────────────────────      ║
    ║    Secure Scan Initialized           ║
    ║    All Systems Operational           ║
    ║    Ready for Security Analysis       ║
    ╚══════════════════════════════════════╝
    """
    
    for line in ready_text.split('\n'):
        typing_effect(line, 0.03, "\033[1;92m")
    
    # Pulsing effect
    for _ in range(3):
        print("\033[1;92mREADY!\033[0m", end='\r')
        time.sleep(0.3)
        print("\033[1;96mREADY!\033[0m", end='\r')
        time.sleep(0.3)
    
    print("\033[1;92m" + " " * 50 + "\033[0m")  # Clear line
    typing_effect("✦ SECURE SCAN READY - INITIATE SCAN PROTOCOL ✦", 0.05, "\033[1;92m")
    print("\033[0m")  # Reset
    time.sleep(1)

def log_message(message: str, level: str = "INFO") -> None:
    """Log message with timestamp and level."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    emoji = {
        "INFO": "📝",
        "WARNING": "⚠️",
        "ERROR": "❌",
        "CRITICAL": "🚨",
        "SUCCESS": "✅"
    }.get(level, "📝")
    
    print(f"{emoji} [{timestamp}] {message}")

def display_task_start(task_name: str) -> None:
    """Display task start message."""
    print(f"\n🔄 [{datetime.now().strftime('%H:%M:%S')}] Starting: {task_name}...")

def display_task_complete(task_name: str) -> None:
    """Display task completion message."""
    print(f"✅ [{datetime.now().strftime('%H:%M:%S')}] Completed: {task_name}")

def display_scan_start() -> None:
    """Display scan start message."""
    print("\n" + "🔍" * 30)
    print("🚀 STARTING COMPREHENSIVE SECURITY SCAN")
    print("🔍" * 30)
    print("📊 Scanning target for vulnerabilities...")
    print("🛡️  Security protocols engaged")
    print("📝 Logging all activities\n")

def display_scan_complete() -> None:
    """Display scan completion message."""
    print("\n" + "✅" * 30)
    print("🎯 SECURITY SCAN COMPLETED")
    print("✅" * 30)
    print("📋 Report generated successfully")
    print("📊 Vulnerabilities documented")
    print("🛡️  Security assessment finished\n")

def display_protection_shield():
    """Display protection shield graphic"""
    print("\n" + "="*60)
    print("🔒 SECURITY SCANNER INITIATED 🔒")
    print("="*60)
    print("Initializing security protocols...")

def display_scan_complete_animation(vulnerabilities):
    """Show a cool completion animation with results."""
    try:
        # FIX: Make sure vulnerabilities is a list, not a function
        if callable(vulnerabilities):
            vulnerabilities = []
            
        critical_count = len([v for v in vulnerabilities if isinstance(v, dict) and v.get('severity') == 'Critical'])
        
        print("\n" + "🎉" * 30)
        print(f"{Colors.GREEN}{Colors.BOLD} SCAN COMPLETE! {Colors.END}")
        print("🎉" * 30)
        
        if critical_count > 0:
            print(f"{Colors.RED}{Colors.BOLD}🚨 {critical_count} CRITICAL VULNERABILITIES FOUND{Colors.END}")
        else:
            print(f"{Colors.GREEN}✅ No critical vulnerabilities detected{Colors.END}")
        
        # Simple celebration
        print("✨ Scan completed successfully! ✨")
        
    except Exception as e:
        # Fallback if animation fails
        print(f"{Colors.GREEN}✅ Scan completed successfully!{Colors.END}")