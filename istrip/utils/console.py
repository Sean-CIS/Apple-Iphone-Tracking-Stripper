"""Console output helpers — colored banners, progress, status messages."""

import sys

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


BANNER = rf"""
{CYAN}{BOLD}
  _ ____  _        _
 (_) ___|| |_ _ __(_)_ __
 | \___ \| __| '__| | '_ \
 | |___) | |_| |  | | |_) |
 |_|____/ \__|_|  |_| .__/
                     |_|
{RESET}
 {MAGENTA}iPhone Tracking Stripper v1.0{RESET}
 {DIM}Advanced tracking removal for iOS devices{RESET}
"""


def print_banner():
    """Print the application banner."""
    print(BANNER)


def status(msg: str, level: str = "info"):
    """Print a colored status message."""
    icons = {
        "info": f"{CYAN}[*]{RESET}",
        "ok": f"{GREEN}[+]{RESET}",
        "warn": f"{YELLOW}[!]{RESET}",
        "error": f"{RED}[-]{RESET}",
        "action": f"{MAGENTA}[>]{RESET}",
    }
    icon = icons.get(level, icons["info"])
    print(f" {icon} {msg}")


def header(title: str):
    """Print a section header."""
    width = 60
    print(f"\n {BOLD}{CYAN}{'─' * width}{RESET}")
    print(f" {BOLD}{CYAN}  {title}{RESET}")
    print(f" {BOLD}{CYAN}{'─' * width}{RESET}\n")


def prompt_confirm(msg: str, default: bool = True) -> bool:
    """Ask the user a yes/no question."""
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f" {YELLOW}[?]{RESET} {msg} {suffix}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def prompt_choice(msg: str, choices: list[str]) -> int:
    """Present numbered choices, return the selected index."""
    print(f"\n {YELLOW}[?]{RESET} {msg}\n")
    for i, choice in enumerate(choices, 1):
        print(f"     {BOLD}{i}.{RESET} {choice}")
    print()
    while True:
        try:
            raw = input(f" {YELLOW}>>>{RESET} Enter choice (1-{len(choices)}): ").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(choices):
                return idx
        except (ValueError, EOFError, KeyboardInterrupt):
            print()
            return 0
        status("Invalid choice, try again.", "warn")


def progress_bar(current: int, total: int, label: str = "", width: int = 40):
    """Print a simple progress bar that overwrites itself."""
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    sys.stdout.write(f"\r {CYAN}[{bar}]{RESET} {pct:6.1%} {label}")
    sys.stdout.flush()
    if current >= total:
        print()
