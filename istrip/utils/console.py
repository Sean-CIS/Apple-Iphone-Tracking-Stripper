"""Console output helpers — works in any terminal on any OS."""

import sys

from colorama import init as colorama_init, Fore, Style

# Initialize colorama — translates ANSI codes to native Win32 calls on
# Windows CMD/PowerShell/Terminal, passes through unchanged on Unix/Mac.
# strip=None lets colorama auto-detect whether the terminal supports colors.
colorama_init(autoreset=False, strip=None)

# Color shortcuts using colorama (works everywhere)
RED = Fore.LIGHTRED_EX
GREEN = Fore.LIGHTGREEN_EX
YELLOW = Fore.LIGHTYELLOW_EX
CYAN = Fore.LIGHTCYAN_EX
MAGENTA = Fore.LIGHTMAGENTA_EX
BOLD = Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL


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
    print(f"\n {BOLD}{CYAN}{'=' * width}{RESET}")
    print(f" {BOLD}{CYAN}  {title}{RESET}")
    print(f" {BOLD}{CYAN}{'=' * width}{RESET}\n")


def prompt_confirm(msg: str, default: bool = True) -> bool:
    """Ask the user a yes/no question."""
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        print(f"\n {YELLOW}[?]{RESET} {msg} {suffix}: ", end="", flush=True)
        answer = input().strip().lower()
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
            print(f" {YELLOW}>>>{RESET} Enter choice (1-{len(choices)}): ", end="", flush=True)
            raw = input().strip()
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
    bar = f"{'#' * filled}{'-' * (width - filled)}"
    print(f"\r {CYAN}[{bar}]{RESET} {pct:6.1%} {label}", end="", flush=True)
    if current >= total:
        print()
