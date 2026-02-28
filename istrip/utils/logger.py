"""Logging utility for iStrip."""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path


def _get_log_dir() -> Path:
    """Get a writable log directory in the user's local app data."""
    # Use LOCALAPPDATA on Windows, ~/.local/share elsewhere
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    log_dir = Path(base) / "istrip" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logger(name: str = "istrip", verbose: bool = False, log_file: bool = True) -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file:
        try:
            log_dir = _get_log_dir()
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            fh = logging.FileHandler(log_dir / f"istrip_{stamp}.log")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except OSError:
            # If we still can't write logs, just skip file logging
            pass

    return logger
