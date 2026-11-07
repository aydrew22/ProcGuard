"""Tiny persistent store for the user's "trusted programs" list."""
from __future__ import annotations

import json
import os
from typing import Set

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".procguard")
TRUSTED_FILE = os.path.join(CONFIG_DIR, "trusted.json")


def load_trusted() -> Set[str]:
    try:
        with open(TRUSTED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(x) for x in data if isinstance(x, str)}
    except (OSError, ValueError):
        return set()


def save_trusted(trusted: Set[str]) -> None:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(TRUSTED_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(trusted), f, indent=2)
    except OSError:
        pass  # non-fatal: trust just won't persist
