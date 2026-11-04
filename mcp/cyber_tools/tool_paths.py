"""Resolve optional scanner binaries installed independently of the MCP venv."""
import os
import shutil
from pathlib import Path


def isolated_cli(name):
    path = Path.home() / '.local/share/cybersec/tools' / name / 'bin' / name
    return str(path) if path.is_file() and os.access(path, os.X_OK) else None


def which_cli(name):
    # Prefer isolated Certipy to an incompatible core environment installation.
    if name == 'certipy':
        return isolated_cli(name) or shutil.which(name)
    return shutil.which(name) or isolated_cli(name)
