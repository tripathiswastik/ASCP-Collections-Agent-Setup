"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Packaging script creating a clean, production-grade release ZIP archive
         guaranteeing zero .git history, zero bytecode/cache (__pycache__/*.pyc),
         and strict release hygiene.
Runs-in: Release pipeline or standalone deployment script.
"""

from __future__ import annotations

import os
import shutil
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
ARCHIVE_NAME = "ascp-diagnostic-agent-release.zip"
ARCHIVE_PATH = DIST_DIR / ARCHIVE_NAME

EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    ".zip",
    ".tar.gz",
}

EXCLUDE_FILENAMES = {
    "Thumbs.db",
    ".gitignore",
}


def clean_local_bytecode(root: Path):
    """Purge all bytecode and pycache directories from the project directory."""
    removed_count = 0
    for path in root.rglob("__pycache__"):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            removed_count += 1
    for pyc in root.rglob("*.pyc"):
        try:
            pyc.unlink(missing_ok=True)
            removed_count += 1
        except OSError:
            pass
    print(f"[+] Purged {removed_count} local pycache / bytecode entries.")


def should_exclude(rel_path: Path) -> bool:
    """Return True if the file or folder should be excluded from release archive."""
    parts = rel_path.parts
    for part in parts:
        if part in EXCLUDE_DIRS:
            return True
        if part.startswith(".") and part != ".env.example":
            return True
    if rel_path.suffix in EXCLUDE_EXTENSIONS:
        return True
    return rel_path.name in EXCLUDE_FILENAMES


def build_release_zip() -> Path:
    """Build a clean distribution ZIP archive excluding .git, caches, and artifacts."""
    print("================================================================================")
    print("      BUILDING CLEAN RELEASE ARCHIVE WITH STRICT ZIP HYGIENE")
    print("================================================================================")

    # 1. Purge local bytecode first
    clean_local_bytecode(PROJECT_ROOT)

    # 2. Ensure dist directory exists
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    if ARCHIVE_PATH.exists():
        ARCHIVE_PATH.unlink()

    # 3. Create zip archive
    packaged_files = []
    with zipfile.ZipFile(ARCHIVE_PATH, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            rel_dir = Path(root).relative_to(PROJECT_ROOT)
            if should_exclude(rel_dir):
                dirs.clear()
                continue

            for file in sorted(files):
                rel_file = rel_dir / file if str(rel_dir) != "." else Path(file)
                if should_exclude(rel_file):
                    continue

                full_path = PROJECT_ROOT / rel_file
                archive_name = f"ascp-diagnostic-agent/{rel_file.as_posix()}"
                zf.write(full_path, arcname=archive_name)
                packaged_files.append(archive_name)

    # 4. Strict Validation of Archive Contents
    print(f"\n[+] Package created: {ARCHIVE_PATH} ({len(packaged_files)} files)")

    forbidden_entries = []
    with zipfile.ZipFile(ARCHIVE_PATH, "r") as zf:
        for name in zf.namelist():
            if ".git" in name or name.endswith(".pyc") or "__pycache__" in name:
                forbidden_entries.append(name)

    if forbidden_entries:
        print(f"[!] FAILED: Found {len(forbidden_entries)} forbidden entries in archive:")
        for entry in forbidden_entries[:10]:
            print(f"    - {entry}")
        sys.exit(1)

    print("[+] VERIFIED: 0 .git entries, 0 .pyc files, 0 __pycache__ directories in release archive.")
    print("================================================================================")
    print("      [SUCCESS] PRODUCTION RELEASE ZIP SUCCESSFULLY PACKAGED!")
    print("================================================================================")
    return ARCHIVE_PATH


if __name__ == "__main__":
    build_release_zip()
