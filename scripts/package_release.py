"""Packaging and Release Verification Script for ASCP Diagnostic Agent.
Builds a clean, production-grade release ZIP archive with strict hygiene guarantees:
1. Zero .git metadata or revision control files.
2. Zero bytecode / cache files (__pycache__, *.pyc, *.pytest_cache).
3. Zero local environment or audit files (.env, *.jsonl, logs/).
4. Verifies inclusion of all mandatory enterprise modules (evidence_engine, guarded_remediation, secret_store, etc.).
5. Extracts and independently smoke-tests the generated archive in an isolated temporary directory.
"""

import os
import shutil
import subprocess
import sys
import tempfile
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
    ".ruff_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "logs",
    "htmlcov",
    "venv",
    ".venv",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    ".zip",
    ".tar.gz",
    ".jsonl",
    ".coverage",
}

EXCLUDE_FILENAMES = {
    "Thumbs.db",
    "Desktop.ini",
    ".gitignore",
    ".env",
    "remediation_audit.jsonl",
}

REQUIRED_ENTRIES = [
    "ascp_agent/__init__.py",
    "ascp_agent/graph.py",
    "ascp_agent/state.py",
    "ascp_agent/drain_parser.py",
    "ascp_agent/evidence_engine.py",
    "ascp_agent/guarded_remediation.py",
    "ascp_agent/hitl_governance.py",
    "ascp_agent/secret_store.py",
    "ascp_agent/timeline_engine.py",
    "ascp_agent/db.py",
    "ascp_agent/lock_engine.py",
    "ascp_agent/remediation.py",
    "ascp_agent/simulator.py",
    "ascp_agent/cli.py",
    "web/server.py",
    "web/index.html",
    "web/style.css",
    "web/app.js",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.test.yml",
    "config/secrets.json.example",
    "deploy/nginx.conf",
    "deploy/generate_certs.py",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
]


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
        if part.startswith(".") and part not in (".env.example", ".gitattributes"):
            return True
    if rel_path.suffix in EXCLUDE_EXTENSIONS:
        return True
    return rel_path.name in EXCLUDE_FILENAMES


def build_release_zip() -> Path:
    """Build a clean distribution ZIP archive excluding .git, caches, and artifacts."""
    print("=" * 80)
    print("      BUILDING CLEAN RELEASE ARCHIVE WITH STRICT ZIP HYGIENE")
    print("=" * 80)

    # 1. Purge local bytecode first
    clean_local_bytecode(PROJECT_ROOT)

    # 2. Ensure dist directory exists
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    if ARCHIVE_PATH.exists():
        ARCHIVE_PATH.unlink()

    # 3. Create zip archive
    packaged_files: list[str] = []
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
        names = zf.namelist()
        for name in names:
            parts = Path(name).parts
            if (
                any(p == ".git" for p in parts)
                or name.endswith((".pyc", ".jsonl"))
                or any(p == "__pycache__" for p in parts)
                or any(p == "logs" for p in parts)
            ):
                forbidden_entries.append(name)

        # Check required files
        missing_required = []
        for req in REQUIRED_ENTRIES:
            expected_arc = f"ascp-diagnostic-agent/{req}"
            if expected_arc not in names:
                missing_required.append(req)

    if forbidden_entries:
        print(f"[!] FAILED: Found {len(forbidden_entries)} forbidden entries in archive:")
        for entry in forbidden_entries[:10]:
            print(f"    - {entry}")
        sys.exit(1)

    if missing_required:
        print(f"[!] FAILED: Missing {len(missing_required)} required files in archive:")
        for entry in missing_required:
            print(f"    - {entry}")
        sys.exit(1)

    print(f"[+] VERIFIED: All {len(REQUIRED_ENTRIES)} mandatory enterprise modules and deployment files present.")
    print("[+] VERIFIED: 0 .git entries, 0 .pyc files, 0 __pycache__ directories, 0 audit logs in release archive.")

    # 5. Extract and test the extracted artifact independently
    verify_extracted_archive(ARCHIVE_PATH)

    print("=" * 80)
    print("      [SUCCESS] PRODUCTION RELEASE ZIP SUCCESSFULLY PACKAGED & VERIFIED!")
    print("=" * 80)
    return ARCHIVE_PATH


def verify_extracted_archive(archive_path: Path):
    """Extracts the archive into an isolated temp directory and runs smoke tests."""
    print("\n[*] Verifying extracted archive in isolated temporary workspace...")
    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(temp_dir)

        extracted_root = Path(temp_dir) / "ascp-diagnostic-agent"
        assert extracted_root.is_dir(), f"Expected root folder missing in {temp_dir}"

        # Run smoke test in clean subprocess with PYTHONPATH pointing to extracted root
        smoke_code = (
            "import sys; "
            "from ascp_agent.graph import create_ascp_diagnostic_graph; "
            "from ascp_agent.evidence_engine import EvidenceAnalysisEngine; "
            "from ascp_agent.guarded_remediation import GuardedRemediationLayer; "
            "from ascp_agent.secret_store import GLOBAL_SECRET_MANAGER; "
            "g = create_ascp_diagnostic_graph(); "
            "assert g is not None; "
            "ev = EvidenceAnalysisEngine(); "
            "assert ev is not None; "
            "gr = GuardedRemediationLayer(); "
            "assert gr is not None; "
            "print('EXTRACTED_ARCHIVE_SMOKE_TEST_OK')"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(extracted_root)

        proc = subprocess.run(
            [sys.executable, "-c", smoke_code],
            cwd=str(extracted_root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        if proc.returncode != 0:
            print("[-] Smoke tests failed on extracted release archive:")
            print(proc.stderr)
            sys.exit(1)

        print("[+] Isolated extraction smoke tests PASSED: Graph, EvidenceEngine, GuardedRemediationLayer initialized cleanly.")


if __name__ == "__main__":
    build_release_zip()
