"""Generates self-signed TLS certificates for local/staging reverse-proxy deployments.
Creates deploy/certs/ascp_server.crt and deploy/certs/ascp_server.key.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

CERTS_DIR = Path(__file__).resolve().parent / "certs"
KEY_FILE = CERTS_DIR / "ascp_server.key"
CRT_FILE = CERTS_DIR / "ascp_server.crt"


def generate_certs() -> bool:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists() and CRT_FILE.exists():
        print(f"[+] TLS certificates already present in {CERTS_DIR}")
        return True

    print(f"[*] Generating self-signed TLS certificate in {CERTS_DIR}...")
    openssl = shutil.which("openssl")
    if not openssl:
        print("[-] 'openssl' binary not found in PATH.")
        print("    Please install OpenSSL or generate ascp_server.crt and ascp_server.key manually.")
        return False

    cmd = [
        openssl, "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(KEY_FILE),
        "-out", str(CRT_FILE),
        "-subj", "/C=US/ST=CA/L=SanFrancisco/O=ASCP/OU=Diagnostics/CN=ascp-monitor.internal",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] Successfully generated self-signed TLS cert: {CRT_FILE}")
        print(f"[+] Successfully generated TLS private key: {KEY_FILE}")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"[-] OpenSSL command failed: {exc.stderr.decode('utf-8', errors='replace')}")
        return False


if __name__ == "__main__":
    success = generate_certs()
    sys.exit(0 if success else 1)
