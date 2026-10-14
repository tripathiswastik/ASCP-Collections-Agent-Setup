"""Wait for Oracle service to be ready (listener open and accepting database connections)."""

from __future__ import annotations

import os
import socket
import sys
import time


def wait_for_tcp(host: str, port: int, max_attempts: int = 60, delay: float = 5.0) -> bool:
    print(f"Waiting for Oracle to accept TCP connections on {host}:{port}...")
    for attempt in range(1, max_attempts + 1):
        try:
            with socket.create_connection((host, port), timeout=2.0):
                print(f"TCP port {port} is open (attempt {attempt}/{max_attempts})")
                return True
        except (OSError, TimeoutError):
            print(f"Waiting for Oracle TCP listener... ({attempt}/{max_attempts})")
            time.sleep(delay)
    return False


def wait_for_db(
    host: str,
    port: int,
    service: str,
    user: str,
    pwd: str,
    max_attempts: int = 30,
    delay: float = 5.0
) -> bool:
    try:
        import oracledb
    except ImportError:
        print("oracledb not installed; skipping database connect probe")
        return True

    dsn = f"{host}:{port}/{service}"
    print(f"Waiting for Oracle DB to accept logins on {dsn} as {user}...")
    for attempt in range(1, max_attempts + 1):
        try:
            conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
            conn.close()
            print(f"Oracle DB connect succeeded on attempt {attempt}")
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"Attempt {attempt}/{max_attempts}: DB connect failed ({exc}), retrying in {delay}s...")
            time.sleep(delay)
    return False


def main() -> int:
    host = os.environ.get("ORACLE_TEST_HOST", "localhost")
    port = int(os.environ.get("ORACLE_TEST_PORT", "1521"))
    service = os.environ.get("ORACLE_TEST_SERVICE") or os.environ.get("ORACLE_SERVICE_NAME", "FREEPDB1")
    user = os.environ.get("ORACLE_TEST_USER") or os.environ.get("ORACLE_USER", "")
    pwd = os.environ.get("ORACLE_TEST_PASSWORD") or os.environ.get("ORACLE_PASSWORD", "")

    if not wait_for_tcp(host, port):
        print(f"[-] Timed out waiting for TCP port {port} on {host}")
        return 1

    if not user or not pwd:
        print("[!] No ORACLE_TEST_PASSWORD or ORACLE_PASSWORD provided; verified TCP port only.")
        return 0

    if not wait_for_db(host, port, service, user, pwd):
        print(f"[-] Timed out waiting for Oracle DB to accept connections on {host}:{port}/{service}")
        return 1

    print("[+] Oracle service is fully ready and accepting database connections.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
