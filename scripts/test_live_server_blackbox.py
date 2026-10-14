"""Live black-box tests against a running ASCP server (http://127.0.0.1:PORT)."""
import http.client
import json
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
HOST = "127.0.0.1"
APPROVER = "tok-approver-9f3a1c"
VIEWER = "tok-viewer-77be20"
results = []


def call(method, path, body=None, headers=None, raw_body=None, token=None, timeout=15):
    h = dict(headers or {})
    if token:
        h["X-API-Token"] = token
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    if data is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request(method, path, body=data, headers=h)  # path sent as-is (no normalization)
        r = c.getresponse()
        txt = r.read().decode("utf-8", "replace")
        try:
            js = json.loads(txt)
        except Exception:  # noqa: BLE001
            js = None
        return r.status, js, txt, dict(r.getheaders())
    except Exception as e:  # noqa: BLE001
        return -1, None, f"{type(e).__name__}: {e}", {}
    finally:
        c.close()


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# ---------- 1. Authentication ----------
for p in ("/api/state", "/api/status", "/api/locks", "/api/scenarios", "/api/audit-log", "/api/metrics"):
    s, *_ = call("GET", p)
    check(f"no token -> 401 {p}", s == 401, s)
s, *_ = call("POST", "/api/diagnose", {"action": "START"})
check("no token POST /api/diagnose -> 401", s == 401, s)
s, *_ = call("GET", "/api/state", token="wrong")
check("wrong token -> 401", s == 401, s)
s, *_ = call("GET", "/api/state", headers={"Referer": "http://127.0.0.1:8085/"})
check("forged Referer -> 401", s == 401, s)
s, *_ = call("GET", f"/api/state?token={APPROVER}")
check("token in query string -> 401", s == 401, s)
s, *_ = call("GET", "/api/state", token="dev" + "-operator-secret-token")
check("old public dev token rejected", s == 401, s)
s, *_ = call("GET", "/api/state", headers={"Authorization": f"Bearer {APPROVER}"})
check("Bearer token accepted", s == 200, s)
s, *_ = call("GET", "/api/state", token=APPROVER + " ")
check("token with trailing space handled", s in (200, 401), s)
s, *_ = call("GET", "/api/state", token="é" * 10)
check("non-ASCII token does not crash (401)", s == 401, s)

# ---------- 2. Static files / traversal ----------
for p in (
    "/../ascp_agent/config.py",
    "/%2e%2e/ascp_agent/config.py",
    "/..%2fascp_agent%2fconfig.py",
    "/server.py",
    "/logs/remediation_audit.jsonl",
    "/remediation_audit.jsonl",
    "/../logs/remediation_audit.jsonl",
    "/.git/config",
    "/../.env",
    "/..\\ascp_agent\\config.py",
    "/index.html/../server.py",
    "/ascp_agent/config.py",
):
    s, _, t, _ = call("GET", p)
    check(f"static blocked {p}", s in (404, 400, 403) and "password" not in t.lower(), s)
s, _, t, h = call("GET", "/")
check("GET / serves dashboard", s == 200 and "<html" in t.lower(), s)
check(
    "security headers on /",
    all(k in h for k in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy")),
    list(h)[:6],
)
s, *_ = call("GET", "/app.js")
check("GET /app.js 200", s == 200, s)
s, *_ = call("GET", "/style.css")
check("GET /style.css 200", s == 200, s)

# ---------- 3. Removed endpoint, methods ----------
s, *_ = call("POST", "/api/remediate", {"action": "KILL_SESSION", "sid": 1, "serial": 2}, token=APPROVER)
check("/api/remediate gone (404)", s == 404, s)
for m in ("PUT", "DELETE", "PATCH"):
    s, *_ = call(m, "/api/state", token=APPROVER)
    check(f"{m} not allowed", s in (404, 405, 501), s)

# ---------- 4. CORS ----------
s, _, _, h = call("GET", "/api/state", token=APPROVER, headers={"Origin": "https://evil.example"})
check("evil origin gets no ACAO", "Access-Control-Allow-Origin" not in h, h.get("Access-Control-Allow-Origin"))
s, _, _, h = call(
    "OPTIONS",
    "/api/diagnose",
    headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-api-token",
    },
)
check("preflight from evil origin not allowed", "Access-Control-Allow-Origin" not in h, (s, h.get("Access-Control-Allow-Origin")))

# ---------- 5. Malformed requests ----------
s, *_ = call("POST", "/api/diagnose", token=APPROVER, headers={"Content-Length": "abc"}, raw_body=b"{}")
check("bad Content-Length -> 4xx/closed, no hang", s in (400, -1), s)
s, _, t, _ = call("POST", "/api/diagnose", token=APPROVER, raw_body=b"x" * (70 * 1024))
check("oversize body rejected (>64KB)", s in (400, 413, -1), s)
s, *_ = call("POST", "/api/diagnose", token=APPROVER, raw_body=b"{not json")
check("invalid JSON -> 400", s == 400, s)
s, *_ = call("POST", "/api/diagnose", token=APPROVER, raw_body=b"[1,2,3]")
check("JSON array body -> 400", s == 400, s)
s, _, t, _ = call("POST", "/api/scenario/load", {"key": "../../etc/passwd"}, token=APPROVER)
check("bad scenario key handled, no traceback", s in (400, 404) and "Traceback" not in t, (s, t[:80]))
s, _, t, _ = call("GET", "/" + "a" * 20000, token=APPROVER)
check("20KB URL handled", s in (404, 414, 400, -1), s)

# ---------- 6. Roles + full HITL flow ----------
s, js, t, _ = call("POST", "/api/scenario/load", {"key": "ora_00054_mode6"}, token=APPROVER)
check("scenario load ok", s == 200, s)
s, js, t, _ = call("POST", "/api/diagnose", {"action": "START"}, token=APPROVER)
check(
    "START -> interrupted with approval payload",
    s == 200 and js and js.get("interrupted") and (js.get("interrupt_payload") or {}).get("approval_id"),
    (s, (js or {}).get("interrupted")),
)
pl = (js or {}).get("interrupt_payload") or {}
aid = pl.get("approval_id")
sess = js.get("session_id") if js else None
print("   payload:", {k: pl.get(k) for k in ("action", "target_sid", "target_serial", "target_object", "approval_id")})


def body(**kw):
    return {"action": "RESUME", "session_id": sess, **kw}


s, _, t, _ = call("POST", "/api/diagnose", body(approved=True, approval_id=aid), token=VIEWER)
check("viewer cannot approve (403)", s == 403, s)
s, *_ = call("POST", "/api/diagnose", body(approved="yes", approval_id=aid), token=APPROVER)
check("non-bool approved -> 400", s == 400, s)
s, *_ = call("POST", "/api/diagnose", body(approved=True), token=APPROVER)
check("missing approval_id -> 400", s == 400, s)
s, *_ = call("POST", "/api/diagnose", body(approved=True, approval_id="appr-forged"), token=APPROVER)
check("wrong approval_id -> 400", s == 400, s)
s, *_ = call("POST", "/api/diagnose", body(approved=True, approval_id=aid, target_sid=999999), token=APPROVER)
check("tampered target_sid -> 400", s == 400, s)
s, *_ = call("POST", "/api/diagnose", body(approved=True, approval_id=aid, target_action="PURGE_STAGING"), token=APPROVER)
check("tampered target_action -> 400", s == 400, s)

# five concurrent approvals of the same valid id
codes = []


def go():
    codes.append(
        call(
            "POST",
            "/api/diagnose",
            body(approved=True, approval_id=aid, target_sid=pl.get("target_sid"), target_action=pl.get("action")),
            token=APPROVER,
        )[0]
    )


th = [threading.Thread(target=go) for _ in range(5)]
for t in th:
    t.start()
for t in th:
    t.join()
print("   concurrent codes:", sorted(codes))
check("exactly one concurrent approval wins", codes.count(200) == 1 and all(c in (200, 409, 400) for c in codes), sorted(codes))
s, js2, *_ = call("POST", "/api/diagnose", body(approved=True, approval_id=aid), token=APPROVER)
check("replay of consumed approval -> 409/400", s in (409, 400), s)
s, js3, *_ = call("GET", "/api/state", token=APPROVER)
print("   post-state is_remediated:", (js3 or {}).get("is_remediated"))
s, js4, t, _ = call("GET", "/api/audit-log", token=APPROVER)
ev = (js4 or {}).get("audit_trail", []) if isinstance(js4, dict) else js4
mine = [e for e in (ev or []) if e.get("approval_id") == aid]
check(
    "audit log has exactly one approval for the id, operator=alice, role=approver",
    len(mine) == 1 and mine[0].get("operator") == "alice" and mine[0].get("role") == "approver",
    [(e.get("operator"), e.get("role")) for e in mine],
)
s, _, t, _ = call("GET", "/api/audit-log", token=VIEWER)
print("   viewer audit-log access ->", s)

# ---------- 7. Reject path ----------
call("POST", "/api/scenario/load", {"key": "ora_00054_mode6"}, token=APPROVER)
s, js, *_ = call("POST", "/api/diagnose", {"action": "START"}, token=APPROVER)
pl2 = (js or {}).get("interrupt_payload") or {}
sess2 = (js or {}).get("session_id")
s, js, t, _ = call("POST", "/api/diagnose", {"action": "RESUME", "session_id": sess2, "approved": False, "approval_id": pl2.get("approval_id")}, token=APPROVER)
check("rejection accepted and nothing remediated", s == 200 and not (js or {}).get("remediation_success"), (s, (js or {}).get("remediation_success")))

# ---------- 7b. Scenario isolation between operators ----------
sc = call("GET", "/api/scenarios", token=APPROVER)[1]["scenarios"]
kx, ky = "ora_00054_mode6", "stuck_st_status_registry"
call("POST", "/api/scenario/load", {"key": kx}, token=APPROVER)      # operator A picks X
call("POST", "/api/scenario/load", {"key": ky}, token=VIEWER)        # operator B picks Y
s, js, *_ = call("POST", "/api/diagnose", {"action": "START"}, token=APPROVER)   # A starts
ran = ((js or {}).get("state") or {}).get("remediation_action")
check("operator A's START runs the scenario A loaded (KILL_SESSION), not B's", ran == "KILL_SESSION", f"ran {ran}")

# ---------- 8. Throughput ----------
t0 = time.time()
n = 60
ok = 0
for _ in range(n):
    ok += call("GET", "/api/status", token=APPROVER)[0] == 200
dt = time.time() - t0
print(f"   {n} sequential /api/status in {dt:.2f}s ({ok} ok)")
check("status endpoint handles burst", ok == n)

print(f"\n{sum(1 for _, o in results if o)}/{len(results)} checks passed")
for n_, o in results:
    if not o:
        print("  FAILED:", n_)

if not all(o for _, o in results):
    sys.exit(1)
