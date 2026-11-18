#!/usr/bin/env python3
"""Install and link a Hermes agent the way it should be done: least privilege, short tokens.

    hermes.py doctor [--home DIR]
    hermes.py keys [--out DIR]                    # HS256 signing secret, 0600, fingerprint only
    hermes.py token mint [--audience hermes-agent] [--scope admin_tasks] [--ttl 900]
    hermes.py token verify --token "$TOKEN" [--audience …] [--scope …]
    hermes.py sql grants --read a,b --write c [--role hermes_agent] [--db app]
    hermes.py env --out .env.hermes [--base-url URL]
    hermes.py link-check --base-url URL --token "$TOKEN" [--path /api/hermes/health]
    hermes.py self-test

The contract this encodes: an agent token carries `aud=hermes-agent`, a `scope` the service
checks, and a short `exp`; the database role sees only the tables it needs, is not a
superuser, and cannot touch the schema. Secrets live in a 0600 env file that is never
committed. Nothing here generates RSA keys: HS256 plus `openssl` covers the cases, and one
less dependency is one less supply-chain path.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

def parse_flags(argv):
    """--key=value and --key value both work; a bare --flag is True."""
    flags, args, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
                flags[k] = v
            elif i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                flags[a[2:]] = argv[i + 1]
                i += 1
            else:
                flags[a[2:]] = True
        else:
            args.append(a)
        i += 1
    return flags, args


DEFAULT_AUDIENCE = "hermes-agent"
DEFAULT_SCOPE = "admin_tasks"
DEFAULT_ROLE = "hermes_agent"
DEFAULT_TTL = 900          # 15 min; the reference setup caps at 30 min
MAX_TTL = 1800


# --------------------------------------------------------------------- jwt

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_hs256(claims: dict, secret: str) -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64(sig)}"


def verify_hs256(token: str, secret: str, audience: str | None = None,
                 scope: str | None = None, now: int | None = None) -> tuple[int, dict | str]:
    """Return (exit_code, claims|reason). 0 ok, 2 bad signature, 3 expired, 4 audience,
    5 scope, 6 malformed."""
    try:
        header, body, sig = token.split(".")
    except ValueError:
        return 6, "malformed token"
    expected = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, unb64(sig)):
        return 2, "bad signature"
    try:
        claims = json.loads(unb64(body))
    except ValueError:
        return 6, "unreadable claims"
    moment = int(now if now is not None else time.time())
    if int(claims.get("exp", 0)) <= moment:
        return 3, "expired"
    if audience and claims.get("aud") != audience:
        return 4, f"audience {claims.get('aud')!r} != {audience!r}"
    if scope:
        scopes = claims.get("scope") or claims.get("scp") or ""
        scopes = scopes if isinstance(scopes, str) else " ".join(scopes)
        if scope not in scopes.split():
            return 5, f"scope {scope!r} missing from {scopes!r}"
    return 0, claims


# --------------------------------------------------------------------- sql

def grants_sql(role: str, db: str, reads: list[str], writes: list[str], schema: str = "public") -> str:
    ident = lambda v: '"' + v.replace('"', '""') + '"'  # noqa: E731 - SQL identifiers are quoted
    lines = [
        "-- least privilege for a Hermes agent: read what it explains, write what it owns.",
        "BEGIN;",
        f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') "
        f"THEN CREATE ROLE {ident(role)} LOGIN; END IF; END $$;",
        f"ALTER ROLE {ident(role)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;",
        f"ALTER ROLE {ident(role)} SET statement_timeout = '30s';",
        f"ALTER ROLE {ident(role)} SET idle_in_transaction_session_timeout = '60s';",
        f"GRANT CONNECT ON DATABASE {ident(db)} TO {ident(role)};",
        f"REVOKE ALL ON SCHEMA {ident(schema)} FROM {ident(role)};",
        f"GRANT USAGE ON SCHEMA {ident(schema)} TO {ident(role)};",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {ident(schema)} FROM {ident(role)};",
    ]
    for table in reads:
        lines.append(f"GRANT SELECT ON {ident(schema)}.{ident(table)} TO {ident(role)};")
    if writes:
        for table in writes:
            lines.append(f"GRANT SELECT, INSERT, UPDATE, DELETE ON "
                         f"{ident(schema)}.{ident(table)} TO {ident(role)};")
        seqs = ", ".join(f"{ident(schema)}.{ident(t + '_id_seq')}" for t in writes)
        lines.append(f"GRANT USAGE, SELECT ON SEQUENCE {seqs} TO {ident(role)};")
    lines += [
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {ident(schema)} REVOKE ALL ON TABLES FROM {ident(role)};",
        "COMMIT;",
        "",
        f"-- verify:  SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants",
        f"--          WHERE grantee = '{role}' ORDER BY table_name, privilege_type;",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------- env

def write_env(path: Path, values: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"
    path.write_text(body)
    os.chmod(path, 0o600)
    inside_repo = (path.parent / ".git").exists()
    ignored = False
    if inside_repo:
        check = subprocess.run(["git", "check-ignore", "-q", str(path)], capture_output=True,
                               cwd=str(path.parent))
        ignored = check.returncode == 0
    return {"file": str(path), "mode": oct(stat.S_IMODE(os.stat(path).st_mode)),
            "insideGitRepo": inside_repo, "gitIgnored": ignored}


# --------------------------------------------------------------------- doctor

def cmd_doctor(home: Path) -> int:
    problems: list[str] = []
    python = shutil_which("python3")
    print(f"python:   {python or 'MISSING'}")
    if not python:
        problems.append("python3 not on PATH")
    print(f"git:      {shutil_which('git') or 'MISSING'}")
    print(f"psql:     {shutil_which('psql') or 'not installed (needed only for `sql grants --apply`)'}")
    install = home / ".hermes"
    print(f"install:  {install} {'present' if install.exists() else 'absent'}")
    notes = install / "INSTALL-NOTES.md"
    if notes.exists():
        print(f"notes:    {notes} ({len(notes.read_text(errors='replace').splitlines())} lines)")
    env_file = install / "env"
    if env_file.exists():
        mode = oct(stat.S_IMODE(os.stat(env_file).st_mode))
        print(f"env:      {env_file} mode {mode}")
        if mode != "0o600":
            problems.append(f"{env_file} is {mode}, must be 0600")
        text = env_file.read_text(errors="replace")
        if "HERMES_JWT_SECRET" not in text and "HERMES_JWT_SECRET" not in os.environ:
            problems.append("no HERMES_JWT_SECRET in env or process — tokens cannot be verified")
    if shutil_which("systemctl"):
        unit = subprocess.run(["systemctl", "list-unit-files", "hermes*"], capture_output=True,
                              text=True).stdout.strip()
        print(f"service:  {unit.splitlines()[1] if len(unit.splitlines()) > 1 else 'not installed'}")
    port = _port_open("127.0.0.1", int(os.environ.get("HERMES_PORT", "8100")))
    print(f"port:     {os.environ.get('HERMES_PORT', '8100')} {'open' if port else 'closed'}")
    for p in problems:
        print(f"PROBLEM:  {p}")
    return 1 if problems else 0


def _port_open(host: str, port: int) -> bool:
    import socket
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def shutil_which(tool: str) -> str | None:
    from shutil import which
    return which(tool)


# --------------------------------------------------------------------- link

def cmd_link_check(base_url: str, token: str, path: str, audience: str, scope: str) -> int:
    url = base_url.rstrip("/") + path
    failures = 0

    def call(name: str, bearer: str) -> int:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except urllib.error.URLError as exc:
            print(f"  {name:<18} unreachable: {exc.reason}")
            return 0
        print(f"  {name:<18} HTTP {code}")
        return code

    print(f"link check → {url}")
    good = call("valid token", token)
    if good == 200:
        ok = True
    else:
        ok = False
        failures += 1
    if call("garbage token", "not.a.token") in (401, 403):
        pass
    else:
        ok = False
        failures += 1
    expired = sign_hs256({"sub": "probe", "aud": audience, "scope": scope,
                          "iat": int(time.time()) - 3600, "exp": int(time.time()) - 1800},
                         os.environ.get("HERMES_JWT_SECRET", ""))
    if call("expired token", expired) in (401, 403):
        pass
    else:
        ok = False
        failures += 1
    print("link OK" if ok else f"link FAILED ({failures} of 3 assertions)")
    return 0 if ok else 1


# --------------------------------------------------------------------- cli

def self_test() -> int:
    secret = "test-secret-value-0123456789"
    now = int(time.time())
    claims = {"sub": "svc", "aud": DEFAULT_AUDIENCE, "scope": DEFAULT_SCOPE,
              "iat": now, "exp": now + 600}
    token = sign_hs256(claims, secret)
    assert token.count(".") == 2
    code, got = verify_hs256(token, secret, DEFAULT_AUDIENCE, DEFAULT_SCOPE)
    assert code == 0 and got["sub"] == "svc", (code, got)
    assert verify_hs256(token, "other-secret", DEFAULT_AUDIENCE)[0] == 2
    assert verify_hs256(token, secret, "wrong-audience")[0] == 4
    assert verify_hs256(token, secret, DEFAULT_AUDIENCE, "write_tables")[0] == 5
    assert verify_hs256(token, secret, DEFAULT_AUDIENCE, None, now=now + 601)[0] == 3
    assert verify_hs256("a.b", secret)[0] == 6

    sql = grants_sql(DEFAULT_ROLE, "app", ["candidates"], ["agent_tasks"])
    for needle in ("NOSUPERUSER", "REVOKE ALL ON ALL TABLES", "GRANT SELECT ON \"public\".\"candidates\"",
                   "INSERT, UPDATE, DELETE", "statement_timeout"):
        assert needle in sql, needle
    assert "INSERT, UPDATE, DELETE ON \"public\".\"agent_tasks\"" in sql

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        info = write_env(Path(tmp) / "env", {"HERMES_JWT_SECRET": secret, "HERMES_PORT": "8100"})
        assert info["mode"] == "0o600", info
        body = (Path(tmp) / "env").read_text()
        assert body.startswith("HERMES_JWT_SECRET=") and not body.strip().endswith("=")

    secret2 = secrets.token_urlsafe(48)
    assert len(secret2) >= 48
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    flags, args = parse_flags(argv[1:])
    if len(args) >= 2 and args[0] == "token":
        sub = args[1]
    elif len(args) >= 2 and args[0] == "sql":
        sub = args[1]
    else:
        sub = args[0] if args else "doctor"

    if sub == "self-test":
        return self_test()

    if sub == "doctor":
        return cmd_doctor(Path(flags.get("home") or Path.home()))

    if sub == "keys":
        out = Path(flags.get("out") or ".").expanduser()
        secret = secrets.token_urlsafe(48)
        info = write_env(out / "env", {"HERMES_JWT_SECRET": secret, "HERMES_AUDIENCE": DEFAULT_AUDIENCE,
                                       "HERMES_SCOPE": DEFAULT_SCOPE, "HERMES_TOKEN_TTL": str(DEFAULT_TTL)})
        print(json.dumps({"written": info["file"], "mode": info["mode"],
                          "fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:12],
                          "note": "value not printed; read it from the file when you deploy"}, indent=2))
        return 0 if info["mode"] == "0o600" else 1

    if sub in ("mint", "verify"):
        secret = os.environ.get("HERMES_JWT_SECRET")
        if not secret:
            print("set $HERMES_JWT_SECRET (see `hermes.py keys`)", file=sys.stderr)
            return 2
        audience = str(flags.get("audience") or DEFAULT_AUDIENCE)
        scope = flags.get("scope")
        if sub == "mint":
            ttl = int(flags.get("ttl") or DEFAULT_TTL)
            if ttl > MAX_TTL:
                print(f"refusing ttl {ttl}s: the reference setup caps tokens at {MAX_TTL}s", file=sys.stderr)
                return 2
            now = int(time.time())
            claims = {"sub": str(flags.get("subject") or "hermes"),
                      "aud": audience, "scope": str(scope or DEFAULT_SCOPE),
                      "iat": now, "exp": now + ttl, "iss": str(flags.get("issuer") or "hermes-cli")}
            token = sign_hs256(claims, secret)
            print(json.dumps({"token": token, "expiresIn": ttl, "aud": audience,
                              "scope": claims["scope"]}, indent=2))
            return 0
        token = flags.get("token") or os.environ.get("HERMES_TOKEN")
        if not token:
            print("pass --token or set $HERMES_TOKEN", file=sys.stderr)
            return 2
        code, result = verify_hs256(str(token), secret, audience,
                                    str(scope) if scope else None)
        print(json.dumps(result if isinstance(result, dict) else {"error": result}, indent=2))
        return code

    if sub == "grants":
        reads = [t for t in str(flags.get("read") or "").split(",") if t]
        writes = [t for t in str(flags.get("write") or "").split(",") if t]
        if not reads and not writes:
            print("give --read tab1,tab2 and/or --write tab3", file=sys.stderr)
            return 2
        print(grants_sql(str(flags.get("role") or DEFAULT_ROLE), str(flags.get("db") or "app"),
                         reads, writes, str(flags.get("schema") or "public")))
        return 0

    if sub == "env":
        out = Path(flags.get("out") or ".env.hermes")
        secret = os.environ.get("HERMES_JWT_SECRET") or secrets.token_urlsafe(48)
        values = {"HERMES_JWT_SECRET": secret,
                  "HERMES_AUDIENCE": str(flags.get("audience") or DEFAULT_AUDIENCE),
                  "HERMES_SCOPE": str(flags.get("scope") or DEFAULT_SCOPE),
                  "HERMES_TOKEN_TTL": str(flags.get("ttl") or DEFAULT_TTL),
                  "HERMES_BASE_URL": str(flags.get("base-url") or "http://127.0.0.1:8100"),
                  "HERMES_PG_ROLE": str(flags.get("role") or DEFAULT_ROLE)}
        info = write_env(out, values)
        print(json.dumps(info, indent=2))
        if info["insideGitRepo"] and not info["gitIgnored"]:
            print("WARNING: this file is inside a git repo and is NOT ignored — add it to "
                  ".gitignore before committing anything", file=sys.stderr)
        return 0 if info["mode"] == "0o600" else 1

    if sub == "link-check":
        base = str(flags.get("base-url") or "")
        token = str(flags.get("token") or os.environ.get("HERMES_TOKEN") or "")
        if not base or not token:
            print("link-check needs --base-url and --token (or $HERMES_TOKEN)", file=sys.stderr)
            return 2
        return cmd_link_check(base, token, str(flags.get("path") or "/api/hermes/health"),
                              str(flags.get("audience") or DEFAULT_AUDIENCE),
                              str(flags.get("scope") or DEFAULT_SCOPE))

    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
