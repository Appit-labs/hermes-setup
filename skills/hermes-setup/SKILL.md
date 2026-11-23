---
name: hermes-setup
description: Install and link a Hermes agent securely — a short-lived JWT with the right audience and scope, a least-privilege Postgres role for exactly the tables it needs, a 0600 env file that stays out of git, and a three-assertion link check that proves the app actually accepts the token. Use when setting up, wiring, rotating or troubleshooting a Hermes agent against an application.
allowed-tools:
  - Bash
  - Read
  - Write
license: MIT
permissions:
  - shell
  - env
  - file_write
  - network
---

# Hermes setup — least privilege, short tokens, no committed secrets

Hermes is an agent service that reads your application's data and writes only what it owns.
The failure modes are always the same: a token that lives too long or is accepted for the wrong
audience, and a database user with more rights than the job needs. This skill fixes both by
generating the artefacts rather than describing them.

```
python3 "$SKILL_DIR/scripts/hermes.py" <command>
```

**Not for:** designing the Hermes agent itself, or rotating a credential somebody else issued — this generates a fresh least-privilege link you own end to end.

## Portability

Works in any agent that can run shell commands. `$SKILL_DIR` is this skill's folder:

```bash
SKILL_DIR=~/.claude/skills/hermes-setup     # or ~/.codex/skills/…, ~/.pi/agent/skills/…
```

## Prerequisites

- Python 3.9+ (stdlib only — no `jwt` package, no RSA dependency).
- `psql` only if you intend to apply the SQL yourself; the script prints it.
- The application must expose a health endpoint that requires the agent token (the link check
  calls `/api/hermes/health` by default; override with `--path`).

## 1. Look at the machine first

```bash
hermes.py doctor
```

Checks python/git/psql, whether `~/.hermes` exists, the mode of its `env` file, whether
`HERMES_JWT_SECRET` is visible, the service unit, and whether the port is open. Anything
wrong is printed as `PROBLEM:` and the exit code is 1.

## 2. A secret, once

```bash
hermes.py keys --out ~/.hermes        # writes ~/.hermes/env, 0600, prints only a fingerprint
```

The value is never echoed: it is a signing secret, and the console it was printed to would be
the weakest link. `hermes.py env --out .env.hermes` does the same for a deployment and warns
when the file lands inside a git repo that does not ignore it.

## 3. Tokens with the contract the service checks

```bash
hermes.py token mint --scope admin_tasks --ttl 900     # 15 min; anything over 1800 is refused
hermes.py token verify --token "$HERMES_TOKEN" --scope admin_tasks
```

Claims: `sub`, `aud=hermes-agent`, `scope`, `iat`, `exp`, `iss`. Verification distinguishes
the failures on purpose, because "it doesn't work" is not a diagnosis:

| exit | meaning |
| --- | --- |
| 0 | valid |
| 2 | bad signature (wrong secret, or a token from another environment) |
| 3 | expired |
| 4 | wrong audience (the service must not accept tokens minted for something else) |
| 5 | missing scope |
| 6 | malformed |

## 4. The database role, generated not hand-written

```bash
hermes.py sql grants --read candidates,positions --write agent_tasks --db app_prod > grants.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f grants.sql
```

What it emits, and why each line matters:

- `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT` — the role cannot escalate through another role.
- `REVOKE ALL ON SCHEMA` then `GRANT USAGE` — it can use names in the schema, not create or alter.
- `REVOKE ALL ON ALL TABLES` then explicit `SELECT` per readable table — new tables are invisible
  by default, so a future migration cannot silently widen the agent's view.
- write tables get `SELECT, INSERT, UPDATE, DELETE` plus `USAGE, SELECT` on their sequences.
- `statement_timeout 30s` and `idle_in_transaction_session_timeout 60s` — an agent that stalls
  cannot hold locks for hours.
- `ALTER DEFAULT PRIVILEGES … REVOKE ALL` — the default stays closed for tables created later.

## 5. Prove the link

```bash
hermes.py link-check --base-url https://ai.example.com --token "$HERMES_TOKEN"
```

Three assertions, and the check fails unless all three hold: a valid token gets **200**, a
garbage token gets **401/403**, and an expired token gets **401/403**. That third one is the
one people skip, and it is the one that catches a service which verifies signatures but never
checks `exp`.

## Rules this skill encodes

- **One agent, one role, one scope.** No `admin_tasks` for a read-only job, no shared `postgres`.
- **Tokens are born short.** Rotate by re-minting; never extend a TTL by editing a claim.
- **Secrets never touch the repo.** `0600` file, gitignored, and the skill says so loudly when
  it is not.
- **Least privilege is default-deny.** Revoke broadly, grant explicitly, keep defaults revoked.
- **Verify with a negative test.** A link check that only proves the happy path proves nothing.

## What it will not do

- It will not create database superusers, disable RLS, or grant `ALL PRIVILEGES`.
- It will not print a secret value, store a password, or write a token into a file that is
  tracked by git.
- It will not guess your schema: `--read` and `--write` are explicit, and an empty list is an
  error rather than "everything".
