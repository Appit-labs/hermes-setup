# Security review — hermes-setup

Static analysis with SkillSpector v2.12.0 (no LLM).

- Raw scan: **72/100**, HIGH, 3 finding(s).
- With the accepted-findings baseline: **0/100, SAFE, 0 open findings**.

```bash
skillspector scan . --baseline .skillspector-baseline.yaml
```

## Accepted findings

| Rule | Severity | Why acceptable |
| --- | --- | --- |
| TT3 | CRITICAL | The only outbound request is the link check to the URL the user passes on the command line; no host is chosen by the model. |
| AST4 | MEDIUM | Child process with a fixed argv list: no `shell=True`, no interpolation of model-supplied strings. |

## What this skill never does

- No `shell=True`, no `eval`/`exec`, no dynamic import of model-supplied code.
- No credential or token is written to a file that git tracks.
- No network destination chosen at runtime.

