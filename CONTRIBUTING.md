# Contributing

Thanks for considering a contribution. This tool is small and opinionated, but
patches, bug reports, and platform-compatibility notes are all welcome.

## Ground rules

- **Security first.** Don't commit anything that could contain a Proton key,
  cert, session token, or SMTP password. The `.gitignore` catches the usual
  locations but always `git diff` before you commit.
- **Stdlib-lean.** Current runtime deps are `requests`, `cryptography`,
  `pynacl`, `proton-client`. Be wary of adding more — each dep is a
  maintenance + supply-chain concern for a security-adjacent tool.
- **Pragmatic tests.** There's no CI yet. A small set of inline/unit checks
  in the README-suggested commands is good enough for now. Integration tests
  require a live Proton Plus account and are intentionally manual.

## Development setup

```bash
git clone https://github.com/marclloydjolly/proton-wg-rotator.git
cd proton-wg-rotator
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/protonwg --help
```

## Useful things to work on

- More refined "spread" heuristics in `selection.py` (e.g. `/24` or geographic
  spread, not just distinct-IP).
- Add a `protonwg swap-to N` command for manual pinning.
- Support multiple pools / countries side-by-side (currently one pool per
  install).
- Port the notifier to a pluggable interface so you can send to Slack,
  Telegram, Matrix, etc., not just SMTP.
- CI: a GitHub Action that runs `python -m compileall` + lint on PRs.

## Reporting bugs

Please include:

- Ubuntu/distro version + `wg --version`
- Python version
- Output of `protonwg --help` showing installed commands
- Redacted output of `protonwg list` and `protonwg swap-status`
- `journalctl -u protonwg-swap-check -u protonwg-refresh` excerpt around the
  problem

Never paste private keys, endpoint IPs that are specific to your session, or
the contents of `state/`.
