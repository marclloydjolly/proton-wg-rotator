# proton-wg-rotator

Automatic, load-aware rotation across a pool of ProtonVPN WireGuard servers
for a Linux VPN-gateway host — with self-healing, auto-rollback, and daily
email reports.

Fixes a real gap: Proton's native WireGuard config is a static `wg0.conf`
pointing at one server. If that server degrades, you have to notice it and
regenerate a config by hand. This tool automates the whole loop.

---

## The problem this solves

- **Static Proton WG configs.** Download a `wg0.conf` from the Proton
  dashboard and you're pinned to that server forever.
- **No public "best server" API.** Proton's official clients query an
  internal endpoint, but it's lightly authenticated and undocumented for
  third parties.
- **Quality drifts.** A server that was great yesterday can be saturated
  today; you only notice when throughput drops or latency spikes.
- **Bulk config download is painful.** The Proton dashboard rate-limits at
  ~20 configs per 20-minute cooldown.

## How it works

Four cooperating pieces — one manual, three on systemd timers:

```
  ┌─────────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ protonwg init   │   │  refresh     │   │  swap-check  │   │ health-check │
  │ (once, manual)  │   │  (nightly)   │   │  (every 5m)  │   │  (every 30s) │
  │                 │   │              │   │              │   │              │
  │ - SRP login     │   │ - Rotate     │   │ - Poll       │   │ - Ping       │
  │ - One Ed25519   │   │   cert near  │   │   /vpn/loads │   │   8.8.8.8    │
  │   key + one     │   │   expiry     │   │ - Rank pool  │   │ - If fail:   │
  │   cert (365d)   │   │ - Replace    │   │ - Swap if    │   │   stop wg0,  │
  │ - Pick N pool   │   │   dead       │   │   ≥20% score │   │   bootstrap- │
  │   servers       │   │   servers    │   │   win        │   │   swap to    │
  │   (distinct IPs)│   │ - Re-render  │   │ - Auto-      │   │   best alive │
  │ - Emit configs/ │   │   .conf      │   │   rollback   │   │   candidate  │
  │   gb-lon-NN.conf│   │ - Email you  │   │ - Email      │   │ - Email      │
  └─────────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
     OPTIMISATION ─────────────────────▶                     LIVENESS ◀──────
```

- **`swap-check`** is for *optimisation* — rotate to a better server when one
  exists. Runs every 5 minutes, respects hysteresis (default 20% better, 30 min
  cooldown), needs internet to reach `/vpn/loads`.
- **`health-check`** is for *liveness* — self-heal when the active tunnel dies.
  Runs every 30 seconds with a cheap ICMP probe (no API calls in the happy
  path). Critically, when the probe fails it **stops `wg0` first** so the LAN
  default route is restored, *then* queries `/vpn/loads` to pick a replacement.
  That breaks the chicken-and-egg problem where the thing that's broken is also
  the only route out.

A single ProtonVPN WireGuard certificate authorises the whole pool. You
don't register a cert per server — you register one, and the tool just swaps
the `[Peer]` block of your `wg0.conf` when it wants to change gateway. That
means:

- No accumulating dashboard entries to revoke.
- Sub-second swap with ~1s handshake verification.
- Automatic rollback if the new peer doesn't handshake.

## Status

Tested on **Ubuntu 24.04 LTS** with WireGuard 1.0.x, Python 3.12, and a paid
ProtonVPN (Plus) account in router mode (the host is a VPN gateway for a
LAN). Other distros with systemd + `wg-quick` + Python 3.10+ should work but
are untested. Please open an issue if you're the first.

---

## Prerequisites

- A Linux host with **WireGuard** (`wg`, `wg-quick`) and **systemd**.
- **Python ≥ 3.10** with `venv`.
- A **paid ProtonVPN account** (Plus, Unlimited, or Visionary). Free tier
  may work with `--max-tier 0` but there will be many fewer candidates.
- Your **Proton account username** (not the login email — see
  [Common problems](#common-problems)).
- (Optional) SMTP credentials if you want email reports.

## Install

```bash
git clone https://github.com/marclloydjolly/proton-wg-rotator.git /opt/proton-wg-rotator
cd /opt/proton-wg-rotator
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/protonwg --help
```

Any install directory is fine; `/opt/proton-wg-rotator` is just a suggestion
(systemd unit examples use it).

## First-time setup

### 1. Log in

```bash
protonwg login
```

You'll be prompted for your Proton **username** (not email) and password.
The tool caches a session token to `state/session.json` (chmod 600) so
subsequent commands don't re-prompt.

**2FA (TOTP) is not currently supported for first-time login.** Disable 2FA
for the SRP auth, or use an account without 2FA. (Patches welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).)

### 2. Build the pool

Two modes:

**Client mode** (one machine, normal VPN use):
```bash
protonwg init --country UK --city London --size 15
```
Generates `configs/gb-lon-NN.conf` files with a vanilla `[Interface]` — drop
one into `/etc/wireguard/wg0.conf` and `wg-quick up wg0`.

**Router mode** (the host routes a LAN through the VPN, with NAT):
```bash
protonwg init --country UK --city London --size 15 \
  --router-mode \
  --wan-iface enp3s0f0 \
  --lan-gateway 192.168.2.254 \
  --wg-address 10.100.0.2/32 \
  --dns 8.8.8.8
```
The generated configs include `Table=off`, PreUp/PostUp/PostDown hooks that
preserve a route to the Proton endpoint via your LAN gateway, swap the
default route onto `wg0` on up, restore it on down, enable IP forwarding,
and install a MASQUERADE rule. This mirrors the layout Proton users
typically hand-build for a gateway box.

`init` will:
- Generate an Ed25519 keypair (stored in `state/`, chmod 600)
- Register a WireGuard certificate with Proton (appears in your dashboard
  as a single entry, valid 365 days)
- Fetch `/vpn/v1/logicals`, filter to your country/city/tier, **prefer
  distinct endpoint IPs** (so your pool spans multiple physical gateways)
- Render the pool into `configs/gb-lon-01.conf` … `gb-lon-NN.conf`
- Write `library.json` (the manifest the refresh + swap loops read)

Inspect the result:

```bash
protonwg list
```

### 3. (Optional) Set up email reports

```bash
protonwg notify-setup       # interactive prompt for SMTP host/user/password/from/to
protonwg notify-test        # sends a synthetic report to verify delivery
```

Config is written to `state/notify.toml` (chmod 600). Known-working providers:
IONOS (`smtp.ionos.co.uk:587`), Fastmail (`smtp.fastmail.com:587`), Gmail
(`smtp.gmail.com:587` with an App Password), Postmark/SendGrid/Mailgun APIs
via their SMTP endpoints.

### 4. Swap `wg0.conf` into place

Whichever pool entry you want to start on:

```bash
sudo cp /opt/proton-wg-rotator/configs/gb-lon-01.conf /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo wg show wg0        # should show a handshake within a few seconds
```

Verify you're egressing via Proton:

```bash
curl -s https://1.1.1.1/cdn-cgi/trace | grep -E '^(ip|loc|colo)='
```

The `ip=` should resolve to a Proton gateway (check
[whatismyipaddress.com](https://whatismyipaddress.com) or similar), and
`loc=` should match your chosen country.

### 5. Install systemd timers

Copy the example units, fill in paths, and enable all three:

```bash
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/

# Edit each .service: replace REPLACE_WITH_YOUR_USER and REPLACE_WITH_PROJECT_ROOT.
# (health-check already runs as User=root by design — no placeholder to swap.)
sudoedit /etc/systemd/system/protonwg-refresh.service
sudoedit /etc/systemd/system/protonwg-swap-check.service
sudoedit /etc/systemd/system/protonwg-health-check.service   # only the WorkingDirectory/ExecStart paths

sudo systemctl daemon-reload
sudo systemctl enable --now protonwg-refresh.timer       # nightly maintenance
sudo systemctl enable --now protonwg-swap-check.timer    # 5-min optimisation
sudo systemctl enable --now protonwg-health-check.timer  # 30-sec liveness + self-heal

systemctl list-timers 'protonwg-*'
```

You can enable any subset. A common minimal install is `refresh` + `health-check`
only (no periodic optimisation; just keep the tunnel alive and the library
maintained). A pure optimisation-focused install skips `health-check`.

### 6. (Optional) Tune the swap policy

The defaults are conservative:

| Knob | Default | Meaning |
|---|---:|---|
| `--min-improvement` | `20` | % score improvement required to swap |
| `--min-interval-minutes` | `30` | cooldown between swaps |
| `--cert-refresh-days` | `30` | rotate cert when within N days of expiry |

For more aggressive rotation (e.g. swap to any 5%-better candidate every
2 hours), edit the swap-check service unit:

```
ExecStart=/opt/proton-wg-rotator/.venv/bin/protonwg swap-check --min-improvement 5 --min-interval-minutes 120
```

Then `sudo systemctl daemon-reload`.

---

## Daily operations

```bash
# See current tunnel, pool ranking, and what the next swap-check would do.
protonwg swap-status                 # use sudo if you're not already root,
sudo protonwg swap-status            # so wg can read the current peer pubkey.

# Pool + cert status.
protonwg list

# Watch the hot-loop live.
sudo journalctl -u protonwg-swap-check -f

# Watch health-check's 30-second probe (mostly silent — only logs on recovery).
sudo journalctl -u protonwg-health-check -f

# Last few refresh runs.
sudo journalctl -u protonwg-refresh --since today

# Force an immediate swap-check run.
sudo systemctl start protonwg-swap-check.service

# Force an immediate health-check run (useful for testing).
sudo systemctl start protonwg-health-check.service

# Re-pick the pool against current best-by-distinct-IP without burning a new cert.
protonwg rebuild-pool

# Force cert rotation (even if expiry is far off).
protonwg refresh --cert-refresh-days 365
```

## Available commands

```
protonwg login              Authenticate with Proton (SRP) and cache session.
protonwg logout             Drop the cached Proton session.

protonwg init               Build the initial identity, cert, and pool.
protonwg rebuild-pool       Re-pick the pool without touching the cert.
protonwg refresh            Nightly maintenance: rotate cert if near expiry,
                            replace dead servers, re-render configs.
protonwg list               Pretty-print the current pool + cert expiry.

protonwg swap-check         Optimisation loop: poll /vpn/loads, swap if a
                            better pool entry exists (≥20% score win, default).
protonwg swap-status        Preview what swap-check would decide now.
protonwg health-check       Liveness probe: ping the internet; on failure,
                            stop wg0 and bootstrap-swap to the best alive
                            candidate. Fires every 30s via its own timer.

protonwg notify-setup       Interactively configure SMTP for email reports.
protonwg notify-test        Send a synthetic report to verify SMTP works.

protonwg api                Run the HTTP API server (see below).
```

Each command's `--help` lists its flags.

---

## HTTP API (v0.3.0+)

For frontend integration — a dashboard, the WAN-tester UI, or anything
else that wants to inspect state and trigger actions programmatically.

### Install as a systemd service

```bash
sudo cp systemd/protonwg-api.service /etc/systemd/system/
sudoedit /etc/systemd/system/protonwg-api.service    # replace REPLACE_WITH_PROJECT_ROOT
sudo systemctl daemon-reload
sudo systemctl enable --now protonwg-api.service
curl -s http://127.0.0.1:8787/health
```

Runs as root (needed for `wg show`, `systemctl start protonwg-*`).
Defaults to a loopback bind with no auth (same-host trust). When bound
to anything else (e.g. a LAN IP), a bearer token is auto-generated to
`state/api-token` and required on every request except `/health`.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + version + timestamp. |
| GET | `/state` | Everything merged: cert + current tunnel + pool with live scores + history. **The one to use.** Cached 1 s. |
| GET | `/pool` | Just the pool array with live scores. |
| GET | `/tunnel` | Just the current wg0 state (peer, endpoint, handshake age, rx/tx). |
| GET | `/cert` | Cert serial + expiry. |
| GET | `/history` | `hotloop.json` contents (last swap timestamp/target/result). |
| POST | `/actions/health-check` | Kick `protonwg-health-check.service` (async, 202). |
| POST | `/actions/swap-check` | Kick `protonwg-swap-check.service` (async, 202). |
| POST | `/actions/refresh` | Kick `protonwg-refresh.service` (async, 202). |
| POST | `/actions/rebuild-pool` | Run `protonwg rebuild-pool` synchronously (~2–5s). |

For a full response-shape reference plus a suggested frontend surface,
see [`docs/frontend-integration-brief.md`](docs/frontend-integration-brief.md).

### Tunables

```bash
protonwg api \
  --bind-host 127.0.0.1 \
  --bind-port 8787 \
  --interface wg0 \
  --cache-ttl 1.0
```

Do NOT bind to `0.0.0.0` without adding an auth layer.

---

## Architecture

### Files on disk

```
proton-wg-rotator/
├── library.json                 # the manifest: pool entries, cert metadata, filters
├── configs/                     # generated .conf files (one per pool entry)
│   ├── gb-lon-01.conf
│   └── …
├── state/
│   ├── session.json             # cached SRP session (chmod 600)
│   ├── ed25519_priv.pem         # long-lived identity private key (chmod 600)
│   ├── ed25519_pub.pem
│   ├── cert.pem                 # Proton-issued cert, rotates yearly
│   ├── notify.toml              # SMTP config (chmod 600) — optional
│   └── hotloop.json             # hot-loop state: last swap, count, last result
└── src/protonwg/                # the Python package
```

### The "one cert, many peers" trick

Proton's certificate endpoint isn't scoped to a server. A single cert
authorises your client for *every* server on your account tier. This tool
leans on that:

- `init` generates one Ed25519 keypair and registers one cert.
- All N pool configs share the same `[Interface]` (same WG private key,
  derived from the Ed25519 identity via NaCl's `sign-to-kx` conversion).
- Only the `[Peer]` block (endpoint IP + peer pubkey) differs per config.
- To "rotate," the swap loop just copies a different config file over
  `/etc/wireguard/wg0.conf` and restarts `wg-quick@wg0`.

### Decision engine

`swap-check` makes a structured decision each run. Action can be:

- **`stay`** — current is already the best, or no candidate is
  `min-improvement` better, or cooldown not elapsed.
- **`swap`** — a live candidate is significantly better *and* the cooldown
  is clear.
- **`emergency_swap`** — current peer is offline OR handshake is older than
  `dead_handshake_seconds` (5 min default). Cooldown and threshold are
  bypassed.
- **`bootstrap_swap`** — current `wg0` peer isn't in the managed pool (first
  run, or user manually swapped to a non-pool config). Forces a swap to the
  best candidate so the rotator has a known baseline.
- **`error`** — no live candidates at all (e.g. your entire pool is marked
  offline, probably a network issue with fetching `/vpn/loads`).

### Rollback

Every swap:

1. Copies `wg0.conf` to `wg0.conf.rollback`.
2. Installs the new config.
3. `systemctl restart wg-quick@wg0`.
4. Polls `wg show wg0` for up to `rollback_wait_seconds` (15s default).
5. If the handshake age is within `handshake_freshness_seconds` (30s
   default), the swap is declared **ok**.
6. Otherwise: restore `wg0.conf.rollback` and restart. Email you the
   failure.

The LAN experiences ~1–2 seconds of WG downtime during a swap. The full
duration (including rollback attempts) is bounded by the timer budget.

---

## Security notes

### What's on disk, and why

| File | Contains | Permissions |
|---|---|---|
| `state/ed25519_priv.pem` | Your long-lived WireGuard identity (private key). | `0600` |
| `state/cert.pem` | Proton-issued cert binding that key to your account. | `0600` |
| `state/session.json` | SRP session tokens (Access + Refresh). | `0600` |
| `state/notify.toml` | SMTP host + **username + password** in plain text. | `0600` |
| `configs/*.conf` | WireGuard configs. `PrivateKey` is inside. | `0600` |
| `library.json` | Server IDs, endpoint IPs, peer public keys (all public info) + cert serial. | `0644` |
| `state/hotloop.json` | Hot-loop state (last swap time, count). No secrets. | `0644` |

The `.gitignore` excludes `state/`, `configs/`, `library.json`, `*.pem`,
`*.key`, and `*.conf` by default. **Do not `git add -f` any of these.**

### TLS pinning

`proton-client` 0.5.1 ships a cert-pinning adapter that is incompatible
with current urllib3 (it passes a removed positional arg). The tool disables
Proton's extra TLS pinning (`TLSPinning=False` in `api.py`) and relies on
standard CA-based TLS for the connection to `vpn-api.proton.me`. This is
the same level of TLS validation used by any ordinary HTTPS client. If you
need strict pinning, pin at the network layer (e.g. an outbound firewall
that only allows the expected IPs) rather than in this tool.

### Email

SMTP credentials sit in `state/notify.toml` (chmod 600). If you'd rather
not put a password on disk, an option is to run a local ProtonMail Bridge
(for Proton accounts) or a trust-listed relay (e.g. Postfix configured for
no-auth relay from localhost), and point `notify.toml` at `localhost:25`
with dummy creds.

---

## Troubleshooting

### Common problems

**"The password is not correct"** after `protonwg login` — Proton
distinguishes your **login email** (marc@example.com) from your **account
username** (marcexample). SRP auth is keyed on the username. Check Proton
→ Account → Account settings for the username; it's usually the local-part
of your original signup email. Use that with `--username`.

**"Invalid access token" on `init` but login succeeded** — This usually
means `Session.load()` was called in the wrong way; make sure you're on the
current code (the static-method usage is fixed in this repo). Try
`protonwg logout && protonwg login`.

**"Timeout cannot be a boolean value"** — `proton-client`'s TLS pinning
adapter crashes against modern urllib3. The code already works around this
via `TLSPinning=False`; if you see it, you're likely running an older
checkout — `git pull && .venv/bin/pip install -e .`.

**"App version no longer supported" (Code 5003)** — Proton has bumped the
required minimum. Edit `APP_VERSION` in `src/protonwg/api.py` to something
current like `linux-vpn@4.X.Y` (check the official Proton Linux client for
the real version string).

**CAPTCHA (Code 9001)** — log in via your browser at
`account.protonvpn.com` once, then retry. Using a `web-*` app version
string triggers this; keep the `linux-vpn@…` prefix.

**`wg show` returns nothing** for `protonwg swap-status` — you're running
as a non-root user and don't have passwordless sudo for `wg`. The status
command auto-tries `sudo -n wg`, but it needs either root or NOPASSWD.
Run `sudo protonwg swap-status`.

**Swap rolled back** — the new peer didn't handshake within 15 s.
Possible causes: Proton server briefly offline, your WAN briefly out,
or a routing change broke the direct-to-endpoint route in router mode.
Check `journalctl -u protonwg-swap-check -u wg-quick@wg0`. If it keeps
happening, run `protonwg swap-status` and see whether the target is
flagged `DEAD`.

### Recovering the original tunnel

If you swap and lose connectivity:

```bash
sudo cp /etc/wireguard/wg0.conf.rollback /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

If you've lost `wg0.conf.rollback` too, your original config from Proton's
dashboard still works with the key it was issued for — download it again
and replace `wg0.conf`.

---

## Limitations & roadmap

- **No TOTP 2FA support** on first login. Disable 2FA or use a non-2FA
  account to bootstrap.
- **Single pool per install.** You can't maintain "15 UK servers + 15
  German servers" in one tree. Running a second checkout in a different
  `--project-root` works as a workaround.
- **Systemd only.** The hot-loop assumes `wg-quick@wg0.service` exists.
  OpenRC / runit users will need to adapt the restart command.
- **IPv6 is untested.** Router mode emits IPv6 AllowedIPs but the iptables
  MASQUERADE rule is IPv4-only.
- **No manual pin command.** `protonwg swap-to N` isn't implemented yet
  (trivial to add — see [CONTRIBUTING.md](CONTRIBUTING.md)).

---

## Disclaimer

**Not affiliated with Proton AG.** This tool reverse-engineers the same
unauthenticated and authenticated HTTP endpoints Proton's own Linux client
uses. Proton can change those endpoints at any time; if they do, this tool
will break until someone updates the constants in `api.py` / `hotloop.py`.

Use within Proton's Terms of Service. The cert-issuance flow this tool
uses is exactly what Proton's own Linux client does — one cert per device,
revocable via the dashboard. You are not bypassing any rate limit or
abusing the API.

## License

[MIT](LICENSE) © 2026 Marc Jolly. See `LICENSE` for terms.
