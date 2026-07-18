# proton-wg-rotator — integration brief for a companion frontend

> **Audience:** you (Claude in a separate code session) are building a frontend
> as part of an existing WAN speed-tester project. That frontend needs to
> surface state from — and optionally trigger actions in — an existing tool
> called `proton-wg-rotator`, which is already installed and running on the
> same host (an Ubuntu Mac Mini acting as a VPN gateway).
>
> This document is the handoff. Everything below is fact, not aspiration. The
> rotator is at v0.2.1, on the box now, running under three systemd timers.

---

## 1. What proton-wg-rotator is (one paragraph)

An opinionated Python CLI that maintains a **pool of ProtonVPN WireGuard
server configs** on disk, and automatically **swaps** the active `wg0` tunnel
to a better peer when the current one degrades or dies. One Proton
certificate authorises the whole pool (Proton's cert isn't server-scoped),
so all 15 pool `.conf` files share a single `[Interface]` (same
`PrivateKey`, same `Address`) and differ only in the `[Peer]` block
(`PublicKey` + `Endpoint`). Rotation = `cp <pool>/gb-lon-NN.conf
/etc/wireguard/wg0.conf && systemctl restart wg-quick@wg0` with a handshake
check and auto-rollback on failure.

Repo: <https://github.com/marclloydjolly/proton-wg-rotator>
Install path on the Mac Mini: `/home/marcjolly/proton-wg-rotator/`
Current version: **v0.2.1**

---

## 2. Architecture — four components

Three of them run on systemd timers; one is manual.

| Component | Trigger | Cadence | Runs as | Purpose |
|---|---|---|---|---|
| `protonwg init` | Manual, once | — | `marcjolly` | Bootstrap: login, generate identity, register cert, build initial pool. |
| `protonwg refresh` | `protonwg-refresh.timer` | Nightly 02:30 UTC | `marcjolly` | Rotate cert near expiry, replace dead servers, re-render configs. |
| `protonwg swap-check` | `protonwg-swap-check.timer` | Every 5 min | `root` | Poll `/vpn/loads`, swap to a better pool entry if ≥20% score improvement. |
| `protonwg health-check` | `protonwg-health-check.timer` | Every 30 sec | `root` | Ping 8.8.8.8. On failure, stop wg0 (restores LAN default route), bootstrap-swap to best. |

`refresh` runs as the unprivileged user (only touches user-space files and
the Proton API). `swap-check` and `health-check` run as **root** because
they manipulate `/etc/wireguard/wg0.conf` and `systemctl restart wg-quick@wg0`.

Systemd service/timer files live at:

```
/etc/systemd/system/protonwg-refresh.{service,timer}
/etc/systemd/system/protonwg-swap-check.{service,timer}
/etc/systemd/system/protonwg-health-check.{service,timer}
```

---

## 3. Files the frontend can read

The rotator maintains all its state under one project root:
`/home/marcjolly/proton-wg-rotator/`. Three files inside it are the
frontend's primary data source. **All secrets live under `state/`; the
frontend should NEVER read `state/session.json`, `state/notify.toml`, or
any `*.pem`.** The below list is the safe set.

### 3.1 `library.json` — the pool manifest

**Location:** `/home/marcjolly/proton-wg-rotator/library.json`
**Permissions:** `0644` (world-readable, safe to read as any user).

Contains the pool definition and metadata about the cert. This is the
single most useful file for the frontend.

Shape (real example, secrets scrubbed):

```json
{
  "version": 1,
  "generated_at": "2026-04-23T09:03:10+00:00",
  "identity": {
    "ed25519_private_pem_path": "state/ed25519_priv.pem",
    "ed25519_public_pem_path":  "state/ed25519_pub.pem",
    "cert_pem_path":            "state/cert.pem",
    "cert_serial":              "12836601960",
    "cert_expires_at":          "2027-04-18T08:57:22+00:00",
    "wg_address":               "10.100.0.2/32"
  },
  "filters": {"country": "UK", "city": "London", "max_tier": 2},
  "render": {
    "mode": "router",
    "wg_address": "10.100.0.2/32",
    "interface_name": "wg0",
    "router": {
      "wan_iface": "enp3s0f0",
      "lan_gateway": "192.168.2.254",
      "dns": "8.8.8.8",
      "persistent_keepalive": 25,
      "mtu": null
    }
  },
  "pool": [
    {
      "index": 1,
      "logical_id": "…opaque base64…",
      "logical_name": "UK#271",
      "country": "UK",
      "city": "London",
      "tier": 2,
      "features": 0,
      "physical_id": "…opaque base64…",
      "endpoint_ip": "146.70.204.162",
      "endpoint_port": 51820,
      "peer_public_key": "…44-char base64 X25519 pubkey…",
      "config_file": "configs/gb-lon-01.conf"
    }
    // …14 more entries…
  ]
}
```

Notes for the frontend:

- **`identity.cert_expires_at`** — ISO 8601, use for a "cert expires in
  Nd" indicator.
- **`filters`** — display the pool's scope (e.g. "UK / London").
- **`pool[i].peer_public_key`** is safe to display — it's the SERVER's
  public key, not yours. This is how you correlate a pool entry with
  the currently-active tunnel: match `wg show wg0`'s peer pubkey
  against `pool[i].peer_public_key`.
- **`pool[i].logical_id`** is what you join against `/vpn/loads` (see
  §5) to get live score/load.
- **`features`** is a bitmask: `1`=Secure Core, `2`=Tor, `4`=P2P,
  `8`=Streaming, `16`=IPv6. Standard rotation excludes Secure Core / Tor.

### 3.2 `state/hotloop.json` — rotation state

**Location:** `/home/marcjolly/proton-wg-rotator/state/hotloop.json`
**Permissions:** `0644`. Written by root (swap-check / health-check).

Small, records the most recent swap:

```json
{
  "version": 1,
  "last_swap_at": "2026-04-23T08:31:06+00:00",
  "last_swap_target_logical": "UK#309",
  "last_swap_result": "ok",
  "swap_count_total": 3
}
```

`last_swap_result` is `"ok"` | `"rolled_back"` | `"failed"`. Use for a
"last swap N minutes ago, was OK" indicator.

### 3.3 `configs/gb-lon-NN.conf` — generated WireGuard configs

**Location:** `/home/marcjolly/proton-wg-rotator/configs/gb-lon-01.conf` …
`gb-lon-15.conf`.
**Permissions:** `0600` (owner read only). Contains the shared
`PrivateKey`. **Do not read/display in the frontend.** All the metadata
you need is already in `library.json`.

### 3.4 `/etc/wireguard/wg0.conf` — active tunnel config

**Permissions:** `0600` root. Do not read from the frontend. The runtime
state you actually want is available via `wg show` — see below.

---

## 4. Runtime state the frontend can inspect

Two authoritative sources, both need `sudo`:

### 4.1 `wg show wg0 dump`

Machine-readable, tab-separated. First line = interface, second (and
subsequent) = peer(s). Fields per peer line:

```
<peer-pubkey>\t<preshared-key>\t<endpoint>\t<allowed-ips>\t<latest-handshake-unix>\t<rx-bytes>\t<tx-bytes>\t<keepalive-sec>
```

Example real output:

```
+ztTAw+K…=  (none)                     84.20.17.195:51820  0.0.0.0/0,::/0  1745395234  807238567  95891234  25
```

To get the current pool index: match column 1 (peer pubkey) against
`library.json:pool[i].peer_public_key`. Column 5 (latest-handshake as
unix seconds; `0` means never) minus `now()` gives handshake age. Columns
6/7 are cumulative rx/tx byte counters — sample every N seconds and
diff for a throughput display.

Requires root to execute. The rotator wraps this with an auto-sudo
fallback in its own helper (`src/protonwg/hotloop.py::get_current_peer_pubkey`).

### 4.2 systemd unit state

```bash
systemctl status protonwg-refresh.service protonwg-swap-check.service protonwg-health-check.service
systemctl list-timers 'protonwg-*'
journalctl -u protonwg-health-check.service -n 50 --no-pager
```

`journalctl` for `protonwg-swap-check` and `protonwg-health-check` is
where the human-readable per-run summaries live. Perfect for a "recent
activity" panel.

### 4.3 Live Proton server load — unauthenticated, no rotator needed

Independently of the rotator, the frontend can hit Proton's public loads
endpoint directly:

```bash
curl -sSf -H 'x-pm-appversion: linux-vpn@4.13.1' \
  https://vpn-api.proton.me/vpn/loads
```

Returns `{"LogicalServers":[{"ID":"…","Load":42,"Score":1.6,"Status":1}, …], "Code":1000}`.
No auth, ~2.5MB response. Join `ID` to
`library.json:pool[i].logical_id` for live pool ranking. Don't hammer
it — every 30 s is plenty; every 5 s is rude.

**Important semantic:** in Proton's ranking, **lower `Score` is
better** (they use `min(key=score)` in their own client). `Load` is
percentage utilization, 0–100.

---

## 5. Commands the frontend can trigger

All CLI commands, invokable via subprocess. All accept `--project-root`
if you need to point at a non-default install (default: the repo
containing the binary).

| Command | Effect | Requires | Idempotent? | Exit codes |
|---|---|---|---|---|
| `protonwg list` | Print pool + cert to stdout. | none (user) | yes | 0 ok, 1 missing library |
| `protonwg swap-status` | Print current tunnel + top candidates + next decision. | needs `sudo` for `wg show` | yes | 0 ok |
| `protonwg refresh` | Nightly maintenance — one-shot. | user | yes | 0 ok, 1 API/library error |
| `protonwg rebuild-pool` | Re-pick pool from fresh logicals (keeps cert). | user | yes | 0 ok, 1 error |
| `protonwg swap-check` | Poll + maybe swap. | **root** | yes | 0 stay/swap-ok, 1 error, 2 rolled_back, 3 no rollback |
| `protonwg health-check` | Ping + maybe recover. | **root** | yes | 0 healthy or recovered, 3 LAN dead, 4 upstream dead, 5-9 various failures |
| `protonwg login` | Interactive SRP login (prompts for password). | user | no, prompts | 0 ok, 1 auth fail |

**Recommended trigger mechanism from a frontend running as non-root:**
prefer `systemctl start <unit>.service` over direct binary invocation.
It uses the already-configured user/env/logging.

```bash
systemctl start protonwg-swap-check.service       # triggers a run now
systemctl start protonwg-health-check.service
systemctl start protonwg-refresh.service
```

Requires the frontend process to be able to talk to systemd — polkit
rule, membership in a group, or `sudo systemctl` with a scoped sudoers
entry are all valid. **Do not** just give the frontend passwordless
sudo across the board.

---

## 6. What a good frontend would surface

Prioritised, roughly by usefulness:

### Display (read-only, no privileges needed beyond `sudo wg show`)

1. **Current tunnel** — peer name (matched from pool), endpoint IP,
   handshake age, cumulative rx/tx (from `wg show`).
2. **Egress IP as seen externally** — periodic
   `curl -s https://1.1.1.1/cdn-cgi/trace` to confirm you're on Proton
   and which POP. Complements the WAN tester perfectly.
3. **Pool ranking with live scores** — 15 pool rows sorted by live
   `Score` from `/vpn/loads`, current entry highlighted.
4. **Cert status** — serial, days-to-expiry, colour-code if <30d.
5. **Last swap** — timestamp, target, result — from `hotloop.json`.
6. **Recent activity feed** — last N health-check + swap-check journal
   entries.
7. **Throughput chart** — rx/tx-per-second overlay, correlated with the
   WAN tester's own measurements.

### Actions (each requires the ability to `systemctl start ...` as root)

- **"Test tunnel now"** → `systemctl start protonwg-health-check.service`
- **"Look for a better server"** → `systemctl start protonwg-swap-check.service`
- **"Rebuild pool from fresh logicals"** → `protonwg rebuild-pool` (user)
- **"Refresh maintenance"** → `systemctl start protonwg-refresh.service`

### Not currently supported (would need rotator code change)

- **"Swap to pool entry N"** manual pin. There's an open TODO to add
  `protonwg swap-to N`; not implemented yet. If the frontend really
  needs this, the cleanest fix is to add the subcommand upstream rather
  than to hack around it from the frontend side.

---

## 7. The HTTP API — use this (shipped in v0.3.0)

**The rotator now ships a small HTTP API.** Use it. Don't scrape files —
that's the fallback if the API isn't running.

- **Binding:** `http://127.0.0.1:8787` on the same host (loopback only).
- **Systemd unit:** `protonwg-api.service` (`Type=simple`, `User=root`,
  `Restart=on-failure`, `WantedBy=multi-user.target`).
- **Deps:** stdlib only (`http.server.ThreadingHTTPServer`). No FastAPI,
  no uvicorn.
- **Auth:** none. Trust boundary is "processes on the same host". Do NOT
  rebind to `0.0.0.0` without adding an auth layer.
- **CORS:** `Access-Control-Allow-Origin: *` — the loopback bind is the
  actual protection.
- **State cache:** 1 s in-memory. A frontend polling `/state` at 4 Hz
  still only hits Proton once per second.

### Endpoints

| Method | Path | Returns |
|---|---|---|
| GET | `/health` | `{ok, version, timestamp}` — quickest liveness check. |
| GET | `/state` | Everything merged: pool joined to live scores + current tunnel + cert + history. **Use this by default.** |
| GET | `/pool` | Just `state.pool` — the array of 15 entries with live `score`/`load`/`status`/`is_current`. |
| GET | `/tunnel` | Just `state.current` — peer pubkey, endpoint, handshake age, rx/tx bytes. |
| GET | `/cert` | `{serial, expires_at, days_remaining}`. |
| GET | `/history` | `hotloop.json` contents. |
| POST | `/actions/health-check` | Kicks `protonwg-health-check.service`. Returns 202 immediately (async). |
| POST | `/actions/swap-check` | Kicks `protonwg-swap-check.service`. 202 async. |
| POST | `/actions/refresh` | Kicks `protonwg-refresh.service`. 202 async. |
| POST | `/actions/rebuild-pool` | Runs `protonwg rebuild-pool` **synchronously** (~2–5s). Returns `{ok, returncode, stdout, stderr}`. |

Any unknown path → `404 {"error":"not found","path":"..."}`.
Any handler exception → `500 {"error":"<type>: <msg>"}`.
Action-unit failed to start → `502 {…}` (systemd returned non-zero).

### `GET /state` response shape (live sample)

```json
{
  "generated_at": "2026-07-18T16:14:11+00:00",
  "version": "0.3.0",
  "interface": "wg0",
  "cert": {
    "serial": "12836601960",
    "expires_at": "2027-04-18T08:57:22+00:00",
    "days_remaining": 273
  },
  "current": {
    "peer_pubkey": "lV7oTc0YRi…=",
    "endpoint": "146.70.204.162:51820",
    "endpoint_ip": "146.70.204.162",
    "endpoint_port": 51820,
    "handshake_age_seconds": 45,
    "rx_bytes": 10190848,
    "tx_bytes": 3810944,
    "keepalive_seconds": 25,
    "in_pool": true,
    "pool_index": 6,
    "logical_name": "UK#262",
    "city": "London"
  },
  "pool": [
    {
      "index": 5,
      "logical_id": "…",
      "logical_name": "UK#261",
      "country": "UK",
      "city": "London",
      "tier": 2,
      "features": 8,
      "endpoint_ip": "146.70.204.162",
      "endpoint_port": 51820,
      "peer_public_key": "…",
      "config_file": "configs/gb-lon-05.conf",
      "score": 1.70,
      "load": 36,
      "status": 1,
      "is_current": false
    }
    // … 14 more entries …
  ],
  "filters": {"country": "UK", "city": "London", "max_tier": 2},
  "history": {
    "last_swap_at": "2026-07-18T16:11:48+00:00",
    "last_swap_target_logical": "UK#262",
    "last_swap_result": "ok",
    "swap_count_total": 5
  },
  "loads_error": null
}
```

Fields the frontend most likely wants:

- **`current.in_pool`** — false means someone/something has swapped `wg0`
  outside our control (e.g. the user's original hand-downloaded config).
- **`current.handshake_age_seconds`** — > 300 s while `rx_bytes` isn't
  growing = probably a dead tunnel.
- **`pool[i].score`** — sort ascending; entry with `is_current: true`
  should ideally be near the top.
- **`loads_error`** — if non-null, all `pool[i].score/load/status` will
  be null; the fetch to Proton failed. Show a warning banner rather than
  blank scores.
- **`history.last_swap_at`** — timestamp for a "last swapped Nm ago"
  badge. `swap_count_total` for a lifetime counter.

### Actions — quick fetch examples

```js
// force a liveness check now (async, returns 202 immediately)
await fetch("http://localhost:8787/actions/health-check", { method: "POST" });

// re-pick the pool synchronously (5s-ish; returns actual result)
const r = await fetch("http://localhost:8787/actions/rebuild-pool", { method: "POST" });
const { ok, stdout } = await r.json();

// polling loop for the dashboard
setInterval(async () => {
  const s = await fetch("http://localhost:8787/state").then(r => r.json());
  render(s);
}, 2000);   // 2 s is fine; server caches state for 1 s so ~half get cache hits
```

### Fallback if the API isn't running

If the frontend is on a host where the API service isn't installed, or
in development against a machine without the rotator, it can still work
by reading `library.json` + `hotloop.json` directly and shelling out to
`sudo wg show wg0 dump` — but there's no reason to prefer this once the
API is available. All the join work you'd re-implement is already in
`build_state_snapshot()`.

---

## 8. Copy-paste-friendly command reference

```bash
# Locations on this host
PROJECT=/home/marcjolly/proton-wg-rotator
BIN=$PROJECT/.venv/bin/protonwg

# READ-ONLY state (safe from anywhere)
cat $PROJECT/library.json          # pool + cert
cat $PROJECT/state/hotloop.json    # last swap event

# Runtime tunnel state (needs root)
sudo wg show wg0 dump              # tab-separated peer state
sudo wg show wg0                   # human-readable

# Live Proton server load (no auth)
curl -sSf -H 'x-pm-appversion: linux-vpn@4.13.1' \
  https://vpn-api.proton.me/vpn/loads

# Trigger actions (needs root or scoped sudoers)
sudo systemctl start protonwg-health-check.service   # test tunnel now
sudo systemctl start protonwg-swap-check.service     # optimise now
sudo systemctl start protonwg-refresh.service        # maintenance now

# Non-root actions
$BIN list
$BIN rebuild-pool

# Follow logs
sudo journalctl -u protonwg-swap-check.service -f
sudo journalctl -u protonwg-health-check.service -f
sudo journalctl -u protonwg-refresh.service -f
```

---

## 9. Security notes for the frontend

- **Never expose to the browser:**
  `state/session.json`, `state/notify.toml`, `state/*.pem`,
  `state/cert.pem`, `configs/*.conf`, `/etc/wireguard/wg0.conf`.
  These contain SRP tokens, SMTP password, WG private key, and X.509
  cert.
- **Safe to expose** (from `library.json`): everything except
  `identity.*_pem_path` if they contain paths you'd rather not leak
  (they're relative paths, low sensitivity, but tidier not to
  surface).
- **The frontend has no need for the SRP session.** All authenticated
  Proton API access lives inside the rotator. The frontend should
  never authenticate against Proton directly.
- **Bind any HTTP API to `127.0.0.1`**, not `0.0.0.0`. There is no auth
  layer — the trust model is "same host". If you need remote access,
  put it behind SSH, a reverse proxy with auth, or a WireGuard
  admin-only network.

---

## 10. Gotchas + non-obvious behaviours

- **Score direction.** Proton's `Score` is *lower is better*. Ranks by
  `min(key=score)`.
- **IP multiplexing.** Proton's logicals share physical IPs. The
  rotator picks one logical per distinct endpoint IP; different pool
  entries may still share `endpoint_ip` if the pool has more entries
  than distinct IPs. Show `logical_name`, not just IP, in the UI.
- **Handshake age.** WireGuard rehandshakes every ~2 minutes on
  keepalive; a fresh tunnel with no traffic will show handshake age
  jumping between 0 and ~120s. Don't paint amber below 5 minutes.
- **`wg show` needs root.** The rotator wraps it with an `os.geteuid()`
  check to auto-prepend `sudo -n` when not root. Your frontend either
  runs as root, has passwordless sudo for `wg`, or (recommended) uses
  the API which already runs as root and returns parsed `wg` output.
- **Egress IP != endpoint IP.** Proton NATs outbound traffic on its
  gateway. The endpoint IP in `wg0.conf` is often different from what
  the internet sees as your egress. Both are useful; label them.
- **Swap-check has a 30-minute cooldown by default.** Don't be
  surprised if `swap-check` reports `[STAY] cooldown not elapsed`
  even when a better server exists. The `min-improvement 20%` +
  `min-interval-minutes 30` policy is intentionally conservative for
  home use.
- **Health-check will NOT swap if it can't reach 8.8.8.8 even with
  wg0 down.** In that case your LAN or upstream is broken, not the
  tunnel. It exits with code 4 and logs loudly.
- **Refresh runs as unprivileged user; swap-check, health-check, and
  the API server run as root.** State files under `state/` are
  auto-chown'd back to their parent-dir owner after every root write
  (see `_fsutil.py`) so user-run refresh can always read them; if you
  ever see the old `PermissionError: state/session.json` it means an
  older build wrote as root without the chown-back. Upgrade.
- **`/vpn/loads` unauthenticated is deprecated by Proton** (as of ~July
  2026). The rotator now sources live scores from the authenticated
  `/vpn/v1/logicals` endpoint. Symptom of an old build: `loads_error`
  is null but every `pool[i].score` is null. Upgrade to v0.3.0+.

---

## 11. The specific integration you're building

The parent project is a WAN speed tester. Natural couplings:

- **Overlay the rotator's swap events** on the speed tester's
  throughput timeline. A drop in throughput followed by a
  `swap_count_total` increment is a great "the tool worked" narrative.
- **Let the speed tester nudge the rotator.** If a speed test result
  is <N% of the median for this server, `POST /actions/swap-check`
  (or `systemctl start protonwg-swap-check.service`). This gives you
  policy-driven rotation based on real throughput, not just Proton's
  score.
- **Show current-egress alongside the speed test result.** So the user
  knows which Proton POP their measurement came from.
- **A "run all pool entries in sequence and measure each" mode.** The
  most valuable thing this combo could do that neither can alone:
  cycle through the 15 pool entries, run a speed test on each, produce
  a rank table by real-world throughput. Store the ranking somewhere
  the rotator could consume it (e.g. a `wan_score` field alongside
  Proton's `Score` in a future rotator release). This would need a
  small rotator change to accept externally-supplied scores; happy to
  wire that up when you're ready.

---

## 12. Ask if you need

- The rotator source is small (~1500 lines Python) and MIT-licensed;
  read it directly if any behaviour above is ambiguous. The relevant
  files are:
  - `src/protonwg/hotloop.py` — decide/execute swap
  - `src/protonwg/commands/health_check.py` — 30-second liveness loop
  - `src/protonwg/commands/swap_check.py` — 5-minute optimiser
  - `src/protonwg/library.py` — the manifest schema
  - `src/protonwg/notifier.py` — HTML email report shape (there are
    already nice render functions for a "swap event" card; the
    frontend could reuse the same shape)

- If the frontend needs a rotator-side change (new command, new
  data-file field, an HTTP API), open an issue at
  <https://github.com/marclloydjolly/proton-wg-rotator/issues>.

That's everything. Build.
