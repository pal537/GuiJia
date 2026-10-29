# Guijia 🛡️

English | [中文](README.zh-CN.md)

Guijia is a security and monitoring panel for Linux servers (VPS / cloud): live connection monitoring, intrusion protection, honeypot trapping, and multi-server control. Go single binary + nftables, running under systemd or Docker.

> The fnOS app edition is maintained separately and is not in this repo.

## Screenshots

![Home: multi-server control (demo data)](docs/screenshots/home.png)
*Home: multi-server control across regions (demo data).*

![Overview: live connections (demo data)](docs/screenshots/overview.png)
*Overview: live connections, split into firewall-rule ports and other ports (demo data).*

## Features

### 📊 Overview & live connections

- 📊 Six stat cards: current connections, today's new source IPs, today's bans, today's SSH failures, active blacklist / total records, watched ports.
- 🖥️ Server cards on Home: connections, today's bans, ports, blacklist, IP, geo + flag, OS logo, uptime, version, IPv6 when present.
- 📡 Live connections, split into firewall-rule ports and other ports, sortable by duration or traffic.
- 🔌 Only new connections are blocked; established connections are never kicked.
- 👤 Login sessions card: IP, geo, login time, last active, remember-me flag; sessions live in memory only and clear on panel restart.

### 🧱 Firewall

- 🧱 Rules are port + protocol + source + action (allow / deny) + enabled switch; ports accept singles, comma lists, and ranges.
- ⚖️ One action per port per protocol; same-action rules merge by source union; ports without rules are untouched.
- 🌍 Eight source types: custom IP, all IPv4, all IPv6, mainland China, outside mainland China, custom China location, custom overseas location, all IPs.
- 🛡️ Intranet, loopback, reserved ranges, and the trust list are always exempt; deny bans are permanent until the rule is deleted, disabled, or manually released.

### 📋 Events

- 📋 Every security event in reverse chronological order, filterable by type and searchable by IP or detail.
- 🗓️ Events are stored per day with configurable retention; new-source events have their own retention (0 = count only, don't store).

### ✅ Allow & block lists

- ✅ Trust list (IP / CIDR): trusted IPs never alert and can never be banned; trust beats blacklist and threat intel.
- 🏠 Trust-all-LAN toggle: the four standard private ranges are trusted implicitly and never written into the list.
- 🚫 Blacklist records are kept forever; expiry and release only change state, never delete records.
- 🔍 Manual ban / unban, status and source filters, IP search; intranet, loopback, and trusted IPs are always refused for banning.

### 🔥 Protection

- 🔥 Flood protection: watch a manual port set; a burst of distinct public IPs on one port temporarily closes that port, intranet unaffected, auto-restores, or restores instantly from the Firewall page.
- 💥 Brute-force auto-ban: SSH failures past a configurable threshold trigger a ban that escalates 1 hour → 24 hours → permanent.
- 🔎 Scan detection (passive only): watches distinct TCP ports touched per IP in the kernel connection table and flags scanners; closed-port probes are visible too.
- 🍯 Honeypot: preset ports (SSH, RDP, Telnet, Redis, MySQL, Docker API, ADB, VNC, and more) plus custom ports, merged and deduplicated; N hits trigger a ban (default 1), duration in hours (default 24, 0 = permanent).
- 🧪 Honeypot ports pass layered validation and can never be real service ports; a honeypot serves nothing and simulates no login page — inbound data is only recorded, never executed.
- 🆘 Rescue: send /rescue in Telegram for trust IP, unban all, pause all interception (auto-restores in 30 minutes), and restore protection; destructive actions require a super password stored as hash only.
- 🌐 Threat intel: public aggregate feeds only (FireHOL level1 by default, free, no key), applied as an independent nft set on all ports; failed fetches keep the old list, and stale lists are flagged.

### 🔀 Reverse proxy

- 🔀 One rule is domain + ports + certificate + intranet backend; adding a rule enables it.
- 🎯 Exact domains beat single-level wildcards (e.g. *.example.com); routing is by SNI; unmatched domains and direct IP access are refused.
- 🔗 Upstream is http://IP:port only; HTTPS backends are not supported.
- ⚙️ Panel-managed nginx vhosts: enabling a rule generates its server block, disabling or deleting removes it and reloads; a failed nginx -t restores everything; the ACME resident block is never touched; takeover only happens when the panel runs as root with nginx present, otherwise it falls back.
- ⚠️ Port bind conflicts report the occupying process name instead of a raw bind error; proxying the panel itself works via http://127.0.0.1:panel-port.

### 🔒 Certificates

- 🔒 Two sources only: online ACME issue or manual upload; the list shows metadata only, never private keys.
- 📜 One SAN certificate covers many domains, one line per domain; wildcard domains require DNS-01.
- 🔑 Challenge modes: auto (HTTP-01 when port 80 is free, DNS-01 when busy), HTTP-01, DNS-01 (Cloudflare), nginx relay (HTTP-01 through nginx, no port 80, no token).
- 🔐 The Cloudflare API token is stored as a 0600 file and never echoed back in plaintext.
- 🔄 Renewal checks every 6 hours and auto-renews 30 days before expiry, plus once at panel start; auto-renew can be toggled per certificate.
- 📊 Status is valid (green) / expired (red) / revoked (red, via OCSP); rows offer view, download (zip with cert + key), refresh, edit, delete.

### 🖥️ Multi-server control

- 📦 One package, one install command, no separate agent; any standalone server can become a hub.
- 🚪 First run is a choice: set a password for standalone use, or enter a hub address + pairing code to join control.
- 📄 A controlled node's local panel becomes a read-only status page; all management happens on the hub.
- 🔑 Pairing codes are one-time, valid 30 minutes, and void after use; the hub shows pending nodes (name + fingerprint prefix + join time) for approval, and approval enables mutual whitelisting.
- 🔁 Wrong or expired codes fail inline on the join page with unlimited retries; a rejected node returns to the join page, and only a temporary network loss keeps retrying.
- 🚪 Leaving: the hub removes management and the node returns to the first-run choice; if the hub is gone entirely, `guijia leave` or `guijia hub-code <code>` on the node recovers it.
- 🗄️ The hub stores only the registry (name, fingerprint, online state, last seen, version, TG mode, reported IP / OS / arch, manual geo); protection data stays on each machine, and viewing a node is a live forwarded read.
- 🛡️ Three anti-mutual-ban guards: node-to-hub traffic returns over the node's own outbound connection, the hub IP is exempt on nodes, and hub link failures only rate-limit and log — never ban.
- 👁️ Node view hides the 2FA card, general notification card, session card, and password row, and keeps the node TG card; a node's panel port can change without breaking management.
- 🔔 New-device reminder bar on Home until dismissed; dismissal persists across restarts and browsers.
- 🔄 Shared blacklist is a network-wide union: the hub pulls full records from online nodes, merges missing IPs as shared entries, and pushes the union to all online nodes; offline nodes are skipped, never treated as empty; local entries are never touched or re-stated.
- ✅ Shared whitelist is hub-only: the hub list is the single source, and stale shared entries converge away.
- 🔄 Blacklist sync only adds and syncs state (a hub unban becomes a released state on nodes, never a hard delete); a newly approved node syncs immediately; sync verifies before reporting failure.
- ⚙️ Shared protection settings (flood, brute-force, scan, threat intel) follow the hub; sync settings live in a homepage popup with draft semantics, interval options, and instant sync.
- ⬆️ One-click push upgrade from the hub to all online nodes; one node's failure doesn't affect the others.

### 🔔 Notifications & daily report

- ✈️ Telegram alerts carry the server name in the title and one-tap ban / trust buttons bound to that server's fingerprint; cross-server callbacks only prompt, never execute.
- 🔁 One bot token polls commands on one server at a time; node events go through the hub bot titled with the node name, or through the node's own bot in independent mode.
- 💾 When the hub is down, node events queue locally in a ring buffer and replay on reconnect.
- 🎛️ Ten alert toggles (SSH login / brute-force, panel login, flood, firewall ban, honeypot hit, new listener, and more) live in one notification-config popup.
- 📰 Telegram daily report at a configurable time; event-log and new-source retention are adjustable on the same card.

### 🔑 Login security

- 👤 Single admin, no multi-user; first login forces a strong password (12+ chars, upper + lower + digit + symbol, confirmed twice).
- 🍪 Remember login (30 days) is optional; panel restarts clear memory sessions, so re-login is required.
- 🚫 Panel brute-force protection: consecutive wrong passwords ban the IP for 7 days (failure count adjustable); intranet and trusted IPs are exempt; bans enter the unified blacklist and auto-release.
- 🌐 Real-IP rule: X-Real-IP / X-Forwarded-For are trusted only behind loopback nginx, never on direct panel-port connections.
- 📱 2FA (opt-in, off by default): locally generated QR PNG (no external QR API) + copyable manual key, activation requires one correct code; a "new one" button regenerates the key instantly; 10 one-time recovery codes are shown once; disabling requires password confirmation.
- 💻 Trusted devices: device cookie bound to real IP, stored as a 0600 file, valid 90 days; password changes and 2FA-off clear all trusted devices.
- 🛠️ Locked out? Server-local root commands recover it: `guijia reset-password`, and `guijia cert-off` drops HTTPS back to HTTP.

### 📈 Traffic & ledger

- 📈 Per-connection bytes come from kernel connection accounting (nf_conntrack_acct); the panel auto-enables it at start and restores the original state on exit, leaving it alone if another tool already had it on.
- 💰 Cumulative per-peer ledger is permanent and only increases; it can only be cleared manually in data cleanup.
- 🗓️ Daily detail retention is adjustable in days (0 = keep forever).

### 🗺️ Geo database

- 🗺️ IPv4 database is embedded as a fallback with manual update checks; IPv6 is downloaded manually by default and never auto-downloaded on fresh installs.
- 🚩 Country flags and geo display follow the manual geo override when set, otherwise automatic lookup.
- 📍 Firewall location sources cover China provinces + cities and overseas countries + regions, searchable in Chinese and English.

### 🧹 Cleanup, backup & upgrade

- 🧹 Data cleanup popup: clear events and stats, blacklist, or traffic ledger separately or all at once, with YES confirmation; cleared data cannot be recovered.
- 💾 Backup and restore popup: settings backup (one JSON download) and data backup (one zip download); a bare settings.json uploaded by mistake is refused instead of wiping the config.
- 🔀 Settings saves merge by field, so values the UI no longer submits are never zeroed.
- ⬆️ Version and upgrade page: detects new releases from GitHub, upgrades in one click with automatic rollback on failure, refreshes after upgrade, and re-login after restart.
- ✅ Upgrade status is verified against the actually running version, so a successful upgrade never shows a false failure; upgrade backups keep the latest 3 by modification time.

### ⌨️ CLI

- ⌨️ `guijia reset-password` · `guijia cert-off` · `guijia unban <ip>` · `guijia leave` · `guijia hub-code <code>` · `guijia nginx-ensure` · `guijia nginx-status` · `guijia upgrade-watch`.

## Install

### Requirements

- Debian / Ubuntu, root, systemd (or Docker); arm64 / amd64 auto-detected.
- Panel default port 59188, data directory `/var/lib/guijia`; both configurable.

### One-line install (systemd, recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo bash
```

The script detects the arch, pulls the matching package + `guijia.service` from this repo's releases, verifies sha256 first (refuses to install on mismatch), installs to `/usr/local/bin/guijia`, creates the data directory, and enables + restarts the service. Re-running upgrades in place (idempotent); the old binary and unit are backed up to `/root/guijia-install/`, and a failed restart restores them automatically.

Pin a version or change port / data dir with environment variables (use `sudo -E bash` so sudo keeps them):

```bash
curl -fsSL https://raw.githubusercontent.com/pal537/GuiJia/main/install-remote.sh | sudo -E bash
# GUIJIA_VERSION=v1.0.20 (default: latest); GUIJIA_PORT / GUIJIA_DATA_DIR
```

### Docker

No Docker Hub image is published, so Docker means local build (host network + NET_ADMIN are required):

```bash
git clone https://github.com/pal537/GuiJia.git && cd GuiJia && docker compose up -d --build
```

```bash
GUIJIA_PORT=59188 docker compose up -d
GUIJIA_DATA_DIR=/srv/guijia docker compose up -d   # default: ./guijia-data, mounted to /var/lib/guijia
```

### Manual install (from releases)

Download the matching arch package + `guijia.service` + `SHA256SUMS` from this repo's releases, verify, then install:

```bash
install -m 0755 guijia-linux-<arm64|amd64> /usr/local/bin/guijia
systemctl restart guijia
```

Then verify: `sha256sum /usr/local/bin/guijia` matches the release, `systemctl is-active guijia` is active, and `curl http://127.0.0.1:59188/login` returns 200.

## First use

Open `http://your-server-ip:59188` (or your configured port) and set the admin password, then choose:

- **Standalone**: set a password and the panel is ready.
- **Join control**: enter the hub address + pairing code; the local panel becomes a read-only status page managed from the hub.

Manage the service:

```bash
systemctl status guijia
systemctl restart guijia
journalctl -u guijia -f
```

Forgot the password? On the server as root: `guijia reset-password`. Panel restarts clear memory sessions, so re-login is required.

## Links

- [Releases](https://github.com/pal537/GuiJia/releases)
- [Issues](https://github.com/pal537/GuiJia/issues)
- [INSTALL.md](INSTALL.md) · [DEPLOY.md](DEPLOY.md) · [DESIGN.md](DESIGN.md)

## Author

pal537
