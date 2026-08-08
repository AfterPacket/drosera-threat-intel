# Technical Capability & Mitigation Framework — Capture 2026-08-07

**TLP:WHITE** · Author: AfterPacket · Date: 2026-08-08
**Scope:** 25 samples, 7 families, sightings 2026-07-28 → 2026-08-07
**Assurance basis:** every capability below is evidenced by a specific string,
line or byte offset in a sample decrypted and read during this review. Nothing
is inferred from family name or reputation.

---

## 0. How to read this document

Capabilities are stated as **what the code can technically do**, not what it was
observed doing. A honeypot capture shows delivery and configuration; it does not
show the full operational life of an implant. Where a capability is present in
code but unobserved in telemetry, it is marked **[CODE]**. Where it was directly
observed, **[OBS]**.

Mitigations are rated for **effectiveness against this corpus specifically**:

| Rating | Meaning |
|--------|---------|
| **P1** | Defeats the capability outright. Attacker must re-tool |
| **P2** | Defeats the observed implementation; a config change evades it |
| **P3** | Raises cost or improves detection; does not prevent |
| **D** | Detective only — no preventive effect |

A control that is P2 is not a weakness to hide. It is a control with a known
bypass, and knowing the bypass is what lets you layer the next control correctly.

---

## 1. Capability matrix

| Capability | OHSHIT | TELNETCURL | PERLBOT | GSOCKET | LOADER | BOTKILL | PROBE |
|------------|:------:|:----------:|:-------:|:-------:|:------:|:-------:|:-----:|
| Remote code execution | ● | ● | ● | ● | ● | — | ◐ |
| Multi-architecture targeting | ●15 | ●5 | — | — | ●5 | — | — |
| Android targeting | — | — | — | — | ● | — | — |
| Telnet propagation | ● | ● | — | — | ● | — | — |
| SSH propagation | ●[CODE] | — | — | ● | — | — | — |
| Interactive shell / C2 | ● | ● | ● | ● | ● | — | — |
| DDoS — Layer 7 HTTP | ●[CODE] | — | ◐ | — | — | — | — |
| DDoS — Layer 3/4 | ◐[CODE] | ◐[CODE] | ◐ | — | — | — | — |
| Persistence | — | — | — | ●×5 | — | — | — |
| Process masquerade | — | — | ● | — | — | — | — |
| Signal / kill resistance | — | — | ● | ● | — | — | — |
| Config obfuscation | ●0x22 | ✗ | — | — | — | — | — |
| Credential exfiltration | — | — | — | ● | — | — | — |
| Host fingerprinting | — | — | — | ● | ● | — | ● |
| Anti-rival / turf control | — | — | — | — | — | ● | — |
| Capability reconnaissance | — | — | — | — | — | — | ● |
| Tor / hidden-service C2 | ● | — | — | — | — | — | — |
| Peer-to-peer C2 | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

● present · ◐ partial//indirect · ✗ explicitly checked and absent · — not applicable

**No P2P C2 anywhere in this corpus.** No DHT bootstrap list, peer table or
gossip protocol in any sample. The only decentralised element is one Tor hidden
service name in MIRAI_OHSHIT.

---

## 2. Capability detail and evidence

### 2.1 Multi-architecture cross-compilation **[OBS]**

`ohshit.sh` lines 4–18 fetch one payload per architecture across 15 targets:
`x86 mips arc i468 i686 x86_64 mpsl arm arm5 arm6 arm7 ppc spc m68k sh4`.
MIRAI_LOADER covers 5 (`arm arm5 arm7 mips mpsl`), TELNETCURL 5.

**Why it matters technically.** The operator does not fingerprint the target
first. They fetch and execute *every* build in sequence and let the wrong ones
fail. This is noisy and cheap, and it means a single successful telnet session
produces up to 15 download attempts — which is itself the detection opportunity
(see §4.2).

### 2.2 Write-and-execute probing **[OBS]**

MIRAI_LOADER lines 5–7:

```sh
for dir in $DIRS; do
  echo > "$dir"/.f && chmod 777 "$dir"/.f && "$dir"/.f && cd "$dir"
done
```

The loader does not assume a writable directory. It creates `.f`, makes it
executable, **executes it**, and only settles where both succeed. `noexec` on
`/tmp` and `/dev/shm` therefore *works* against this family — the probe fails
and the loader moves on. `DIRS` includes `/data/local/tmp`, an Android path.

### 2.3 Layer-7 HTTP flood, obfuscated **[CODE]**

Present in all seven MIRAI_OHSHIT ELF builds, hidden behind single-byte XOR
`0x22` — Mirai's `table.c` scheme, where the leaked-source `TABLE_KEY`
`0xdeadbeef` collapses to one effective byte (`0xef^0xbe^0xad^0xde = 0x22`).

Recovered: `HTTP/1.1`, `User-Agent:`, `Accept:`, `Accept-Language:`,
`Accept-Encoding:`, `Referer:`, `Cookie:`, `Origin:`,
`Content-Type: application/x-www-form-urlencoded`; a rotating User-Agent pool
spanning archaic MSIE/Trident through current Chrome 131 and Firefox 126; and
20 Referer URLs of real sites.

**Technical significance.** Header and Referer randomisation is specifically
designed to defeat signature-based DDoS filtering — each request is individually
indistinguishable from a browser. Mitigation must therefore be **rate- and
behaviour-based, never signature-based** (§4.5).

> **The 20 recovered domains are `google.com`, `facebook.com`, `cloudflare.com`
> and similar. They are flood header values, not infrastructure. Blocklisting
> them removes the estate's internet access. The XOR region contains no C2 at
> all — verified across all seven builds.**

### 2.4 Dual-vector propagation **[CODE]**

MIRAI_OHSHIT payloads embed a complete SSH client — `ssh-ed25519`,
`curve25519`, `chacha20`, `aes128-ctr`, `hmac-sha2`, and `@openssh.com`
algorithm suffixes. The loader chain is **telnet-only**.

**Consequence for incident scoping.** An investigation that scopes lateral
movement from the observed delivery vector will examine telnet and conclude the
blast radius is telnet-reachable hosts. That is wrong. Audit SSH authentication
logs on every affected host.

### 2.5 Layered persistence with self-healing **[OBS]**

GSOCKET_SSHIT installs five independent mechanisms:

| # | Mechanism | Location |
|---|-----------|----------|
| 1 | systemd unit, `Restart=always`, `StartLimitBurst=0` | `/etc/systemd/system/gsocket-watchdog.service` |
| 2 | crontab, every minute | user crontab |
| 3 | crontab, `@reboot sleep 10` | user crontab |
| 4 | shell rc injection | `.bashrc`, `.profile`, `.zshrc`, `.bash_profile` |
| 5 | the watchdog script | `~/.config/prng/watchdog.sh` |

`StartLimitBurst=0` disables systemd's restart-rate limiter — the unit will
restart indefinitely rather than entering a failed state. The watchdog polls
every 30 s; if `gs-netcat` is absent it reinstalls from `https://gsocket.io/y`,
derives a **new** secret, and POSTs it to the operator.

**This inverts normal response instinct.** Killing the process is not
containment — it is a trigger that regenerates access *and* notifies the
attacker. Removal order is mandatory: mechanisms 1→5, then kill.

### 2.6 Rendezvous-by-secret C2 **[OBS]**

GSOCKET uses THC Global Socket. Peers meet through the Global Socket Relay
Network addressed **by shared secret, not by host**. There is no attacker
hostname or IP in the C2 path.

**This defeats every IP- and DNS-based control.** No blocklist entry, sinkhole
or DNS RPZ can touch it. The only preventive control is egress restriction to
the relay network; the only detective controls are behavioural (§4.6).

### 2.7 Runtime C2 override **[OBS]**

All three Perl bots, line 45 (`/duba`, `/dodu`) and 139 (`/gots`):

```perl
$server="$ARGV[0]" if $ARGV[0];
```

Any IP-based control is defeated by relaunching with an argument. **However**,
all three share hardcoded operator constants that the override does not touch:

```perl
my @admins   = ("MAD");
my @channels = ("#mot");
```

These are identical across *both* C2 servers, which is what proves one operator
runs both — and they are the only indicators that survive both a server change
and the override.

### 2.8 Evasion and resilience **[OBS]**

| Technique | Family | Implementation |
|-----------|--------|----------------|
| Process-name masquerade | PERLBOT | `$0="$process"."\0"x16` — 11-entry pool of `httpd`, `sshd`, `syslogd`, `cron` |
| Signal ignore | PERLBOT | `SIG{INT,HUP,TERM,CHLD} = 'IGNORE'` |
| Self-deletion | OHSHIT | `rm -rf ohshit.sh` after execution |
| Config obfuscation | OHSHIT | XOR 0x22 |
| Legitimate-tool cover | GSOCKET | The backdoor *is* a signed, published tool |
| CTCP VERSION spoofing | PERLBOT `/gots` | 11-entry mIRC version pool |

Note `SIG{TERM}='IGNORE'` means `kill` without `-9` will not stop the Perl bot.

### 2.9 Reconnaissance and turf control **[OBS]**

**WEBROOT_PROBE** — two-line scripts (`#!/bin/sh` + `echo "xxxxxx"`) written to
`/var/www/html/filter`. A write-and-execute capability probe: plant, request via
HTTP, look for `xxxxxx`. **Finding one means someone already confirmed RCE.**

**BOTKILL_PROCWIPE** — competitor removal. `41d9a2a0` kills any process whose
`/proc/$pid/exe` ends `(deleted)`; `2733d565` targets `dvrHelper` by name — the
exact payload of MIRAI_LOADER in this same capture. `2733d565` is **corrupt as
delivered** (bytes `5c 33 42` where `;` belongs) and could not execute.

---

## 3. ATT&CK mapping

| Tactic | ID | Technique | Families |
|--------|----|-----------|---------|
| Initial Access | T1078.001 | Valid Accounts: Default | OHSHIT, TELNETCURL, LOADER |
| Initial Access | T1190 | Exploit Public-Facing Application | PROBE |
| Execution | T1059.004 | Unix Shell | all script families |
| Execution | T1129 | Shared Modules | OHSHIT (busybox staging) |
| Persistence | T1543.002 | Systemd Service | GSOCKET |
| Persistence | T1053.003 | Cron | GSOCKET |
| Persistence | T1546.004 | Shell Config Modification | GSOCKET |
| Defense Evasion | T1027 | Obfuscated Files or Information | OHSHIT (XOR 0x22) |
| Defense Evasion | T1036.004 | Masquerade Task or Service | PERLBOT, GSOCKET |
| Defense Evasion | T1070.004 | File Deletion | OHSHIT |
| Defense Evasion | T1562.001 | Impair Defenses | PERLBOT (signal ignore) |
| Discovery | T1082 | System Information Discovery | GSOCKET, LOADER |
| Discovery | T1614 | System Location Discovery | GSOCKET (`ifconfig.me`) |
| Lateral Movement | T1021.004 | Remote Services: SSH | OHSHIT, GSOCKET |
| Collection/Exfil | T1041 | Exfiltration Over C2 Channel | GSOCKET |
| C2 | T1071.001 | Web Protocols | OHSHIT, TELNETCURL, LOADER |
| C2 | T1071 | Application Layer Protocol: IRC | PERLBOT |
| C2 | T1090.003 | Multi-hop Proxy: Tor | OHSHIT (.onion) |
| C2 | T1573 | Encrypted Channel | GSOCKET (GSRN) |
| Impact | T1498.001 | Direct Network Flood | OHSHIT, TELNETCURL |
| Impact | T1499.002 | Service Exhaustion Flood | OHSHIT (L7) |
| Impact | T1489 | Service Stop | BOTKILL |

---

## 4. Mitigation framework

### 4.1 Initial access — credential and service exposure

| Control | Rating | Notes |
|---------|:------:|-------|
| Disable telnet (tcp/23, 2323) estate-wide | **P1** | Removes the delivery vector for OHSHIT, TELNETCURL, LOADER and BOTKILL outright. Nothing in this corpus reaches those hosts without it |
| Enforce key-only SSH; disable password auth | **P1** | Defeats OHSHIT's embedded SSH client and the GSOCKET delivery path |
| Eliminate vendor-default credentials | **P1** | The entire IoT-botnet segment of this capture depends on them |
| Rate-limit / tarpit failed auth | P3 | Slows scanning; does not prevent |

**Assessment.** Four of seven families in this capture are defeated at this layer
alone. Telnet removal is the single highest-value preventive control here.

### 4.2 Execution — staging directories

| Control | Rating | Notes |
|---------|:------:|-------|
| `noexec,nosuid,nodev` on `/tmp`, `/var/tmp`, `/dev/shm` | **P1** | MIRAI_LOADER's `.f` probe *tests exec* and fails closed. OHSHIT stages in `/tmp` via busybox |
| Restrict `/data/local/tmp` (Android) | **P1** | Same control, Android estate |
| Remove or restrict busybox where not required | P2 | OHSHIT copies `/bin/busybox` to `/tmp`; a determined build ships its own |
| Application allow-listing | **P1** | Defeats all payload execution; high operational cost |

**Assessment.** `noexec` is unusually effective against *this* corpus because
MIRAI_LOADER explicitly probes for exec permission and honours the result.

### 4.3 Persistence — GSOCKET

| Control | Rating | Notes |
|---------|:------:|-------|
| File-integrity monitoring on `/etc/systemd/system/`, user crontabs, shell rc files | **D** | Catches all five mechanisms; none are stealthy |
| Alert on any new systemd unit not from a package manager | **D** | `ls -la /etc/systemd/system/*.service \| grep -v dpkg` |
| Hunt `~/.config/prng/` | **D** | Collides with nothing legitimate — best single indicator |
| Restrict `sudo` for service installation | P2 | The script degrades to crontab when `sudo` fails |

**Mandatory removal order** — deviating makes things worse:

```
1. systemctl disable --now gsocket-watchdog.service; rm the unit file
2. crontab -e  — remove the per-minute and @reboot entries
3. strip the "GSocket Watchdog auto-start" block from .bashrc/.profile/.zshrc/.bash_profile
4. rm -rf ~/.config/prng/
5. ONLY NOW: pkill gs-netcat
6. rotate every credential and SSH key on the host
```

Step 6 is not optional: the beacon exfiltrated the gs-netcat secret, and ssh-it
propagates through the host's own SSH client and known-hosts relationships.

### 4.4 Command and control — egress

| Control | Rating | Notes |
|---------|:------:|-------|
| Default-deny egress from server subnets | **P1** | The only control effective against *all* families including GSOCKET |
| Block cleartext IRC 6660–6669, 6697, 7000 | **P1** for PERLBOT | Survives the `$ARGV[0]` override that defeats every IP control |
| DNS RPZ / sinkhole on the 4 OHSHIT apexes | **P1** for OHSHIT | One action covers all 15 architectures incl. 8 never captured |
| Blocklist the 41 IPs | P2 | Defeated by infrastructure rotation |
| Block Tor and tor2web gateway egress | **P2** | Addresses `control.tor2web-relay-fast.onion` |
| Block gsocket.io + GSRN egress | **P2** | Only preventive option for GSOCKET; relay set can change |
| Cloudflare abuse report — `sync.softwaremirror.workers.dev` | **P1** (that host) | **Never block the `workers.dev` apex** — shared infrastructure |

### 4.5 Impact — the L7 flood

**Signature-based filtering does not work here, by design.** Header and Referer
randomisation makes each request browser-indistinguishable.

| Control | Rating | Notes |
|---------|:------:|-------|
| Per-source rate limiting / adaptive thresholds | **P1** | The only reliable control against randomised L7 |
| Egress rate limiting from server subnets | **P1** | Stops your estate *participating*; often overlooked |
| Alert: archaic MSIE/Trident UA at volume from a server subnet | **D** | Suricata 9001011 (thresholded) |
| Alert: embedded Referer pool at volume | **D** | Suricata 9001012 (thresholded) |
| Challenge/JS interstitial at the edge | P2 | The bot is not a browser; effective until it is |

**Deploy 9001011/9001012 thresholded only.** Unthresholded they will fire on
ordinary browsing.

### 4.6 Detection where prevention is impossible

For GSOCKET, whose C2 cannot be blocked by name or address, detect on behaviour:

- long-lived outbound TLS from a host with no business making it
- a process named `gs-netcat`, or one respawning within ~30 s of every kill
- outbound HTTP POST to a bare IP with `hostname` in the body
- `curl`/`wget` to `ifconfig.me` from a server

---

## 5. Control-to-capability coverage

| Capability | Prevented by | Residual risk |
|------------|--------------|---------------|
| Telnet propagation | 4.1 telnet removal | **None** if enforced estate-wide |
| SSH propagation | 4.1 key-only auth | Low — key theft via GSOCKET remains |
| Payload execution | 4.2 `noexec` | Low — attacker may stage elsewhere |
| GSOCKET persistence | 4.3 (detective) + 4.4 egress | **Medium — no clean preventive control** |
| GSOCKET C2 | 4.4 default-deny egress only | **Medium — unsinkholeable by design** |
| PERLBOT C2 | 4.4 IRC port block | Low |
| OHSHIT C2 | 4.4 DNS sinkhole | Low — Tor path remains |
| L7 flood | 4.5 rate limiting | Medium — absorption, not prevention |
| Recon probing | None practical | **Accepted** — detect and treat as prior-compromise signal |

**Two capabilities carry medium residual risk under a complete control set:**
GSOCKET's rendezvous-by-secret C2, and L7 flood participation. Both are
architectural, not configuration gaps. Neither is closed by anything in this
repository's blocklist — they close only with default-deny egress.

---

## 6. Validation

Before relying on the artifacts in this repository:

```bash
# YARA — NOT YET RUN. yara is absent from the analysis workstation and every
# rule file was edited on 2026-08-08. Run this on a host that has YARA.
yara -r yara/*.yar /dev/null

# Suricata
suricata -T -c /etc/suricata/suricata.yaml

# Reproduce the XOR finding
python3 tools/binstrings.py <ohshit-payload>.bin --xor sweep      # expect 0x22 to win
python3 tools/binstrings.py <ohshit-payload>.bin --xor 0x22 --ioc
python3 tools/binstrings.py <telnetcurl-payload>.bin --xor sweep  # expect nothing

# Blocklist hygiene
grep -E "^#|^$" blocklist.txt && echo "WARNING: comments or blanks present"
```

**Known-unverified:** YARA rule syntax. Do not treat the rules as validated
until the first command above runs clean.
