# Infrastructure & Sinkhole Analysis — Capture 2026-08-07

**TLP:WHITE** · Author: AfterPacket · Date: 2026-08-08

Per-sample determination of the command-and-control channel, the namespace it
depends on, and whether that namespace can be sinkholed. Sinkholing here means
the defensive/coordinated sense: taking control of the name or route a bot
depends on, so infected hosts reach a controlled collector instead of the
operator, and can be enumerated and notified.

**Method.** All 25 samples decrypted and read directly. ELF payloads processed
with `tools/binstrings.py --ioc`, then re-processed under single-byte XOR to
recover obfuscated configuration. Every indicator below was observed in sample
bytes during this review.

---

## 1. Channel inventory

| Family | C2 channel | Namespace depended on | Sinkholable? |
|--------|-----------|----------------------|--------------|
| MIRAI_OHSHIT | HTTP + custom, 5 domains + 6 IPs + 1 .onion | **DNS (attacker-owned)** | **Yes — high value** |
| MIRAI_TELNETCURL | HTTP staging, bare IP | None (IP literal) | No — route-level only |
| PERLBOT_SHELLBOT | IRC tcp/6667, 2 IPs | None (IP literal, overridable) | Partial — see §4 |
| GSOCKET_SSHIT | GSRN relay + HTTP exfil | Shared secret, not a host | C2 no / exfil **yes** |
| MIRAI_LOADER | HTTP staging, bare IP | None (IP literal) | No — route-level only |
| BOTKILL_PROCWIPE | None | — | N/A (no network code) |
| WEBROOT_PROBE | None | — | N/A (recon only) |

**No true peer-to-peer C2 was found.** No DHT bootstrap lists, no peer-exchange
tables, no gossip protocol in any sample. The only decentralised element in the
capture is a single Tor hidden-service name (§2.3).

---

## 2. MIRAI_OHSHIT — the sinkhole target

Nine samples: 2 shell scripts + 7 ELF payloads (`de9cfdf7`, `8b1a2fb6`,
`81ea2a39`, `78a57de8`, `15b950d6`, `7b8add30`, `2ae7dc16`, `98994017`,
`9d7cd494`).

### 2.1 Staging tier — `94.154.43.123`

Bare IP, both delivery and payload host. Serves `/ohshit.sh` and
`//bot.<arch>` across 15 architectures. No domain, so **not DNS-sinkholable**;
handle by null-route, provider abuse report or upstream takedown.

### 2.2 C2 tier — five attacker-owned domains (the leverage point)

Compiled **identically into all seven captured builds**. Because the set is
build-invariant, it is equally present in the 8 architecture builds that were
never captured.

| FQDN | Apex | Sinkhole route |
|------|------|----------------|
| `api-relay-3.metrics-collector.io` | `metrics-collector.io` | Registrar/registry — `.io` |
| `cdn-edge-updates.hostcloud-eu.net` | `hostcloud-eu.net` | Registrar — `.net` |
| `mgmt-panel.serverstats-daemon.com` | `serverstats-daemon.com` | Registrar — `.com` |
| `glibc.malloc.top` | `malloc.top` | Registrar — `.top` |
| `sync.softwaremirror.workers.dev` | `workers.dev` | **Cloudflare abuse only** |

Every name impersonates ordinary infrastructure — a metrics collector, CDN edge
updates, a stats daemon, a software mirror, and (audaciously) glibc's allocator.

> **Recommendation.** Seizing or sinkholing the four attacker-owned apexes is
> the single highest-leverage action available against this capture. One action
> covers all 15 architectures, captured and uncaptured alike, and yields a
> complete victim census. Verify registration ownership before acting.

> **`workers.dev` is different and must be handled differently.** The apex is
> Cloudflare Workers — shared infrastructure. **Never block or sinkhole the
> apex.** Only `sync.softwaremirror.workers.dev` is attacker-controlled;
> remediation is a Cloudflare abuse report, not a DNS action.

### 2.3 Tor tier — `control.tor2web-relay-fast.onion`

Not resolvable through normal DNS and **not sinkholable** by conventional
means. The `tor2web` label indicates the operator expects to reach it through
public tor2web gateways, which is the practical control point: block Tor egress
and known tor2web gateway domains. Recorded in the IOC feed but deliberately
**excluded from `blocklist.txt`**, which is a DNS/IP feed and cannot express it.

### 2.4 Hardcoded C2 IPs

`45.61.161.207` · `45.83.140.28` · `5.101.221.87` · `51.15.68.114` ·
`94.130.53.201` · `195.201.24.6` — present in all seven builds. Route-level
handling; a redirect to a collector is possible with upstream cooperation.

### 2.5 Obfuscated capability — XOR 0x22

Mirai's `table.c` XORs config with the four bytes of `TABLE_KEY`; the leaked
default `0xdeadbeef` collapses to a single effective byte
(`0xef^0xbe^0xad^0xde = 0x22`). All seven builds carry such a region. Recovered
contents:

- HTTP request scaffolding: `HTTP/1.1`, `User-Agent:`, `Accept:`,
  `Accept-Language:`, `Accept-Encoding:`, `Referer:`
- A large rotating **User-Agent pool** (MSIE 8/9/10, Firefox, Gecko builds)
- **20 Referer URLs** of real, legitimate sites
- `http://www.useragentstring.com/Firefox25.0_id_19710.php` — the page the
  author scraped the UA list from

This is a **Layer-7 HTTP flood module**, previously undocumented for this family.

> ### ⚠ Do NOT blocklist the recovered Referer domains
> `www.google.com` · `www.facebook.com` · `twitter.com` · `www.instagram.com` ·
> `www.reddit.com` · `www.youtube.com` · `www.bing.com` · `www.linkedin.com` ·
> `t.co` · `duckduckgo.com` · `search.yahoo.com` · `www.tiktok.com` ·
> `www.pinterest.com` · `www.baidu.com` · `www.cloudflare.com` · `github.com` ·
> `stackoverflow.com` · `news.ycombinator.com` · `discord.com` · `telegram.org` ·
> `www.useragentstring.com`
>
> These are flood **Referer** values, not infrastructure. An automated
> "extract domains from malware, add to blocklist" pipeline would ingest them
> and take down the estate's access to most of the internet. **The XOR region
> contains no C2 whatsoever** — verified across all seven builds.

### 2.6 Propagation

Payloads embed a complete SSH client (`ssh-ed25519`, `curve25519`, `chacha20`,
`aes128-ctr`, `hmac-sha2`, `openssh.com` algorithm suffixes). The loader chain
is telnet-only, so **scoping containment from the dropper alone misses the SSH
vector**. Audit SSH auth logs, not just telnet.

---

## 3. MIRAI_TELNETCURL — no sinkholable namespace

Seven samples: `3801a288`, `e1568cae` (droppers) + `b6260a8c`, `9cbe35b1`,
`a834705a`, `3afa3a11`, `f6f9c5f1` (ELF).

Staging `205.237.110.232`, delivery `60.185.49.73` and `138.117.43.19` — all
bare IPs. The droppers contain no domain at all.

**Verified not obfuscated.** XOR sweep across the full single-byte keyspace
returned zero meaningful strings at 0x22 or any other key. The family is
genuinely IP-only; that is now established rather than assumed.

The only domain in the payloads is `www.ikindalikemenbutonlyontuesday.com`, the
decoy from the leaked Mirai source. It is a **lineage marker, not
infrastructure** — historically already sinkholed/parked, and sinkholing it
again achieves nothing. Treat a hit as "some Mirai descendant" and require
corroborating infrastructure before attributing to this campaign.

**Sinkhole verdict: not possible.** Null-route the two hosts.

---

## 4. PERLBOT_SHELLBOT — sinkholable, but fragile

Three samples: `03a4f492` (/duba), `fe6b7b4c` (/dodu), `fd93b4f7` (/gots).

Two live IRC C2 servers on tcp/6667: `213.139.77.150` (/duba) and
`213.177.179.11` (/dodu, /gots).

### The override problem

All three read a C2 override from the first argument:

```perl
$server="$ARGV[0]" if $ARGV[0];
```

An IP sinkhole is therefore **defeated by relaunching the bot against any other
host**. Sinkholing the two known servers is worth doing for census purposes but
must not be mistaken for containment.

### The durable fingerprint

All three samples — across *both* C2 servers — share:

```perl
my @admins   = ("MAD");
my @channels = ("#mot");
```

This is strong evidence of **one operator running both servers**, and it is the
control that survives everything else: a sinkhole IRC server accepting any
connection can enumerate victims by watching for `JOIN #mot`, regardless of
which host the bot was pointed at. Now shipped as Suricata SID 9003005.

**Sinkhole design:** stand up an IRC daemon on the two known IPs, accept all
`NICK`/`USER` registration, log every client that issues `JOIN #mot`. Do not
issue commands — `@admins=("MAD")` means the bot only accepts instructions from
that nick, and issuing any would be acting on victim hosts.

**Durable control:** egress-block 6660–6669, 6697 (IRC-over-TLS) and 7000.

---

## 5. GSOCKET_SSHIT — C2 unsinkholable, exfil highly sinkholable

One sample: `22585585` (`/da`, 538 lines of bash, VT 2/60).

### Why the C2 cannot be sinkholed

The backdoor is THC **Global Socket**, a legitimate published tool. Peers rendezvous
through the Global Socket Relay Network using a **shared secret as the address** —
there is no attacker hostname or IP in the C2 path to seize. The relay network
itself is legitimate infrastructure serving lawful users.

Practical controls: block egress to the GSRN and to `gsocket.io`, and detect on
behaviour (§5.3). **Attribute the abuse, not the tool** — do not blocklist
`gsocket.io`, `thc.org` or `github.com`.

### The exfil endpoint is the opportunity

```bash
GS_UPLOAD_URL="http://192.253.248.9/gsocket/up.php"
```

The beacon is an ordinary HTTP POST to attacker-owned infrastructure carrying:

| Field | Content |
|-------|---------|
| `data` | the **`gs-netcat -s "<secret>" -i` line — the access credential itself** |
| `host` | victim hostname |
| `ip` | victim public IP, via `ifconfig.me` |

> **This is the richest sinkhole target in the capture.** A collector on
> `192.253.248.9` receives a self-identifying census of every victim, complete
> with hostname and public IP. Note the exfil host and the delivery host
> (`192.253.248.92`) sit in the same /24 — one operator.
>
> Handling caution: captured secrets *are* live access credentials to victim
> machines. Collect and use them for notification only, under whatever legal
> authority applies.

### Why killing the process does not work

A watchdog checks every 30 seconds; if `gs-netcat` is not running it reinstalls
gsocket **and uploads a fresh secret to the operator**. Killing the process
regenerates access and re-notifies the attacker. Persistence must be removed
first, in this order:

1. `systemd` unit `/etc/systemd/system/gsocket-watchdog.service` (`Restart=always`,
   `StartLimitBurst=0`)
2. crontab `* * * * *` and `@reboot sleep 10`
3. `~/.bashrc`, `~/.profile`, `~/.zshrc`, `~/.bash_profile` injections
4. the watchdog itself, `~/.config/prng/watchdog.sh`
5. only then kill `gs-netcat`

### Host indicators

`~/.config/prng/` — containing `watchdog.sh`, `gs_output.log`, `gs_line.txt`,
`thc_cli`. Staging in `/tmp/thc_tmp` (mode 700). **`~/.config/prng/` collides
with nothing legitimate and is the best single hunt string for this family.**

---

## 6. MIRAI_LOADER — no sinkholable namespace

One sample: `246c3c37` (`/wget`, 409 B, no shebang).

```sh
DIRS="/tmp /var /dev /var/tmp /dev/shm /data/local/tmp"
ARCHS="arm arm5 arm7 mips mpsl"
SERVER="77.90.185.66"
```

Bare IP staging, serving `http://77.90.185.66/mirai.<arch>` → written to
`dvrHelper`, executed with exec tag **`tscan`**. `/data/local/tmp` in the
directory list means this loader **targets Android** as well as Linux — not
previously recorded.

**Sinkhole verdict: not possible.** Null-route `77.90.185.66`.

---

## 7. WEBROOT_PROBE and BOTKILL_PROCWIPE — nothing to sinkhole

**WEBROOT_PROBE** (`af77b643`, `f3abe9aa`) — two-line scripts, no network code.
Value is the 18 source IPs rotating ~2/day inside five bulletproof /24s:
`2.57.122.0/24`, `92.118.39.0/24`, `80.94.92.0/24`, `195.178.110.0/24`,
`193.32.162.0/24`. Perimeter-block the ranges if policy allows.

**BOTKILL_PROCWIPE** (`41d9a2a0`, `2733d565`) — no network code at all.
Note `2733d565` was **inert as delivered**: byte sequence `5c 33 42` (`\3B`)
appears where a `;` (0x3B) belongs — the operator's own typo for `\x3B` —
leaving a `for` loop with no `do` and a `done` with no opener. **That drop was
inert and could not have executed.** Do not infer capability from it; the
intent is still evidenced by the source. Its SHA-256 is a sensor artefact and
must not be used for matching; see the README's *Sample digests* section.

---

## 8. Priority of action

| Priority | Action | Coverage |
|----------|--------|----------|
| 1 | Sinkhole the 4 MIRAI_OHSHIT apex domains | All 15 arch builds, incl. 8 never captured |
| 2 | Sinkhole `192.253.248.9` (GSOCKET exfil) | Full victim census with hostname + public IP |
| 3 | Egress-block IRC 6660–6669/6697/7000 | Survives PERLBOT's C2 override |
| 4 | Cloudflare abuse report — `sync.softwaremirror.workers.dev` | Apex is shared; cannot be blocked |
| 5 | Null-route bare-IP staging hosts | TELNETCURL, MIRAI_LOADER, OHSHIT staging |
| 6 | Block Tor / tor2web gateway egress | The one .onion C2 |
| 7 | Perimeter-block the 5 WEBROOT_PROBE /24s | Recon campaign |
