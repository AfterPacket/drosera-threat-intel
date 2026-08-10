# Executive Summary — Drosera Capture 2026-08-07

**Classification:** TLP:WHITE · **Author:** AfterPacket · **Date:** 2026-08-08
**Corpus:** 25 samples, 7 families, sightings 2026-07-28 → 2026-08-07
**Basis:** full static analysis of all 25 decrypted samples. Every claim below was
re-derived from sample bytes in this review, not carried over from prior notes.

---

## 1. Bottom line

Seven distinct actors touched the honeypot in eleven days. Five run malware; one
runs competitor-removal scripts; one is a reconnaissance campaign that plants
nothing. The single most consequential finding of this review is that
**MIRAI_OHSHIT carries a Layer-7 HTTP flood module that was previously
undocumented**, hidden behind XOR-0x22 obfuscation that plaintext string
extraction cannot see.

The capture's centre of gravity is **MIRAI_OHSHIT**: it is the only family with
attacker-owned C2 *domains*, and therefore the only one where a DNS sinkhole
neutralises the botnet rather than merely inconveniencing it.

## 2. What changed in this review

| # | Finding | Impact |
|---|---------|--------|
| 1 | **XOR-0x22 obfuscated config in all 7 MIRAI_OHSHIT ELF builds** — a full HTTP flood kit: header templates, 20 Referer URLs, a large User-Agent pool | Capability was missed entirely. Family is a DDoS platform, not just a loader |
| 2 | MIRAI_TELNETCURL confirmed **not** obfuscated — 0 hits at 0x22 | The "genuinely IP-only" assessment holds, now proven rather than assumed |
| 3 | XOR region contains **no hidden C2** — 20 revealed domains are all legitimate Referer targets | Blocklist confirmed complete. Critical: these must never be blocklisted |
| 4 | `ohshit.sh` loops **15** architectures, not 16 | Published figures in README/site were wrong |
| 5 | MIRAI_TELNETCURL droppers clean up **7** filenames, only 5 are fetched | `PLXMKJ` and `KFGDFG` are new hunt strings for uncaptured builds |
| 6 | MIRAI_LOADER targets **Android** (`/data/local/tmp`) and passes exec tag `tscan` | Scope and detection both widen |
| 7 | All three Perl bots share `@admins=("MAD")` and `@channels=("#mot")` | Proves one operator across two C2 servers; survives the C2-override evasion |
| 8 | GSOCKET installs **five** persistence mechanisms, not two | Containment guidance was materially incomplete |
| 9 | BOTKILL sample `2733d565` was **inert as delivered** (`\3B` where `;` belongs — the operator's own typo) | That drop never ran; do not infer capability from it. Its SHA-256 is a sensor artefact — do not match on it |

## 3. Risk ranking

| Rank | Family | Why |
|------|--------|-----|
| 1 | **GSOCKET_SSHIT** | Full interactive backdoor with five persistence mechanisms and a self-healing watchdog that re-exfiltrates a fresh access credential every 30 s. VT 2/60. Killing the process *regenerates* access |
| 2 | **MIRAI_OHSHIT** | 15-architecture reach, attacker-owned C2 domains, SSH **and** telnet propagation, plus the newly found L7 flood module |
| 3 | **PERLBOT_SHELLBOT** | Interactive shell over IRC, two live C2 servers, one sample with **zero** VT coverage |
| 4 | **MIRAI_TELNETCURL** | Conventional Mirai loader, 5 architectures, IP-only infrastructure |
| 5 | **MIRAI_LOADER** | Self-identifying, trivially detected, but now known to target Android |
| 6 | **WEBROOT_PROBE** | Plants nothing — but a hit means someone already confirmed RCE on that host |
| 7 | **BOTKILL_PROCWIPE** | Not a payload. Its presence is evidence of *prior* compromise by a second actor |

## 4. Sinkhole posture — the operational recommendation

Full detail in `CAPTURE_20260807_infrastructure_and_sinkhole.md`. In short:

- **MIRAI_OHSHIT is the one worth sinkholing.** Its five C2 domains are compiled
  identically into every architecture build, so a DNS sinkhole on the four
  attacker-owned apexes covers all 15 architectures — including the 8 builds
  never captured. This is the highest-leverage single action available.
- **GSOCKET cannot be sinkholed at its C2**, because the Global Socket Relay
  Network addresses peers by shared secret rather than by host. But its *exfil*
  endpoint `192.253.248.9` is ordinary attacker infrastructure and is
  sinkholable — and every beacon to it carries victim hostname, public IP and
  the gs-netcat secret, making it an unusually rich victim-enumeration point.
- **PERLBOT resists IP sinkholing** because it accepts a C2 override argument.
  The durable control is an egress block on IRC ports; the durable *detection*
  is `JOIN #mot`, which survives both the override and a server change.
- **MIRAI_TELNETCURL, MIRAI_LOADER and WEBROOT_PROBE have no sinkholable
  namespace** — bare IPs only. Null-route or perimeter-block.
- **One .onion exists** (`control.tor2web-relay-fast.onion`, MIRAI_OHSHIT). It
  is not DNS-resolvable and cannot be sinkholed conventionally; the practical
  control is blocking Tor and tor2web gateway egress. No true P2P/DHT C2 was
  found in any sample.

## 5. Immediate actions

1. **Block or sinkhole** the four MIRAI_OHSHIT apex domains after verifying
   registration. Highest single-action coverage in this capture.
2. **Never blocklist** the 20 Referer domains recovered from the XOR region —
   they are google.com, facebook.com, cloudflare.com and similar. An automated
   "extract domains from malware" pipeline would blocklist them and cause a
   major outage. This is the most dangerous mistake available in this dataset.
3. **Hunt `~/.config/prng/`** across the estate. It is the GSOCKET staging
   directory and does not collide with anything legitimate.
4. **Egress-block cleartext IRC** (6660–6669, 6697, 7000). It is the only
   control that survives PERLBOT's runtime C2 override.
5. **Reimage, do not clean,** any host with `/home/.k` — it has been compromised
   by at least two separate actors.

## 6. Detection coverage after this review

| Artifact | State |
|----------|-------|
| YARA | 7 rules, 5 files — now YARAhub-compliant and XOR-aware |
| Suricata | 7 rulesets, SID blocks 9001001–9007003 |
| IOC feeds | 7 families |
| Blocklist | 41 IPs, 5 domains — **unchanged by this review**, which independently confirms it |

**Deliberately shipping no YARA rule:** WEBROOT_PROBE and BOTKILL_PROCWIPE. Both
are generic two-to-ten-line shell scripts; a signature would false-positive
across any estate. That is a decision, not a gap.

## 7. Caveat

`yara` is not installed on the analysis workstation, so the rule files in this
repository have **not** been compile-verified. Treat rule syntax as unverified
until `yara -r yara/*.yar` is run on a host that has it.
