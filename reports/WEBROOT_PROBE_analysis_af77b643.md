# WEBROOT_PROBE — Analysis Report

**Lead sample:** `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 2

---

## 1. Incident summary

The two most-seen samples in this capture — **224 sightings combined** — and by
a wide margin the least interesting as files. Both are two lines long. Both were
written over SSH to `/var/www/html/filter` between 2026-07-28 and 2026-08-05,
from 18 source IPs rotating inside five bulletproof /24s.

They are **write-and-execute capability probes**, not payloads. The operator
plants one, requests it over HTTP, and looks for `xxxxxx` in the response. A hit
confirms two things at once: they can write to the webroot, and that webroot
executes scripts. They then return with something real.

**Finding one of these means someone has already confirmed RCE on that host.**
The file is harmless; what it proves is not.

## 2. Phase 1 — Triage

| SHA-256 (8) | Size | Sightings | Shebang | Type |
|---|---|---|---|---|
| `af77b643` | 26 B | **168** | `#!/bin/bash` | Bourne-Again shell |
| `f3abe9aa` | 24 B | **56** | `#!/bin/sh` | POSIX shell |

MD5 `2fd06197c21c19fe142f8ff38019c91c` and `2806a6e59843f0f7269e5050ab883898`.
Delivered over SSH, both to `/var/www/html/filter`. Neither carries a
VirusTotal record — correctly so; there is nothing malicious in the bytes.

## 3. Phase 2 — Source

`af77b643`, complete:

```sh
#!/bin/bash
echo "xxxxxx"
```

`f3abe9aa`, complete:

```sh
#!/bin/sh
echo "xxxxxx"
```

The **only** difference between the two files is the interpreter on line 1 —
which accounts for the two-byte size difference. Two probe variants for targets
where `bash` may not exist.

## 4. Phase 3 — Capabilities

**None, by design.** No network code, no persistence, no execution of anything
beyond `echo`. The capability being tested belongs to the *operator*, not the
script:

| Tested | How it is confirmed |
|--------|---------------------|
| Webroot write access | the file lands at `/var/www/html/filter` |
| Script execution in webroot | `GET /filter` returns `xxxxxx` rather than the source |
| Interpreter availability | `bash` variant vs `sh` variant |

The token `xxxxxx` is chosen to be trivially greppable in an HTTP response and
to look like nothing in particular if a human sees it.

## 5. Phase 4 — C2 protocol

**None in the sample.** The C2 channel here is the operator's own HTTP request
back to the planted file — the probe is the response half of a transaction whose
request half never touches the sample.

There is nothing to sinkhole. The entire intelligence value of this family is
the **source IP set**.

## 6. Phase 5 — Persistence

**None.** The file persists only in the sense that it was written to disk and
not cleaned up — which is itself a hunting opportunity, since operators
frequently leave probes behind.

## 7. Phase 6 — Attribution

No family attribution is possible or meaningful from two lines of shell. The
attribution signal is entirely infrastructural: 18 IPs, tightly clustered in
five /24s, rotating at roughly two per day across nine days. That pattern —
narrow ranges, steady rotation, bulletproof hosting — is characteristic of a
managed scanning operation rather than an individual.

```
2.57.122.209     2.57.122.168
92.118.39.77     92.118.39.50     92.118.39.71     92.118.39.49    92.118.39.14
80.94.92.234     80.94.92.55      80.94.92.179
195.178.110.217  195.178.110.232  195.178.110.228  195.178.110.227
193.32.162.84    193.32.162.34    193.32.162.15    193.32.162.27
```

Netblocks: `2.57.122.0/24`, `92.118.39.0/24`, `80.94.92.0/24`,
`195.178.110.0/24`, `193.32.162.0/24`.

Given ~2 IPs/day rotation inside fixed /24s, blocking individual hosts is
short-lived. **Block the /24s at the perimeter if policy allows** — but note
`blocklist.txt` takes individual IPs only, by design, so the CIDR guidance lives
in `firewalla/drosera_block.txt` rather than the machine feed.

## 8. Phase 7 — Host detection

```bash
ls -la /var/www/html/filter 2>/dev/null
find /var/www -name "filter" -o -name "*.sh" -newermt "2026-07-01" 2>/dev/null
grep -rl "xxxxxx" /var/www 2>/dev/null
# and the part that actually matters:
grep -iE "accepted|failed" /var/log/auth.log | tail -200
```

**Treat a hit as a prior-compromise indicator, not a malware finding.** The
correct response is to scope how the operator obtained webroot write access in
the first place, not to delete the file and move on.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1190 | Exploit Public-Facing Application | webroot write + execution |
| T1078 | Valid Accounts | SSH delivery |
| T1505.003 | Server Software Component: Web Shell | precursor — proves web shell viability |
| T1083 | File and Directory Discovery | webroot writability test |
| T1592 | Gather Victim Host Information | interpreter availability |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| SHA-256 | `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32` | — |
| SHA-256 | `f3abe9aa18137a8002706fd584b24b4c0d95cbc4f6ad25915bdd7a5ec184e002` | — |
| IP | the 18 addresses in §7 | HIGH — direct capture |
| CIDR | the five /24s in §7 | HIGH — perimeter guidance only |
| Path | `/var/www/html/filter` | HIGH |
| String | `echo "xxxxxx"` | **LOW — see §11** |

## 11. Why no YARA rule ships

Deliberate, and this is the clearest case in the capture. A signature on a
two-line script containing `echo "xxxxxx"` would fire on test fixtures,
scaffolding, tutorial files and throwaway debug scripts across any estate. The
false-positive cost vastly exceeds the detection value, particularly since the
file itself does nothing harmful.

The value of this family is the **source IP set and what a hit implies about the
host** — both served far better by the IOC feed, the Firewalla list and the
Suricata rules (`9007001–9007003`) than by a file signature.

**Artifacts:** `ioc/WEBROOT_PROBE_ioc.txt` · `suricata/webroot_probe.rules`
(9007001–9007003) · `firewalla/drosera_block.txt`
