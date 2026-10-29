# NET_BOT_LOADER — tagged multi-architecture staging chain

**TLP:WHITE** · Author: AfterPacket · Static review: 2026-10-29

## Summary

**Observed:** sample `39be6853` has 30 HTTP retrieval/permission/execution chains:
wget and curl variants for each of 15 architecture labels. Each overwrites
`net_bot`, invokes it with a `net.<arch>` argument and exits the script only if
the preceding commands return success. **Inferred:** the operator tries builds
until one succeeds, rather than detecting architecture first. **Unverified:**
named botnet or actor attribution, C2, actual execution and child capabilities.
`NET_BOT_LOADER` is a **descriptive local source-cluster label**, not a family
verdict imported from a vendor scan label.

**Observed:** no existing YARA rule matched this loader during Phase 0. Existing
[MIRAI_OHSHIT_analysis_8b1a2fb6.md](MIRAI_OHSHIT_analysis_8b1a2fb6.md) already
covers a different multi-architecture loader; this report adds only the new
`net_bot` chain and capture-side relationships.

## Sample metadata

| Field | Value / evidence status |
|---|---|
| SHA-256 — Observed | `39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96` |
| MD5 — Observed | `9e3b46f7626b0408ec194c37d7dd9c06` |
| SHA-1 — Observed | `182b94055cbf17b68cd32fca2828a7049320fc35` |
| Size / newlines — Observed | 3,241 bytes / 33 LF bytes |
| Type — Observed | ASCII POSIX shell source, `#!/bin/sh` at `0x0000` |
| Architecture / endianness / linkage / stripped | Not applicable to the script; URL suffixes are not binary-header identifications |
| Packing / compiler — Observed | Fully readable source, no ELF sections or compiler metadata; whole-file Shannon entropy 4.68083 bits/byte, not an independent unpacking verdict |
| TLSH / ssdeep | Not checked |
| ELF import/symbol hash | Not applicable |
| Capture records — Observed in sidecar | `2026-09-10T17:33:34+00:00`: telnet `loader-fetch`, `/bins/net_http.sh`, source `94.154.43.203`; `2026-09-14T03:32:07+00:00`: telnet `loader-fetch`, `/bins/kla.sh`, source `160.119.66.206` |
| VT / ASN / geo / ownership | Not checked externally; supplied scan labels are not used as attribution |
| Archive — Observed | [samples/39be6853….zip](../samples/39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96.zip), AES-256, password `infected`; extracted digest verified |

## Static findings

**Observed:** repository `tools/binstrings.py` at minimum length 6 returned 33
ASCII runs; an independent byte-by-byte printable-run method returned identical
offsets/text. UTF-16LE returned no runs of length 6. No decoding was necessary.
**Unverified:** exhaustive absence of arbitrary custom encodings; none is needed
to read the observed shell logic.

| Source | Observed bytes / structure | Classification |
|---|---|---|
| L2, `0x000a` | `/tmp`, `/var/run`, `/mnt`, `/root`, `/` cd fallbacks | Filesystem staging |
| L3, `0x0041` | `/bins/net.x86_64`, `-O net_bot`, `chmod 777 net_bot`, tagged exec, `&& exit;` | wget retrieval/execution chain |
| L4, `0x00ad` | same path/tag, `curl -L`, `-o net_bot` | curl fallback for same build |
| L7, `0x01eb` | `/bins/net.mips` | Architecture-labelled URL |
| L9, `0x02be` | `/bins/net.mpsl` | Architecture-labelled URL |
| L17, `0x0606` | `/bins/net.arm7` | Architecture-labelled URL |
| L27, `0x0a19` | `/bins/net.arc` | Architecture-labelled URL |
| L33, `0x0c8e` | `rm -rf net_bot net_http.sh` | Cleanup after all earlier chains fall through |

**Observed:** strings contain 15 HTTP URLs, one unique IPv4 literal, no literal
domain, no credential list, no persistence path and no diagnostic message pool.
The architecture labels occur in both URL paths and execution arguments.

## Extracted configuration

**Observed:** all 15 URLs use base `hxxp://160.119.66.206/bins/net.`. Suffixes in
source order are `x86_64 x86 mips mpsl arm arm5 arm6 arm7 ppc m68k sh4 spc arc
i686 i486`. Output is always `net_bot`; the execution tag is always `net.` plus
the attempted suffix. There is no argument-based override or name resolution
in this loader's readable source. No child C2 was extracted by this review.

### Offline infrastructure disposition

| Indicator | Existing IOC/blocklist comparison | Disposition and one-line reason |
|---|---|---|
| `160.119.66.206`; its 15 `/bins/net.<suffix>` URLs | NEW | EXCLUDED from blocking: source proves a retrieval role, not dedicated malicious ownership or absence of legitimate co-tenants |
| `94.154.43.203` | NEW; capture-source sidecar | EXCLUDED from blocking: source-address context alone does not clear shared-hosting/ownership tests |
| Domains | None observed | No domain inclusion proposed |

**Unverified:** current provider, ASN, geo, ownership, reachability and malicious
exclusivity. No resolution or infrastructure connection was performed.

## Behavior

**Observed:** there is no `uname`/architecture test. The shell performs the cd
fallback once, then tries each chained command in order. `&& exit` requires the
child to **return exit status zero**; merely starting a long-running foreground
child does not reach `exit`. The curl branch for a given architecture can run if
the wget chain or child fails. `curl -L` allows redirects in the sample, but no
redirect destination is present in the source or verified by this review.

**Inferred:** a successful child that daemonizes and returns zero would stop the
remaining loader attempts. **Unverified:** actual child daemonization/exit
behavior. The final cleanup at L33 is **not guaranteed after success**, because
an earlier `exit` bypasses it. No cleanup of `/bins/kla.sh` by that name appears
in the source. No cron, systemd or rc-file persistence is implemented here.

## Relationships to other samples

**Observed in supplied metadata:** 28 distinct ELF samples, across two capture
runs, carry `lineage.parent_sha256` equal to this loader's full digest and a
`source_line` exactly present in its source. Each run records 14 paths. The
`net.spc` URL is present in the script but no corresponding captured sample
appears in these sidecars. These are explicit capture lineage records, not an
inference from similar IP ranges or a similarity score. The child samples are
not newly published or claimed as YARA-covered by this work.

| Observed fetched path | SHA-256, source 94.154.43.203 (Sep 10) | SHA-256, source 160.119.66.206 (Sep 14) |
|---|---|---|
| `/bins/net.arc` | `794eec489531313a274c646b3418d514ebc20acddb0e21e9511c440097469257` | `4979c83681a310a8d3789fb8728b1c291c93babc2883edbebd5f470d45d618fe` |
| `/bins/net.arm` | `7fd90b8a783caecdd0609a13ba0b0fb0bc0348c657dbda5d0ab1660840cbeaea` | `cc049286a66056a4a80331b3c08494f8c7c73b4cc6e26328d3e6fb31deef729f` |
| `/bins/net.arm5` | `05ace3bf9402f36cc5b0cd36a0afe0ae0090c6c954b167a645f0123c65ea779c` | `45bee2b10761884f47fac2f515056d15569d85ecfafc662573bf915dbcb8f943` |
| `/bins/net.arm6` | `d6a1e8e40d7e77a126f19e595a44ecf7333b745eddb29a344d468aca97e5645a` | `dd225f82614fbe9734a58b04c77858a2491a9ad5071c5988ec8b9896135ec17d` |
| `/bins/net.arm7` | `600f454199baf384ede4592873473af6c28c283c71f207defac7968a2d99ba29` | `61317fa3019a3a2c66142ebb0e76bcca6374bde0e5b330f04bcb81b366923533` |
| `/bins/net.i486` | `6d8bbd045375e6523dcc28e1f46e89354e3cdb12da1c93fdb040cc6824e08969` | `9bce93a6ea7f1cc1e49f93f0d21bc41d8c065f19a5d9c42f8fb93e0c6e081ebc` |
| `/bins/net.i686` | `c9a25d77eca95fa6c6859681684101a00cdb25e2337ad3a02d946caa8ad247b2` | `1bbf752e3f82b21cbc035fc23de08d0b2539fde3c83cc27c257764a18788cff4` |
| `/bins/net.m68k` | `58d2eb7726146364b492a86571921d12e3ee684c5599d1da01499afdc595c735` | `c11473d154b0e18791a5befe375768beed8e93fe0eb6ed71ed6ea642bead7626` |
| `/bins/net.mips` | `10b386e9d58b7b50d8749289e16b1e6958146d4ace974af96b18d5e047bb6b7a` | `683a3f7c5992c013d4cd71eeaf2d0d3b5a781261fa19a30e4d073ddf712c5ea4` |
| `/bins/net.mpsl` | `c2337d2c2d89a66c4579fa01c82c049a34e606952893bd3c01aa26538add69d1` | `57a4487a6f882b2448048164a1b0ea71c104aa94e9ad6aca8d3f8d2c60401ed4` |
| `/bins/net.ppc` | `119964637064cb5ba87875504b5411f949f5e8a802419639c036adc7bf92f7a3` | `f24f459b6526c8583f40a62a3c97485f4c80b812e81c926bf832a67c208fbbfc` |
| `/bins/net.sh4` | `b13629ce9fa8cba1f1189ddf4a5918c7ab8b4311f45d8ad6334adec7b2186e8d` | `7352f6d206a1aa92c316b0384979fb021fc75a5c2458210455da586a125f7c4c` |
| `/bins/net.x86` | `f0adc635e76a971aa3dd68c8652ba3179433ef9e0f9bcd8c171c4615aeabd1d5` | `2136980fc01c33fcd1f5cf0541ebfce02093eec928921654dc35c17d69205946` |
| `/bins/net.x86_64` | `daec3dc3411585087f53d9601c176a48dcf2ceb343c6ebd47ace2fa8c5b567b3` | `cd6ccc5dabe85309a938e43c9508998bb0f52a9264fa9ba9276956f7fa42f48d` |

**Observed:** each path's two recorded payload hashes differ, while the loader
hash remains identical. **Inferred:** capture-time payload churn or host-specific
builds are plausible. **Unverified:** reason for the differences or a shared
operator; binary similarity was not established here.

**Observed:** the generic cd fallback list overlaps OHSHIT source L4, but the
`net_bot` name, architecture argument and conditional early exit differ from
OHSHIT's `WTF` chain. [KTHREAD_LOADER_analysis_b1a84cfd.md](KTHREAD_LOADER_analysis_b1a84cfd.md)
instead selects a payload by `uname` and uses a hidden destination.
**Unverified:** shared ancestry; generic shell idioms are not attribution.

## ATT&CK mapping

**Inferred from observed source; no runtime behavior claimed:**

| Technique | Source basis |
|---|---|
| T1059.004 — Unix Shell | POSIX shell source |
| T1105 — Ingress Tool Transfer | wget/curl HTTP retrieval |
| T1222.002 — Linux and Mac File and Directory Permissions Modification | `chmod 777 net_bot` |
| T1070.004 — File Deletion | cleanup at L33, reachable only after chains fall through |

**Unverified / not mapped:** exploitation, default credentials, DDoS, propagation,
C2 protocol and persistence. Telnet delivery metadata does not prove which
credentials or initial-access mechanism were used.

## Detection coverage

**Observed:** [NET_BOT_LOADER_staging](../yara/NET_BOT_LOADER_staging.yar) requires
`filesize < 64KB`, three of four `/bins/net.<arch>` paths, both wget and curl
output/chmod chains, two of three tagged execution/exit strings, and exact
`net_bot net_http.sh` cleanup. This intentionally detects source, not child ELFs.

**Observed logic difference:**

| Existing rule | Existing condition ingredients | New logic |
|---|---|---|
| `MIRAI_OHSHIT_loader` | ohshit.sh / //bot. / host with WTF/cat/busybox alternatives | Multiple net.* paths AND both output chains AND tagged exit quorum AND cleanup; none of the old distinguishing strings is reused |
| `MIRAI_TELNETCURL_dropper` | fixed six-letter filenames, telnet.curl and/or staging host | No old fixed filename/tag/host branch |
| `MIRAI_LOADER_dvrhelper` | SERVER/mirai.$arch/dvrHelper tscan or IP/capability combination | No old fetch template, execution tag or host branch |
| Other four existing rules | ELF C2/XOR/decoy, Perl structure, gsocket exfil | None appears in this condition |

**Observed:** [net_bot_loader_tagged_execution.yml](../sigma/net_bot_loader_tagged_execution.yml)
requires the process image to end in `/net_bot` and its expanded command line to
contain a ` net.<arch>` argument. This is not another network-content rule and
does not look for source variables in ordinary process logs. Existing Sigma
rules do not use this image-and-tag conjunction. Prefix matching intentionally
covers arm/arm5/arm6/arm7 and mips variants; this is not strict argv parsing.

**Observed:** validation: 9/9 YARA files compile warning-free; the new rule hits
only `39be6853` in 96 unique samples, including the original 25 and all 28
metadata-linked children (none of the children hits it). All 672 old-rule/sample
cells are unchanged. Both new rules passed seven harmless-text and 11 near-miss
tests in total. Ten Sigma files parse and convert; 31 synthetic events test the
two new rules. Full matrix: [capture validation](CAPTURE_20261029_triage.md).
Reproducer: [tools/validate_static.py](../tools/validate_static.py).
**Unverified:** family-wide generalization beyond the set, real SIEM execution,
representative clean-corpus false-positive rate and YARAify acceptance.

## Exclusions and limits

**Observed:** static analysis only; no sample was run and no endpoint was
contacted. Only the loader's encrypted archive is added; the 28 linked ELFs remain
in the supplied loot, with hashes recorded above. No Suricata rule is shipped
because engine syntax validation is unavailable. No SID allocation, IOC-feed,
firewall or blocklist addition is made. The staging literal is not claimed as
verified command infrastructure.

## Hunting notes

**Inferred:** correlate downloader creation of `net_bot`, permissive chmod and
execution with the architecture argument. A filename or cd-fallback idiom alone
is too generic to attribute. **Unverified:** cleanup success and payload lifetime;
conditional `exit` and foreground execution make both runtime-dependent.
