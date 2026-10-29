# KTHREAD_LOADER — architecture-selected hidden-file loader

**TLP:WHITE** · Author: AfterPacket · Static review: 2026-10-29

## Summary

**Observed:** sample `b1a84cfd` contains a POSIX shell loader which maps `uname -m`
results to kernel-thread-like payload names, downloads into a hidden file, starts
it in the background, and removes its own script (source evidence below).
**Inferred:** the names and leading dot are intended to reduce the payload's
visibility. **Unverified:** botnet family, operator, payload capabilities,
successful execution, persistence and a C2 endpoint. `KTHREAD_LOADER` is a new
**descriptive source-cluster label**, not attribution to a known family.

**Observed:** Phase 0 found no existing YARA hit or report for this sample.
This report fills that loader-specific gap without extending the claims in
[MIRAI_OHSHIT_analysis_8b1a2fb6.md](MIRAI_OHSHIT_analysis_8b1a2fb6.md).

## Sample metadata

| Field | Value / evidence status |
|---|---|
| SHA-256 — Observed | `b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9` |
| MD5 — Observed | `ef38b770bef2edfe47529229264fde1e` |
| SHA-1 — Observed | `57e64e12b878922a9f8b30ab28e89fc012b25dce` |
| Size / newlines — Observed | 1,969 bytes / 73 LF bytes |
| Type — Observed | ASCII POSIX shell source, `#!/bin/sh` at offset `0x0000` |
| Architecture / endianness / linkage / stripped | Not applicable to shell source; target labels below are not binary-header identifications |
| Packing / compiler — Observed | Readable source; no ELF sections, packer header or compiler metadata. Whole-file Shannon entropy 4.98260 bits/byte; this alone does not prove absence of encoded content |
| TLSH / ssdeep | Not checked; not required for this source-based comparison |
| ELF import/symbol hash | Not applicable |
| Capture record — Observed in sidecar | `b1a84cfd…json`: `2026-10-28T21:33:08+00:00`, SSH `loader-fetch`, filename `/bins/loader.sh`, source `78.17.98.2` |
| VT / ASN / geo / ownership | Not checked. No external queries performed |
| Archive — Observed | [samples/b1a84cfd….zip](../samples/b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9.zip), AES-256, password `infected`; extracted-byte digest verified |

**Observed:** sidecar values are supplied capture metadata, not independent
verification of the remote server or evidence of subsequent victim behavior.

## Static findings

**Observed:** byte offsets below refer to the hash-verified, unmodified source;
line numbers are one-indexed. Repository `tools/binstrings.py` ASCII extraction
(minimum length 6) returned 54 runs, exactly equal in text and offset to an
independent byte-by-byte printable-run pass. UTF-16LE extraction returned no
runs of length 6. Printable source lines are the usable strings; no decoder was
needed. **Unverified:** arbitrary encoded payload absence; no exhaustive custom
encoding search is claimed.

| Source | Observed artifact | Classification / interpretation |
|---|---|---|
| L3, `0x000b` | `SRV="http://44.210.140.205/bins"` | Network: payload retrieval base, not proven C2 |
| L6, `0x0037` | `echo -n I`, `od -to2`, test for `49` | Command: purported endian test; limitation below |
| L10, `0x008a` | `uname -m`, lowercase transform | Command: architecture selection |
| L14–26, `0x00ea`–`0x041c` | `BIN_NAME` assignments | Name/architecture configuration |
| L33, `0x049a` | `/dev/shm /tmp /var/system /mnt /var/tmp /run /dev` | Filesystem candidates; checks directory and write permission only |
| L54, `0x0620` | `DST="$WRITABLE_DIR/.$BIN_NAME"` | Hidden destination |
| L56–63, `0x0640` | `-s` test; wget then curl fallback | Reuses an existing nonempty file; no integrity/signature validation in source |
| L65–66, `0x0705` | chmod then background invocation | Execution intent, not an observed process event |
| L68–70, `0x0730` | `realpath "$0"`, `rm -f "$SELF"` | Script self-deletion intent |

**Observed:** network strings comprise one HTTP URL and its IPv4 literal; no
literal domain or credential list was extracted. `exit 1` is the failure path;
no credential prompt, error-message catalogue or build residue is present in
this readable source.

## Extracted configuration

**Observed:** all mappings are literal assignments, not demonstrated support for
those machine types:

| Input labels (abridged from source) | Payload name |
|---|---|
| x86_64 / amd64 / x64 / x86-64 | `kworker_u8` |
| i386 / i486 / i586 / i686 / i786 / x86 / ia32 | `ksoftirqd0` |
| armv5 variants | `bioset0` |
| armv6 variants | `kblockd0` |
| armv7 / armv8l / armv8-compat | `jbd2_sda1d` |
| aarch64 / arm64 / armv8 / armv8a / armv9 | `rcuop_0` |
| explicit little-endian MIPS labels; initial default | `ecryptfsd` |
| generic MIPS labels | `ecryptfsd` if `is_le`; otherwise `kswapd0` |
| ppc / powerpc / ppc32 / ppc64 | `devfreq_wq` |
| ppc64le | `zswap_shrinkd` |
| s390x | `edac_polld` |
| riscv64 | `cfg80211d` |

**Observed:** URL construction is the base plus `/` plus `BIN_NAME` (L47).
Unknown architectures retain the initial `ecryptfsd` default (L11).

### Offline infrastructure disposition

**Observed — contextual IOC follow-up:** [KTHREAD_LOADER IOC feed](../ioc/KTHREAD_LOADER_ioc.txt)
now publishes the source-observed retrieval host/base, explicitly constructed
candidate payload URLs, loader hashes and host-hunting context. The sidecar-only
capture source is labeled separately. This is an investigation feed, not a deny
list; publishing retrieval evidence does not establish current activity or C2.
**Operator-approved enforcement follow-up:** `44.210.140.205` is now included
in the raw/Firewalla blocklists and destination-specific port policy Rule 5.
This is a policy decision based on source-observed payload retrieval, not new
verification of ownership, current activity or C2. Whole-IP blocking may affect
legitimate co-tenants or reassigned addresses; review before use and reassess.
The metadata-only capture-source address remains excluded.

| Indicator | Comparison with existing IOC/feed | Disposition and one-line reason |
|---|---|---|
| `44.210.140.205`; `hxxp://44.210.140.205/bins` | Source-observed payload retrieval | INCLUDED as operator-approved whole-IP destination block; ownership, co-tenancy and current activity remain unverified; not proven C2 |
| `78.17.98.2` | NEW; sidecar only | EXCLUDED from blocking: a capture-source address is not proof of dedicated malicious ownership |
| Domains | None observed in source | No domain inclusion proposed |

**Unverified:** provider, ASN, geo, current reachability and whether either
address still serves this campaign. No resolution or connection was attempted.

## Behavior

**Observed:** source chooses a writable directory, skips retrieval if the
hidden destination is already nonempty, makes the destination executable, and
backgrounds it with output discarded. No execute-permission probe occurs in
`find_writable_dir`; write access is not proof that the mount permits execution.
The loader contains no cron, systemd or shell-profile modification.

**Inferred:** kernel-thread-like names and dot-prefixed storage provide
masquerading and hidden-file staging. **Unverified:** an actual process-name
rewrite, propagation, flooding, persistence or credential theft by the child.
Those cannot be inferred from the executable's basename.

**Observed:** L6 uses `od -to2` (octal output) but greps `49` (a decimal-looking
value). **Inferred:** this is not a reliable little-endian discriminator:
standard octal output has no digit `9`; additionally a one-byte input cannot
reliably distinguish byte order that way. **Unverified:** exact behavior of the
target's `od` implementation; the sample was not run. Consequently the generic
MIPS branch must not be advertised as verified endian support.

## Relationships to other samples

**Observed:** `kworker_u8`, `jbd2_sda1d`, `zswap_shrinkd`, `ecryptfsd` and the
literal retrieval base occur only in this loader among the 96 unique inputs.
No matching captured child was identified by those exact plaintext strings;
that is a bounded negative string result, not proof that no related binary exists.

**Observed:** [NET_BOT_LOADER_analysis_39be6853.md](NET_BOT_LOADER_analysis_39be6853.md)
uses different names and a try-each-architecture chain. The existing OHSHIT
report describes `WTF` / `//bot.` staging, neither of which appears here.
**Unverified:** shared operator or shared code ancestry; generic wget/curl and
`/tmp` overlap does not establish either.

## ATT&CK mapping

**Inferred from the observed source, not observed runtime activity:**

| Technique | Static basis |
|---|---|
| T1059.004 — Unix Shell | `#!/bin/sh` and shell functions |
| T1082 — System Information Discovery | `uname -m` at L10 |
| T1105 — Ingress Tool Transfer | wget/curl retrieval at L58 |
| T1222.002 — Linux and Mac File and Directory Permissions Modification | chmod at L65 |
| T1564.001 — Hidden Files and Directories | leading dot in destination at L54 |
| T1036 — Masquerading | architecture mapping to kernel-thread-like names |
| T1070.004 — File Deletion | removal of `SELF` at L70 |

## Detection coverage

**Observed:** [KTHREAD_LOADER_archmap](../yara/KTHREAD_LOADER_archmap.yar) requires
`filesize < 64KB`, at least three of four exact `BIN_NAME` assignments, and **all
five** hidden-destination, wget, curl-fallback, self-path and self-delete strings.
No IP or domain is a condition. This is intentionally source-layout-sensitive;
there is no family-wide generalization claim beyond the tested sample set.

**Observed logic difference, not just a new name:**

| Existing rule | Existing condition ingredients | New condition difference |
|---|---|---|
| `MIRAI_OHSHIT_loader` | `ohshit.sh` or host/`//bot.`; alternatively host plus two `WTF`/`cat bot.`/busybox markers | No old marker is reused; requires architecture-name map + hidden destination + both fetch forms + self-cleanup |
| `MIRAI_LOADER_dvrhelper` | SERVER/fetch-template/tscan or IP plus capability markers | No dvrHelper, mirai template, tscan or host branch |
| `MIRAI_TELNETCURL_dropper` | fixed six-letter names or host/tag combinations | No fixed-name quorum or telnet.curl |
| Other four existing rules | ELF C2/XOR/decoy constants, Perl structure, or gsocket exfil | None is used; no equivalent branch |

**Observed:** [kthread_loader_hidden_download.yml](../sigma/kthread_loader_hidden_download.yml)
requires a wget/curl image, one selected `/bins/<name>` URL path and a selected
`/.<name>` hidden destination in the **same expanded command line**. Existing
Sigma rules use other staging names/hosts, not this conjunction. This covers
four distinctive names, not all architecture mappings. Command-line truncation,
BusyBox-as-image and renamed downloaders can evade it.

**Observed:** validation on 2026-10-29: 9/9 YARA files compile individually and
together without warnings; each new rule hits only its intended loader in 96
unique samples (including the original 25). All 672 original-rule/sample cells
are unchanged. Seven benign-text fixtures and 11 structural near-miss tests
passed. Ten Sigma files parse and convert to Splunk; the new selections pass 31
synthetic-event tests total. See [capture test table](CAPTURE_20261029_triage.md)
and [offline validator](../tools/validate_static.py). **Unverified:** real SIEM
ingestion, broad clean-software false-positive rate, and YARAify acceptance.

## Exclusions and limits

**Observed:** analysis was static only; no sample executed, no sample endpoint
contacted. No new Suricata rule (engine unavailable) or SID ships. The follow-up
adds one operator-approved payload-host block and destination-specific egress
policy guidance; no live firewall is changed. The staging IP is deliberately not
substituted for C2.
No actor attribution, external VT result, ASN or geo claim is made.

## Hunting notes

**Inferred:** correlate a downloader writing a dot-prefixed kernel-thread-like
file in a writable temporary directory with its chmod and subsequent execution.
Treat filenames as leads, not proof: legitimate kernel threads must not alert
solely on name. **Unverified:** child-payload behavior and whether the reused
nonempty destination is stale, attacker-controlled or a failed prior download.
