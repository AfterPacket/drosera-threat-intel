# Drosera Threat Intel

Static analysis and detection artifacts for malware captured live by the **Drosera honeypot**.
Every capture ships a YARA rule, Suricata rules, Sigma rules, an IOC feed, firewall block
entries and a full written report.

**TLP:WHITE** — free to share and republish.
Author: **AfterPacket** · Site: <https://afterpacket.github.io/drosera-threat-intel>

---

## Samples

### Capture 2026-08-07 — 25 samples, 7 families

| Date | Family | Lead SHA-256 | Type | Severity | Artifacts |
|------|--------|--------------|------|----------|-----------|
| 2026-08-07 | [MIRAI_OHSHIT](#mirai_ohshit) | `8b1a2fb6b3584847...` | sh + ELF ×7 | 🔴 CRITICAL | YARA · Suricata · IOC · Firewalla |
| 2026-08-07 | [MIRAI_TELNETCURL](#mirai_telnetcurl) | `3801a288c16a19c5...` | sh + ELF ×5 | 🔴 CRITICAL | YARA · Suricata · IOC · Firewalla |
| 2026-08-07 | [PERLBOT_SHELLBOT](#perlbot_shellbot) | `03a4f492af99d204...` | Perl | 🔴 CRITICAL | YARA · Suricata · IOC · Firewalla |
| 2026-08-02 | [GSOCKET_SSHIT](#gsocket_sshit) | `22585585074dfaf8...` | Shell | 🔴 CRITICAL | YARA · Suricata · IOC · Firewalla |
| 2026-08-03 | [MIRAI_LOADER](#mirai_loader) | `246c3c37a0de2987...` | Shell | 🟠 HIGH | YARA · Suricata · IOC · Firewalla |
| 2026-08-04 | [BOTKILL_PROCWIPE](#botkill_procwipe) | `2733d565138186645...` | Shell | 🟠 HIGH | IOC · Firewalla |
| 2026-08-05 | [WEBROOT_PROBE](#webroot_probe) | `af77b643964afd79...` | Shell | 🟠 HIGH | Suricata · IOC · Firewalla |

**41 IPs and 5 domains blocked.** String extraction over the ELF payloads is
complete; the domain feed is no longer partial.

The MIRAI_OHSHIT payloads carry a compiled-in C2 set, identical across all seven
architecture builds — so the same indicators cover the eight architectures the
loader fetches but we never captured:

```
api-relay-3.metrics-collector.io     mgmt-panel.serverstats-daemon.com
cdn-edge-updates.hostcloud-eu.net    sync.softwaremirror.workers.dev
glibc.malloc.top                     control.tor2web-relay-fast.onion
```

Every one impersonates ordinary infrastructure — a metrics collector, CDN edge
updates, a server stats daemon, a software mirror, glibc's allocator. The
`.onion` is recorded but not blocklisted: it does not resolve through normal DNS.

**Deliberately excluded from the blocklist**, though present in the same
binaries: `185.199.108.153` (GitHub Pages), `104.21.234.17` (Cloudflare), the
`workers.dev` apex, `bugs.launchpad.net` (glibc boilerplate), and `1.2.3.4` /
`131.0.0.0` / `119-121.0.0.0` (placeholders and scanner range constants, not
hosts). Adding shared CDN to a blocklist is the most damaging mistake this feed
could make.

MIRAI_TELNETCURL is **genuinely IP-only** — established by extraction, not
assumed. Its payloads carry one domain,
`www.ikindalikemenbutonlyontuesday.com`, the decoy from the leaked Mirai source.
That is a lineage marker useful for attribution, not infrastructure, and is not
blocked.

---

### MIRAI_OHSHIT

Multi-architecture IoT botnet, staged entirely from `94.154.43.123`. Full chain
recovered: a 104-byte fetcher written to `/tmp/.p` over telnet pulls `ohshit.sh`,
which loops 15 architectures, `cat`s each payload into a file named `WTF`, runs
`chmod +x *`, and executes. Seven of the fifteen architecture builds were captured.
The doubled slash in `http://94.154.43.123//bot.<arch>` is a reliable detection string.

**Hidden L7 flood module (XOR 0x22).** All seven payloads carry a single-byte-XOR
obfuscated config region — Mirai's `table.c` scheme, where the leaked-source
`TABLE_KEY` `0xdeadbeef` collapses to one effective byte
(`0xef^0xbe^0xad^0xde = 0x22`). It holds a full HTTP flood kit: header templates,
a rotating User-Agent pool, and 20 Referer URLs. **This family is a DDoS platform,
not just a loader.** Plaintext string extraction cannot see any of it.

⚠ The 20 Referer domains recovered are `google.com`, `facebook.com`,
`cloudflare.com` and similar — **legitimate sites used as flood header values.**
They are *not* infrastructure and must never be blocklisted. The XOR region
contains **no C2 at all**, verified across all seven builds, which independently
confirms `blocklist.txt` complete.

**SSH propagation.** The payloads embed a full SSH client — `ssh-ed25519`,
`curve25519`, `chacha20`, `aes128-ctr` and `hmac-sha2` algorithm strings are all
present. The loader chain is telnet-only, so scoping containment from the dropper
alone misses the SSH vector entirely. Audit SSH auth logs on affected hosts, not
just telnet. This was found while chasing down the `openssh.com` string.

### MIRAI_TELNETCURL

Telnet-propagated Mirai variant fetching from `205.237.110.232`. Ships as two
dropper variants — a `curl` version and a `busybox wget` version — with fixed
non-dictionary output filenames per architecture (`VFASXC`, `WQZRTY`, `YUIOXC`,
`GHJKLB`, `MNCXOP`) and the exec argument `telnet.curl`. Those five filenames served
by `205.237.110.232` match the five dropped directly by `60.185.49.73` exactly:
one kit, two hosts.

Both droppers `rm -rf` **seven** filenames but fetch only five. `PLXMKJ` and
`KFGDFG` are cleanup targets for architecture builds this kit ships but these two
hosts did not serve — hunt strings for a variant not yet captured.

Verified **not obfuscated**: a sweep of the full single-byte XOR keyspace across
all five payloads returned nothing at `0x22` or any other key. Unlike
MIRAI_OHSHIT, this family really is IP-only — established by negative result
rather than by the absence of plaintext domains.

### PERLBOT_SHELLBOT

Perl IRC shellbot, C2 `213.139.77.150:6667`, with randomised nick and process-name
masquerade. **Contains an undetected twin:** `/duba` and `/dodu` are both exactly
29,427 bytes and arrived from different IPs five days apart. `/duba` is flagged by
29 of 60 VirusTotal engines; `/dodu` has no VirusTotal record at all. The bot accepts
a C2 override via `$ARGV[0]`, so the hardcoded server is a default, not a guarantee —
the shipped YARA rule includes C2-independent structural matches.

**One operator, two servers.** All three samples share `@admins = ("MAD")` and
`@channels = ("#mot")` — identical across both C2 hosts. The nick is randomised
and the server is overridable, but these two are hardcoded and survive both.
`JOIN #mot` is therefore the durable detection (Suricata 9003005, any destination,
any port) and `$op1`/`$op2` in YARA. `/duba` and `/dodu` differ by **exactly one
line** — the C2 IP. `/gots` is a larger, distinct build that spoofs mIRC CTCP
VERSION replies and self-describes as `[alavojda's dd0s b0ts]`.

### GSOCKET_SSHIT

Abuse of **THC Global Socket / ssh-it**, a legitimate published security tool, for
persistent remote access. Beacons to `POST http://192.253.248.9/gsocket/up.php`.
Detection here targets the attacker's wrapper and exfil callback only — never
gsocket itself. VirusTotal 2/60, very low for a working persistent backdoor installer.

**Five persistence mechanisms**, not two: a systemd unit
(`gsocket-watchdog.service`, `Restart=always`), a per-minute crontab, an `@reboot`
crontab, injections into `.bashrc`/`.profile`/`.zshrc`/`.bash_profile`, and the
watchdog script itself. **Kill the process last, not first** — the watchdog polls
every 30 s and, if `gs-netcat` is absent, reinstalls it, derives a *new* secret and
uploads that to the operator. Killing it regenerates access and re-notifies the
attacker. Best host indicator: `~/.config/prng/`, which collides with nothing
legitimate. The beacon carries hostname, public IP **and the gs-netcat credential**,
making `192.253.248.9` the richest sinkhole target in this capture.

### MIRAI_LOADER

Unobfuscated Mirai loader, `SERVER="77.90.185.66"`, fetching `mirai.<arch>` and
writing `dvrHelper`, executed with the tag `tscan`. Self-identifying and trivially
detected. Notable for being actively targeted by BOTKILL_PROCWIPE below.

**Targets Android.** Its directory list includes `/data/local/tmp` alongside the
usual Linux paths — scoping an investigation to Linux hosts alone misses part of
the affected estate. The directory loop is a write-and-execute probe, not a plain
`chdir`: it creates `.f`, chmods it 777, *runs* it, and only then settles there,
selecting the first location permitting both write and exec.

### BOTKILL_PROCWIPE

Not malware — **competitor-removal scripts**, written to `/home/.k` over telnet by an
operator clearing rivals off a box it wants to keep. One kills any process whose
`/proc/$pid/exe` symlink ends in `(deleted)`, the standard tell of a self-deleting
bot. The other greps process cmdlines specifically for `dvrHelper` and kills matches —
**the exact payload name used by MIRAI_LOADER in this same capture.** A host with
`/home/.k` present has been compromised by at least two separate actors; reimage
rather than clean. No YARA rule ships: generic `/proc`-walking kill loops would
false-positive on legitimate process management.

**The dvrHelper-killer was delivered corrupt and never ran.** At offset `0x22` it
carries the bytes `5c 33 42` (`\3B`) where a `;` (`0x3B`) belongs — a shell-escaping
artefact of writing the script over telnet. That leaves a `for` loop with no `do`
and a `done` with no opener, so `/bin/sh` rejects it outright. The operator's intent
stands and the MIRAI_LOADER linkage holds, but this drop was inert. The sibling
sample `41d9a2a0` is intact and does execute.

### WEBROOT_PROBE

The two most-seen samples in the capture (224 sightings combined) and the least
interesting as files — both are two lines: a shebang and `echo "xxxxxx"`, written to
`/var/www/html/filter` over ssh. They are **write-and-execute capability probes**:
the operator plants one, requests it, and looks for `xxxxxx` in the response to
confirm webroot write plus RCE, then returns with a real payload. Finding one means
someone has already confirmed RCE on that host.

No YARA rule ships, deliberately — a signature on `echo "xxxxxx"` would false-positive
across any estate. The value is the 18 source IPs, rotating ~2/day inside five /24s:
`2.57.122.0/24`, `92.118.39.0/24`, `80.94.92.0/24`, `195.178.110.0/24`, `193.32.162.0/24`.

### Do not block

These appear in sample source but are legitimate infrastructure. Blocking them breaks
real traffic:

```
gsocket.io    thc.org    github.com    ifconfig.me
```

`gsocket.io` and `thc.org` are the genuine THC project. The sample abuses a real tool —
attribute the abuse, not the tool.

---

## Repository layout

| Path | Contents |
|------|----------|
| `blocklist.txt` | **Master feed.** Raw IPs and domains, one per line. No comments, no blank lines, no wildcards — it is machine-read. |
| `firewalla/drosera_block.txt` | The same indicators, annotated with family, role and confidence, for pasting into Firewalla MSP. |
| `firewalla/drosera_port_policy.txt` | **Port and egress rules.** A Target List cannot express a port, so these are written to be created manually. Rule 1 blocks outbound IRC — the one control that survives this capture's C2-override evasion. |
| `ioc/<FAMILY>_ioc.txt` | One IOC feed per family — hashes, IPs, domains, ports, protocol indicators, grep strings. |
| `yara/<FAMILY>_<campaign>.yar` | **Exactly one rule per file** — YARAify rejects multi-rule uploads ("Multiple YARA rules found in a single file"). Families needing both a dropper and a payload rule ship two files. |
| `suricata/<family>.rules` | One Suricata ruleset per family. |
| `sigma/<family>_<detection>.yml` | Log-based detection, 8 rules. Covers the two families that ship **no** YARA rule by design, plus host-side behaviour that file signatures cannot see. |
| `reports/<FAMILY>_analysis_<sha256short>.md` | Full structured analysis report, one per family. |
| `reports/CAPTURE_<date>_executive_summary.md` | Risk ranking, key findings, immediate actions. **Start here.** |
| `reports/CAPTURE_<date>_capability_mitigation_framework.md` | Capability matrix, ATT&CK mapping, and mitigation controls rated for effectiveness against this corpus. |
| `reports/CAPTURE_<date>_infrastructure_and_sinkhole.md` | Per-sample C2 channel, namespace dependency, and sinkhole viability. |
| `reports/CAPTURE_<date>_hashes.txt` | SHA-256 / MD5 / SHA-1 for every sample. |
| `samples/<sha256>.zip` | The sample itself — AES-256, password `infected`. |
| `drosera-detection-bundle.zip` | Everything above except samples, regenerated after each capture. |

---

## Consuming the feeds

**Everything at once** — `drosera-detection-bundle.zip` (117 KB, 44 files) packs
every YARA rule, Suricata ruleset, Sigma rule, IOC feed, the Firewalla lists,
`blocklist.txt`, all reports and this README. Plain zip, no password:

```
https://raw.githubusercontent.com/Afterpacket/drosera-threat-intel/main/drosera-detection-bundle.zip
```

It contains **no samples** — nothing in it is malware, and it is safe to unpack
anywhere. Live samples remain in `samples/`, AES-256 encrypted, and are never
bundled. Regenerated after every capture.

**Blocklist** — plain newline-delimited IPs and domains, safe to `curl` on a cron:

```
https://raw.githubusercontent.com/Afterpacket/drosera-threat-intel/main/blocklist.txt
```

Shared CDN ranges (Cloudflare, AWS, Fastly, GitHub, Akamai) are **never** added — blocking
them breaks legitimate traffic.

**YARA** — scan a directory tree:

```bash
yara -r yara/*.yar /path/to/scan
```

> **⚠ Rule syntax is currently UNVERIFIED.** These files have **not** been
> compile-checked. Run `yara -r yara/*.yar /dev/null` on a host with YARA
> before relying on them.
>
> A previous revision of this README claimed validation against YARA 4.5.5 with
> zero errors and a clean corpus run. That claim could not be substantiated and
> has been withdrawn.
>
> *Why it is still unverified (checked 2026-08-08, so nobody re-treads this):*
> `yara` is not installed and cannot readily be. `pip install yara-python`
> finds **no wheel** for CPython 3.14 on Windows and falls back to a source
> build, which fails in the Windows SDK — `specstrings.h` includes
> `specstrings_strict.h`, which is absent from SDK 10.0.26100.0. Note also that
> `import yara` from the repo root silently resolves to this repository's own
> `yara/` **directory** as an empty namespace package, so an import succeeding
> proves nothing. Verify on a Linux host or a box with a working MSVC/SDK pair.

All rules carry the YARAhub mandatory metadata (`yarahub_uuid`,
`yarahub_license`, `yarahub_reference_md5`, `yarahub_rule_matching_tlp`,
`yarahub_rule_sharing_tlp`) and are formatted for direct submission to
[YARAify](https://yaraify.abuse.ch/). Each `yarahub_reference_md5` points at a
sample the rule genuinely matches — ELF-conditioned rules reference ELF samples,
not the shell droppers.

**Sigma** — 8 log-based rules in `sigma/`, targeting Linux `process_creation`
and `file_event` telemetry. Convert to your SIEM's query language with
[sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk -p sysmon_linux sigma/*.yml
```

| Rule | Covers |
|------|--------|
| `gsocket_sshit_persistence.yml` | `~/.config/prng/`, the systemd unit, PID files — **critical**, no benign explanation |
| `gsocket_sshit_credential_exfil.yml` | the beacon carrying the gs-netcat secret |
| `botkill_procwipe_rival_removal.yml` | `/home/.k` and the `dvrHelper` hunt — this family ships **no YARA rule** |
| `webroot_probe_rce_confirmation.yml` | webroot script drops — also **no YARA rule** by design |
| `mirai_ohshit_multiarch_staging.yml` | `WTF` staging, doubled-slash fetch, busybox copy |
| `mirai_telnetcurl_dropper.yml` | all 7 fixed filenames, incl. the 2 uncaptured-build hunt strings |
| `mirai_loader_dvrhelper.yml` | `dvrHelper tscan`, the `.f` write-exec probe |
| `perlbot_shellbot_irc_c2.yml` | `#mot` / `MAD` operator constants — survive the C2 override |

**Validated 2026-08-08.** All 8 rules parse under **pysigma 1.5.0** and convert
cleanly to Splunk SPL via **pysigma-backend-splunk 2.1.0** — every rule produces
a working query. Also checked: YAML validity, required fields, unique UUIDv4
ids, and that every selection referenced in a `condition` exists with no
selection left unused.

**Suricata** — drop the `.rules` files into your rules directory and add them to
`suricata.yaml`, then validate before reload:

```bash
suricata -T -c /etc/suricata/suricata.yaml
```

**Confidence tags** used across the IOC files:

| Tag | Meaning |
|-----|---------|
| `HIGH` | Direct honeypot capture (delivery IP) or C2 read from the sample's config block |
| `MEDIUM` | C2 from a hardcoded array, not observed live |
| `LOW` | Sample was packed or encrypted; extraction is uncertain |

---

## Suricata SID registry

SIDs are allocated one block per family so rules never collide. Before writing new rules,
take the next free block from this table and update it.

| Family | SID block | Status |
|--------|-----------|--------|
| MIRAI_OHSHIT | `9001001–9001999` | in use (9001001–9001012) |
| MIRAI_TELNETCURL | `9002001–9002999` | in use (9002001–9002005) |
| PERLBOT_SHELLBOT | `9003001–9003999` | in use (9003001–9003005) |
| GSOCKET_SSHIT | `9004001–9004999` | in use (9004001–9004003) |
| MIRAI_LOADER | `9005001–9005999` | in use (9005001–9005003) |
| BOTKILL_PROCWIPE | `9006001–9006999` | reserved — no network activity, no rules |
| WEBROOT_PROBE | `9007001–9007999` | in use (9007001–9007003) |
| — | `9008001–9008999` | **next available** |

---

## Handling samples

Everything in `samples/` is **live malware**. All 25 samples from the 2026-08-07
capture are present as `samples/<sha256>.zip`, 4.5 MB total. MD5 and SHA-1 for
each are in [`reports/CAPTURE_20260807_hashes.txt`](reports/CAPTURE_20260807_hashes.txt).

- Archives are AES-256 encrypted with the password `infected`.
- Extract and analyse only inside an isolated VM with no network path to anything you care about.
- Never extract into a cloud-synced folder — samples get quarantined by the sync provider's
  scanner mid-analysis, and can get the storage account actioned.

---

## Analysis reports

Capture 2026-08-07, all 25 samples read directly from source:

| Report | Contents |
|--------|----------|
| [Executive summary](reports/CAPTURE_20260807_executive_summary.md) | Risk ranking, what changed, immediate actions |
| [Capability & mitigation framework](reports/CAPTURE_20260807_capability_mitigation_framework.md) | Capability matrix, ATT&CK, controls rated P1–P3/D, residual risk |
| [Infrastructure & sinkhole](reports/CAPTURE_20260807_infrastructure_and_sinkhole.md) | C2 channel per sample, sinkhole viability, priority of action |
| [MIRAI_OHSHIT](reports/MIRAI_OHSHIT_analysis_8b1a2fb6.md) | 9 samples — 15 arch, SSH propagation, XOR-0x22 L7 flood |
| [MIRAI_TELNETCURL](reports/MIRAI_TELNETCURL_analysis_3801a288.md) | 7 samples — fixed filenames, obfuscation ruled out |
| [PERLBOT_SHELLBOT](reports/PERLBOT_SHELLBOT_analysis_03a4f492.md) | 3 samples — undetected twin, one operator/two C2 |
| [GSOCKET_SSHIT](reports/GSOCKET_SSHIT_analysis_22585585.md) | 1 sample — 5× persistence, credential exfil |
| [MIRAI_LOADER](reports/MIRAI_LOADER_analysis_246c3c37.md) | 1 sample — Android targeting, `tscan` |
| [BOTKILL_PROCWIPE](reports/BOTKILL_PROCWIPE_analysis_41d9a2a0.md) | 2 samples — turf war, one corrupt on delivery |
| [WEBROOT_PROBE](reports/WEBROOT_PROBE_analysis_af77b643.md) | 2 samples — 224 sightings, RCE precursor |

## Reporting

Corrections, missed IOCs and false positives are welcome via GitHub issues.
