# Drosera Threat Intel

Static analysis and detection artifacts for malware captured live by the **Drosera honeypot**.
Every capture ships a YARA rule, Suricata rules, Sigma rules, an IOC feed, firewall block
entries and a full written report.

**TLP:WHITE** — free to share and republish.
Author: **AfterPacket** · Site: <https://afterpacket.github.io/drosera-threat-intel>

---

## Samples

### Capture 2026-08-07 — 25 samples, 6 families

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
architecture builds — so the same indicators cover the nine architectures the
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
which loops 16 architectures, `cat`s each payload into a file named `WTF`, runs
`chmod +x *`, and executes. Seven of the sixteen architecture builds were captured.
The doubled slash in `http://94.154.43.123//bot.<arch>` is a reliable detection string.

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

### PERLBOT_SHELLBOT

Perl IRC shellbot, C2 `213.139.77.150:6667`, with randomised nick and process-name
masquerade. **Contains an undetected twin:** `/duba` and `/dodu` are both exactly
29,427 bytes and arrived from different IPs five days apart. `/duba` is flagged by
29 of 60 VirusTotal engines; `/dodu` has no VirusTotal record at all. The bot accepts
a C2 override via `$ARGV[0]`, so the hardcoded server is a default, not a guarantee —
the shipped YARA rule includes C2-independent structural matches.

### GSOCKET_SSHIT

Abuse of **THC Global Socket / ssh-it**, a legitimate published security tool, for
persistent remote access. Installs a systemd unit plus watchdog script and beacons
the victim's public IP to `POST http://192.253.248.9/gsocket/up.php`. Detection here
targets the attacker's wrapper and exfil callback only — never gsocket itself.
VirusTotal 2/60, very low for a working persistent backdoor installer.

### MIRAI_LOADER

Unobfuscated Mirai loader, `SERVER="77.90.185.66"`, fetching `mirai.<arch>` and
writing `dvrHelper`. Self-identifying and trivially detected. Notable for being
actively targeted by BOTKILL_PROCWIPE below.

### BOTKILL_PROCWIPE

Not malware — **competitor-removal scripts**, written to `/home/.k` over telnet by an
operator clearing rivals off a box it wants to keep. One kills any process whose
`/proc/$pid/exe` symlink ends in `(deleted)`, the standard tell of a self-deleting
bot. The other greps process cmdlines specifically for `dvrHelper` and kills matches —
**the exact payload name used by MIRAI_LOADER in this same capture.** A host with
`/home/.k` present has been compromised by at least two separate actors; reimage
rather than clean. No YARA rule ships: generic `/proc`-walking kill loops would
false-positive on legitimate process management.

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
| `yara/<FAMILY>_<campaign>.yar` | One YARA rule per family. |
| `suricata/<family>.rules` | One Suricata ruleset per family. |
| `sigma/<family>_<detection>.yml` | One or more Sigma rules per family. |
| `reports/<FAMILY>_analysis_<sha256short>.md` | Full structured analysis report. |
| `samples/<sha256>.zip` | The sample itself — AES-256, password `infected`. |
| `drosera-detection-bundle.zip` | Everything above except samples, regenerated after each capture. |

---

## Consuming the feeds

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
| MIRAI_OHSHIT | `9001001–9001999` | in use (9001001–9001010) |
| MIRAI_TELNETCURL | `9002001–9002999` | in use (9002001–9002005) |
| PERLBOT_SHELLBOT | `9003001–9003999` | in use (9003001–9003004) |
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

## Reporting

Corrections, missed IOCs and false positives are welcome via GitHub issues.
