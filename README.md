# Drosera Threat Intel

Static analysis and detection artifacts for malware captured live by the **Drosera honeypot**.
Every capture ships a YARA rule, Suricata rules, Sigma rules, an IOC feed, firewall block
entries and a full written report.

**TLP:WHITE** — free to share and republish.
Author: **AfterPacket** · Site: <https://afterpacket.github.io/drosera-threat-intel>

---

## Samples

| Date | Family | SHA-256 | Arch | Severity | Artifacts |
|------|--------|---------|------|----------|-----------|
| — | _No captures published yet_ | — | — | — | — |

---

## Repository layout

| Path | Contents |
|------|----------|
| `blocklist.txt` | **Master feed.** Raw IPs and domains, one per line. No comments, no blank lines, no wildcards — it is machine-read. |
| `firewalla/drosera_block.txt` | The same indicators, annotated with family, role and confidence, for pasting into Firewalla MSP. |
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
| — | `9001001–9001999` | **next available** |

---

## Handling samples

Everything in `samples/` is **live malware**.

- Archives are AES-256 encrypted with the password `infected`.
- Extract and analyse only inside an isolated VM with no network path to anything you care about.
- Never extract into a cloud-synced folder — samples get quarantined by the sync provider's
  scanner mid-analysis, and can get the storage account actioned.

---

## Reporting

Corrections, missed IOCs and false positives are welcome via GitHub issues.
