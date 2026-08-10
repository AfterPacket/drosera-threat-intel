# BOTKILL_PROCWIPE — Analysis Report

**Lead sample:** `41d9a2a07ccfc769854bf71c82258da1f0a622644f12fada54320e7ff310fcfa`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 2

---

## 1. Incident summary

Two short shell scripts written over telnet to `/home/.k` between 2026-08-02 and
2026-08-04 from four separate IPs. **Neither is malware in the usual sense.**
Both are competitor-removal scripts: one operator clearing rival bots off a box
it intends to keep for itself.

They matter for two reasons. Presence of `/home/.k` means the host was **already
compromised by someone else first** — a second, earlier incident. And the second
sample names its target explicitly, linking two otherwise unconnected families
in this capture.

A third finding emerged in this review: **sample `2733d565` is corrupt as
delivered and could not have executed.**

## 2. Phase 1 — Triage

| SHA-256 (8) | Size | Lines | Sightings | Delivery IPs |
|---|---|---|---|---|
| `41d9a2a0` | 200 B | 10 | 3 | `27.137.233.190`, `211.219.254.187`, `175.198.110.15` |
| `2733d565` | 390 B | 17 | 1 | `123.145.11.38` |

Both `POSIX shell script, ASCII text executable`, both written to `/home/.k`
over telnet. Neither has a VirusTotal record — expected for short,
network-silent shell scripts with no malicious API surface.

## 3. Phase 2 — Source

### 3.1 `41d9a2a0` — the `(deleted)` sweeper, complete

```sh
#!/bin/sh

for proc_dir in /proc/*; do
    pid=${proc_dir##*/}
    result=$(ls -l "/proc/$pid/exe" 2> /dev/null)

    if [ "$result" != "${result%(deleted)}" ]; then
        kill -9 "$pid"
    fi
done
```

Intact and functional.

### 3.2 `2733d565` — the `dvrHelper` hunter, as captured

```sh
#!/bin/sh

for proc_dir in /proc/*\3B  pid=${proc_dir##*/}

  # Skip non-numeric directories
  if ! [ "$pid" -eq "$pid" ] 2> /dev/null; then
    continue
  fi

  # Get the command line of the process
  cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2> /dev/null)

  # Check if the command line contains "dvrHelper"
  if echo "$cmdline" | grep -q "dvrHelper"; then
      kill -9 "$pid"
  fi
done
```

## 4. Phase 3 — Capabilities

### 4.1 `41d9a2a0` — indiscriminate self-deleter kill

Walks `/proc/*`, resolves each `/proc/$pid/exe` symlink, and `kill -9`s any
process whose target ends in `(deleted)`.

This is elegant for its size. Deleting one's own binary after execution is
**standard IoT-botnet hygiene**, so the `(deleted)` suffix reliably identifies
other people's bots while leaving normal daemons — whose binaries still exist on
disk — untouched. Broad, indiscriminate, and effective without needing to know
anything about the targets.

*Caution for defenders:* legitimate software occasionally runs from a deleted
inode, most commonly after a package upgrade where a long-running daemon has not
been restarted. This script would kill those too.

### 4.2 `2733d565` — targeted strike, **inert as delivered**

The intent is precise: walk `/proc/*`, skip non-numeric entries, read
`/proc/$pid/cmdline`, translate NULs to spaces, and `kill -9` anything whose
cmdline contains `dvrHelper`.

> **`dvrHelper` is the exact output filename used by MIRAI_LOADER
> (`246c3c37`, `SERVER="77.90.185.66"`) elsewhere in this same capture.**

**But the file cannot run.** Verified at byte level:

```
00000020: 2f2a 5c33 4220 2070 6964 3d24 7b70 726f  /*\3B  pid=${pro
```

At offset `0x22` the three bytes `5c 33 42` — literal `\`, `3`, `B` — sit where
a single `;` (`0x3B`) belongs.

> **Correction, 2026-08-08.** An earlier revision of this report attributed
> those bytes to "a shell- or URL-escaping artefact of writing the script over
> telnet" — that is, to the attacker's delivery. **It was the sensor.**
>
> The operator sent `\3B` — their own typo for `\x3B` — inside a
> `busybox echo -ne` argument. BusyBox decodes bare octal, so a real target
> writes `\3` as the single byte `0x03` followed by `B`: **two bytes**. The
> honeypot's shell emulator did not implement bare octal and wrote the three
> characters literally. The three bytes above are therefore **this sensor's
> output, not the attacker's**.
>
> The finding is unchanged: `0x03 B` is not a `;` either, so the script was
> inert on a real host too, for the operator's own reason rather than ours.
> What changes is the hash — see below.

The result is `for proc_dir in /proc/*\3B  pid=...` — a `for` loop with no `do`,
and a trailing `done` with no opener. `/bin/sh` rejects it with a syntax error
before executing anything.

**Consequences for reporting.** This drop was inert; it never killed anything.
The operator's *intent* is still fully evidenced by the source, and the
MIRAI_LOADER linkage stands. But do not cite this sample as evidence of
successful bot-killing activity. The sibling `41d9a2a0` does run.

**⚠ Do not match on the SHA-256 of `2733d565`.** It is a hash of the sensor's
transcription, and no other collector will reproduce it. A real target's copy
differs in two places: `5c 33 42` → `03 42` at offset `0x22`, and a trailing
newline that the emulator's `echo` handling stripped. The two changes cancel
in length, so the corrected file is also 390 bytes — with a different digest.
`41d9a2a0` and the MIRAI_OHSHIT `/tmp/.p` fetcher (`de9cfdf7`) are affected by
the trailing-newline issue alone and are likewise one byte short as captured.

Everything these samples *did*, named and targeted is unaffected — the
`/home/.k` path, the two-actor conclusion, the `dvrHelper` linkage and all
four source IPs stand. It is the file digests alone that cannot be quoted.

## 5. Phase 4 — C2 protocol

**None.** Neither script contains any network code — no sockets, no HTTP, no
DNS, no hardcoded hosts. They are purely local process manipulation. There is
nothing to sinkhole, block or alert on at the network layer.

## 6. Phase 5 — Persistence

**None.** Single-shot scripts. No cron, systemd, rc or profile modification.

## 7. Phase 6 — Attribution

Not a malware family — a tactic. `/proc`-walking kill loops are widely
recirculated among IoT botnet operators, and these two are commodity. The
consistent `/home/.k` drop path across four delivery IPs suggests one operator
or one toolkit.

The `dvrHelper` targeting is the interesting signal: it places this operator in
direct competition with the MIRAI_LOADER operator, on the same victims, inside
the same eleven-day window.

## 8. Phase 7 — Host detection

```bash
ls -la /home/.k 2>/dev/null
grep -rl "deleted)}\|dvrHelper" /home /tmp /var/tmp 2>/dev/null
```

> **A host with `/home/.k` present has been compromised by at least two separate
> actors. Reimage it — do not clean it.** The file's presence is evidence that
> someone considered the host already infested enough to be worth clearing, and
> the original infestation is a separate incident you have not yet scoped.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078.001 | Valid Accounts: Default | telnet with default credentials |
| T1059.004 | Unix Shell | POSIX shell scripts |
| T1057 | Process Discovery | `/proc/*` enumeration |
| T1489 | Service Stop | `kill -9` on matched processes |
| T1518.001 | Software Discovery: Security Software | rival-implant identification |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| SHA-256 | `41d9a2a07ccfc769854bf71c82258da1f0a622644f12fada54320e7ff310fcfa` | — |
| SHA-256 | `2733d565138186645b2ff2485f88cfdaee2a1cf2cd3af1306273fc0f6191a58c` | — (inert) |
| IP | `27.137.233.190`, `211.219.254.187`, `175.198.110.15` | HIGH — direct capture |
| IP | `123.145.11.38` | HIGH — direct capture |
| Path | `/home/.k` | HIGH — **treat as two-actor compromise** |
| String | `${result%(deleted)}`, `dvrHelper` | HIGH |
| Domain / Port | none — no network code | — |

## 11. Why no YARA rule ships

Deliberate. Both samples are generic `/proc`-walking kill loops; a rule matching
`kill -9` plus `/proc/` would fire on legitimate process-management scripts
across any estate. The durable indicators here are the **file path `/home/.k`**
and the **target string `dvrHelper`**, both better served by host hunting and
Sigma than by file signatures. This is a decision, not a gap.

**Artifacts:** `ioc/BOTKILL_PROCWIPE_ioc.txt` · SID block `9006001–9006999`
reserved, unused — no network activity to alert on
**Related:** `MIRAI_LOADER_analysis_246c3c37.md` — the targeted family
