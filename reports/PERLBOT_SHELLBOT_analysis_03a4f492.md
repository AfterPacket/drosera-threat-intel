# PERLBOT_SHELLBOT — Analysis Report

**Lead sample:** `03a4f492af99d2048f713081560b8fa45312e594e8439eefa714f0c67a1e0550`
**TLP:WHITE** · Author: AfterPacket · Analysed: 2026-08-08 · Samples: 3

---

## 1. Incident summary

Three Perl IRC shellbots delivered over SSH between 2026-08-02 and 2026-08-07
from three separate IPs, dropped as `/duba`, `/dodu` and `/gots`. They provide
interactive remote shell access over cleartext IRC and are controlled by a
single operator across **two** C2 servers.

Two findings drive the response. `/duba` and `/dodu` are **identical builds
differing by exactly one line** — the C2 IP — yet `/duba` is flagged by 29 of 60
VirusTotal engines while `/dodu` **has no VirusTotal record at all**. And all
three samples share hardcoded operator constants (`@admins`, `@channels`) that
survive both a server change and the runtime C2 override, making them the only
durable indicators this family has.

## 2. Phase 1 — Triage

| SHA-256 (8) | Dropped as | Size | Lines | C2 | VT | Delivery IP |
|---|---|---|---|---|---|---|
| `03a4f492` | `/duba` | 29427 B | 820 | `213.139.77.150` | **29/60** | `160.30.204.101` |
| `fe6b7b4c` | `/dodu` | 29427 B | 820 | `213.177.179.11` | **none** | `77.90.185.42` |
| `fd93b4f7` | `/gots` | 40272 B | 908 | `213.177.179.11` | none | `54.37.11.139` |

All delivered over SSH. `/duba` is `ASCII text, with very long lines (1131)`;
`/gots` is `Perl script text executable`.

**The undetected twin.** `/duba` and `/dodu` are the same size to the byte and
arrived from different IPs five days apart. A `diff` of the two normalised files
returns **one** differing line:

```
< my $server = '213.139.77.150'
---
> my $server = '213.177.179.11'
```

Same bot, same build, different C2 — and one is invisible to VirusTotal. Hunt
`/dodu`'s hash specifically; it is the higher-value indicator.

## 3. Phase 2 — Configuration block

`/duba` lines 8–35 (`/dodu` identical except line 27):

```perl
my @rps = ("/usr/local/apache/bin/httpd", "/usr/sbin/httpd -k start",
           "/usr/sbin/httpd", "/usr/sbin/sshd -i", "/usr/sbin/sshd",
           "/usr/sbin/sshd -D", "/usr/sbin/apache2 -k start", "/sbin/syslogd",
           "/sbin/klogd -c 1 -x -x", "/usr/sbin/acpid", "/usr/sbin/cron");
my $process  = $rps[rand scalar @rps];
my @rircname = ("bad");
my $server   = '213.139.77.150';
my $port     = '6667';
my $homedir  = "/tmp";
my $version  = 'v.02';
my @admins   = ("MAD");
my @channels = ("#mot");
```

`/gots` config sits at lines 107–120, same values except
`$version = 'Hello To This WOrld'` and a several-hundred-entry `@rircname`
list. Its server assignment is guarded:

```perl
$server = '213.177.179.11' unless $server;    # line 107
```

**Operator constants are identical in all three, across both servers:**
`@admins = ("MAD")`, `@channels = ("#mot")`. This is the strongest available
evidence that one operator runs both `213.139.77.150` and `213.177.179.11`.

Lines 38–46 (`/duba`):

```perl
$SIG{'INT'} = 'IGNORE';  $SIG{'HUP'}  = 'IGNORE';
$SIG{'TERM'} = 'IGNORE'; $SIG{'CHLD'} = 'IGNORE';
chdir("$homedir");
$server="$ARGV[0]" if $ARGV[0];
$0="$process"."\0"x16;
```

## 4. Phase 3 — Capabilities

| Capability | Implementation |
|-----------|----------------|
| Interactive shell | IRC PRIVMSG command handler; admin-gated on `@admins` |
| Process masquerade | `$0="$process"."\0"x16` — 11-entry pool of plausible daemons |
| Randomised nick | `$rircname[rand scalar @rircname]` |
| Signal resistance | `SIG{INT,HUP,TERM,CHLD}='IGNORE'` — **plain `kill` will not stop it** |
| Daemonisation | `fork` then parent `exit` |
| Runtime C2 override | `$server="$ARGV[0]" if $ARGV[0]` |
| HTTP flood | URL-parsing with `$port = $2 \|\| 80` |
| CTCP VERSION spoof | `/gots` only — 11-entry mIRC version pool |

`/gots` is a distinct, larger build. Its help menu self-describes as
`[alavojda's dd0s b0ts] Lets DDOSSSS!` and takes commands prefixed `!u @`
(`@system`, `@version`, `@channel`, `@flood`, `@utils`). **`alavojda` is a
campaign handle worth tracking.**

## 5. Phase 4 — C2 protocol

Cleartext IRC, tcp/6667, to a bare IP. Registration is standard `NICK`/`USER`,
then `JOIN #mot`. Commands arrive as PRIVMSG and are gated on the sender's nick
matching `@admins`:

```perl
if (grep {$_ =~ /^\Q$pn\E$/i } @admins ) { ... }
```

**The override problem.** Because `$ARGV[0]` replaces the server at launch, any
IP-based control is defeated by relaunching the bot. Blocking
`213.139.77.150` alone is doubly insufficient — it leaves `213.177.179.11`
operating, and either can be redirected.

**The durable control** is `JOIN #mot`, which fires regardless of destination
host or port. Shipped as Suricata SID 9003005. The durable *preventive* control
is an egress block on 6660–6669, 6697 and 7000.

## 6. Phase 5 — Persistence

**None.** No cron, systemd, rc or profile modification. The bot daemonises and
masquerades but does not survive reboot. Persistence is presumably handled
out-of-band by whatever obtained the SSH access.

## 7. Phase 6 — Attribution

Perl IRC shellbot of the ShellBot/legend lineage — a long-lived, widely
recirculated code family. `/duba` and `/dodu` are one build; `/gots` is a
larger, older-style variant with mIRC spoofing. Common `@admins`/`@channels`
across all three ties them to one operator.

## 8. Phase 7 — Host detection

```bash
grep -rl "rircname\|#mot\|213.139.77.150\|213.177.179.11" / 2>/dev/null
ss -tanp | grep -E ':(6667|6660|666[0-9]|6697|7000)'
ps aux | grep -i perl
find / -name "duba" -o -name "dodu" -o -name "gots" 2>/dev/null
```

Note the process-name masquerade: the bot appears as `httpd`, `sshd`, `syslogd`
or `cron`. Cross-check any such process whose binary path does not match the
package manager's record.

## 9. Phase 8 — MITRE ATT&CK

| ID | Technique | Implementation |
|----|-----------|----------------|
| T1078 | Valid Accounts | SSH delivery |
| T1059.004 | Unix Shell | Perl bot, shell command execution |
| T1071 | Application Layer Protocol: IRC | cleartext C2 on 6667 |
| T1036.004 | Masquerade Task or Service | `$0` rewrite from daemon pool |
| T1562.001 | Impair Defenses | signal handlers set to IGNORE |
| T1498.001 | Direct Network Flood | flood command handlers |

## 10. IOC table

| Type | Value | Confidence |
|------|-------|-----------|
| IP | `213.139.77.150` | HIGH — config block, `/duba` |
| IP | `213.177.179.11` | HIGH — config block, `/dodu` + `/gots` |
| IP | `160.30.204.101`, `77.90.185.42`, `54.37.11.139` | HIGH — direct capture |
| Port | 6667 | HIGH |
| IRC | channel `#mot`, admin `MAD` | HIGH — **C2-independent** |
| String | `rircname`, `$rps[rand scalar`, `alavojda` | HIGH |

**Artifacts:** `yara/PERLBOT_SHELLBOT_irc.yar` ·
`suricata/perlbot_shellbot.rules` (9003001–9003005) ·
`ioc/PERLBOT_SHELLBOT_ioc.txt` · `firewalla/drosera_port_policy.txt` Rule 1
