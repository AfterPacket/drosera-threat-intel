# Deep static review — batch 1: Perl variants and a loader-linked ELF cluster

**Review status: bounded findings, not completion of the 96-sample corpus.**
Base: `c122f0c` (merged approved two-host blocking follow-up). Static only: no sample
was executed, emulated, compiled or contacted; no DNS resolution or infrastructure
requests were made. ELF parsing/disassembly used pyelftools 0.33 and Capstone
(runtime version 5.0.7); YARA 4.5.4 was used only for detection coverage.

## Scope and honest completion accounting

The 96 unique samples remain the same hash-verified inventory. The existing 27
published archives/reports are inherited work, not 27 fresh reverse-engineering
reviews in this batch. Of the 69 previously unpublished samples:

- **6 source reviews completed:** five Perl configurations and one 53-line loader.
- **13 ELF files partially reviewed:** configuration recovered independently in
  all 13; selected control-flow paths disassembled in one x86-64 representative.
  This is **not** complete per-architecture reverse engineering of 13 payloads.
- **50 samples pending deep review.** No conclusion of harmlessness follows from
  pending status or a YARA miss.

The [96-row review tracker](DEEP_STATIC_BATCH1_coverage.csv) separates these states.
[ELF evidence](DEEP_STATIC_BATCH1_elf_evidence.json) records full hashes, machine
headers, symbol virtual addresses, raw configuration-pointer bytes and recovered
strings. Virtual addresses below are specific to the named representative.

No new encrypted archives, YARA/Sigma/Suricata rules, blocking targets or port
policies were added in this batch. At batch-1 publication, detection-bundle contents
and release counters were unchanged and this report was not in that prior bundle.
The later [automation follow-up](AUTOMATION_AND_LIMITS.md) rebuilds the current
sample-free bundle to include these reports/tools; this historical batch accounting
must not be mistaken for the current bundle manifest.

## Work item 1 — five Perl source variants

**Observed:** each newly reviewed script differs from original sample `03a4f492`
only in the `server` assignment and, for two variants, `homedir`. The comparison
covered every byte, not just selected strings. Original `fe6b7b4c` is another
configuration variant in this narrow cluster. After normalizing only those two
assignments, all seven scripts share SHA-256:

`1e792103def877e098a7d0e08123f7323394f966c901646b4662c4d208f4e39e`

This equivalence statement does not include original Perl sample `fd93b4f7`,
which is a different, larger script. Family labels are inherited/descriptive,
not attribution to an operator.

### Newly reviewed configurations

| SHA-256 | Bytes | Hardcoded IRC server | Port | Working directory |
|---|---:|---|---:|---|
| `1c38a8b346804cfceae26b7136c8d0ddadfbf90d97d93b47de9f3a4a8bde7e20` | 29427 | `213[.]177[.]179[.]52` | 6667 | `/tmp` |
| `7370f944b9d5a76172b2f4bf78d919a294cc93b099d666fa95d4ec6c8073718c` | 29431 | `213[.]177[.]179[.]52` | 6667 | `/dev/shm` |
| `b1d781a7a2861f99795f9ceee19eb2326dcb919573dbe3a052bfe8d02f519cae` | 29431 | `192[.]253[.]248[.]46` | 6667 | `/dev/shm` |
| `b3a548a1110ae32b998408ed7a37387e97ad261ded4b182f5a8ca6ea7f8304af` | 29427 | `213[.]177[.]179[.]32` | 6667 | `/tmp` |
| `ef2272062f3b67a1095838326e26a8ec364a9d0c032d31f659ac9e447baac019` | 29427 | `193[.]23[.]118[.]161` | 6667 | `/tmp` |

### Source control flow and limitations

Line references use the five newly reviewed scripts; the configuration substitutions
do not change line numbering.

- **Startup (lines 1–56):** first line is `#/usr/bin/perl`, not a valid `#!`
  shebang. Direct execution and explicit Perl invocation are different cases;
  no interpreter invocation was attempted here. Source changes directory,
  permits the first argument to override the server, sets a randomly selected
  daemon-like `$0` process title, ignores several signals and forks into the
  background. No boot-persistence mechanism was identified in this source.
- **IRC connection/parser (`conectar`, `parse`):** plaintext TCP IRC registration,
  PING/PONG handling, nickname-collision handling, and channel `#mot` join. The
  compiled-in admin nickname is `MAD`; the hostmask-authentication test is
  commented out. The active check compares sender nicknames case-insensitively,
  not a cryptographic credential or verified host identity. This is an observed
  trust weakness, not evidence that a live bot was taken over.
- **Execution (`parse` → `shell`, `ircase`):** permitted private messages can reach
  shell execution; command output is sent back over IRC with eight-line/five-second
  pacing. `ircase` also has an `eval` branch and can open another IRC connection.
- **Other implemented branches (`bfunc`):** operator-specified HTTP download and
  file writing, TCP port checks/scanning, DNS lookup, connect-back shell, local
  sendmail invocation, and UDP/TCP/HTTP/IRC flooding code. These are source
  capabilities, not observed attacks. Raw-socket branches require appropriate
  privileges; help text alone is not proof of packet correctness. One UDP branch
  uses uninitialized `$rand`; we do not claim every advertised mode functions.
- **HTTP helper (`getstore` → `_get` → `_trivial_http_get`):** HTTP/proxy support,
  `get-minimal/20000118/u` User-Agent, redirect handling and output-file writes.
  The later success message is not reliable proof that retrieval succeeded.

**Detection disposition:** all five match existing `PERLBOT_SHELLBOT_irc`.
No equivalent new rule is warranted. The hardcoded server is runtime-overridable;
matching only these IP literals would not provide complete coverage.

**Unverified:** Perl syntax/runtime behavior, connection success, operator
identity, current host ownership, activity, ASN/geo and whole-IP exclusivity.

## Work item 2 — 7b1cbba5 loader and 13 metadata-linked payloads

### Loader: fully read source

SHA-256: `7b1cbba56bb80e185cdf2097f5716c31d7e0f88f28ad7220b3b5a2cf73859ec8`; **6734 bytes**, 53 lines.

**Observed:** lines 2–18, 19–35 and 36–52 repeat 17 retrieval/execution
chains with `wget`, `busybox wget` and `curl -O` respectively. Source host is
`213[.]232[.]114[.]14`, HTTP TCP/80. Literal paths are:

`/telnetd`, `/telnet`, `/kworker`, `/sshd`, `/bash`, `/getty`, `/kernal`,
`/gnome`, `/ntp`, `/ext4`, `/watchdogd`, `/systemd`, `/ntpd`, `/login`,
`/dbus`, `/kde`, `/crypto`.

Each chain tries `/tmp`, `/var/run`, `/mnt`, `/root`, then `/` as its working
directory, makes the fetched basename executable, invokes it in the foreground
and then removes that basename. Commands are separated by semicolons rather
than download-success guards. A failed retrieval can therefore leave a pre-existing
local file as the execution target. Successful long-running payload execution can
prevent subsequent cleanup/lines until it exits. Final line is `history -c`;
that does not establish removal of a parent shell's persisted history.

**Observed:** 51 source URL occurrences, 17 distinct paths. There is no explicit
architecture-selection branch, no payload integrity verification and no shell
persistence installation in the loader itself. Masquerading basenames are not
reliable architecture or malware-family labels.

**Inferred:** the repeated download tools are compatibility fallbacks. Metadata
links 13 captured children to this parent hash; that is provenance, not proof
that all 17 paths were captured, that the loader executed, or that all 13 ELF
builds have identical behavior.

### Per-file ELF structure/configuration recovery

**Observed:** every listed ELF has a symbol-backed `commServer` pointer leading
to `64[.]89[.]160[.]222:65481`; no string-only candidate guessing was used for
this field. Pointers were decoded using each file's own ELF class and endianness,
then mapped through file-backed PT_LOAD segments. No listed file has PT_INTERP.
No PT_INTERP alone does not prove complete absence of runtime dependencies.

| SHA-256 | Bytes | ELF machine | Class / byte order | commServer VA |
|---|---:|---|---|---|
| `05aea199775e5214c7b970acd4e2e1171fcb96d0c36ba8ac9cf16d5c10e54ca8` | 109952 | `EM_X86_64` | 64-bit / LE | `0x512060` |
| `11040b3b2a24379975f6f618adc4d6943d54a7964ce40985b00a8824f248b76e` | 119547 | `EM_SPARC` | 32-bit / BE | `0x36028` |
| `34b7558c823dce388432fe16b997c0a02646956d171f72eb7557774a1e1d66b3` | 143488 | `EM_MIPS` | 32-bit / BE | `0x45a0a0` |
| `46741363ec3bdf4e30df9a50cd55392595d537193149752345659b17153cb680` | 105320 | `EM_SH` | 32-bit / LE | `0x423020` |
| `54f07e4c8358c4947e5fba61c9a3fe0e66e31abdb8fd9e39b8962df6e9bbfa6c` | 111421 | `EM_68K` | 32-bit / BE | `0x80016604` |
| `5c84dbb875ee198050a661a9f0182462b34e745f1c8e31026f23c0ea6fb2e15e` | 91331 | `EM_386` | 32-bit / LE | `0x80588e0` |
| `6955d78197fe503a53c57ffff66643de59c4bea21d79fbc95f2c24ec5ae89a82` | 118011 | `EM_ARM` | 32-bit / LE | `0x24024` |
| `9334bd5e315feaae8317952ab96080f1063d3b8443d38086b381460bc975bd43` | 173331 | `EM_ARM` | 32-bit / LE | `0x2a0c8` |
| `bb08fd9ce1f3508bc30a33646aeb66df3024e5c7da843cabd09ed19ae07bd8d1` | 121461 | `EM_ARM` | 32-bit / LE | `0x24024` |
| `c220d6eee6083d31de215defb91161812ba3d998bad7d8babf258c9af4bdcee2` | 143488 | `EM_MIPS` | 32-bit / LE | `0x45a0a0` |
| `c458e443759ea633cde8929b4337726136675141d82251158f973f54008e20ac` | 132978 | `EM_ARM` | 32-bit / LE | `0x264d4` |
| `ca4b5afd66233bd10a41fd11bcd56554283e945c461e2fd9f5673df4bcebbeb3` | 93219 | `EM_386` | 32-bit / LE | `0x8058040` |
| `e16117e61605d82e9f61aac203effbe8baf8acebb3390859759e48da2d070c53` | 109461 | `EM_PPC` | 32-bit / BE | `0x10024990` |

### Selected x86-64 control-flow verification

Representative: `05aea199` (full hash in table above). These observations apply
to this build; configuration similarity is not proof of full semantic equivalence
across architectures.

| Function / virtual address | Static finding |
|---|---|
| `main` `0x4061d6` | Architecture check; fork/setsid; process-name spoofing; starts killer and persistence routines; C2 reconnect loop and incoming command parsing. Failed connection leads to a five-second sleep. |
| `initConnection` `0x406015` | Reads the `commServer` pointer at `0x512060`, splits at `:`, parses configured port, creates AF_INET/SOCK_STREAM socket and calls `connectTimeout` with 30-second parameter. This is the basis for a configured outbound TCP C2 role at port 65481, not a claim of successful contact. |
| `initConnection` `0x406130–0x406195` | Constructs a 23-byte buffer, calls `xor_encrypt` with a static handshake-key string, then sends 23 bytes. This alone does not establish encryption/authentication of the subsequent command channel. |
| `processCmd` `0x404bab` | String dispatch includes TCP, UDP, HTTPSTOMP, VSE, STDHEX, GRE, ICMP, UDPL2, UDPBYPASS, TCPACK, TCPSYNACK and TLS labels. Labels identify branches, not independently validated protocol fidelity or attack effectiveness. |
| `processCmd` `0x405d21–0x405d7e` | UPDATE branch formats an operator-supplied retrieval/execution shell command involving `/tmp/update.bin`, passes it to `system`, then exits. No successful update is observed. |
| `processCmd` `0x405d90–0x405e8d` | DEADMAN branch attempts to stop killer/children, remove persistence, run `pkill -f bot`, read its executable path, unlink and exit. Unchecked/non-terminated readlink output means self-deletion success must not be assumed. |
| `telnet_scanner` `0x4045af` | Generates one candidate address per invocation, skips RFC1918 address ranges, attempts TCP 23/2323, sends credential strings, recognizes password/shell-prompt substrings and formats a credential report. Its index bound allows 91 credential pairs. No propagation/exploit delivery is established by this routine. |
| `exploit_scanner` `0x404a68` | Random-gated report stub: formats `REPORT exploited: CVE-2026-XXXX on simulated IP` and sends that text to the C2 socket. Its call path contains no victim connection or exploit implementation. This is **not evidence of a real CVE exploit**. |
| `killer_loop` `0x404157` | Enumerates numeric `/proc` entries, reads cmdline/exe, applies `is_whitelisted`, then attempts SIGTERM/SIGKILL against non-whitelisted processes. This is broader than a verified competitor-malware-only killer. |
| `install_persistence` `0x404454` | Opens cron, init script, systemd service and rc.local paths; writes startup entries and calls systemctl/at-related shell commands. Static path choice is not proof installation would succeed. |

**Important persistence defect:** this representative passes the literal
`/proc/self/exe` into persistence templates, rather than the durable resolved
payload path. A later service/shell process resolves `self` to itself, not this
original executable. Combined with permission/init-system assumptions, this
prevents a claim of reliable reboot persistence from the presence of those
strings. The removal routine includes `/etc/rc.local`; **do not run or reuse
its cleanup command**, which can remove legitimate host configuration.

The ELF includes an embedded `Snoopy.` banner and
`Snoopy2026SecureHandshakeKey`. These are observed build markers only, not
verified botnet/operator attribution or evidence of a 2026 exploit.

### IOC roles and detection disposition

- `213[.]232[.]114[.]14`: source-observed HTTP payload-retrieval host in this
  loader; not thereby proven C2.
- `64[.]89[.]160[.]222:65481`: symbol-backed configured endpoint in all 13 ELFs;
  selected representative control flow establishes intended outbound TCP C2 use.
- Four new Perl server IPs in the configuration table: source-configured IRC C2,
  TCP/6667 by default; distinct hashes can share a server.
- Metadata source IPs are separate provenance and are not automatically malicious
  infrastructure. No metadata-only IP is promoted to enforcement.

All these indicators are **context only in this report**. No new enforcement
approval, current activity, exclusivity, current ownership or co-tenancy assessment
is inferred. The two previously approved blocks remain untouched.

The loader and all 13 children miss the existing nine-rule YARA set. That is an
explicit coverage gap, not benign classification. No new detector is shipped
before distinct logic, near-miss tests and suite packaging are validated. No new
Suricata SID is allocated. In particular, a simulated exploit string must not be
published as a real exploit detection or a verified CVE attribution.

## Validation and remaining work

- All 96 sample hashes and metadata hash/size pairs rechecked from private corpus.
- Nine YARA files compile warning-free; all 864 rule/sample evaluations rerun.
- Five new Perl variants match the existing rule; loader/13 children do not.
- Whole-file equivalence of the seven narrow-cluster Perl variants checked with
  only server/homedir normalization; all differences reviewed.
- Thirteen independent ELF header/pointer/configuration recoveries performed.
- Representative selected-function disassembly cross-checked against symbol and
  read-only data references; no runtime or protocol-compliance validation.
- Original artifacts and the detection bundle remain unchanged. This is a
  feature-branch analysis follow-up, not an assertion of deployment.

Next batches must address the 28 NET_BOT-linked children, nine children of loader
`8e06754e` plus that parent, remaining standalone ELF/text artifacts, and deeper
per-architecture review of this cluster. Inventory, strings, a family label,
configuration recovery and YARA hits must never be substituted for complete
behavioral reverse engineering.
