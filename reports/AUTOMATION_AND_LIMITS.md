# Repository automation, documentation corrections and validation limits

Follow-up to deep-analysis batch 1; base `2822264` (merged PR #6).
These are reliability/documentation improvements, **not demonstrated security
vulnerabilities**. No detector logic, SID allocations, blocking targets or sample
archives are changed by this follow-up.

## Coverage remains incomplete

All **96 unique samples** were hash-verified and YARA-scanned. That is inventory
and detection testing, not complete behavioral analysis. The **nine YARA rules
do not comprehensively cover this corpus**. A miss is not a benign verdict.

Of the 69 previously unpublished samples, six whole-source reviews are complete,
13 ELF reviews are partial (configuration in all 13, selected-function disassembly
in one representative), and **50 await deep review**. Existing reports/archives
for 27 samples are inherited work, not 27 fresh disassembly audits. The
[96-row tracker](DEEP_STATIC_BATCH1_coverage.csv) is explicit about each state.

## Automated sample-free checks

`.github/workflows/validate.yml` defines GitHub pull-request, main-push and manual
checks. It uses read-only repository permissions, SHA-pinned actions, disabled
checkout credential persistence, direct dependency version pins and timeouts.
There is no `pull_request_target`, secret-dependent job, deployment step or
sample decryption. Third-party/transitive dependencies and the runner OS package
are not fully hash-locked; engine/package versions must be read from run output.

`python tools/check_repository.py --rules` checks:

- Warning-free YARA compilation, globally unique identifiers, one rule per file,
  and three harmless-text fixtures. These are not broad false-positive tests.
- Sigma parse and Splunk conversion for every rule, unique UUIDs and false-positive
  notes; six small positive/negative synthetic events for the two added rules.
  The small evaluator handles only their supported literal/contains/endswith
  subset. It is not a general Sigma engine or live SIEM test.
- Feed syntax, no duplicates, raw/Firewalla target-set equality and protection for
  known legitimate/header/decoy/shared-apex and metadata-only indicators. This
  cannot establish an indicator's current ownership, reputation or maliciousness;
  syntactically valid new indicators still need evidence and human review.
- Unique Suricata SIDs, allocation against the README registry and reserved-block
  preservation. This static check alone is not Suricata engine validation.
- Current release counters, the 96-row tracker and explicit partial/pending states;
  sample-archive filenames are checked, never opened or extracted.
- Corrected website display **7/15 architectures captured**, consistent with the
  loader/report's 15 targets and seven captured builds, plus visible coverage limits.
- Exact ZIP member set and bytes against canonical staged Git text, with duplicate,
  encryption, size and sample/binary exclusion checks.

The standard-library negative regression suite deliberately supplies malformed
feeds, protected entries, stale/missing/unexpected bundle members, duplicate SIDs,
website count drift and false review-completion states. It uses temporary text
fixtures and empty archive-name placeholders, not malware payloads.

## Suricata gate — execution still must be verified

The separate Ubuntu job installs Suricata, prints build information, combines all
six repository rule files and runs `suricata -T --init-errors-fatal` against that
combined set and the runner's packaged configuration. It neither captures live
traffic nor replays samples. Invalid signatures must fail the job; pre-existing
engine-compatibility errors may therefore be exposed on the first hosted run.
A configuration test does not establish alert correctness, packet-level coverage,
performance, or low false-positive rates.

**At this change, no passing hosted Suricata run is claimed.** Suricata was not
available in the local Windows analysis environment. The previous review did not
perform engine validation. Do not label this gap closed just because a workflow
file exists. Live SIEM integration and representative benign-corpus/traffic
false-positive testing also remain outstanding.

The workflow lives in the Gitea source to survive mirroring, but GitHub Actions
must be enabled and the workflow must reach the GitHub mirror before it can run.
Gitea publication is not evidence of a successful GitHub workflow or Pages
release. This change does not restore/configure Pages deployment.

## Running and rebuilding safely

Run Git/bundle/CI gates from a Git checkout, not a standalone extracted bundle.
Use a virtual environment and install the direct validation dependencies:

```sh
python -m pip install -r tools/requirements-ci.txt
python -m unittest discover -s tests -p 'test_*.py' -v
python tools/check_repository.py --rules
```

The checker/rebuilder uses **staged Git bytes**, matching HEAD in a clean CI
checkout, so Windows checkout line endings do not silently alter bundled content.
After reviewing and staging the intended text changes (including new tools,
reports and tests), regenerate and validate:

```sh
python tools/check_repository.py --build-bundle
python tools/check_repository.py --rules
git add drosera-detection-bundle.zip
```

Never stage decrypted malware, private corpus data or credentials. The builder
rejects sample/binary/archive inputs in allowed bundle directories. It does not
extract archives or contact IOC infrastructure. Fixed member ordering, timestamps
and permissions produce repeatable bytes with the same Python/zlib environment.
The checker compares content rather than assuming compression is identical across
all implementations.

The bundle includes `README.md`, `blocklist.txt` and tracked files in `reports/`,
`ioc/`, `firewalla/`, `suricata/`, `sigma/`, `yara/`, `tools/` and `tests/`.
It excludes sample archives, nested ZIPs, raw binaries, Python caches, the website
index and GitHub workflow metadata. This rebuild brings the previously separate
batch-1 report/tracker into the current sample-free bundle. No detection coverage
is gained merely by repackaging reports.

Private full-corpus testing remains a separate operation:

```sh
python tools/validate_static.py --corpus /private/extracted --output /private/results
```

Supply an external previously decrypted corpus; keep output outside Git. Do not
place a corpus on public CI. CI does not claim to have run those 864 evaluations.

## Local follow-up validation

Observed locally before publication: all 12 regression tests passed; sample-free
checks compiled nine YARA rules warning-free, converted ten Sigma rules, evaluated
six synthetic Sigma events, verified 48 feed targets/31 SIDs/96 tracker rows, and
verified all 62 bundle members against canonical staged text. The separate private
corpus check reran all 864 evaluations over 96 samples, preserved 672 old-rule
baseline cells, passed seven harmless-text/11 near-miss cases and 31 synthetic
Sigma events. Neither test set is a representative benign-software FP study.
Suricata engine execution and hosted workflow execution remain unverified.

## Historical documentation

Original August reports describe that capture's samples, infrastructure and
validation state; historical totals are not current release counters. The README
labels this scope explicitly. Current machine-checked release counts remain:
27 encrypted archives, nine YARA rules, ten Sigma rules, nine contextual IOC feeds,
six Suricata rule files/31 SIDs and 48 blocking targets (43 IPv4 hosts/five domains).

The website's `7/16` display was an inconsistency: source and corrected analysis
both establish 15 loader architecture labels, seven captured. It is corrected to
`7/15`; no exploitability or host-security impact was demonstrated. Older reports'
claims are not silently converted into fresh runtime/disassembly validation.
