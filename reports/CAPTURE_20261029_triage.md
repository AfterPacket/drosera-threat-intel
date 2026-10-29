# Additional capture triage and detection validation — 2026-10-29

**TLP:WHITE** · Author: AfterPacket · Static analysis only

## Scope and selection

**Observed:** repository baseline `c8cdaa1628955e582be7f362e1a60c2daefd6211`
contains 25 AES-encrypted samples, seven YARA files, eight Sigma files and seven
family reports. Supplied October loot contains 96 sample/JSON pairs; all 25
repository samples are included byte-for-byte. Thus there are **96 unique
samples**, not 121 unique samples. All 121 originally extracted instances passed
SHA-256 verification, with no mismatches. Decryption stayed outside the Git tree
and outside OneDrive. No sample was executed and no sample infrastructure was
resolved, scanned or contacted. Tool installation used official Python/PyPI
infrastructure, not sample endpoints.

**Observed:** supplied loot archive SHA-256: `b6d78d6100e905b74c2f9e28dbe7075f1d6dec1b42cf7cbd04dd163072155337`.
The loot sidecars are capture records, not newly checked external intelligence.
**Unverified:** any claim of current VT verdict, provider, ASN, geo, ownership,
reachability, attribution or runtime success.

**Observed:** the pre-edit scratch coverage matrix has one row per unique
sample, using COVERED / WEAK / GAP / N/A-BY-DESIGN, and the scratch work plan
selects only two items. Existing YARA initially hits 27/96 unique samples and
21/25 originals; its original four misses are the deliberately unsigned BOTKILL
and WEBROOT scripts. Their no-YARA decisions are retained, not counted as gaps.
The other 65 misses are not documented as deliberate exclusions; they remain
unresolved gaps unless selected below. A miss alone does not justify a safe rule.

**Observed:** selected uncovered loader source clusters:

1. [KTHREAD_LOADER_analysis_b1a84cfd.md](KTHREAD_LOADER_analysis_b1a84cfd.md):
   architecture-to-kernel-thread-like name map, hidden destination, self-cleanup.
2. [NET_BOT_LOADER_analysis_39be6853.md](NET_BOT_LOADER_analysis_39be6853.md):
   net.<arch> fetch, net_bot execution tags and conditional early exit, with 28
   child hashes linked by explicit capture sidecar lineage.

**Inferred:** these provide defender value with stronger static evidence and
lower signature ambiguity than generic new probes or unexplored child binaries.
The labels describe source clusters; they are not named botnet attribution.
No third malware-analysis work item was selected. Tests/tooling/packaging below
support these same two items rather than expanding detection scope.

## Validation gates

**Observed:** results below were generated locally on 2026-10-29. A skipped test
is not a pass. New rule/report logic comparisons are in the per-loader reports.

| Gate | Result | Evidence / limits |
|---|---|---|
| 1 — YARA compilation | PASS | libyara/yara-python 4.5.4, all nine files individually and combined, warnings fatal, zero errors/warnings |
| 2 — all-rule/all-sample scan | PASS | 9 × 96 = 864 evaluations; includes original 25; 672 old-rule/sample cells unchanged |
| 3 — intended hits | PASS within tested set | Each new rule hits exactly its intended loader; no other sample hit; seven harmless-text fixtures and 11 structural near-miss cases pass. No claim of generalization or broad clean-corpus FP rate |
| 4 — Suricata runtime syntax | NOT RUN; no new artifact | Engine unavailable. All six original files unchanged. Static checks find 31 unique SIDs and exact agreement with registry; 9006 remains reserved |
| 5 — Sigma | PASS, bounded | All ten files parse/required-field/UUID checks and convert via pysigma 2.0.1 + Splunk backend 3.0.0; 31 new-rule synthetic events pass a limited selection evaluator; no live SIEM execution |
| 6 — blocklist | PASS exact two-host enforcement delta; ownership NOT CHECKED | Initially 46 unchanged entries; operator-approved follow-up adds exactly two payload-host IPs: 48 entries / 43 IPs / 5 unchanged domains. Raw/Firewalla parity, LF, final newline, no duplicates/blanks/comments; metadata-only/shared-service/decoy exclusions retained. Current tenancy and activity not certified |
| 7 — samples | PASS | All 121 extracted instances rehashed; all 27 repository archives decrypt to their filename digest with AES-256. Two new archives reject wrong password; no original sample archive changed |
| 8 — links | PASS active local links | README markdown destinations and active index.html hrefs exist; commented template placeholders excluded and recorded below |
| 9 — diff / packaging review | PASS scoped review | Two reports, two YARA, two Sigma, two encrypted sample ZIPs, validator, this capture note, README and regenerated existing bundle; no extracted bytes or decoded payload committed |

**Observed:** new rules are deliberately loader-source-specific. One sample per
new YARA rule is not evidence of robust detection across a wider malware family.
All nine have one rule per file. YARAhub reference MD5 values for the new rules
were recomputed and their referenced samples hit the intended rules.
**Unverified:** acceptance by YARAify/YARAhub; no submission was performed.

**Observed:** the validator's negative tests are inert text and in-memory byte
removal, never executable reconstructed loaders. The Sigma checks exercise both
positive conjunctions and missing/wrong-image/path/tag negatives. The Splunk
queries use Image and CommandLine; ingestion pipelines must map those fields.

## Full YARA rule-by-sample hit table

**Observed:** `1` means a hit, `0` a miss. `O` marks an original repository
sample; `L` is loot-only. These columns are independent rules, not family verdicts:

| Key | Rule |
|---|---|
| G | GSOCKET_SSHIT_deployer |
| K | KTHREAD_LOADER_archmap (new) |
| M | MIRAI_LOADER_dvrhelper |
| OL | MIRAI_OHSHIT_loader |
| OP | MIRAI_OHSHIT_payload |
| TD | MIRAI_TELNETCURL_dropper |
| TP | MIRAI_TELNETCURL_payload (lineage-oriented, not campaign-exclusive) |
| N | NET_BOT_LOADER_staging (new) |
| P | PERLBOT_SHELLBOT_irc |

| SHA-256 | Set | G | K | M | OL | OP | TD | TP | N | P |
|---|---|---|---|---|---|---|---|---|---|---|
| `03a4f492af99d2048f713081560b8fa45312e594e8439eefa714f0c67a1e0550` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `05ace3bf9402f36cc5b0cd36a0afe0ae0090c6c954b167a645f0123c65ea779c` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `05aea199775e5214c7b970acd4e2e1171fcb96d0c36ba8ac9cf16d5c10e54ca8` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `0a303df379fd147b55442d958ccb6a8b9ab1d1ddac8e7aa4fc4647b796815c41` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `0b2c198d3d0320b5a082643c0ceed74b8bba52a16c9621371a970e3d2c3ff3a8` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `10b386e9d58b7b50d8749289e16b1e6958146d4ace974af96b18d5e047bb6b7a` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `11040b3b2a24379975f6f618adc4d6943d54a7964ce40985b00a8824f248b76e` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `119964637064cb5ba87875504b5411f949f5e8a802419639c036adc7bf92f7a3` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `15b950d6b732fba9021b829331a2277c1d88609b60b4238a34fcbfea676f465d` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `163582db1c9f586d178686343668a5d16af7a64d7bebc5e969948eedbddf8206` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `1bbf752e3f82b21cbc035fc23de08d0b2539fde3c83cc27c257764a18788cff4` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `1c38a8b346804cfceae26b7136c8d0ddadfbf90d97d93b47de9f3a4a8bde7e20` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `2136980fc01c33fcd1f5cf0541ebfce02093eec928921654dc35c17d69205946` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `22585585074dfaf862ab5bf0de958b99f146f0942b651af4f2f3ff3077b2513b` | O | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `246c3c37a0de2987d9352411f22ea4805f7e75287f2782d5ee56770219a096a4` | O | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `2733d565138186645b2ff2485f88cfdaee2a1cf2cd3af1306273fc0f6191a58c` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `2ae7dc16ca036cb5c2c7ce2cd8099edb07d96b8846188c92eb39a7feba2fec08` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `2cfb69efca445421005807b41469ca27f7ea98e2bcb1c4c0d530c83bda9eb0ed` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `30c7d351e70323915566d2bb648b4313c9722b34252929a8c7050f6495ae14fc` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `34b7558c823dce388432fe16b997c0a02646956d171f72eb7557774a1e1d66b3` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `3801a288c16a19c57c7a8a7b0f139cf630d2cd0c4bbcb26876e3593c492ffc5d` | O | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `3aea28dce9986a41162613578b287deb73d0e197ba618306d525353bc7297c9a` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `3afa3a117915cf21b105ea9c8aae346af4f733556e6a6fe62e1352901d2b4831` | O | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `410b186df9b8c000638face4673aabd7145ebca2baaa4a047318ada473d868ab` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `41d9a2a07ccfc769854bf71c82258da1f0a622644f12fada54320e7ff310fcfa` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `448a8ecf922d0d4893a808a706b8a70f04376a0fd2180be2b536cd256818a3be` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `45bee2b10761884f47fac2f515056d15569d85ecfafc662573bf915dbcb8f943` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `46741363ec3bdf4e30df9a50cd55392595d537193149752345659b17153cb680` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `47ad3cf2e40ac559b550d22cfa72793998ac35aeab543a93dc5c96a765dd4d1c` | L | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `4979c83681a310a8d3789fb8728b1c291c93babc2883edbebd5f470d45d618fe` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `54f07e4c8358c4947e5fba61c9a3fe0e66e31abdb8fd9e39b8962df6e9bbfa6c` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `57a4487a6f882b2448048164a1b0ea71c104aa94e9ad6aca8d3f8d2c60401ed4` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `58d2eb7726146364b492a86571921d12e3ee684c5599d1da01499afdc595c735` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `5c84dbb875ee198050a661a9f0182462b34e745f1c8e31026f23c0ea6fb2e15e` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `600f454199baf384ede4592873473af6c28c283c71f207defac7968a2d99ba29` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `61317fa3019a3a2c66142ebb0e76bcca6374bde0e5b330f04bcb81b366923533` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `683a3f7c5992c013d4cd71eeaf2d0d3b5a781261fa19a30e4d073ddf712c5ea4` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `6955d78197fe503a53c57ffff66643de59c4bea21d79fbc95f2c24ec5ae89a82` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `6d8bbd045375e6523dcc28e1f46e89354e3cdb12da1c93fdb040cc6824e08969` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `7352f6d206a1aa92c316b0384979fb021fc75a5c2458210455da586a125f7c4c` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `7370f944b9d5a76172b2f4bf78d919a294cc93b099d666fa95d4ec6c8073718c` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `78a57de8eb7d70af3d44dda3ea3fc11ed44879d34db45fb8c22211b852398763` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `794eec489531313a274c646b3418d514ebc20acddb0e21e9511c440097469257` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `7b1cbba56bb80e185cdf2097f5716c31d7e0f88f28ad7220b3b5a2cf73859ec8` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `7b8add306d87da91ed1ff4608ad8f829c83f6035cbc852c73869ec66977d93f8` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `7cc0b40e8819ec9139ffae5942add2db1c26e168edaeda57302c9047f23dfb6c` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `7fd90b8a783caecdd0609a13ba0b0fb0bc0348c657dbda5d0ab1660840cbeaea` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `81ea2a392b6d71c7cd381f48ebffb992457a1d3897d1484a3fd7823f2e9f69a3` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `83b36b3a80677d6ef4a165cbbc808b4889c76d194f976eab37a8dfe5c8eabae1` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `8b1a2fb6b358484b7769aeeb63209f2b277d91b5015cf28ce471a67e0ef83d28` | O | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `8e06754e5e64bdf5f61dd604a5f12e9bc10f5502316b5379fb258f84a5d84702` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `8f7a3c8df5f9e467b8e4645ae07856b53ba16ac53e2b5de85f07eb61deaddd76` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `9334bd5e315feaae8317952ab96080f1063d3b8443d38086b381460bc975bd43` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `98994017c070389b3ddfe557847dc6aaa00ce7bc79760faf3dcfe68036b56431` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `9bce93a6ea7f1cc1e49f93f0d21bc41d8c065f19a5d9c42f8fb93e0c6e081ebc` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `9cbe35b1d10f55d712738644c60c2cc47eac13e06f23ba849abb1bbdbdfdc5f2` | O | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `9d7cd4948a1fcbaeadc425752fce9a933bd6fc41eeede030dffd7b99b3bc51d5` | O | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `9fca540b88a7ea5dc0890c567e844003cdc43977f4a93d7cdee8fdd7f91c2f4b` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `a2f3d6d2bd82a65939f4e939bce242e8e246014fb3a9a9d5c3769ed7dcfffe24` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `a834705aedd521b2d75ec51b593ee82f49d8f3b9c61b5ef6034dc8340b70a98b` | O | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `ac619a5cba97b835cf875b44ce8486f147c66aa63fbd4990ad77a3b5017a147f` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `b13629ce9fa8cba1f1189ddf4a5918c7ab8b4311f45d8ad6334adec7b2186e8d` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9` | L | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `b1d781a7a2861f99795f9ceee19eb2326dcb919573dbe3a052bfe8d02f519cae` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `b3a548a1110ae32b998408ed7a37387e97ad261ded4b182f5a8ca6ea7f8304af` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `b6260a8c94f54ff97d7838eee6391c9c32284d4b6f81e36401757cbafdc99a46` | O | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `ba9c9d9d361d7df77a94b04aa66b7ae34c9d92b38e620ceeccc95058ea1c08a9` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `bb08fd9ce1f3508bc30a33646aeb66df3024e5c7da843cabd09ed19ae07bd8d1` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c030f061903119a557b2bccc2009837296bac13b1922fc01da6977b6a8fd1253` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c11473d154b0e18791a5befe375768beed8e93fe0eb6ed71ed6ea642bead7626` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c220d6eee6083d31de215defb91161812ba3d998bad7d8babf258c9af4bdcee2` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c2337d2c2d89a66c4579fa01c82c049a34e606952893bd3c01aa26538add69d1` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c458e443759ea633cde8929b4337726136675141d82251158f973f54008e20ac` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `c9a25d77eca95fa6c6859681684101a00cdb25e2337ad3a02d946caa8ad247b2` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ca4b5afd66233bd10a41fd11bcd56554283e945c461e2fd9f5673df4bcebbeb3` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `cc049286a66056a4a80331b3c08494f8c7c73b4cc6e26328d3e6fb31deef729f` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `cd6ccc5dabe85309a938e43c9508998bb0f52a9264fa9ba9276956f7fa42f48d` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `d6a1e8e40d7e77a126f19e595a44ecf7333b745eddb29a344d468aca97e5645a` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `daec3dc3411585087f53d9601c176a48dcf2ceb343c6ebd47ace2fa8c5b567b3` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `dd225f82614fbe9734a58b04c77858a2491a9ad5071c5988ec8b9896135ec17d` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `de9cfdf7d1330534731e8354ec5927db99e06365850a8fe1d07c6bf8dec97ad0` | O | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9` | O | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `e16117e61605d82e9f61aac203effbe8baf8acebb3390859759e48da2d070c53` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `e6613f1dc334e1e11e2dd0bb518d7abdbb9db5078caef0c31400e55f43df864f` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `e914bd76c24431fdfbe2c5f40a00aef6a679668b730b5a07ec8e4db2d03acd32` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `edc3f61193ba8d5d4941334360b8c8141b308fbb12c5b9edf4417b76d1c2faf7` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ef2272062f3b67a1095838326e26a8ec364a9d0c032d31f659ac9e447baac019` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `f0adc635e76a971aa3dd68c8652ba3179433ef9e0f9bcd8c171c4615aeabd1d5` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `f24f459b6526c8583f40a62a3c97485f4c80b812e81c926bf832a67c208fbbfc` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `f3abe9aa18137a8002706fd584b24b4c0d95cbc4f6ad25915bdd7a5ec184e002` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `f6f9c5f16c7d2b9e4df3b132c05f356c9abc48a7ee1d5f079016338bc2030e40` | O | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `fb8b93e7b241c70a533fefacb7dcb0bdc3bcec514e8575b4ed433d3c7a4be120` | L | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `fd93b4f7bd5e8360ecd6e782dd445356728e698b9f25e335131b28bcdd3e56e3` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `fe6b7b4c09ec79caa51ee7a7c46bbfdb11b0c7e0a380292675fb5ac6ce2b26c2` | O | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |

## Changed-file review

**Observed — initial loader publication:** changes were limited to the files below;
all prior detector conditions, original IOC/firewall feeds, blocklist bytes and
original sample archives were preserved. The contextual IOC follow-up below adds
two investigation feeds without changing automatic enforcement policies.

| Path | One-line reason |
|---|---|
| `yara/KTHREAD_LOADER_archmap.yar` | New conjunction-only source detection for previously unmatched b1a84cfd |
| `sigma/kthread_loader_hidden_download.yml` | Host-side downloader/path/destination conjunction |
| `reports/KTHREAD_LOADER_analysis_b1a84cfd.md` | Offset-backed loader config, limits, ATT&CK and detection reasoning |
| `samples/b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9.zip` | Only AES-256 encrypted original sample, verified against archive stem |
| `yara/NET_BOT_LOADER_staging.yar` | New multi-group source detection for previously unmatched 39be6853 |
| `sigma/net_bot_loader_tagged_execution.yml` | Host-side executable-and-architecture-argument conjunction |
| `reports/NET_BOT_LOADER_analysis_39be6853.md` | Static control flow and explicit sidecar-linked child-hash inventory |
| `samples/39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96.zip` | Only AES-256 encrypted original sample, verified against archive stem |
| `tools/validate_static.py` | Reproducible static-only compilation, corpus and bounded fixture tests |
| `reports/CAPTURE_20261029_triage.md` | Scope, full 864-cell results, validation limits and unresolved inconsistencies |
| `README.md` | Links to new work and actual dated validation rather than an unsupported status |
| `drosera-detection-bundle.zip` | Regenerate the existing sample-free bundle with current reports/rules/tools |

## Contextual IOC publication follow-up — 2026-10-29 (before enforcement update)

The publication/preservation results in this section record the contextual-only
stage. The subsequent operator-approved enforcement section below supersedes
the earlier decision to keep both retrieval hosts out of the blocking feeds.

**Observed:** two investigation feeds now accompany the loader detections:

| Feed | Payload retrieval evidence | Separate capture-source context |
|---|---|---|
| [KTHREAD_LOADER](../ioc/KTHREAD_LOADER_ioc.txt) | `44.210.140.205`, literal `/bins` base and 12 constructed candidate payload URLs from source assignments | `78.17.98.2`, supplied sidecar only; not promoted to a payload host |
| [NET_BOT_LOADER](../ioc/NET_BOT_LOADER_ioc.txt) | `160.119.66.206` and all 15 literal `/bins/net.<arch>` URLs | `94.154.43.203` plus the separate sidecar occurrence of `160.119.66.206` |

**Observed:** each feed includes loader hashes, evidence roles, defanged URLs,
source-derived host context and explicit limits. HIGH refers to extraction
confidence, not current maliciousness or ownership. TCP/80 is HTTP retrieval
context, not a broad deny recommendation. These feeds must not be imported
wholesale into firewall or IP/domain blocking lists.

**Observed:** README, HTML index and both loader reports link the new feeds;
there are now nine IOC feeds. The sample-free detection bundle is rebuilt with
55 entries from canonical Git content, including both feeds and current reports
and README. It intentionally excludes sample ZIPs and the website index, as in
the existing bundle layout. The separate repository index remains the website entry point.
Original YARA/Sigma/Suricata files, seven older IOC feeds, 27 sample archives,
Firewalla lists, port policy, 41-IP/five-domain blocklist and SID registry are
preserved. Original August reports retain their historical scope.

**Observed — follow-up detector regression:** the offline validator was rerun on
the same 96 unique samples: nine warning-free YARA files, 864 evaluations,
672 unchanged old-rule baseline cells, one intended hit per new rule and zero
new cross-sample hits. Seven benign-text fixtures, 11 near-miss tests, all ten
Sigma parse/conversions and 31 synthetic Sigma events passed. These are bounded
offline checks, not live engine/deployment validation.

**Observed — publication checks:** all SHA-256/SHA-1/MD5 feed values were checked
against the two extracted sample byte streams, without execution. All 15 NET_BOT
URL literals and 12 constructed KTHREAD candidates match source; metadata-only
capture addresses are not bare payload-host entries. All active index links and
links in the changed Markdown files resolve locally. The seven original capture
cards are unchanged. Sixty-seven existing detector, policy, original-feed and
sample files were checked unchanged against the parent commit; all 31 Suricata
SIDs remain unique and registry-consistent. All 55 ZIP entries match canonical
Git content and the bundle contains no samples or nested ZIPs.

**Unverified:** current endpoint availability, dedicated malicious ownership,
co-tenancy, C2, broad clean-software false positives and live deployment. No
samples were executed and no sample infrastructure was contacted.

## Operator-approved payload-host enforcement follow-up — 2026-10-29

**Observed source evidence:** `44.210.140.205` is the KTHREAD retrieval host;
`160.119.66.206` is the NET_BOT retrieval host in 15 literal URLs. The operator
explicitly approved whole-IP destination blocking of these two hosts. This is a
policy choice based on sample-source evidence, not new verification of current
activity, C2, dedicated ownership or absence of legitimate co-tenants. IP reuse
or co-tenancy may cause collateral impact; review before importing and reassess.

**Observed publication changes:**
- `blocklist.txt` and `firewalla/drosera_block.txt`: exactly those two IPv4 hosts
  added, giving **48 unique entries: 43 IPs and five unchanged domains**.
- `firewalla/drosera_port_policy.txt`: Rule 5 documents outbound destination-only
  blocks for those two /32 hosts. Any-port scope is a policy choice; observed
  retrieval is HTTP/TCP 80. No blanket HTTP deny or new inbound rule is added.
- Both loader IOC feeds and reports now distinguish the included retrieval host
  from the still-excluded metadata-only source (`78.17.98.2` / `94.154.43.203`).
- README, index counters/descriptions and the 55-entry sample-free bundle are
  synchronized. This supersedes the earlier contextual-only blocking disposition.

**Observed limits:** no additional addresses, new domains, provider ranges or
Suricata rules were added. YARA, Sigma, all six Suricata files/31 SIDs, seven
original IOC feeds, 27 encrypted archives and the seven original index cards
remain unchanged. No sample execution, sample-infrastructure contact or live
firewall alteration was performed; deployment/application is operator-controlled.

**Observed — enforcement follow-up checks:** raw/Firewalla sets are identical,
with exactly the two approved additions and no removals, duplicates or new domains.
All four original egress-policy rules and the existing HTTP guidance are preserved;
Rule 5 adds only the two destination hosts. Sixty-four existing detector, original
IOC-feed and archive files are byte-identical to the parent. Source/hash/URL,
link, seven-card preservation, 31-SID registry and 55-entry canonical-bundle
checks passed. The 96-sample detector regression was rerun: 864 evaluations,
672 unchanged baseline cells, nine warning-free YARA files, ten Sigma conversions,
seven benign-text fixtures, 11 near-miss cases and 31 Sigma synthetic events passed.
Suricata runtime validation and live policy enforcement remain untested.

## Reproduction

**Observed:** [tools/validate_static.py](../tools/validate_static.py) performs
warning-fatal YARA compilation and the full corpus table, hash checks, benign and
near-miss tests, Sigma parsing/conversion and synthetic selection checks. It does
not decrypt samples or execute them. Install the documented dependencies in an
analysis environment. Extract samples to a private, nonsynced directory first.

```text
python tools/validate_static.py --corpus /private/96-decrypted-samples --output /private/test-results
```

**Observed:** scratch evidence includes `coverage_matrix.md`, `work_plan.md`,
`yara-baseline.csv`, `validation/yara-hits.csv`, `validation/validation.json`,
`validation/sigma-splunk.json`, `manifest.json` and `selected-evidence.txt`.
These are operator-side files, deliberately not new repository directories.
An optional `--baseline` takes the pre-edit CSV to compare every old rule cell.
The supplied loot is needed to reproduce the 96-sample run; the repository's 27
archives alone cannot reproduce the full table.

## Corrections, conflicts and restrained exclusions

**Observed — validation status update:** the README's historical YARA syntax
warning is superseded by the actual 4.5.4 run above. The withdrawn earlier 4.5.5
claim is not reinstated, and historical reports retain their dated caveats.
No old family finding or detection condition was silently overwritten.

**Observed:** KTHREAD_LOADER's purported endian test uses octal `od` output but
greps a value containing `9`; the new report documents why reliable endian
selection is **inferred to fail**, not dynamically demonstrated.

**Observed — initial publication, superseded in part by the contextual IOC follow-up:**
loader staging literals and capture-source addresses were initially documented
only in reports. They are now also published in two role-labeled investigation
feeds. The later operator-approved enforcement follow-up includes the two
source-observed retrieval hosts in the blocking feeds despite unresolved current
ownership/co-tenancy, while metadata-only capture sources remain excluded. Domains
used as Mirai decoys or HTTP headers remain non-blocking context, specifically
`www.ikindalikemenbutonlyontuesday.com`. No rule for generic probes, sudoers
content, authorized keys or a generic /proc killer was added. No new Suricata
artifact is shipped without engine validation.

**Observed — README follow-up:** the opening overview and Analysis reports table
now explicitly distinguish 27 published sample archives from the 96-sample
validation corpus. Both new loader reports are listed alongside the original
seven family reports, and the Sigma section reflects all ten current rules.

## Repository inconsistencies noticed

**Observed:** the following existed at the baseline; only bundle freshness and
README validation/current-extension counts were addressed as part of this work:

- No `.github/workflows/` directory exists. No CI was assumed or invented.
- No genuinely empty artifact directory exists: Sigma already had eight rules;
  `.gitkeep` files remain in populated directories.
- The executive summary says "7 rules, 5 files" and "7 rulesets"; baseline
  actually had seven YARA files and six Suricata files. Historical reports were
  not revised for those count errors.
- August triage still calls bundle regeneration outstanding. The baseline bundle
  was present but stale: seven bundled entries differed from the baseline Git
  versions (README, BOTKILL IOC/report and four capture reports). It is regenerated
  here; the dated triage note remains as historical provenance.
- `index.html` contains intentionally commented template paths such as
  `yara/FAMILY_campaign.yar` and `samples/0000.zip`, not active broken links.
- The OHSHIT card still shows `7/16` captured architectures despite the written
  15-architecture correction, and the IOC's stage-3 header also says 7 of 16.
- README's digest discussion mentions twenty-six captured samples while the
  original published corpus contains 25. No missing twenty-sixth archive was
  invented or assumed.
- README's old `yara -r yara/*.yar /path/to/scan` example is not a portable
  all-rule invocation: shell expansion supplies multiple source arguments to a
  CLI normally accepting one rule source. Use the validator or iterate individual
  rule files. **Correction — README follow-up:** the current README now iterates
  individual rule files; the dated August reports' examples remain unchanged.
- Active index cards lack per-family report links even though the commented
  template includes one. Existing links resolve; the site was not redesigned.

**Unverified:** broader claims in old reports, such as successful propagation,
operator identity, ownership of every C2-looking name, or capabilities of
uncaptured builds, are not revalidated by a YARA hit table. New reports distinguish
sample bytes, supplied metadata, inference and unverified runtime behavior.
