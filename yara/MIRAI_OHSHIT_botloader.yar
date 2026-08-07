/*
 * MIRAI_OHSHIT — multi-architecture IoT botnet loader chain
 * Drosera honeypot capture, 2026-08-07
 *
 * Two rules: the shell loader chain, and the ELF payloads.
 *
 * The payload rule is architecture-independent by design. The C2 domain set
 * is compiled identically into all seven builds (ARM, ARM7, SH4, MIPS, i686,
 * PowerPC, x86-64), so matching on strings rather than code covers builds we
 * never captured — 9 of the 16 architectures the loader fetches.
 */

rule MIRAI_OHSHIT_loader
{
    meta:
        description  = "Mirai-derived multi-arch loader chain staged from 94.154.43.123"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "8b1a2fb6b358484b7769aeeb63209f2b277d91b5015cf28ce471a67e0ef83d28"
        hash_sha256_2 = "de9cfdf7d1330534731e8354ec5927db99e06365850a8fe1d07c6bf8dec97ad0"
        family       = "MIRAI_OHSHIT"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"

    strings:
        /* High-confidence unique strings */
        $uniq1 = "ohshit.sh" ascii
        /* The doubled slash after the host is characteristic and low-noise */
        $uniq2 = "94.154.43.123//bot." ascii

        /* C2 / staging indicators */
        $c2_1 = "94.154.43.123" ascii
        $c2_2 = "http://94.154.43.123/ohshit.sh" ascii

        /* Capability markers — the loader's staging idiom */
        $cap1 = ">WTF" ascii
        $cap2 = "chmod +x *;./WTF" ascii
        $cap3 = "cat bot." ascii
        $cap4 = "busybox /tmp/" ascii

    condition:
        /* Shell scripts — keep the rule off large binaries entirely */
        filesize < 64KB and
        (
            /* HIGH: a unique string alone is sufficient */
            any of ($uniq*) or

            /* MEDIUM: staging host plus loader behaviour */
            (any of ($c2_*) and 2 of ($cap*))
        )
}


rule MIRAI_OHSHIT_payload
{
    meta:
        description  = "MIRAI_OHSHIT ELF payload — compiled-in C2 set, all architectures"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "81ea2a392b6d71c7cd381f48ebffb992457a1d3897d1484a3fd7823f2e9f69a3"
        hash_sha256_2 = "9d7cd4948a1fcbaeadc425752fce9a933bd6fc41eeede030dffd7b99b3bc51d5"
        family       = "MIRAI_OHSHIT"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"

    strings:
        /* C2 domains — identical across all 7 captured builds.
         * Each is individually rare enough to stand alone. */
        $d1 = "api-relay-3.metrics-collector.io" ascii
        $d2 = "cdn-edge-updates.hostcloud-eu.net" ascii
        $d3 = "mgmt-panel.serverstats-daemon.com" ascii
        $d4 = "sync.softwaremirror.workers.dev" ascii
        $d5 = "glibc.malloc.top" ascii
        $d6 = "control.tor2web-relay-fast.onion" ascii

        /* C2 IPs, compiled in alongside the domains */
        $ip1 = "45.61.161.207" ascii
        $ip2 = "45.83.140.28" ascii
        $ip3 = "5.101.221.87" ascii
        $ip4 = "51.15.68.114" ascii
        $ip5 = "94.130.53.201" ascii
        $ip6 = "195.201.24.6" ascii

        /* Retrieval template used by the payload itself */
        $cap1 = "/bins.sh" ascii

        /* Deliberately NOT matched on: bugs.launchpad.net (glibc
         * boilerplate), 185.199.108.153 (GitHub Pages) and 104.21.234.17
         * (Cloudflare) all appear in these binaries and would drag in
         * unrelated software. */

    condition:
        uint32be(0) == 0x7F454C46 and
        (
            /* HIGH: any single C2 domain — none occur in benign software */
            any of ($d*) or

            /* MEDIUM: two hardcoded C2 IPs together */
            2 of ($ip*) or

            /* MEDIUM: one C2 IP plus the payload's own fetch template */
            (any of ($ip*) and $cap1)
        )
}
