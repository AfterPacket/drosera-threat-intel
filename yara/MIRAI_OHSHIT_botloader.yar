/*
 * MIRAI_OHSHIT — multi-architecture IoT botnet loader chain
 * Drosera honeypot capture, 2026-08-07
 *
 * SCOPE: matches the stage-1 fetcher and stage-2 loader scripts only.
 * The 7 captured ELF payloads are NOT covered — no strings were extracted
 * from them, and a rule asserting coverage would be unfounded.
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
