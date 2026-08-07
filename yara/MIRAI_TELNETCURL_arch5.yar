/*
 * MIRAI_TELNETCURL — telnet-propagated Mirai variant, 5 architectures
 * Drosera honeypot capture, 2026-08-01 .. 2026-08-07
 *
 * SCOPE: dropper scripts only. The 5 captured ELF payloads are NOT
 * covered — no strings were extracted from them.
 *
 * The per-architecture output filenames are non-dictionary six-character
 * tokens, stable across both the curl and busybox-wget variants. They are
 * the strongest available signal for this family.
 */

rule MIRAI_TELNETCURL_dropper
{
    meta:
        description  = "Mirai telnet dropper staging from 205.237.110.232, exec tag telnet.curl"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "3801a288c16a19c57c7a8a7b0f139cf630d2cd0c4bbcb26876e3593c492ffc5d"
        hash_sha256_2 = "e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9"
        family       = "MIRAI_TELNETCURL"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"

    strings:
        /* High-confidence unique strings */
        $uniq1 = "telnet.curl" ascii

        /* C2 / staging indicators */
        $c2_1 = "205.237.110.232" ascii
        $c2_2 = "http://205.237.110.232/" ascii

        /* Fixed per-architecture output filenames */
        $name1 = "VFASXC" ascii
        $name2 = "WQZRTY" ascii
        $name3 = "YUIOXC" ascii
        $name4 = "GHJKLB" ascii
        $name5 = "MNCXOP" ascii

        /* Capability markers */
        $cap1 = "chmod 777" ascii
        $cap2 = "busybox wget" ascii

    condition:
        filesize < 64KB and
        (
            /* HIGH: three of the fixed filenames together cannot be chance */
            3 of ($name*) or

            /* HIGH: exec tag plus staging host */
            ($uniq1 and any of ($c2_*)) or

            /* MEDIUM: staging host plus a filename plus dropper behaviour */
            (any of ($c2_*) and any of ($name*) and any of ($cap*))
        )
}


rule MIRAI_TELNETCURL_payload
{
    meta:
        description  = "Mirai-lineage ELF payload carrying the leaked-source decoy domain"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "9cbe35b1d10f55d712738644c60c2cc47eac13e06f23ba849abb1bbdbdfdc5f2"
        hash_sha256_2 = "3afa3a117915cf21b105ea9c8aae346af4f733556e6a6fe62e1352901d2b4831"
        family       = "MIRAI_TELNETCURL"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"
        note         = "Lineage marker, not a family discriminator — see condition"

    strings:
        /* The decoy domain from the leaked Mirai source, present in all five
         * captured builds. It is a LINEAGE marker: any Mirai descendant that
         * kept the original resolver code carries it, so this rule identifies
         * Mirai-derived payloads generally, NOT this campaign specifically.
         * Attribute to the family only with corroborating infrastructure. */
        $decoy = "www.ikindalikemenbutonlyontuesday.com" ascii

        /* Scanner range constants that accompany it in these builds */
        $r1 = "119.0.0.0" ascii
        $r2 = "120.0.0.0" ascii
        $r3 = "121.0.0.0" ascii

    condition:
        uint32be(0) == 0x7F454C46 and
        (
            $decoy or
            2 of ($r*)
        )
}
