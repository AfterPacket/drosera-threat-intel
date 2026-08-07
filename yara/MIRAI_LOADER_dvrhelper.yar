/*
 * MIRAI_LOADER — unobfuscated Mirai loader, dvrHelper payload
 * Drosera honeypot capture, 2026-08-03
 *
 * This family is self-identifying: it fetches a path literally named
 * mirai.<arch> and writes it to dvrHelper, the classic Mirai binary name.
 *
 * Note "dvrHelper" alone is deliberately NOT sole-condition — it is a
 * widely reused Mirai artefact name and appears in unrelated samples,
 * detection content, and in this same capture inside a rival operator's
 * kill script (see BOTKILL_PROCWIPE). Matching it alone would misattribute.
 */

rule MIRAI_LOADER_dvrhelper
{
    meta:
        description  = "Mirai loader fetching mirai.<arch> from 77.90.185.66, writes dvrHelper"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "246c3c37a0de2987d9352411f22ea4805f7e75287f2782d5ee56770219a096a4"
        family       = "MIRAI_LOADER"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"

    strings:
        /* High-confidence unique strings */
        $uniq1 = "SERVER=\"77.90.185.66\"" ascii
        $uniq2 = "http://$SERVER/mirai.$arch" ascii

        /* C2 / staging indicators */
        $c2_1 = "77.90.185.66" ascii

        /* Capability markers */
        $cap1 = "dvrHelper" ascii
        $cap2 = "chmod +x dvrHelper" ascii
        $cap3 = "mirai." ascii
        $cap4 = "chmod 777" ascii

    condition:
        filesize < 64KB and
        (
            /* HIGH: config assignment or the literal fetch template */
            any of ($uniq*) or

            /* MEDIUM: staging host plus two capability markers.
             * dvrHelper alone is intentionally insufficient — it is a
             * shared Mirai artefact name, not a family discriminator. */
            ($c2_1 and 2 of ($cap*))
        )
}
