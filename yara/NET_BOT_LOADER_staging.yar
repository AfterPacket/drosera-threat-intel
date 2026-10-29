/*
 * NET_BOT_LOADER -- descriptive loader cluster, not botnet attribution.
 * Evidence: 39be6853 source, architecture-specific net.* URLs, net_bot output,
 * chmod/exec chains ending in && exit, and final net_http.sh cleanup.
 * All structure groups are required. No sole IP, domain or generic wget match.
 * This rule matches the loader, NOT its ELF children.
 */
rule NET_BOT_LOADER_staging
{
    meta:
        description = "Shell loader staging net.<arch> as net_bot with tagged execution and early exit"
        author = "AfterPacket"
        date = "2026-10-29"
        hash_sha256 = "39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96"
        family = "NET_BOT_LOADER"
        tlp = "TLP:WHITE"
        reference = "https://github.com/AfterPacket/drosera-threat-intel"
        status = "EXPERIMENTAL"
        note = "Descriptive source cluster; tested on 96 unique samples, one positive; untested beyond this set"
        yarahub_uuid = "eb574783-ef12-4dfb-b233-09e46b414e65"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9e3b46f7626b0408ec194c37d7dd9c06"
        yarahub_reference_link = "https://github.com/AfterPacket/drosera-threat-intel"
        yarahub_author_twitter = "@AfterPacket"
        yarahub_author_email = "AfterPacketTru@protonmail.com"
    strings:
        $path1 = "/bins/net.x86_64" ascii
        $path2 = "/bins/net.mpsl" ascii
        $path3 = "/bins/net.arm7" ascii
        $path4 = "/bins/net.arc" ascii
        $wget = "-O net_bot && chmod 777 net_bot" ascii
        $curl = "-o net_bot && chmod 777 net_bot" ascii
        $exec1 = "./net_bot net.x86_64 && exit;" ascii
        $exec2 = "./net_bot net.mpsl && exit;" ascii
        $exec3 = "./net_bot net.arm7 && exit;" ascii
        $cleanup = "rm -rf net_bot net_http.sh" ascii
    condition:
        filesize < 64KB and
        3 of ($path*) and $wget and $curl and
        2 of ($exec*) and $cleanup
}
