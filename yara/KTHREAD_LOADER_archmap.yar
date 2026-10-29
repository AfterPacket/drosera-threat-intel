/*
 * KTHREAD_LOADER -- descriptive cluster label, not botnet attribution.
 * Static evidence: b1a84cfd, loader source lines 14-26, 54, 58, 68-70.
 * Requires architecture/name mappings AND hidden-destination/retrieval/cleanup
 * structure. No IP, domain, or legitimate kernel-thread name alone can match.
 * Scope is this shell-loader source; downloaded binaries are NOT covered.
 */
rule KTHREAD_LOADER_archmap
{
    meta:
        description = "Shell loader with architecture-specific kernel-thread-like names and hidden staging"
        author = "AfterPacket"
        date = "2026-10-29"
        hash_sha256 = "b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9"
        family = "KTHREAD_LOADER"
        tlp = "TLP:WHITE"
        reference = "https://github.com/AfterPacket/drosera-threat-intel"
        status = "EXPERIMENTAL"
        note = "Descriptive source cluster; tested on 96 unique samples, one positive; untested beyond this set"
        yarahub_uuid = "3147d8d6-51f2-4c6e-9f26-c7a1ba43c9fb"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ef38b770bef2edfe47529229264fde1e"
        yarahub_reference_link = "https://github.com/AfterPacket/drosera-threat-intel"
        yarahub_author_twitter = "@AfterPacket"
        yarahub_author_email = "AfterPacketTru@protonmail.com"
    strings:
        $map1 = "BIN_NAME=\"kworker_u8\"" ascii
        $map2 = "BIN_NAME=\"jbd2_sda1d\"" ascii
        $map3 = "BIN_NAME=\"zswap_shrinkd\"" ascii
        $map4 = "BIN_NAME=\"cfg80211d\"" ascii
        $dst = "DST=\"$WRITABLE_DIR/.$BIN_NAME\"" ascii
        $fetch = "wget -qO \"$DST\" \"$URL\"" ascii
        $fallback = "curl -sfLo \"$DST\" \"$URL\"" ascii
        $self = "SELF=\"$(realpath \"$0\" 2>/dev/null)\"" ascii
        $delete = "rm -f \"$SELF\"" ascii
    condition:
        filesize < 64KB and
        $dst and $fetch and $fallback and $self and $delete and
        3 of ($map*)
}
