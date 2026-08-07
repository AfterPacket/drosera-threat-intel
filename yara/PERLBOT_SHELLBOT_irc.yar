/*
 * PERLBOT_SHELLBOT — Perl IRC shellbot
 * Drosera honeypot capture, 2026-08-02 .. 2026-08-07
 *
 * Covers all three captured samples (/duba, /dodu, /gots), including
 * /dodu — which carries NO VirusTotal record despite being the same size
 * as /duba, which 29 of 60 engines flag. The undetected twin is the
 * higher-value hunt target.
 *
 * NOTE: the bot accepts a C2 override as $ARGV[0], so the hardcoded server
 * is the default rather than a guarantee. The structural strings below
 * survive a redirected C2; the IP string does not.
 */

rule PERLBOT_SHELLBOT_irc
{
    meta:
        description  = "Perl IRC shellbot, C2 213.139.77.150:6667, randomised nick and process name"
        author       = "AfterPacket"
        date         = "2026-08-07"
        hash_sha256  = "03a4f492af99d2048f713081560b8fa45312e594e8439eefa714f0c67a1e0550"
        hash_sha256_2 = "fe6b7b4c09ec79caa51ee7a7c46bbfdb11b0c7e0a380292675fb5ac6ce2b26c2"
        hash_sha256_3 = "fd93b4f7bd5e8360ecd6e782dd445356728e698b9f25e335131b28bcdd3e56e3"
        family       = "PERLBOT_SHELLBOT"
        tlp          = "TLP:WHITE"
        reference    = "https://github.com/Afterpacket/drosera-threat-intel"
        status       = "PRODUCTION"

    strings:
        /* C2 indicators — defeated by an $ARGV[0] override, so never sole-condition */
        $c2_1 = "213.139.77.150" ascii
        $c2_2 = "my $server = '213.139.77.150'" ascii
        $c2_3 = "my $port = '6667'" ascii

        /* Structural markers — survive C2 redirection */
        $s1 = "rircname" ascii
        $s2 = "$rps[rand scalar" ascii
        $s3 = "[rand scalar @rircname]" ascii
        $s4 = "$server=\"$ARGV[0]\" if $ARGV[0]" ascii

        /* Perl script anchor */
        $perl = "#!/usr/bin/perl" ascii

    condition:
        filesize < 512KB and
        (
            /* HIGH: the full config-block assignment */
            $c2_2 or

            /* HIGH: two structural markers — C2-redirection resistant */
            2 of ($s*) or

            /* MEDIUM: Perl script carrying the C2 and one structural marker */
            ($perl and any of ($c2_*) and any of ($s*))
        )
}
