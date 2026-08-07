#!/usr/bin/env python3
"""
strings(1) and `readelf -h` substitute for analysis hosts without binutils.

The Drosera workflow assumes a POSIX box with binutils. Windows hosts
generally have neither `strings` nor `readelf`, and ripgrep skips binary
files outright, so ELF triage stalls. This reproduces the two things
Phases 1-2 actually need, reading the raw bytes directly.

Extraction is regex-driven rather than byte-at-a-time: a multi-megabyte
static IoT binary is common in this corpus and the Python-level loop was
the dominant cost.

    python3 binstrings.py SAMPLE                  # ASCII runs, min length 6
    python3 binstrings.py SAMPLE -n 8             # longer runs only
    python3 binstrings.py SAMPLE --header         # ELF header only
    python3 binstrings.py SAMPLE --utf16          # also scan UTF-16LE
    python3 binstrings.py SAMPLE -t               # prefix each run with its offset
    python3 binstrings.py *.bin --header          # batch; filename-prefixed
    python3 binstrings.py *.bin --ioc             # IPs, domains and URLs only
"""

import argparse
import ipaddress
import re
import struct
import sys

# Printable ASCII plus tab, matching GNU strings' default notion of printable.
PRINTABLE_CLASS = rb"[\x20-\x7e\t]"

# ---------------------------------------------------------------------------
# IOC extraction
#
# These patterns are applied to already-extracted printable runs, never to raw
# bytes. Running them against raw bytes is how you manufacture false positives:
# an unanchored domain pattern happily matches inside arbitrary binary noise.
# The leading (?<![...]) guards are load-bearing — drop them and a corpus of
# IoT binaries will report .xyz and .onion "C2 domains" that do not exist.
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

DOMAIN_RE = re.compile(
    r"(?<![a-z0-9.@-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|su|io|cc|xyz|top|info|biz|me|tv|pw|club|online|site|"
    r"shop|link|dev|onion|tk|ml|ga|cf|gq|cn|br|in|ua|pl|nl|de|uk)"
    r"(?![a-z0-9-])",
    re.IGNORECASE,
)

URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>\\)]+", re.IGNORECASE)

# Domains that routinely appear in statically linked binaries as protocol or
# library strings rather than infrastructure. Reported, but flagged, so nobody
# blocklists them. openssh.com is the one that matters: OpenSSH algorithm names
# carry an @openssh.com suffix, so every binary with an embedded SSH client
# contains it and it is never C2.
KNOWN_BENIGN = {
    "openssh.com", "libssh.org", "gnu.org", "openwall.com", "example.com",
    "example.net", "example.org", "ietf.org", "zlib.net", "sourceware.org",
    "tartarus.org", "openssl.org", "musl.libc.org", "uclibc.org",
}


def is_routable_ipv4(text):
    """True for a syntactically valid, publicly routable IPv4 address.

    Version strings ("1.2.3.4") are indistinguishable from addresses by shape
    alone, so this cannot be perfect — but rejecting malformed octets and
    private/loopback/multicast space removes most of the noise.
    """
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified or addr.is_link_local)


def extract_iocs(runs):
    """Collect IOCs from (offset, text) runs. Returns dict of kind -> sorted set."""
    found = {"url": set(), "ipv4": set(), "domain": set(), "benign": set()}

    for _, text in runs:
        for match in URL_RE.finditer(text):
            found["url"].add(match.group())

        for match in IPV4_RE.finditer(text):
            candidate = match.group()
            if is_routable_ipv4(candidate):
                found["ipv4"].add(candidate)

        for match in DOMAIN_RE.finditer(text):
            domain = match.group().lower()
            bucket = "benign" if domain in KNOWN_BENIGN else "domain"
            found[bucket].add(domain)

    return {kind: sorted(values) for kind, values in found.items()}


def ascii_runs(data, minlen):
    """Yield (offset, text) for maximal printable runs of at least minlen."""
    pattern = re.compile(PRINTABLE_CLASS + rb"{%d,}" % minlen)
    for match in pattern.finditer(data):
        yield match.start(), match.group().decode("ascii")


def utf16le_runs(data, minlen):
    """Yield (offset, text) for printable UTF-16LE runs.

    Scans both parities — a wide string is not guaranteed to begin on an
    even offset inside a binary, and the naive even-only scan silently
    drops half of them.
    """
    pattern = re.compile(rb"(?:" + PRINTABLE_CLASS + rb"\x00){%d,}" % minlen)
    seen = set()
    for base in (0, 1):
        for match in pattern.finditer(data, base):
            offset = match.start()
            if offset in seen:
                continue
            seen.add(offset)
            yield offset, match.group()[::2].decode("ascii")


EI_CLASS = {1: "ELF32", 2: "ELF64"}
EI_DATA = {1: "2's complement, little endian", 2: "2's complement, big endian"}
E_TYPE = {0: "NONE", 1: "REL (Relocatable)", 2: "EXEC (Executable)",
          3: "DYN (Shared object)", 4: "CORE"}

# Only the machines that actually show up in IoT botnet multi-arch drops.
E_MACHINE = {
    2: "SPARC", 3: "Intel 80386", 4: "Motorola 68000", 8: "MIPS R3000",
    18: "SPARC32PLUS", 20: "PowerPC", 21: "PowerPC64", 22: "IBM S/390",
    40: "ARM", 42: "Renesas SH", 43: "SPARC V9", 50: "Intel IA-64",
    62: "Advanced Micro Devices X86-64", 83: "Atmel AVR",
    93: "Tensilica Xtensa", 183: "AArch64", 195: "Synopsys ARCv2",
    243: "RISC-V",
}

# Values 64-255 are processor-specific rather than OS-specific. Cross-compiled
# IoT payloads routinely carry ELFOSABI_ARM (97) — reporting that as "unknown"
# hides a normal, expected value and invites a false anomaly finding.
OSABI = {
    0: "UNIX - System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
    4: "GNU Hurd", 6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD",
    10: "Tru64", 12: "OpenBSD", 13: "OpenVMS", 64: "ARM EABI",
    97: "ARM", 255: "Standalone (embedded)",
}


def elf_header(data):
    """Parse the ELF header. Returns None if this is not an ELF file."""
    # 32 bytes, not 28: ELF64's e_entry spans offsets 24-31.
    if len(data) < 32 or data[:4] != b"\x7fELF":
        return None

    ei_class, ei_data = data[4], data[5]
    endian = "<" if ei_data == 1 else ">"
    is_64 = ei_class == 2

    osabi = data[7]
    osabi_text = OSABI.get(osabi)
    if osabi_text is None:
        kind = "processor-specific" if osabi >= 64 else "unknown"
        osabi_text = f"{kind} ({osabi})"

    version = data[6]
    fields = {
        "Class": EI_CLASS.get(ei_class, f"unknown ({ei_class})"),
        "Data": EI_DATA.get(ei_data, f"unknown ({ei_data})"),
        "Version": f"{version} (current)" if version == 1 else str(version),
        "OS/ABI": osabi_text,
    }

    # e_ident occupies 0-15; e_type at 16, e_machine at 18, e_version at 20,
    # e_entry at 24 for both ELF32 (4 bytes) and ELF64 (8 bytes).
    e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
    fields["Type"] = E_TYPE.get(e_type, f"unknown ({e_type})")
    fields["Machine"] = E_MACHINE.get(e_machine, f"unknown ({e_machine})")

    try:
        fmt = "Q" if is_64 else "I"
        fields["Entry point"] = hex(struct.unpack_from(endian + fmt, data, 24)[0])
    except struct.error:
        fields["Entry point"] = "(truncated)"

    return fields


def process(path, args, prefix):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    header = elf_header(data)

    if args.header:
        if header is None:
            # Not an error. Scanning a mixed corpus of scripts and ELF binaries
            # is the normal case, and returning non-zero here made the batch
            # usage in the docstring abort under `set -e`.
            print(f"{prefix}not an ELF file (no \\x7fELF magic)")
            return 0
        for key, value in header.items():
            print(f"{prefix}{key + ':':<14} {value}")
        return 0

    # Lead with the header when present — it frames everything that follows.
    if header is not None and not args.ioc:
        print(f"{prefix}### ELF: {header['Class']}, {header['Machine']}, "
              f"{header['Data']}, {header['Type']}, entry {header['Entry point']}")

    if args.utf16:
        # Both sources must be in hand before sorting by offset.
        runs = list(ascii_runs(data, args.min_len))
        runs.extend(utf16le_runs(data, args.min_len))
        runs.sort()
    elif args.ioc:
        runs = list(ascii_runs(data, args.min_len))
    else:
        # Stream — no need to hold every string from a multi-megabyte binary.
        runs = ascii_runs(data, args.min_len)

    if args.ioc:
        iocs = extract_iocs(runs)
        if not any(iocs.values()):
            print(f"{prefix}no IOCs found")
            return 0
        for label, kind in (("URL", "url"), ("IPv4", "ipv4"),
                            ("DOMAIN", "domain"),
                            ("DOMAIN (known-benign, do not block)", "benign")):
            for value in iocs[kind]:
                print(f"{prefix}{label:<36} {value}")
        return 0

    for offset, text in runs:
        if args.radix:
            print(f"{prefix}{offset:>8x}  {text}")
        else:
            print(f"{prefix}{text}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="strings(1) / readelf -h substitute for hosts without binutils."
    )
    parser.add_argument("file", nargs="+")
    parser.add_argument("-n", "--min-len", type=int, default=6,
                        help="minimum run length (default: 6, matching the workflow)")
    parser.add_argument("--header", action="store_true",
                        help="print the ELF header and exit")
    parser.add_argument("--utf16", action="store_true",
                        help="also scan for UTF-16LE strings")
    parser.add_argument("-t", "--radix", action="store_true",
                        help="prefix each run with its hex offset, like strings -t x")
    parser.add_argument("--ioc", action="store_true",
                        help="report only URLs, routable IPv4 addresses and domains")
    args = parser.parse_args()

    if args.min_len < 1:
        parser.error("--min-len must be at least 1")

    if args.ioc and args.header:
        parser.error("--ioc and --header are mutually exclusive")

    # Only prefix with the filename when it would otherwise be ambiguous.
    multi = len(args.file) > 1
    status = 0
    for path in args.file:
        prefix = f"{path}: " if multi else ""
        status |= process(path, args, prefix)
    return status


if __name__ == "__main__":
    sys.exit(main())
