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
"""

import argparse
import re
import struct
import sys

# Printable ASCII plus tab, matching GNU strings' default notion of printable.
PRINTABLE_CLASS = rb"[\x20-\x7e\t]"


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
    if len(data) < 28 or data[:4] != b"\x7fELF":
        return None

    ei_class, ei_data = data[4], data[5]
    endian = "<" if ei_data == 1 else ">"
    is_64 = ei_class == 2

    osabi = data[7]
    osabi_text = OSABI.get(osabi)
    if osabi_text is None:
        kind = "processor-specific" if osabi >= 64 else "unknown"
        osabi_text = f"{kind} ({osabi})"

    fields = {
        "Class": EI_CLASS.get(ei_class, f"unknown ({ei_class})"),
        "Data": EI_DATA.get(ei_data, f"unknown ({ei_data})"),
        "Version": data[6],
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
            print(f"{prefix}not an ELF file (no \\x7fELF magic)")
            return 1
        for key, value in header.items():
            print(f"{prefix}{key + ':':<14} {value}")
        return 0

    # Lead with the header when present — it frames everything that follows.
    if header is not None:
        print(f"{prefix}### ELF: {header['Class']}, {header['Machine']}, "
              f"{header['Data']}, {header['Type']}, entry {header['Entry point']}")

    runs = list(ascii_runs(data, args.min_len))
    if args.utf16:
        runs.extend(utf16le_runs(data, args.min_len))
        runs.sort()

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
    args = parser.parse_args()

    if args.min_len < 1:
        parser.error("--min-len must be at least 1")

    # Only prefix with the filename when it would otherwise be ambiguous.
    multi = len(args.file) > 1
    status = 0
    for path in args.file:
        prefix = f"{path}: " if multi else ""
        status |= process(path, args, prefix)
    return status


if __name__ == "__main__":
    sys.exit(main())
