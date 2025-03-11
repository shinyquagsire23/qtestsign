#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2022 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

from fw import hashseg
from fw.elf import Elf

def _read_mbn(elff: Elf):
    hashes = []
    cert_segments = []

    print(f"Entry: 0x{elff.ehdr.e_entry:8x}")
    print("")

    print("Sections:")
    print("PhdrType    Type   Offset   Vaddr    Paddr    Filesz   Memsz    Align     Perms")
    for phdr in elff.phdrs:
        
        seg_type = phdr.p_flags >> 20
        seg_perm = phdr.p_flags & 0xFF
        p_type = phdr.p_type
        
        outstr = "PT_"

        if (p_type == 0):
            outstr += "NULL     "
        elif (p_type == 1):
            outstr += "LOAD     "
        elif (p_type == 2):
            outstr += "DYNAMIC  "
        elif (p_type == 3):
            outstr += "INTERP   "
        elif (p_type == 4):
            outstr += "NOTE     "
        elif (p_type == 5):
            outstr += "SHLIB    "
        elif (p_type == 6):
            outstr += "PHDR     "
        elif (p_type == 7):
            outstr += "TLS      "
        else:
            outstr += "UNK      "

        if (seg_type == 0x70):
            outstr += "HEADER "
        elif (seg_type == 0x20):
            outstr += "CERTS7 "
            off_certs = phdr.p_offset
            vaddr_certs = phdr.p_vaddr
            cert_segments += [phdr]
        elif (seg_type == 0x22):
            outstr += "CERTS  "
            off_certs = phdr.p_offset
            vaddr_certs = phdr.p_vaddr
            cert_segments += [phdr]
        elif (seg_type == 0x10):
            outstr += "LOAD   "
        elif (seg_type == 0x00):
            outstr += "NULL   "
        else:
            outstr += "SECT   "
        outstr += '%08x %08x %08x %08x %08x %08x  ' % (phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz, phdr.p_memsz, phdr.p_align)
        
        outstr += '['
        outstr += 'R' if seg_perm & 4 else ' '
        outstr += 'W' if seg_perm & 2 else ' '
        outstr += 'X' if seg_perm & 1 else ' '
        outstr += ']'
        outstr += ' (%02x) ' % seg_type
        outstr += ' '

        print(outstr)

    print("")

    for seg in cert_segments:
        hashseg.dump(elf, seg)
    


parser = argparse.ArgumentParser(description="""
    Print out an ELF file's program headers and signing information
""")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF image to read")
args = parser.parse_args()

with args.elf:
    elf = Elf.parse(args.elf.read())

_read_mbn(elf)
