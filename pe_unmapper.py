import sys, os, re
import pefile

# Check if the PE file has a valid import table
def pe_has_valid_import_table(pe: pefile.PE):
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return False

    # A valid import name must contain printable characters
    # Empty name is also acceptable (may have been erased)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name is not None:
                funcname = imp.name
                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                if not funcname.rstrip("\x00").isprintable():
                    return False
    return True

# Check if the PE file has a valid relocation table
def pe_has_valid_relocation_table(pe: pefile.PE):
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return False

    relocs = 0
    for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        relocs += len(base_reloc.entries)
    return relocs != 0

# Check if the gap between the end of headers and the first section is typical for Virtual Alignment
def pe_has_virtual_section_alignment(pe: pefile.PE, file_buf: bytes):
    v_align = pe.OPTIONAL_HEADER.SectionAlignment
    if pe.OPTIONAL_HEADER.SizeOfHeaders >= v_align:
        return False

    for section in pe.sections:
        if section.PointerToRawData >= v_align:
            continue
        diff = v_align - section.PointerToRawData

        # check for sizes
        alignment_buf = file_buf[
            section.PointerToRawData : section.PointerToRawData + diff
        ]
        return alignment_buf.count(b"\x00") == diff

# Check if the PE is memory mapped
def is_pe_mapped(pe: pefile.PE, file_buf: bytes):
    return (
        (not pe_has_valid_import_table(pe))
        or (not pe_has_valid_relocation_table(pe))
        or (pe_has_virtual_section_alignment(pe, file_buf))
    )

# Copy sections to their memory mapped addresses
def sections_virtual_to_raw(pe: pefile.PE, file_buf: bytearray):
    file_size = len(file_buf)
    raw_end = pe.OPTIONAL_HEADER.SizeOfHeaders

    for section in pe.sections:
        sec_vaddr = section.VirtualAddress
        sec_raddr = section.PointerToRawData
        sec_rsize = section.SizeOfRawData

        new_end = sec_raddr + sec_rsize
        if new_end > raw_end:
            raw_end = new_end

        if (sec_vaddr > file_size) or (sec_raddr + sec_rsize > file_size):
            break

        if sec_vaddr + sec_rsize > file_size:
            sec_rsize = file_size - sec_vaddr

        file_buf[sec_raddr : sec_raddr + sec_rsize] = file_buf[
            sec_vaddr : sec_vaddr + sec_rsize
        ]

    if raw_end > file_size:
        raw_end = file_size
    return file_buf[:raw_end]

# Unmap PE file
def pe_virtual_to_raw(pe: pefile.PE, new_base: int, file_buf: bytearray):
    out = sections_virtual_to_raw(pe, file_buf)
    unmapped_pe = pefile.PE(data=out)

    unmapped_pe.OPTIONAL_HEADER.ImageBase = new_base
    for section in unmapped_pe.sections:
        section.Misc_VirtualSize = section.SizeOfRawData

    return unmapped_pe

# Check if the memdump comes from triage
def is_triage_memdump(filename):
    pattern = re.compile("0x[A-F0-9]{16}-0x[A-F0-9]{16}-memory.dmp$")
    if pattern.search(filename):
        return True
    return False

def main():
    # Check commandline args
    if len(sys.argv) < 2:
        print("Usage: pe_unmapper.py <pe_file>")
        exit()

    # Read memdump file
    file_path = sys.argv[1]
    file_size = os.path.getsize(file_path)
    file_buf = bytearray(file_size)
    open(file_path, "rb").readinto(file_buf)

    # Check if the file is a valid PE
    try:
        pe = pefile.PE(file_path)
    except:
        print("[-] Memdump is not a PE file")
        exit()

    # Determine new image base for the unmapped memdump
    new_base = pe.OPTIONAL_HEADER.ImageBase
    if is_triage_memdump(file_path):
        new_base = int(file_path.split("-")[-3], 16)

    if is_pe_mapped(pe, file_buf):
        print(f"[+] Unmapping {file_path}...")
        unmapped_pe = pe_virtual_to_raw(pe, new_base, file_buf)

        # Build unmapped file name
        split_name = file_path.rsplit(".", 1)
        if len(split_name) == 1:
            unmapped_filename = "{0}_unmapped".format(*split_name)
        else:
            unmapped_filename = "{0}_unmapped.{1}".format(*split_name)

        print(f"[+] Unmapped file: {unmapped_filename}")
        unmapped_pe.write(unmapped_filename)
    else:
        print(f"[!] No need for unmapping!")

if __name__ == "__main__":
    main()
