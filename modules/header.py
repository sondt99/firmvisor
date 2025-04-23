import os
import struct
from .compiler import detect_compiler

from elftools.elf.elffile import ELFFile

def analyze_elf_header(path):
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            header = elf.header

            segments = []
            for seg in elf.iter_segments():
                segments.append({
                    "type": str(seg.header.p_type),
                    "offset": hex(seg.header.p_offset),
                    "vaddr": hex(seg.header.p_vaddr),
                    "filesz": seg.header.p_filesz,
                    "memsz": seg.header.p_memsz,
                })

            return {
                "architecture": elf.get_machine_arch(),
                "endianness": "LSB" if elf.little_endian else "MSB",
                "entry_point": hex(header["e_entry"]),
                "segments": segments
            }
    except Exception as e:
        return {
            "architecture": "unknown",
            "endianness": "unknown",
            "entry_point": None,
            "segments": [],
            "error": str(e)
        }

def analyze_pe_header(header):
    try:
        if header[:2] != b'MZ':
            return {
                "architecture": "Not PE",
                "endianness": "unknown",
                "entry_point": None,
                "segments": []
            }

        pe_offset = struct.unpack('<I', header[0x3C:0x40])[0]
        with open(path, 'rb') as f:
            f.seek(pe_offset)
            pe_header = f.read(24)
            if pe_header[:4] != b'PE\0\0':
                return {
                    "architecture": "Invalid PE signature",
                    "endianness": "LSB",
                    "entry_point": None,
                    "segments": []
                }

            machine = struct.unpack('<H', pe_header[4:6])[0]
            arch_map = {
                0x14c: 'x86',
                0x8664: 'x86-64',
                0x1c0: 'ARM',
                0xaa64: 'AArch64'
            }

            arch = arch_map.get(machine, f"unknown ({hex(machine)})")

            # Optional Header Standard Fields
            f.seek(pe_offset + 24)
            optional_header = f.read(96)
            entry_point = struct.unpack('<I', optional_header[16:20])[0]

            return {
                "architecture": arch,
                "endianness": "LSB",
                "entry_point": hex(entry_point),
                "segments": []
            }
    except Exception as e:
        return {
            "architecture": "unknown",
            "endianness": "unknown",
            "entry_point": None,
            "segments": [],
            "error": str(e)
        }

def analyze_cgc_header(header):
    pass

def analyze_header(path):
    with open(path, 'rb') as f:
        header = f.read(0x40)  # Read more header bytes
        result = {
            "file_name": os.path.basename(path),
            "file_size": os.path.getsize(path),
            "magic_bytes": header[:4].hex(),
            "architecture": "unknown",
            "endianness": "unknown",
            "entry_point": None,
            "segments": [],
            "compiler_info": None
        }
        
        # Detect architecture and format
        if header.startswith(b'\x7fELF'):
            result.update(analyze_elf_header(header))
        elif header.startswith(b'MZ'):
            result.update(analyze_pe_header(header))
        elif header.startswith(b'\x7fCGC'):
            result.update(analyze_cgc_header(header))
            
        # Try to detect compiler
        result["compiler_info"] = detect_compiler(path)
        
        return result
