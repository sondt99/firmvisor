import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def analyze_sections(path):
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            sections = {}

            for section in elf.iter_sections():
                info = {
                    "name": section.name,
                    "type": section["sh_type"],
                    "addr": hex(section["sh_addr"]),
                    "offset": hex(section["sh_offset"]),
                    "size": section["sh_size"],
                    "flags": section["sh_flags"]
                }
                sections[section.name] = info

            return sections
    except Exception as e:
        return f"Section analysis failed: {e}"
