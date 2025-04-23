import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def analyze_sections(path):
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            sections = {}
            
            # Analyze sections
            for section in elf.iter_sections():
                info = {
                    'size': section['sh_size'],
                    'addr': section['sh_addr'],
                    'type': section['sh_type'],
                    'flags': section['sh_flags']
                }
                
                # Get symbols if available
                if isinstance(section, SymbolTableSection):
                    symbols = []
                    for sym in section.iter_symbols():
                        if sym.name:
                            symbols.append({
                                'name': sym.name,
                                'addr': sym['st_value'],
                                'size': sym['st_size'],
                                'type': sym['st_info']['type']
                            })
                    info['symbols'] = symbols
                
                sections[section.name] = info
                
            return sections
    except Exception as e:
        return f"Section analysis failed: {e}"