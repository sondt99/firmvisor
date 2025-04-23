import re
import capstone
from collections import defaultdict

def analyze_functions(path, arch='arm'):
    try:
        with open(path, 'rb') as f:
            code = f.read()
            
        if arch == 'arm':
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch == 'x86':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            
        functions = defaultdict(list)
        current_func = None
        
        for i in md.disasm(code, 0x0):
            # Detect function boundaries
            if i.mnemonic in ['push', 'mov'] and 'lr' in i.op_str:
                current_func = i.address
            elif i.mnemonic in ['pop', 'bx'] and 'lr' in i.op_str:
                current_func = None
                
            if current_func:
                functions[current_func].append({
                    'address': i.address,
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str
                })
                
        return functions
    except Exception as e:
        return f"Function analysis failed: {e}"