import re
from collections import defaultdict

def detect_compiler(path):
    compiler_signatures = {
        'gcc': [
            rb'GCC: \(GNU\) [\d\.]+',
            rb'__GNUC__',
            rb'__gnu_',
            rb'_GLOBAL_OFFSET_TABLE_'
        ],
        'clang': [
            rb'clang version',
            rb'__llvm__',
            rb'__clang__'
        ],
        'armcc': [
            rb'ARM C Compiler',
            rb'__arm__',
            rb'__ARMCC_VERSION'
        ],
        'icc': [
            rb'Intel\(R\) \w+ Compiler',
            rb'__INTEL_COMPILER'
        ],
        'msvc': [
            rb'Microsoft \(R\) Optimizing Compiler',
            rb'_MSC_VER'
        ]
    }

    try:
        with open(path, 'rb') as f:
            content = f.read()

        matches = defaultdict(list)
        for compiler, patterns in compiler_signatures.items():
            for pattern in patterns:
                found = re.findall(pattern, content)
                if found:
                    matches[compiler].extend(found)

        if not matches:
            return {
                "detected": False,
                "compiler": "unknown",
                "signatures": []
            }

        # Get the compiler with most matches
        detected_compiler = max(matches.items(), key=lambda x: len(x[1]))
        
        return {
            "detected": True,
            "compiler": detected_compiler[0],
            "signatures": [sig.decode('utf-8', errors='ignore') for sig in detected_compiler[1]]
        }

    except Exception as e:
        return {
            "detected": False,
            "compiler": f"Detection failed: {e}",
            "signatures": []
        }