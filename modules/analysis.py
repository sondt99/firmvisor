import math
import zlib
from collections import Counter

def analyze_entropy(data, block_size=256):
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        entropy = 0
        counter = Counter(block)
        for count in counter.values():
            probability = count / len(block)
            entropy -= probability * math.log2(probability)
        results.append({
            'offset': hex(i),
            'entropy': entropy,
            'compressed': entropy > 7.0
        })
    return results

def detect_compression(path):
    with open(path, 'rb') as f:
        data = f.read()
    
    signatures = {
        b'\x1f\x8b\x08': 'GZIP',
        b'PK\x03\x04': 'ZIP',
        b'BZh': 'BZIP2',
        b'\xFD7zXZ\x00': 'XZ',
        b'LZMA': 'LZMA'
    }
    
    compression = []
    for sig, name in signatures.items():
        if sig in data:
            offset = data.find(sig)
            compression.append({
                'type': name,
                'offset': hex(offset)
            })
            
    return compression