import math
from collections import Counter

def read_chunks(fpath, size=1024):
    with open(fpath, 'rb') as f:
        while True:
            chunk = f.read(size)
            if not chunk:
                break
            yield chunk

def shannon_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * math.log2(count/total) for count in freq.values())
    return entropy

def entropy_scan(path, window=1024):
    entropies = []
    for chunk in read_chunks(path, window):
        entropies.append(round(shannon_entropy(chunk), 3))
    return entropies
