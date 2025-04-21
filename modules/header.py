import os

def analyze_header(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        return {
            "file_name": os.path.basename(path),
            "file_size": os.path.getsize(path),
            "magic_bytes": magic.hex()
        }
