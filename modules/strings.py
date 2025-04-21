def extract_strings(path, min_len=4):
    strings_found = []
    with open(path, 'rb') as f:
        result = b""
        while byte := f.read(1):
            if 32 <= ord(byte) <= 126:
                result += byte
            else:
                if len(result) >= min_len:
                    strings_found.append(result.decode(errors='ignore'))
                result = b""
    return strings_found
