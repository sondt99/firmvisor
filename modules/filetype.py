import magic

def detect_file_type(path):
    try:
        mime = magic.Magic(mime=False)
        filetype = mime.from_file(path)
        return filetype
    except Exception as e:
        return f"Detection failed: {e}"
