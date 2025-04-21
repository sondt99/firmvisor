import magic
import struct
import binascii

def get_arm_arch(e_flags):
    # Phân tích ARM architecture version
    if e_flags & 0x05000000:
        return "ARMv5"
    elif e_flags & 0x06000000:
        return "ARMv6"
    elif e_flags & 0x07000000:
        return "ARMv7"
    elif e_flags & 0x08000000:
        return "ARMv8"
    return "ARM"

def detect_file_type(path):
    try:
        # Base detection using libmagic
        mime = magic.Magic(mime=False, keep_going=True)
        filetype = mime.from_file(path)
        
        with open(path, 'rb') as f:
            header = f.read(64)  # Read more header bytes
            
            # ELF Analysis
            if header.startswith(b'\x7fELF'):
                ei_class = header[4]  # 1 for 32-bit, 2 for 64-bit
                ei_data = header[5]   # 1 for little endian, 2 for big endian
                ei_version = header[6]
                ei_osabi = header[7]
                e_type = struct.unpack("<H", header[16:18])[0]
                e_machine = struct.unpack("<H", header[18:20])[0]
                e_flags = struct.unpack("<I", header[36:40])[0]
                
                bits = "32-bit" if ei_class == 1 else "64-bit"
                endian = "LSB" if ei_data == 1 else "MSB"
                
                # Machine type detection
                arch = ""
                if e_machine == 0x28:
                    arch = get_arm_arch(e_flags)
                elif e_machine == 0x3E:
                    arch = "x86-64"
                elif e_machine == 0x03:
                    arch = "x86"
                elif e_machine == 0xB7:
                    arch = "AArch64"
                
                filetype = f"ELF {bits} {endian} "
                if arch:
                    filetype += f"{arch} "
                
                # ELF Type
                if e_type == 1:
                    filetype += "relocatable"
                elif e_type == 2:
                    filetype += "executable"
                elif e_type == 3:
                    filetype += "shared object"
                elif e_type == 4:
                    filetype += "core dump"

            # PE Analysis
            elif header.startswith(b'MZ'):
                # Get PE header offset
                pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
                with open(path, 'rb') as f:
                    f.seek(pe_offset)
                    pe_header = f.read(24)
                    if pe_header.startswith(b'PE\0\0'):
                        machine = struct.unpack("<H", pe_header[4:6])[0]
                        characteristics = struct.unpack("<H", pe_header[22:24])[0]
                        
                        # Machine type
                        if machine == 0x14c:
                            arch = "x86"
                        elif machine == 0x8664:
                            arch = "x86-64"
                        elif machine == 0x1c0:
                            arch = "ARM"
                        elif machine == 0xaa64:
                            arch = "AArch64"
                        
                        filetype = f"PE {arch} "
                        if characteristics & 0x2000:
                            filetype += "DLL "
                        if characteristics & 0x0002:
                            filetype += "executable"

            # Check for common firmware formats
            elif header.startswith(b'FOTA'):
                filetype = "FOTA firmware package"
            elif header.startswith(b'OPPO'):
                filetype = "OPPO firmware package"
            elif binascii.hexlify(header[:4]).decode() == "80960220":
                filetype = "Possible ARM firmware (Magic: 80960220)"
                
        return filetype
    except Exception as e:
        return f"Detection failed: {e}"
