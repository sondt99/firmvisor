
# 🛠️ firmvisor

**firmvisor** is a Python-based static analysis tool for inspecting IoT firmware images.  
It supports both **filesystem-based** and **RTOS-based** (e.g., FreeRTOS, Zephyr) firmware, offering modular analysis features such as:

- 📦 Binary filetype and header parsing  
- 🧠 Interrupt vector table analysis  
- 🔐 Entropy scanning for encryption/compression  
- 🧵 String extraction (ASCII, Unicode)  
- 🧬 Compiler and architecture inference  
- 🧰 Integration with Binwalk for embedded filesystem extraction

---

## 🚀 Features

| Feature                    | Description                                                   |
|---------------------------|---------------------------------------------------------------|
| Filetype Detection         | Detect ELF, PE, raw bin, squashfs, compressed archives        |
| Header Analysis            | Parse ELF/PE headers: entry point, sections, arch, endianness |
| Interrupt Vector Analysis  | Extract and identify vector tables in bare-metal firmware     |
| String Extraction          | Dump ASCII and Unicode strings with filtering options         |
| Entropy Scan               | Compute entropy over sliding window to detect packed sections |
| Compiler Info              | Infer toolchain used from headers, sections, metadata         |
| Binwalk Integration        | Leverage Binwalk to unpack firmware filesystems               |
| JSON Output                | Export analysis results to structured JSON report             |

---

## 📦 Installation

### 🔹 1. Clone the repository
```bash
git clone https://github.com/yourusername/firmvisor.git
cd firmvisor
```

### 🔹 2. Create a virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 🔹 3. Install required packages
```bash
pip install -r requirements.txt
```

### 🔹 4. (Optional) Install `binwalk` for filesystem extraction
```bash
sudo apt install binwalk
```

### 🔹 5. Install libmagic for `python-magic`
```bash
# On Debian/Ubuntu:
sudo apt install libmagic1
```

---

## 🧪 Usage

### 🔹 Help:
```bash
python3 firmvisor.py -h
```

### 🔹 Basic usage:
```bash
python3 firmvisor.py firmware/firmware.bin
```

### 🔹 Run specific modules:
```bash
python3 firmvisor.py firmware/firmware.bin --strings --entropy --arch --filetype
```

### 🔹 Full analysis with JSON export:
```bash
python3 firmvisor.py firmware/firmware.bin --all
```

---

## 🧩 Output Example

```json
{
  "filetype": "ELF 32-bit LSB executable, ARM",
  "entry_point": "0x8000",
  "architecture": "ARM 32-bit",
  "endianness": "Little Endian",
  "entropy": [
    {"offset": 0, "value": 7.91},
    {"offset": 1024, "value": 3.20}
  ],
  "strings": [
    "/etc/init.d/rcS",
    "admin:1234",
    "Firmware v1.2"
  ]
  ...
}
```

---

## 📁 Project Structure

```
firmvisor/
├── firmvisor.py
├── requirements.txt
├── modules/
│   ├── __init__.py
│   ├── analysis.py
|   ├── binwalk_analysis.py
│   ├── compiler.py
│   ├── entropy.py
│   ├── filetype.py
│   ├── header.py
│   ├── reporter.py
│   ├── sections.py
│   └── strings.py
├── report.json
```

---

## 🌱 Contributing

Contributions are welcome! Feel free to:
- Submit issues or bugs
- Request new features
- Open pull requests

For large contributions, please open an issue first to discuss.

---

## 📄 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.

---