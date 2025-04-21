# firmvisor - Static Firmware Analyzer (modular version)

import os
import sys
import argparse
from rich import print
from rich.table import Table

from modules.header import analyze_header
from modules.entropy import entropy_scan
from modules.strings import extract_strings
from modules.reporter import save_report
from modules.filetype import detect_file_type

# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description="firmvisor - Static Firmware Analyzer")
    parser.add_argument("file", help="Firmware binary path")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    parser.add_argument("--entropy", action="store_true", help="Perform entropy analysis")
    parser.add_argument("--output", help="Save report to file (JSON)")

    args = parser.parse_args()
    fpath = args.file

    if not os.path.isfile(fpath):
        print("[red]File not found:", fpath)
        sys.exit(1)

    print(f"[bold cyan]Analyzing: {fpath}[/bold cyan]")
    report = analyze_header(fpath)
    report["file_type"] = detect_file_type(fpath)

    if args.strings:
        print("[green]Extracting strings...")
        report["strings"] = extract_strings(fpath)

    if args.entropy:
        print("[green]Calculating entropy...")
        report["entropy"] = entropy_scan(fpath)

    if args.output:
        save_report(report, args.output)
        print(f"[yellow]Report saved to {args.output}")
    else:
        table = Table(title="Firmware Analysis Report")
        for k, v in report.items():
            if isinstance(v, (list, dict)):
                v = f"({len(v)} items)"
            table.add_row(str(k), str(v))
        print(table)

if __name__ == '__main__':
    main()