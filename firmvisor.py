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
from modules.analysis import analyze_entropy, detect_compression
from modules.sections import analyze_sections
from modules.functions import analyze_functions
from modules.binwalk_analysis import run_binwalk

# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description="firmvisor - Static Firmware Analyzer")
    parser.add_argument("file", help="Firmware binary path")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    parser.add_argument("--entropy", action="store_true", help="Perform entropy analysis")
    parser.add_argument("--sections", action="store_true", help="Analyze sections and segments")
    parser.add_argument("--functions", action="store_true", help="Analyze functions")
    parser.add_argument("--binwalk", action="store_true", help="Run binwalk analysis")
    parser.add_argument("--all", action="store_true", help="Perform all analyses")
    parser.add_argument("--output", help="Save report to file (JSON)")

    args = parser.parse_args()
    fpath = args.file

    if not os.path.isfile(fpath):
        print("[red]File not found:", fpath)
        sys.exit(1)

    print(f"[bold cyan]Analyzing: {fpath}[/bold cyan]")
    report = analyze_header(fpath)
    report["file_type"] = detect_file_type(fpath)
    
    if args.all or args.sections:
        print("[green]Analyzing sections...")
        report["sections"] = analyze_sections(fpath)
        
    if args.all or args.functions:
        print("[green]Analyzing functions...")
        report["functions"] = analyze_functions(fpath)
        
    if args.all or args.strings:
        print("[green]Extracting strings...")
        report["strings"] = extract_strings(fpath)
        
    if args.all or args.entropy:
        print("[green]Analyzing entropy...")
        with open(fpath, 'rb') as f:
            data = f.read()
        report["entropy"] = analyze_entropy(data)
        report["compression"] = detect_compression(fpath)
    
    if args.all:
        print("[green]Running binwalk...")
        report["binwalk"] = run_binwalk(fpath)

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
