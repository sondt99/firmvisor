# firmvisor - Static Firmware Analyzer (modular version)

import os
import sys
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from modules.header import analyze_header
from modules.entropy import entropy_scan
from modules.strings import extract_strings
from modules.reporter import save_report
from modules.filetype import detect_file_type
from modules.analysis import analyze_entropy, detect_compression
from modules.sections import analyze_sections
from modules.binwalk_analysis import run_binwalk

console = Console()

def show_banner():
    banner = "[bold magenta]firmvisor[/bold magenta] - [cyan]Static Firmware Analyzer[/cyan]"
    console.print(Panel(banner, expand=False, border_style="bright_blue"))

def validate_file(fpath):
    if not os.path.isfile(fpath):
        console.print(f"[bold red]❌ File not found:[/bold red] {fpath}")
        sys.exit(1)

def print_summary(report):
    table = Table(title="[bold green]Firmware Analysis Report[/bold green]", show_lines=True)
    table.add_column("Section", style="cyan", no_wrap=True)
    table.add_column("Details", style="white")
    for k, v in report.items():
        detail = f"({len(v)} items)" if isinstance(v, (list, dict)) else str(v)
        table.add_row(str(k), detail)
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="firmvisor - Static Firmware Analyzer")
    parser.add_argument("file", help="Firmware binary path")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    parser.add_argument("--entropy", action="store_true", help="Perform entropy and compression analysis")
    parser.add_argument("--sections", action="store_true", help="Analyze sections and segments")
    parser.add_argument("--binwalk", action="store_true", help="Run binwalk analysis")
    parser.add_argument("--all", action="store_true", help="Perform all analyses")
    parser.add_argument("--output", help="Save report to file (JSON)")

    args = parser.parse_args()
    fpath = args.file
    validate_file(fpath)

    show_banner()
    console.print(f"[bold cyan]📂 Analyzing:[/bold cyan] {fpath}")

    report = analyze_header(fpath)
    report["file_type"] = detect_file_type(fpath)
    console.print("[purple]🔍 Basic file info analyzed.\n")

    if args.all or args.binwalk:
        console.print("[yellow]📦 Running binwalk...[/yellow]")
        report["binwalk"] = run_binwalk(fpath)

    if args.all or args.sections:
        console.print("[yellow]📑 Analyzing sections...[/yellow]")
        report["sections"] = analyze_sections(fpath)

    if args.all or args.strings:
        console.print("[yellow]🔤 Extracting strings...[/yellow]")
        report["strings"] = extract_strings(fpath)

    if args.all or args.entropy:
        console.print("[yellow]📈 Analyzing compression & entropy...[/yellow]")
        report["compression"] = detect_compression(fpath)
        with open(fpath, 'rb') as f:
            data = f.read()
        report["entropy"] = analyze_entropy(data)

    if args.output:
        save_report(report, args.output)
        console.print(f"[bold green]✅ Report saved to:[/bold green] {args.output}")
    else:
        print_summary(report)

if __name__ == '__main__':
    main()
