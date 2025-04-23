# firmvisor - Static Firmware Analyzer (enhanced version)

import os
import sys
import argparse
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from modules.header import analyze_header
from modules.entropy import entropy_scan
from modules.strings import extract_strings
from modules.reporter import save_report
from modules.filetype import detect_file_type
from modules.analysis import analyze_entropy, detect_compression
from modules.sections import analyze_sections
from modules.binwalk_analysis import run_binwalk

# ========== Logging setup ==========
logging.basicConfig(
    filename="firmvisor.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

console = Console()

def show_banner():
    banner = "[bold magenta]firmvisor[/bold magenta] - [cyan]Static Firmware Analyzer[/cyan]"
    console.print(Panel(banner, expand=False, border_style="bright_blue"))

def validate_file(fpath):
    if not os.path.isfile(fpath):
        console.print(f"[bold red]❌ File not found:[/bold red] {fpath}")
        logging.error(f"File not found: {fpath}")
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
    logging.info(f"Started analysis on {fpath}")

    report = analyze_header(fpath)
    report["file_type"] = detect_file_type(fpath)

    tasks = []
    if args.all or args.binwalk:
        tasks.append(("📦 Running binwalk", lambda: run_binwalk(fpath), "binwalk"))

    if args.all or args.sections:
        tasks.append(("📑 Analyzing sections", lambda: analyze_sections(fpath), "sections"))

    if args.all or args.strings:
        tasks.append(("🔤 Extracting strings", lambda: extract_strings(fpath), "strings"))

    if args.all or args.entropy:
        def full_entropy():
            return {
                "compression": detect_compression(fpath),
                "entropy": analyze_entropy(open(fpath, 'rb').read())
            }
        tasks.append(("📈 Analyzing compression & entropy", full_entropy, "entropy_block"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        for desc, func, key in tasks:
            task = progress.add_task(desc, start=True)
            try:
                result = func()
                if key == "entropy_block":
                    report["compression"] = result["compression"]
                    report["entropy"] = result["entropy"]
                else:
                    report[key] = result
                logging.info(f"{key} analysis complete.")
            except Exception as e:
                console.print(f"[bold red]❌ Error in {key}:[/bold red] {str(e)}")
                logging.error(f"Error analyzing {key}: {str(e)}")
            progress.update(task, completed=1)

    if args.output:
        save_report(report, args.output)
        console.print(f"[bold green]✅ Report saved to:[/bold green] {args.output}")
        logging.info(f"Report saved to {args.output}")
    else:
        default_path = "report.json"
        save_report(report, default_path)
        console.print(f"[bold yellow]⚠ No output path provided. Saved default report to {default_path}[/bold yellow]")
        logging.info(f"Default report saved to {default_path}")

if __name__ == '__main__':
    main()
