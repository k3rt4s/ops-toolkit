r"""
Analyze-C.py

An optimized, memory-safe, and crash-resistant storage inventory scanner.
Streams C: drive metrics directly to a file to prevent memory exhaustion.
"""

import os
import argparse
import stat
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter

# Aggressive System & Environment Exclusions
EXCLUDE_DIRS = {
    "$recycle.bin", "system volume information", "windows", "programdata",
    "appdata", ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", "node_modules", ".vscode", ".idea"
}

EXCLUDE_FILES = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", ".ds_store", "thumbs.db"
}

def _fmt_size(bytes_val):
    if bytes_val < 1024: return f"{bytes_val}B"
    if bytes_val < 1048576: return f"{bytes_val / 1024:.1f}KB"
    if bytes_val < 1073741824: return f"{bytes_val / 1048576:.1f}MB"
    return f"{bytes_val / 1073741824:.1f}GB"

def _fmt_time(timestamp):
    try: return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
    except Exception: return "Unknown"


def _md(value):
    return str(value).replace("|", "\\|").replace("`", "\\`")


def _is_reparse(entry):
    try:
        attrs = entry.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return entry.is_symlink()
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def scan_drive(root_path, out_file):
    total_files = 0
    total_dirs = 0
    total_size = 0
    file_types = Counter()
    largest_files = []

    print(f"[INFO] Scanning {root_path}. Streaming data directly to file...")
    
    # Write the ledger header immediately
    out_file.write("\n## Detailed Inventory Ledger\n")
    out_file.write("| Type | Path | Size | Created | Modified | Last Accessed |\n")
    out_file.write("| --- | --- | --- | --- | --- | --- |\n")

    # Manual iterative stack instead of rglob to handle permissions & symlinks safely
    stack = [root_path]

    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    # Skip Windows Symlinks / Junction points to prevent infinite loops
                    try:
                        if _is_reparse(entry):
                            continue
                    except Exception:
                        continue

                    name_lower = entry.name.lower()
                    
                    if entry.is_dir(follow_symlinks=False):
                        if name_lower in EXCLUDE_DIRS:
                            continue
                        total_dirs += 1
                        out_file.write(f"| DIR | `{_md(entry.path)}` | - | - | - | - |\n")
                        stack.append(entry.path)
                        
                    elif entry.is_file(follow_symlinks=False):
                        if name_lower in EXCLUDE_FILES or name_lower.startswith("~$"):
                            continue
                        total_files += 1
                        
                        try:
                            file_stat = entry.stat()
                            size = file_stat.st_size
                            total_size += size
                            
                            # File extension tracking
                            ext = os.path.splitext(name_lower)[1]
                            ext = ext if ext else "no_ext"
                            file_types[ext] += 1
                            
                            # Track potential large files for the summary header
                            if len(largest_files) < 20 or size > largest_files[0][0]:
                                largest_files.append((size, entry.path))
                                largest_files.sort(key=lambda x: x[0])
                                if len(largest_files) > 20:
                                    largest_files.pop(0)

                            # Stream row immediately to disk
                            out_file.write(
                                f"| FILE | `{_md(entry.path)}` | {_fmt_size(size)} | "
                                f"{_fmt_time(file_stat.st_ctime)} | {_fmt_time(file_stat.st_mtime)} | "
                                f"{_fmt_time(file_stat.st_atime)} |\n"
                            )
                        except (PermissionError, FileNotFoundError):
                            continue
        except (PermissionError, FileNotFoundError):
            continue

    return total_files, total_dirs, total_size, file_types, reversed(largest_files)

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Stream a junction-safe drive inventory to Code_data."
    )
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="Root to inventory. The report contains sensitive full paths.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(r"C:\Code_data\ops-toolkit\windows-file-cleanup\reports"),
    )
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Analyze-C.py is Windows-only")
    target_drive = str(args.root.resolve())
    run_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Setup safe output structure
    output_dir = os.path.abspath(args.output_dir)
    code_root = os.path.normcase(os.path.abspath(r"C:\Code"))
    try:
        under_code = os.path.commonpath((os.path.normcase(output_dir), code_root)) == code_root
    except ValueError:
        under_code = False
    if under_code:
        parser.error(f"refusing generated inventory under source tree: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    
    temp_ledger_path = os.path.join(output_dir, f"temp_ledger_{run_stamp}.md")
    final_report_path = os.path.join(output_dir, f"c_drive_inventory_{run_stamp}.md")

    # Phase 1: Stream detailed ledger rows to a temp file
    with open(temp_ledger_path, "w", encoding="utf-8") as temp_file:
        t_files, t_dirs, t_size, types, heavy_files = scan_drive(target_drive, temp_file)

    # Phase 2: Compile front-matter metadata summary
    print("[INFO] Writing summary report...")
    with open(final_report_path, "w", encoding="utf-8") as final_file:
        final_file.write(f"# Drive Analytics & Storage Inventory: {target_drive}\n")
        final_file.write(f"- **Run Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        final_file.write("## Summary Metrics\n")
        final_file.write(f"- **Scanned Directories:** {t_dirs:,}\n")
        final_file.write(f"- **Scanned Files:** {t_files:,}\n")
        final_file.write(f"- **Total Non-System Footprint:** {_fmt_size(t_size)}\n\n")
        
        final_file.write("## Top 15 File Extensions By Count\n")
        final_file.write("| Extension | Count |\n| --- | --- |\n")
        for ext, count in types.most_common(15):
            final_file.write(f"| `{ext}` | {count:,} |\n")
            
        final_file.write("\n## Top 20 Largest Files (Candidates for immediate Cleanup)\n")
        final_file.write("| Size | Path |\n| --- | --- |\n")
        for size, path in heavy_files:
            final_file.write(f"| {_fmt_size(size)} | `{_md(path)}` |\n")

        # Phase 3: Stitch the ledger rows underneath the summaries
        with open(temp_ledger_path, "r", encoding="utf-8") as temp_file:
            for line in temp_file:
                final_file.write(line)

    # Clean up temporary streaming file
    os.remove(temp_ledger_path)
    notindexed = Path(r"C:\Code\scripts\set_notindexed.ps1")
    if notindexed.exists():
        subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(notindexed), "-Path", final_report_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    print(f"\n[DONE] Successfully generated: {final_report_path}")

if __name__ == "__main__":
    main()
