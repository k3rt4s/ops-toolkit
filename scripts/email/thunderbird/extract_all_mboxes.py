"""
extract_all_mboxes.py — Stage 2 of the Thunderbird MBOX extraction pipeline.

Recursively walks a Thunderbird profile directory, finds every MBOX file, and
calls the Stage 1 chunker on each one.  Per-mailbox failures are caught and
logged without stopping the batch.

Usage:
    python extract_all_mboxes.py --source-dir <path> --output-root <path> [--chunk-size 1000]

Output layout:
    <output-root>/
        <MailboxName>/
            chunk_0000/msg_000001.eml
            ...
            logs/chunk_log.txt
            logs/chunk_errors.txt

Default output root: C:\\Code_data\\ops-toolkit\\thunderbird-extract\\
    (pass as --output-root)
Never write output under C:\\Code\\.

Dependencies: stdlib only (os, pathlib, argparse).
Calls: extract_mbox_chunks.extract_mbox_in_chunks
"""

import argparse
import os
import sys
import traceback
from pathlib import Path

# Ensure the package directory is on sys.path so the import works regardless
# of the working directory the caller uses.
sys.path.insert(0, str(Path(__file__).parent))

from extract_mbox_chunks import extract_mbox_in_chunks


# ---------------------------------------------------------------------------
# MBOX detection
# ---------------------------------------------------------------------------

_SKIP_EXTENSIONS = {".msf", ".dat"}
_SKIP_NAMES = {"msgFilterRules.dat"}


def is_valid_mbox(path: Path) -> bool:
    """Return True if *path* looks like an MBOX file rather than an index/config."""
    if not path.is_file():
        return False
    if path.suffix.lower() in _SKIP_EXTENSIONS:
        return False
    if path.name in _SKIP_NAMES:
        return False
    return True


# ---------------------------------------------------------------------------
# Batch wrapper
# ---------------------------------------------------------------------------

def process_all_mboxes(source_dir: str, output_root: str, chunk_size: int = 1000) -> None:
    """Recursively find MBOX files under *source_dir* and chunk each one."""
    source = Path(source_dir)
    root = Path(output_root)

    mbox_files = [p for p in source.rglob("*") if is_valid_mbox(p)]

    if not mbox_files:
        print(f"No MBOX files found under: {source_dir}")
        return

    print(f"Found {len(mbox_files)} MBOX file(s) under {source_dir}\n")

    ok = 0
    failed = 0

    for mbox_path in mbox_files:
        mailbox_name = mbox_path.stem
        dest_dir = root / mailbox_name
        print(f"Processing: {mbox_path.name}")
        try:
            total = extract_mbox_in_chunks(str(mbox_path), str(dest_dir), chunk_size)
            print(f"  -> {total} messages written to {dest_dir}\n")
            ok += 1
        except Exception:
            tb = traceback.format_exc()
            print(f"  -> FAILED: {tb}")
            # Write failure into the output root logs so it is easy to find
            batch_log = root / "batch_errors.txt"
            root.mkdir(parents=True, exist_ok=True)
            with open(batch_log, "a", encoding="utf-8") as fh:
                from datetime import datetime
                fh.write(f"[{datetime.now()}] {mbox_path}\n{tb}\n")
            failed += 1

    print(f"\nBatch complete: {ok} succeeded, {failed} failed.")
    if failed:
        print(f"Failure details: {root / 'batch_errors.txt'}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch-extract all MBOX files under a Thunderbird directory into .eml chunks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source-dir",
        required=True,
        help="Root Thunderbird profile directory containing MBOX files.",
    )
    parser.add_argument(
        "--output-root",
        required=True,
        help=(
            "Root directory for all chunked output. "
            "Recommended: C:\\Code_data\\ops-toolkit\\thunderbird-extract"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1000,
        help="Number of messages per chunk folder.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.source_dir):
        parser.error(f"--source-dir does not exist: {args.source_dir}")

    process_all_mboxes(args.source_dir, args.output_root, args.chunk_size)


if __name__ == "__main__":
    main()
