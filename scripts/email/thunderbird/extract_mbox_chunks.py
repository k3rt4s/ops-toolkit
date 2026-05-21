"""
extract_mbox_chunks.py — Stage 1 of the Thunderbird MBOX extraction pipeline.

Splits a single MBOX file into individual .eml files stored in numbered chunk
folders. Designed to handle large archives (10 GB+) without loading everything
into memory.

Usage:
    python extract_mbox_chunks.py --mbox <path> --output-dir <path> [--chunk-size 1000]

Output layout:
    <output-dir>/
        chunk_0000/msg_000001.eml
        chunk_0000/msg_000002.eml
        ...
        chunk_0001/msg_001001.eml
        ...
        logs/
            chunk_log.txt      — progress + timestamps
            chunk_errors.txt   — tracebacks for individual write failures

Default output root: C:\\Code_data\\ops-toolkit\\thunderbird-extract\\
    (pass a mailbox-specific subdirectory as --output-dir, e.g.
     C:\\Code_data\\ops-toolkit\\thunderbird-extract\\Inbox)
Never write output under C:\\Code\\.

Dependencies: stdlib only (mailbox, email, argparse, pathlib, datetime).
"""

import argparse
import mailbox
import os
import traceback
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _write(log_path: Path, text: str) -> None:
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def log_info(log_path: Path, message: str) -> None:
    _write(log_path, f"[{datetime.now()}] {message}")


def log_error(err_path: Path, message: str) -> None:
    _write(err_path, f"[{datetime.now()}] ERROR: {message}")


def print_ts(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


# ---------------------------------------------------------------------------
# Core extraction function (importable by extract_all_mboxes.py)
# ---------------------------------------------------------------------------

def extract_mbox_in_chunks(mbox_path: str, output_dir: str, chunk_size: int = 1000) -> int:
    """
    Extract all messages from *mbox_path* into .eml files under *output_dir*.

    Returns the total number of messages written.  Raises on a fatal open
    failure so the batch wrapper can catch and log it per-mailbox.
    """
    output_dir = Path(output_dir)
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    chunk_log = logs_dir / "chunk_log.txt"
    chunk_errors = logs_dir / "chunk_errors.txt"

    log_info(chunk_log, f"Opening mbox: {mbox_path}")
    print_ts(f"Loading mbox: {mbox_path}")

    mbox = mailbox.mbox(mbox_path)  # raises if path is invalid

    total = 0
    chunk_index = 0
    chunk_dir = output_dir / f"chunk_{chunk_index:04}"
    chunk_dir.mkdir(parents=True, exist_ok=True)

    log_info(chunk_log, f"Writing chunks of {chunk_size} to: {output_dir}")

    for i, message in enumerate(mbox, 1):
        # Rotate chunk folder
        if i > 1 and (i - 1) % chunk_size == 0:
            chunk_index += 1
            chunk_dir = output_dir / f"chunk_{chunk_index:04}"
            chunk_dir.mkdir(parents=True, exist_ok=True)
            log_info(chunk_log, f"New chunk folder: {chunk_dir}")
            print_ts(f"Chunk {chunk_index:04} started at message {i}")

        eml_path = chunk_dir / f"msg_{i:06}.eml"
        try:
            with open(eml_path, "wb") as fh:
                fh.write(bytes(message))
        except Exception:
            log_error(chunk_errors, f"Failed to write {eml_path}:\n{traceback.format_exc()}")

        total += 1
        if i % 100 == 0:
            print_ts(f"Progress: {i} messages extracted")

    log_info(chunk_log, f"Complete: {total} messages from {mbox_path}")
    print_ts(f"Done — {total} messages written to {output_dir}")
    return total


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Split a single MBOX file into numbered .eml chunk folders.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mbox", required=True, help="Path to the MBOX file to extract.")
    parser.add_argument(
        "--output-dir",
        required=True,
        help=(
            "Directory to write chunk folders into. "
            "Recommended: C:\\Code_data\\ops-toolkit\\thunderbird-extract\\<mailbox-name>"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1000,
        help="Number of messages per chunk folder.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.mbox):
        parser.error(f"--mbox path does not exist or is not a file: {args.mbox}")

    try:
        total = extract_mbox_in_chunks(args.mbox, args.output_dir, args.chunk_size)
        print(f"\nExtraction complete: {total} messages.")
    except Exception:
        print(f"Fatal error opening mbox:\n{traceback.format_exc()}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
