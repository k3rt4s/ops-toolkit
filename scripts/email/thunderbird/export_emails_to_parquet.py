"""
export_emails_to_parquet.py — Stage 3 of the Thunderbird MBOX extraction pipeline.

Recursively scans a directory of .eml files (output of Stage 1 or Stage 2),
parses each message with multiprocessing, and streams structured data to
Parquet files.  Malformed messages are logged and skipped without halting.

Usage:
    python export_emails_to_parquet.py \\
        --source-dir <path> \\
        --output-dir <path> \\
        [--batch-size 25000] \\
        [--workers N]

Output layout:
    <output-dir>/
        emails_part_0000.parquet
        emails_part_0001.parquet
        ...
        logs/
            parse_errors.txt   — per-file tracebacks for failed messages

Default output root: C:\\Code_data\\ops-toolkit\\thunderbird-extract\\parquet\\
    (pass as --output-dir)
Never write output under C:\\Code\\.

Parquet columns per message:
    file_path, subject, from, to, cc, bcc, date, message_id,
    in_reply_to, body, has_attachments (bool), attachment_count (int)

Dependencies: pandas, pyarrow, tqdm  (see requirements.txt)
"""

import argparse
import email
import os
import traceback
from datetime import datetime
from email.policy import default as email_default
from email.utils import parsedate_to_datetime
from multiprocessing import Pool, cpu_count
from pathlib import Path

import pandas as pd
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Module-level error log path — set once by main() before spawning workers
# ---------------------------------------------------------------------------
_ERROR_LOG: Path = Path(os.devnull)


def _set_error_log(path: Path) -> None:
    global _ERROR_LOG
    _ERROR_LOG = path


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log_error(file_path: str, exc_tb: str) -> None:
    with open(_ERROR_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"[{datetime.now()}] {file_path}\n{exc_tb}\n")


# ---------------------------------------------------------------------------
# Email parsing helpers
# ---------------------------------------------------------------------------

def _safe_date(date_str: str) -> str:
    try:
        return parsedate_to_datetime(date_str).isoformat()
    except Exception:
        return date_str or ""


def _detect_attachments(msg: email.message.Message) -> tuple[bool, int]:
    count = sum(
        1 for part in msg.walk()
        if part.get_content_disposition() == "attachment"
    )
    return count > 0, count


def _extract_body(msg: email.message.Message) -> str:
    """Return plain-text body; fall back to HTML if no plain part found."""
    plain_parts = []
    html_fallback = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    plain_parts.append(part.get_content())
                except Exception:
                    pass
            elif ctype == "text/html" and not plain_parts:
                try:
                    html_fallback.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == "text/plain":
                plain_parts.append(content)
            else:
                html_fallback.append(content)
        except Exception:
            pass

    return "".join(plain_parts).strip() or "".join(html_fallback).strip()


# ---------------------------------------------------------------------------
# Worker function (runs in subprocess — must be module-level for pickling)
# ---------------------------------------------------------------------------

def _parse_eml(file_path: str) -> dict | None:
    """Parse a single .eml file.  Returns a dict or None on failure."""
    try:
        with open(file_path, "rb") as fh:
            msg = email.message_from_binary_file(fh, policy=email_default)

        body = _extract_body(msg)
        has_attachments, attachment_count = _detect_attachments(msg)

        return {
            "file_path": file_path,
            "subject": msg.get("subject", ""),
            "from": msg.get("from", ""),
            "to": msg.get("to", ""),
            "cc": msg.get("cc", ""),
            "bcc": msg.get("bcc", ""),
            "date": _safe_date(msg.get("date", "")),
            "message_id": msg.get("message-id", ""),
            "in_reply_to": msg.get("in-reply-to", ""),
            "body": body,
            "has_attachments": has_attachments,
            "attachment_count": attachment_count,
        }
    except Exception:
        _log_error(file_path, traceback.format_exc())
        return None


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _find_eml_files(source_dir: str) -> list[str]:
    paths = []
    for root, _, files in os.walk(source_dir):
        for f in files:
            if f.lower().endswith(".eml"):
                paths.append(os.path.join(root, f))
    return paths


# ---------------------------------------------------------------------------
# Main export logic
# ---------------------------------------------------------------------------

def export_to_parquet(
    source_dir: str,
    output_dir: str,
    batch_size: int = 25000,
    workers: int | None = None,
) -> None:
    output_path = Path(output_dir)
    logs_dir = output_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    error_log = logs_dir / "parse_errors.txt"
    _set_error_log(error_log)

    eml_files = _find_eml_files(source_dir)
    if not eml_files:
        print(f"No .eml files found under: {source_dir}")
        return

    print(f"Found {len(eml_files):,} .eml files — parsing with {workers} workers...")

    n_workers = workers if workers else min(16, cpu_count())
    batch: list[dict] = []
    part_index = 0
    processed = 0

    with Pool(processes=n_workers, initializer=_set_error_log, initargs=(error_log,)) as pool:
        it = pool.imap_unordered(_parse_eml, eml_files, chunksize=20)
        for result in tqdm(it, total=len(eml_files), desc="Parsing .eml files", unit="msg"):
            if result is not None:
                batch.append(result)
                processed += 1

            if len(batch) >= batch_size:
                _flush_batch(batch, output_path, part_index)
                part_index += 1
                batch = []

    if batch:
        _flush_batch(batch, output_path, part_index)
        part_index += 1

    print(f"\nDone. {processed:,} messages written across {part_index} Parquet file(s).")
    skipped = len(eml_files) - processed
    if skipped:
        print(f"{skipped} message(s) skipped — see {error_log}")


def _flush_batch(batch: list[dict], output_path: Path, part_index: int) -> None:
    out_file = output_path / f"emails_part_{part_index:04}.parquet"
    pd.DataFrame(batch).to_parquet(out_file, index=False)
    print(f"\n  Saved {len(batch):,} messages -> {out_file}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse .eml files to structured Parquet (Stage 3 of the Thunderbird pipeline).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source-dir",
        required=True,
        help="Directory tree containing .eml files (output of Stage 1 or Stage 2).",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help=(
            "Directory for Parquet output files and logs. "
            "Recommended: C:\\Code_data\\ops-toolkit\\thunderbird-extract\\parquet"
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=25000,
        help="Number of messages per Parquet file.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel worker processes (default: min(16, cpu_count())).",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.source_dir):
        parser.error(f"--source-dir does not exist: {args.source_dir}")

    export_to_parquet(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        batch_size=args.batch_size,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
