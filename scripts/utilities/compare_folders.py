# compare_folders.py
# General-purpose bidirectional folder comparison tool.
# Windows-only: st_ctime is file creation time on Windows (not inode change time).
#
# BLAKE3-hashes every file in two folder trees using multiprocessing, then
# produces four output files:
#   - index_files.csv    : all files from both folders
#   - only_in_<A>.csv    : files whose hash exists in A but not B
#   - only_in_<B>.csv    : files whose hash exists in B but not A
#   - shared.csv         : files whose hash exists in both A and B
#   - summary.txt        : counts and run metadata
#
# Comparison is by BLAKE3 content hash. Two files with identical bytes are
# "shared" regardless of path or name — this is a content-deduplication view,
# not a directory-tree diff.
#
# An optional second pass computes SHA-256 for additional verification.
#
# Output location: C:\Code_data\ops-toolkit\compare_folders\<label-a>_vs_<label-b>_<YYYYMMDD_HHMMSS>\
#
# Usage:
#   python compare_folders.py --folder-a <path> --folder-b <path> \
#       [--label-a <name>] [--label-b <name>] [--sha256] \
#       [--exclude <path>] [--workers <n>]

from __future__ import annotations

import argparse
import csv
import hashlib
import multiprocessing
import re
import sys
from datetime import datetime
from pathlib import Path

import blake3
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OUTPUT_BASE = Path(r"C:\Code_data\ops-toolkit\compare_folders")

JUNK_FRAGMENTS = (
    ".ds_store",
    ".trash",
    "~$",
    "$recycle.bin",
    "system volume information",
)

CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB
HASH_CHUNKSIZE = 20  # Pool.imap_unordered chunksize

INDEX_COLUMNS = [
    "Source",
    "Path",
    "FileName",
    "Extension",
    "SizeBytes",
    "Modified",
    "Created",
    "BLAKE3",
    "SHA256",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise(p: Path) -> str:
    """Return resolved, lower-cased string form of a path for comparisons."""
    return str(p.resolve()).lower()


def _is_junk(path_str: str) -> bool:
    """Return True if the path contains a known junk fragment (case-insensitive)."""
    lower = path_str.lower()
    return any(frag in lower for frag in JUNK_FRAGMENTS)


def _is_excluded(path_str: str, excluded_prefixes: list[str]) -> bool:
    """Return True if path_str starts with any excluded prefix."""
    return any(path_str.startswith(prefix) for prefix in excluded_prefixes)


def _walk(folder: Path, excluded_prefixes: list[str]) -> list[Path]:
    """Return all non-junk files under folder, silently skipping PermissionErrors.

    Iterates rglob one entry at a time so PermissionError on individual entries
    can be caught mid-walk. The full list is still materialised so callers can
    use len() for progress bars before hashing begins.
    Individual PermissionError entries are skipped; a PermissionError on the
    root itself returns an empty list.
    """
    results: list[Path] = []
    try:
        it = folder.rglob("*")
    except PermissionError:
        return results

    while True:
        try:
            entry = next(it)
        except StopIteration:
            break
        except PermissionError:
            continue

        try:
            if not entry.is_file():
                continue
        except PermissionError:
            continue

        norm = _normalise(entry)
        if _is_junk(norm):
            continue
        if _is_excluded(norm, excluded_prefixes):
            continue
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Hashing — top-level functions so they are picklable for multiprocessing
# ---------------------------------------------------------------------------


def _blake3_hash(file_path: Path) -> tuple[Path, str, int, str, str]:
    """
    Compute BLAKE3 hash plus stat metadata for one file.
    Returns (path, blake3_hex, size_bytes, modified_iso, created_iso).
    On any error returns an empty hash string.
    """
    hasher = blake3.blake3()
    size = 0
    try:
        stat = file_path.stat()
        size = stat.st_size
        modified = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
        created = datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds")
        with open(file_path, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                hasher.update(chunk)
        return file_path, hasher.hexdigest(), size, modified, created
    except (PermissionError, OSError):
        return file_path, "", size, "", ""


def _sha256_hash(file_path: Path) -> tuple[Path, str]:
    """Compute SHA-256 for one file. Returns (path, hex) or (path, '') on error."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                hasher.update(chunk)
        return file_path, hasher.hexdigest()
    except (PermissionError, OSError):
        return file_path, ""


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def hash_files(
    files: list[Path], workers: int, desc: str
) -> dict[Path, dict]:
    """BLAKE3-hash all files via Pool.imap_unordered; return dict keyed by path."""
    results: dict[Path, dict] = {}
    with multiprocessing.Pool(workers) as pool:
        for path, b3, size, modified, created in tqdm(
            pool.imap_unordered(_blake3_hash, files, chunksize=HASH_CHUNKSIZE),
            total=len(files),
            desc=desc,
            unit="file",
        ):
            results[path] = {
                "blake3": b3,
                "size": size,
                "modified": modified,
                "created": created,
                "sha256": "",
            }
    return results


def sha256_files(
    files: list[Path], workers: int, desc: str
) -> dict[Path, str]:
    """SHA-256-hash all files; return dict mapping path -> hex."""
    results: dict[Path, str] = {}
    with multiprocessing.Pool(workers) as pool:
        for path, digest in tqdm(
            pool.imap_unordered(_sha256_hash, files, chunksize=HASH_CHUNKSIZE),
            total=len(files),
            desc=desc,
            unit="file",
        ):
            results[path] = digest
    return results


# ---------------------------------------------------------------------------
# CSV writing
# ---------------------------------------------------------------------------


def _row(source: str, path: Path, meta: dict) -> dict:
    return {
        "Source": source,
        "Path": str(path),
        "FileName": path.name,
        "Extension": path.suffix.lower(),
        "SizeBytes": meta["size"],
        "Modified": meta["modified"],
        "Created": meta["created"],
        "BLAKE3": meta["blake3"],
        "SHA256": meta["sha256"],
    }


def write_csv(out_path: Path, rows: list[dict]) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=INDEX_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Bidirectional BLAKE3 folder comparison. Produces CSV reports of "
            "files unique to each folder and files shared between both."
        )
    )
    parser.add_argument("--folder-a", required=True, help="Path to folder A")
    parser.add_argument("--folder-b", required=True, help="Path to folder B")
    parser.add_argument(
        "--label-a",
        default="folder_a",
        help="Label for folder A, used in report filenames and the Source column (default: folder_a)",
    )
    parser.add_argument(
        "--label-b",
        default="folder_b",
        help="Label for folder B, used in report filenames and the Source column (default: folder_b)",
    )
    parser.add_argument(
        "--sha256",
        action="store_true",
        help="Compute SHA-256 for every file after the BLAKE3 pass",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATH",
        help="Exclude files whose path starts with this prefix (repeatable)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(16, multiprocessing.cpu_count()),
        help="Number of worker processes (default: min(16, cpu_count))",
    )
    args = parser.parse_args()

    folder_a = Path(args.folder_a).resolve()
    folder_b = Path(args.folder_b).resolve()

    for folder, label in ((folder_a, "--folder-a"), (folder_b, "--folder-b")):
        if not folder.is_dir():
            print(f"Error: {label} path does not exist or is not a directory: {folder}", file=sys.stderr)
            sys.exit(1)

    # Normalise excluded prefixes
    excluded_prefixes = [_normalise(Path(p)) for p in args.exclude]

    # Sanitize labels: keep alphanumerics, hyphens, underscores only so they
    # are safe to embed in directory and file names (prevents path traversal
    # via label values containing "..", ":", "\", etc.)
    def _safe_label(raw: str) -> str:
        sanitized = re.sub(r"[^\w\-]", "_", raw)
        return sanitized or "folder"

    label_a: str = _safe_label(args.label_a)
    label_b: str = _safe_label(args.label_b)
    workers: int = max(1, args.workers)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_BASE / f"{label_a}_vs_{label_b}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {run_dir}")
    print(f"Workers: {workers}")
    print()

    # Walk both folders
    print(f"Walking {label_a} ...")
    files_a = _walk(folder_a, excluded_prefixes)
    print(f"  {len(files_a):,} files found")

    print(f"Walking {label_b} ...")
    files_b = _walk(folder_b, excluded_prefixes)
    print(f"  {len(files_b):,} files found")
    print()

    # BLAKE3 pass
    meta_a = hash_files(files_a, workers, f"Hashing {label_a}")
    meta_b = hash_files(files_b, workers, f"Hashing {label_b}")

    # Optional SHA-256 pass
    if args.sha256:
        print()
        sha_a = sha256_files(files_a, workers, f"SHA-256 {label_a}")
        sha_b = sha256_files(files_b, workers, f"SHA-256 {label_b}")
        for path, digest in sha_a.items():
            meta_a[path]["sha256"] = digest
        for path, digest in sha_b.items():
            meta_b[path]["sha256"] = digest

    # Count and report hash failures (PermissionError / OSError during hashing)
    failures_a = sum(1 for meta in meta_a.values() if not meta["blake3"])
    failures_b = sum(1 for meta in meta_b.values() if not meta["blake3"])
    if failures_a or failures_b:
        print(f"Warning: {failures_a} file(s) in {label_a} and {failures_b} file(s) in {label_b} could not be hashed (permission/IO error) — excluded from comparison.")

    # Build hash sets for set operations (exclude files that failed to hash)
    hashes_a = {meta["blake3"] for meta in meta_a.values() if meta["blake3"]}
    hashes_b = {meta["blake3"] for meta in meta_b.values() if meta["blake3"]}

    only_a_hashes = hashes_a - hashes_b
    only_b_hashes = hashes_b - hashes_a
    shared_hashes = hashes_a & hashes_b

    # Build row lists
    all_rows: list[dict] = []
    only_a_rows: list[dict] = []
    only_b_rows: list[dict] = []
    shared_rows: list[dict] = []

    for path, meta in meta_a.items():
        row = _row(label_a, path, meta)
        all_rows.append(row)
        h = meta["blake3"]
        if h in only_a_hashes:
            only_a_rows.append(row)
        elif h in shared_hashes:
            shared_rows.append(row)

    for path, meta in meta_b.items():
        row = _row(label_b, path, meta)
        all_rows.append(row)
        h = meta["blake3"]
        if h in only_b_hashes:
            only_b_rows.append(row)
        elif h in shared_hashes:
            shared_rows.append(row)

    # Write CSVs
    write_csv(run_dir / "index_files.csv", all_rows)
    write_csv(run_dir / f"only_in_{label_a}.csv", only_a_rows)
    write_csv(run_dir / f"only_in_{label_b}.csv", only_b_rows)
    write_csv(run_dir / "shared.csv", shared_rows)

    # Summary
    summary_lines = [
        f"Run timestamp : {timestamp}",
        f"Folder A      : {folder_a}  (label: {label_a})",
        f"Folder B      : {folder_b}  (label: {label_b})",
        f"Workers       : {workers}",
        f"SHA-256 pass  : {'yes' if args.sha256 else 'no'}",
        "",
        f"Total files in {label_a} : {len(files_a):,}",
        f"Total files in {label_b} : {len(files_b):,}",
        f"Hash failures in {label_a} : {failures_a:,}",
        f"Hash failures in {label_b} : {failures_b:,}",
        "",
        f"Shared hashes (in both)  : {len(shared_hashes):,}  ({len(shared_rows):,} files)",
        f"Only in {label_a:<20}: {len(only_a_hashes):,}  ({len(only_a_rows):,} files)",
        f"Only in {label_b:<20}: {len(only_b_hashes):,}  ({len(only_b_rows):,} files)",
        "",
        "Output files:",
        "  index_files.csv",
        f"  only_in_{label_a}.csv",
        f"  only_in_{label_b}.csv",
        "  shared.csv",
        "  summary.txt",
    ]

    summary_path = run_dir / "summary.txt"
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")

    print()
    print("\n".join(summary_lines))
    print(f"\nDone. Reports written to: {run_dir}")


if __name__ == "__main__":
    # Required for multiprocessing on Windows
    multiprocessing.freeze_support()
    main()
