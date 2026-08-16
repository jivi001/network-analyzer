"""
path_helpers.py — Safe, intelligent path resolution, normalization, and typo matching for PCAP files.
"""

import os
import difflib
from pathlib import Path
from typing import List, Optional, Tuple

SUPPORTED_PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def clean_pcap_path_input(raw_input: str) -> str:
    """
    Cleans raw user input by stripping whitespace and matching quotes.
    Preserves valid Windows drive letters, backslashes, and UNC paths.
    """
    if not raw_input:
        return ""
    cleaned = raw_input.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def resolve_pcap_path(raw_input: str) -> Optional[Path]:
    """
    Normalizes and expands user path strings into a Path object.
    Supports absolute Windows paths (e.g. D:\\path\\file.pcap), relative paths, and ~ expansion.
    """
    cleaned = clean_pcap_path_input(raw_input)
    if not cleaned:
        return None
    try:
        path_obj = Path(cleaned).expanduser()
        return path_obj
    except Exception:
        return None


def get_available_pcaps_in_dir(dir_path: Path, limit: int = 10) -> List[Path]:
    """
    Lists valid PCAP files in a directory up to the specified limit.
    """
    if not dir_path.exists() or not dir_path.is_dir():
        return []

    try:
        pcap_files = []
        for entry in dir_path.iterdir():
            if entry.is_file() and entry.suffix.lower() in SUPPORTED_PCAP_EXTENSIONS:
                pcap_files.append(entry)
        pcap_files.sort(key=lambda p: p.name.lower())
        return pcap_files[:limit]
    except (PermissionError, OSError):
        return []


def find_similar_pcap(target_path: Path, cutoff: float = 0.5) -> Optional[Path]:
    """
    Intelligently searches for closely matching PCAP filenames in the target or candidate directories.
    Handles typos (e.g. tast1.pcap -> test1.pcap, testl.pcap -> test1.pcap) and case differences.
    """
    candidate_dirs = []

    # 1. Check parent directory of target path if accessible
    try:
        parent = target_path.parent
        if parent.exists() and parent.is_dir():
            candidate_dirs.append(parent)
    except Exception:
        pass

    # 2. Check current directory and exports directory
    cwd = Path.cwd()
    if cwd not in candidate_dirs and cwd.exists():
        candidate_dirs.append(cwd)
    exports_dir = cwd / "exports"
    if exports_dir not in candidate_dirs and exports_dir.exists():
        candidate_dirs.append(exports_dir)

    target_name = target_path.name.lower()
    target_stem = target_path.stem.lower()

    for directory in candidate_dirs:
        available = get_available_pcaps_in_dir(directory, limit=50)
        if not available:
            continue

        # Map lowercased names and stems back to Path
        name_map = {f.name.lower(): f for f in available}
        stem_map = {f.stem.lower(): f for f in available}

        # Exact stem match with different case or extension (e.g. test1.PCAP or test1.pcapng)
        if target_name in name_map:
            return name_map[target_name]
        if target_stem in stem_map:
            return stem_map[target_stem]

        # Fuzzy match on full filename
        matches = difflib.get_close_matches(target_name, list(name_map.keys()), n=1, cutoff=cutoff)
        if matches:
            return name_map[matches[0]]

        # Fuzzy match on stem
        stem_matches = difflib.get_close_matches(target_stem, list(stem_map.keys()), n=1, cutoff=cutoff)
        if stem_matches:
            return stem_map[stem_matches[0]]

    return None
