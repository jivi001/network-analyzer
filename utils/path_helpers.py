"""
path_helpers.py — Safe, intelligent path resolution, normalization, and typo matching for PCAP files.
"""

import os
import difflib
from pathlib import Path
from typing import List, Optional

SUPPORTED_PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")
SUPPORTED_JSON_EXTENSIONS = (".json",)


def clean_path_input(raw_input: str) -> str:
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


# Retain clean_pcap_path_input for backward compatibility
clean_pcap_path_input = clean_path_input


def resolve_path(raw_input: str) -> Optional[Path]:
    """
    Normalizes and expands user path strings into a Path object.
    Supports absolute Windows paths (e.g. D:\\path\\file.json), relative paths, and ~ expansion.
    """
    cleaned = clean_path_input(raw_input)
    if not cleaned:
        return None
    try:
        path_obj = Path(cleaned).expanduser()
        return path_obj
    except Exception:
        return None


# Retain resolve_pcap_path for backward compatibility
resolve_pcap_path = resolve_path


def get_available_files_in_dir(
    dir_path: Path, extensions: tuple = SUPPORTED_PCAP_EXTENSIONS, limit: int = 10
) -> List[Path]:
    """
    Lists valid files matching the specified extensions in a directory up to limit.
    """
    if not dir_path.exists() or not dir_path.is_dir():
        return []

    try:
        matched_files = []
        for entry in dir_path.iterdir():
            if entry.is_file() and entry.suffix.lower() in extensions:
                matched_files.append(entry)
        matched_files.sort(key=lambda p: p.name.lower())
        return matched_files[:limit]
    except (PermissionError, OSError):
        return []


def get_available_pcaps_in_dir(dir_path: Path, limit: int = 10) -> List[Path]:
    """Lists valid PCAP files in a directory up to the specified limit."""
    return get_available_files_in_dir(dir_path, extensions=SUPPORTED_PCAP_EXTENSIONS, limit=limit)


def get_available_json_in_dir(dir_path: Path, limit: int = 10) -> List[Path]:
    """Lists valid JSON export files in a directory up to the specified limit."""
    return get_available_files_in_dir(dir_path, extensions=SUPPORTED_JSON_EXTENSIONS, limit=limit)


def find_similar_files(
    target_path: Path,
    extensions: tuple = SUPPORTED_PCAP_EXTENSIONS,
    cutoff: float = 0.45,
    max_suggestions: int = 5,
) -> List[Path]:
    """
    Intelligently searches for closely matching filenames in candidate directories.
    """
    candidate_dirs = []

    try:
        parent = target_path.parent
        if parent.exists() and parent.is_dir():
            candidate_dirs.append(parent)
    except Exception:
        pass

    cwd = Path.cwd()
    if cwd not in candidate_dirs and cwd.exists():
        candidate_dirs.append(cwd)
    exports_dir = cwd / "exports"
    if exports_dir not in candidate_dirs and exports_dir.exists():
        candidate_dirs.append(exports_dir)

    target_name = target_path.name.lower()
    target_stem = target_path.stem.lower()

    results: List[Path] = []
    seen_paths = set()

    for directory in candidate_dirs:
        available = get_available_files_in_dir(directory, extensions=extensions, limit=50)
        if not available:
            continue

        name_map = {f.name.lower(): f for f in available}
        stem_map = {f.stem.lower(): f for f in available}

        if target_name in name_map:
            p = name_map[target_name]
            if p.resolve() not in seen_paths:
                seen_paths.add(p.resolve())
                results.append(p)
        if target_stem in stem_map:
            p = stem_map[target_stem]
            if p.resolve() not in seen_paths:
                seen_paths.add(p.resolve())
                results.append(p)

        matches = difflib.get_close_matches(target_name, list(name_map.keys()), n=max_suggestions, cutoff=cutoff)
        for m in matches:
            p = name_map[m]
            if p.resolve() not in seen_paths:
                seen_paths.add(p.resolve())
                results.append(p)

        stem_matches = difflib.get_close_matches(target_stem, list(stem_map.keys()), n=max_suggestions, cutoff=cutoff)
        for sm in stem_matches:
            p = stem_map[sm]
            if p.resolve() not in seen_paths:
                seen_paths.add(p.resolve())
                results.append(p)

    return results[:max_suggestions]


def find_similar_pcaps(target_path: Path, cutoff: float = 0.45, max_suggestions: int = 5) -> List[Path]:
    """Searches for matching PCAP files."""
    return find_similar_files(target_path, extensions=SUPPORTED_PCAP_EXTENSIONS, cutoff=cutoff, max_suggestions=max_suggestions)


def find_similar_pcap(target_path: Path, cutoff: float = 0.45) -> Optional[Path]:
    """Compatibility helper returning the top closest matching PCAP or None."""
    matches = find_similar_pcaps(target_path, cutoff=cutoff, max_suggestions=1)
    return matches[0] if matches else None


def find_similar_json(target_path: Path, cutoff: float = 0.45, max_suggestions: int = 5) -> List[Path]:
    """Searches for matching JSON files."""
    return find_similar_files(target_path, extensions=SUPPORTED_JSON_EXTENSIONS, cutoff=cutoff, max_suggestions=max_suggestions)
