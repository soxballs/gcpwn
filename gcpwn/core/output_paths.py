from __future__ import annotations

import hashlib
import re
from pathlib import Path


OUTPUT_ROOT_DIR_NAME = "gcpwn_output"
OUTPUT_DIR_NAMES = {
    "downloads": "downloads",
    "exports": "exports",
    "logs": "tool_logs",
}

NAMED_SAVE_PATHS = {
    "Storage": {"bucket": "downloads", "service": "storage", "scope": "global"},
    "Secrets": {"bucket": "downloads", "service": "secretmanager", "scope": "global"},
    "Compute Base": {"bucket": "downloads", "service": "compute", "scope": "global"},
    "Compute Serial": {
        "bucket": "downloads",
        "service": "compute",
        "scope": "global",
        "subdirs": ["serial"],
    },
    "Compute Screenshots": {
        "bucket": "downloads",
        "service": "compute",
        "scope": "global",
        "subdirs": ["screenshots"],
    },
    "Functions": {"bucket": "downloads", "service": "functions", "scope": "global"},
    "Reports": {"bucket": "exports", "service": "reports", "scope": "global"},
    "Reports Snapshot": {
        "bucket": "exports",
        "service": "reports",
        "scope": "global",
        "subdirs": ["snapshots"],
    },
    "Reports Graphs": {
        "bucket": "exports",
        "service": "reports",
        "scope": "global",
        "subdirs": ["graphs"],
    },
    "System Log": {"bucket": "logs"},
}


def safe_path_component(value: str) -> str:
    text = str(value or "")
    text = text.replace("/", "_").replace("\\", "_").replace(":", "_")
    text = re.sub(r"\s+", "_", text)
    return re.sub(r"[^A-Za-z0-9_.\-]", "", text).strip("._-")


def compact_filename_component(filename: str, *, max_len: int = 128) -> str:
    safe_name = safe_path_component(filename) or "file"
    if len(safe_name) <= max_len:
        return safe_name

    stem, dot, ext = safe_name.rpartition(".")
    if not stem:
        stem, ext = safe_name, ""

    digest = hashlib.sha1(safe_name.encode("utf-8")).hexdigest()[:12]
    ext_len = (len(ext) + 1) if ext else 0
    keep = max(24, max_len - ext_len - len(digest) - 2)
    compact_stem = stem[:keep]
    compact = f"{compact_stem}__{digest}"
    return f"{compact}.{ext}" if ext else compact


def make_workspace_slug(workspace_id: int | str, workspace_name: str) -> str:
    safe_name = re.sub(r"\s+", "_", str(workspace_name or "workspace").strip().lower())
    safe_name = re.sub(r"[^a-z0-9_\-]+", "", safe_name) or "workspace"
    return f"{workspace_id}_{safe_name}"


def build_output_path(
    workspace_slug: str,
    *,
    bucket: str,
    filename: str = "",
    service_name: str | None = None,
    scope: str | None = None,
    subdirs: list[str] | None = None,
    mkdir: bool = True,
) -> Path:
    safe_slug = safe_path_component(workspace_slug) or "workspace"
    output_root = (Path.cwd() / OUTPUT_ROOT_DIR_NAME) / safe_slug
    if mkdir:
        output_root.mkdir(parents=True, exist_ok=True)
    parts = [output_root, OUTPUT_DIR_NAMES[bucket]]

    if service_name:
        parts.append(safe_path_component(service_name) or "service")
    if scope:
        parts.append(safe_path_component(scope) or "global")

    for raw_part in subdirs or []:
        cleaned = safe_path_component(raw_part)
        if cleaned:
            parts.append(cleaned)

    if filename:
        output_path = Path(*parts) / compact_filename_component(filename)
        if mkdir:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        return output_path

    output_dir = Path(*parts)
    if mkdir:
        output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def resolve_named_save_path(
    workspace_slug: str,
    *,
    filename: str = "",
    key: str,
    mkdir: bool = True,
) -> Path:
    path_config = NAMED_SAVE_PATHS[key]
    return build_output_path(
        workspace_slug,
        bucket=path_config["bucket"],
        filename=filename,
        service_name=path_config.get("service"),
        scope=path_config.get("scope"),
        subdirs=path_config.get("subdirs"),
        mkdir=mkdir,
    )
