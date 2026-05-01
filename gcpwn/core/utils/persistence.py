from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Callable, Iterable

from gcpwn.core.utils.module_helpers import load_mapping_data
from gcpwn.core.utils.serialization import resource_to_dict


_CAMEL_SPLIT_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_SPLIT_2 = re.compile(r"([a-z0-9])([A-Z])")
_EMPTY_VALUES = (None, "", [], {})
_COMMON_ALIASES = {
    "created": ("creation_time", "creationtime"),
    "modified": ("last_modified_time", "lastmodifiedtime"),
    "expires": ("expiration_time", "expirationtime"),
    "retention_policy_locked": ("retention_policy_is_locked",),
    "schema_json": ("schema",),
    "access_entries": ("access",),
    "partitioning_type": ("time_partitioning_type",),
}
_DATABASE_SPECS = (load_mapping_data("database_info.json", kind="json") or {}).get("databases", [])


def to_snake_key(name: str) -> str:
    token = str(name or "").strip()
    if not token:
        return ""
    token = token.replace("-", "_")
    token = _CAMEL_SPLIT_1.sub(r"\1_\2", token)
    token = _CAMEL_SPLIT_2.sub(r"\1_\2", token)
    return token.lower()


def _normalize_keys(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


def _has_value(value: Any) -> bool:
    return value not in _EMPTY_VALUES


def _encode_value(value: Any) -> Any:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if isinstance(value, (dict, list, tuple))
        else value
    )


def _expand_reference_ids(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload or {})
    for key in ("dataset_reference", "table_reference"):
        ref = payload.get(key)
        if not isinstance(ref, dict):
            continue
        for ref_key in ("project_id", "dataset_id", "table_id"):
            if ref_key in ref and not _has_value(payload.get(ref_key)) and _has_value(ref.get(ref_key)):
                payload[ref_key] = ref.get(ref_key)
    return payload


def _apply_common_aliases(payload: dict[str, Any], *, columns: set[str]) -> dict[str, Any]:
    payload = dict(payload or {})
    for target_key, aliases in _COMMON_ALIASES.items():
        if target_key not in columns or _has_value(payload.get(target_key)):
            continue
        for alias in aliases:
            value = payload.get(alias)
            if _has_value(value):
                payload[target_key] = value
                break
    return payload


def _flatten_top_level_scalars(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload or {})
    for key, value in list(payload.items()):
        if not isinstance(value, dict):
            continue
        for child_key, child_value in value.items():
            if isinstance(child_value, dict):
                continue
            payload[f"{key}_{child_key}"] = child_value
    return payload


@lru_cache(maxsize=256)
def _table_spec(table_name: str) -> tuple[list[str], list[str]]:
    wanted = str(table_name or "").strip()
    if not wanted:
        return ([], [])
    for database_info in _DATABASE_SPECS:
        for table in database_info.get("tables", []):
            if str(table.get("table_name")) == wanted:
                return (list(table.get("columns", [])), list(table.get("primary_keys", [])))
    return ([], [])


def save_to_table(
    session,
    table_name: str,
    response: Any,
    *,
    defaults: dict[str, Any] | None = None,
    extras: dict[str, Any] | None = None,
    extra_builder: Callable[[Any, dict[str, Any]], dict[str, Any]] | None = None,
    only_if_new_columns: list[str] | None = None,
    dont_change: list[str] | None = None,
    if_column_matches: list[str] | None = None,
) -> None:
    """
    Universal persistence helper.

    Goal: keep per-module code tiny by passing API responses directly.

    Typical usage:
      - Save a single API object/dict:
        `save_to_table(session, "pubsub_topics", topic, defaults={"project_id": project_id})`
      - Save an iterator/list of API objects:
        `save_to_table(session, "pubsub_topics", topics_iterable, extra_builder=...)`

    `save_to_table()`:
      - normalizes keys (`camelCase`/`kebab-case` → `snake_case`)
      - filters to columns defined in `mappings/database_info.json`
      - auto-fills `raw_json` when the table has it
      - skips rows missing required primary keys
    """

    if response is None:
        return

    columns, required_keys = _table_spec(table_name)
    if not columns:
        return

    if isinstance(response, (dict, str, bytes)) or any(
        hasattr(response, attr) for attr in ("_pb", "to_api_repr", "to_dict")
    ):
        objects: Iterable[Any] = [response]
    else:
        try:
            iter(response)  # type: ignore[arg-type]
            objects = response
        except TypeError:
            objects = [response]

    column_set = set(columns)
    base_defaults = dict(defaults or {})
    base_extras = dict(extras or {})

    for obj in objects or []:
        raw = _apply_common_aliases(
            _flatten_top_level_scalars(_expand_reference_ids(_normalize_keys(resource_to_dict(obj)))),
            columns=column_set,
        )
        save_data = {
            key: _encode_value(raw[key])
            for key in columns
            if _has_value(raw.get(key))
        }

        for key, value in base_defaults.items():
            if _has_value(value) and key not in save_data:
                save_data[key] = _encode_value(value)
        for key, value in base_extras.items():
            if _has_value(value):
                save_data[key] = _encode_value(value)
        if callable(extra_builder):
            for key, value in (extra_builder(obj, raw) or {}).items():
                if _has_value(value):
                    save_data[key] = _encode_value(value)

        if "raw_json" in column_set and "raw_json" not in save_data:
            save_data["raw_json"] = _encode_value(raw) if raw else ""

        if any(not _has_value(save_data.get(key)) for key in required_keys):
            continue

        session.insert_data(
            table_name,
            save_data,
            only_if_new_columns=only_if_new_columns,
            dont_change=dont_change,
            if_column_matches=if_column_matches,
        )
