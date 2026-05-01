from __future__ import annotations

from typing import Any, Callable, Iterable

from google.protobuf.json_format import MessageToDict


def resource_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "_pb"):
        return MessageToDict(value._pb, preserving_proto_field_name=True)  # type: ignore[attr-defined]
    if hasattr(value, "to_api_repr") and callable(getattr(value, "to_api_repr")):
        try:
            payload = value.to_api_repr()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            payload = value.to_dict()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    try:
        return dict(vars(value))
    except Exception:
        return {}


def field_from_row(row: Any, payload: dict[str, Any] | None = None, *field_names: str) -> str:
    if isinstance(row, str):
        return row.strip()
    source = payload if payload is not None else resource_to_dict(row)
    for field_name in field_names:
        value = source.get(field_name)
        if value not in (None, ""):
            return str(value).strip()
        attr = getattr(row, field_name, None)
        if attr not in (None, ""):
            return str(attr).strip()
    return ""


def hydrate_get_request_rows(
    rows: Iterable[Any] | None,
    fetcher: Callable[[Any, dict[str, Any]], Any | None],
) -> list[Any]:
    detailed: list[Any] = []
    for row in rows or []:
        payload = resource_to_dict(row)
        fetched = fetcher(row, payload)
        if fetched is not None and not isinstance(fetched, str):
            detailed.append(fetched)
            continue
        if isinstance(row, str):
            continue
        detailed.append(payload if payload else row)
    return detailed
