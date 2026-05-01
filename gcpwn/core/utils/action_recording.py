from __future__ import annotations

from typing import Any, Iterable


def record_permissions(
    action_dict: dict[str, Any] | Any,
    *,
    permissions: str | Iterable[str] | None,
    scope_key: str | None = None,
    scope_label: str | None = None,
    project_id: str | None = None,
    resource_type: str | None = None,
    resource_label: str | None = None,
) -> None:
    normalized_permissions: list[str] = []
    seen_permissions: set[str] = set()
    if isinstance(permissions, str):
        token = permissions.strip()
        if token:
            normalized_permissions = [token]
    else:
        for permission in permissions or []:
            token = str(permission or "").strip()
            if not token or token in seen_permissions:
                continue
            seen_permissions.add(token)
            normalized_permissions.append(token)
    if not normalized_permissions or action_dict is None:
        return

    if scope_key is not None or scope_label is not None:
        scope_key_token = str(scope_key or "").strip()
        scope_label_token = str(scope_label or "").strip()
        if not scope_key_token or not scope_label_token:
            return
        action_dict.setdefault(scope_key_token, {}).setdefault(scope_label_token, set()).update(normalized_permissions)
        return

    project_token = str(project_id or "").strip()
    resource_type_token = str(resource_type or "").strip()
    resource_label_token = str(resource_label or "").strip()
    if not project_token or not resource_type_token or not resource_label_token:
        return
    project_actions = action_dict.setdefault(project_token, {})
    for permission in normalized_permissions:
        project_actions.setdefault(permission, {}).setdefault(resource_type_token, set()).add(resource_label_token)


def has_recorded_actions(action_dict: dict[str, Any] | Any) -> bool:
    for value in (action_dict or {}).values():
        if isinstance(value, dict):
            if any(bool(item) for item in value.values()):
                return True
        elif value:
            return True
    return False
