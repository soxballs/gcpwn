from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

from google.iam.v1 import iam_policy_pb2

from gcpwn.core.utils.service_runtime import handle_service_error


@lru_cache(maxsize=1)
def _all_unique_permissions() -> tuple[str, ...]:
    permissions_path = (
        Path(__file__).resolve().parents[1]
        / "modules"
        / "resourcemanager"
        / "utilities"
        / "data"
        / "all_project_permissions.txt"
    )
    if not permissions_path.exists():
        permissions_path = Path(__file__).resolve().parents[3] / "scripts" / "all_unique_permissions.txt"
    if not permissions_path.exists():
        return ()
    return tuple(
        line.strip()
        for line in permissions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )


def permissions_with_prefixes(
    *prefixes: str | Iterable[str],
    exclude_permissions: Iterable[str] | None = None,
) -> tuple[str, ...]:
    normalized_prefixes = tuple(str(prefix or "").strip() for prefix in prefixes if str(prefix or "").strip())
    if not normalized_prefixes:
        return ()

    excluded = {
        str(permission or "").strip()
        for permission in exclude_permissions or ()
        if str(permission or "").strip()
    }

    return tuple(
        permission
        for permission in _all_unique_permissions()
        if any(permission.startswith(prefix) for prefix in normalized_prefixes)
        and permission not in excluded
    )


def call_test_iam_permissions(
    *,
    client: Any,
    resource_name: str,
    permissions: Iterable[str],
    api_name: str,
    service_label: str,
    project_id: str | None = None,
    request_builder: Callable[[str, list[str]], Any] | None = None,
    caller: Callable[[Any], Any] | None = None,
    not_found_label: str | None = None,
    quiet_not_found: bool = False,
    return_not_enabled: bool = False,
) -> list[str]:
    normalized_resource_name = str(resource_name or "").strip()
    normalized_permissions = [str(permission).strip() for permission in permissions or [] if str(permission).strip()]
    if not normalized_resource_name or not normalized_permissions:
        return []

    request = (
        request_builder(normalized_resource_name, normalized_permissions)
        if callable(request_builder)
        else iam_policy_pb2.TestIamPermissionsRequest(
            resource=normalized_resource_name,
            permissions=normalized_permissions,
        )
    )

    def _invoke():
        if callable(caller):
            return caller(request)
        return client.test_iam_permissions(request=request)

    try:
        response = _invoke()
        return list(getattr(response, "permissions", []) or [])
    except Exception as exc:
        result = handle_service_error(
            exc,
            api_name=api_name,
            resource_name=normalized_resource_name,
            service_label=service_label,
            project_id=project_id,
            return_not_enabled=return_not_enabled,
            not_found_label=not_found_label,
            quiet_not_found=quiet_not_found,
        )
        return [] if result in (None, "Not Enabled") else list(result or [])
