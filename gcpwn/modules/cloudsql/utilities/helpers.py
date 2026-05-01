from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service, handle_discovery_error
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_csv_file_args


def _instance_settings(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    settings = (raw.get("settings") or {}) if isinstance(raw.get("settings"), dict) else {}
    ip_cfg = (settings.get("ip_configuration") or {}) if isinstance(settings.get("ip_configuration"), dict) else {}
    return settings, ip_cfg


def _instance_extra_columns(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    settings, ip_cfg = _instance_settings(raw)
    return {
        "name": raw.get("name") or raw.get("instance"),
        "connection_name": raw.get("connection_name"),
        "ip_addresses": raw.get("ip_addresses"),
        "settings_tier": settings.get("tier", ""),
        "settings_activation_policy": settings.get("activation_policy", ""),
        "settings_ip_configuration_ipv4_enabled": ip_cfg.get("ipv4_enabled", ""),
        "settings_ip_configuration_require_ssl": ip_cfg.get("require_ssl", ""),
        "settings_ip_configuration_authorized_networks": ip_cfg.get("authorized_networks", ""),
    }


class _CloudSqlBaseResource:
    SERVICE_LABEL = "Cloud SQL Admin"

    def __init__(self, session) -> None:
        self.session = session
        self.service = build_discovery_service(session.credentials, "sqladmin", "v1beta4")


class CloudSqlInstancesResource(_CloudSqlBaseResource):
    TABLE_NAME = "cloudsql_instances"
    COLUMNS = [
        "name",
        "database_version",
        "region",
        "state",
    ]
    LIST_PERMISSION = "cloudsql.instances.list"
    GET_PERMISSION = "cloudsql.instances.get"
    ACTION_RESOURCE_TYPE = "instances"

    def manual_targets(self, *, instance_names: str | None = None, instance_file: str | None = None) -> list[str]:
        return parse_csv_file_args(instance_names, instance_file)

    def resolve_cached_targets(self, *, project_id: str) -> list[str]:
        rows = get_cached_rows(self.session, self.TABLE_NAME, project_id=project_id, columns=["name"])
        return [str(row.get("name") or "").strip() for row in rows or [] if str(row.get("name") or "").strip()]

    def list(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            response = self.service.instances().list(project=project_id).execute()
            items = response.get("items", []) if isinstance(response, dict) else []
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return [item for item in items if isinstance(item, dict)]
        except Exception as exc:
            return handle_discovery_error(self.session, "sqladmin.instances.list", project_id, exc, service_label=self.SERVICE_LABEL)

    def get(self, *, project_id: str, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        try:
            response = self.service.instances().get(project=project_id, instance=resource_id).execute()
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return response if isinstance(response, dict) else None
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                "sqladmin.instances.get",
                resource_id,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return result if isinstance(result, dict) else None

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_instance_extra_columns,
            )

    def enumerate(
        self,
        *,
        project_id: str,
        instance_names: list[str],
        include_get: bool = False,
        scope_actions=None,
        api_actions=None,
    ) -> dict[str, Any]:
        manual_requested = bool(instance_names)
        if manual_requested:
            if include_get:
                rows = [
                    row
                    for row in (
                        self.get(project_id=project_id, resource_id=name, action_dict=api_actions)
                        for name in instance_names
                    )
                    if row
                ]
                if rows:
                    self.save(rows, project_id=project_id)
            else:
                rows = []
        else:
            listed = self.list(project_id=project_id, action_dict=scope_actions)
            rows = listed if isinstance(listed, list) else []
            if rows:
                self.save(rows, project_id=project_id)

        target_names = [str(row.get("name") or "").strip() for row in rows if isinstance(row, dict) and str(row.get("name") or "").strip()]
        if manual_requested and not include_get:
            target_names = list(instance_names)

        return {
            "rows": rows,
            "manual_requested": manual_requested,
            "target_names": target_names,
        }


class CloudSqlDatabasesResource(_CloudSqlBaseResource):
    TABLE_NAME = "cloudsql_databases"
    COLUMNS = ["instance", "name", "charset", "collation"]
    LIST_PERMISSION = "cloudsql.databases.list"
    ACTION_RESOURCE_TYPE = "instances"

    def list(self, *, project_id: str, instance: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            response = self.service.databases().list(project=project_id, instance=instance).execute()
            items = response.get("items", []) if isinstance(response, dict) else []
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=instance,
            )
            return [item for item in items if isinstance(item, dict)]
        except Exception as exc:
            return handle_discovery_error(self.session, "sqladmin.databases.list", instance, exc, service_label=self.SERVICE_LABEL)

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, instance: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id, "instance": instance})

    def enumerate(self, *, project_id: str, instance_names: list[str], action_dict=None) -> list[dict[str, Any]]:
        all_rows: list[dict[str, Any]] = []
        for instance_name in instance_names:
            rows = self.list(project_id=project_id, instance=instance_name, action_dict=action_dict)
            if isinstance(rows, list) and rows:
                self.save(rows, project_id=project_id, instance=instance_name)
                all_rows.extend(rows)
        return all_rows


class CloudSqlUsersResource(_CloudSqlBaseResource):
    TABLE_NAME = "cloudsql_users"
    COLUMNS = ["instance", "name", "host", "type"]
    LIST_PERMISSION = "cloudsql.users.list"
    ACTION_RESOURCE_TYPE = "instances"

    def list(self, *, project_id: str, instance: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            response = self.service.users().list(project=project_id, instance=instance).execute()
            items = response.get("items", []) if isinstance(response, dict) else []
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=instance,
            )
            return [item for item in items if isinstance(item, dict)]
        except Exception as exc:
            return handle_discovery_error(self.session, "sqladmin.users.list", instance, exc, service_label=self.SERVICE_LABEL)

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, instance: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id, "instance": instance})

    def enumerate(self, *, project_id: str, instance_names: list[str], action_dict=None) -> list[dict[str, Any]]:
        all_rows: list[dict[str, Any]] = []
        for instance_name in instance_names:
            rows = self.list(project_id=project_id, instance=instance_name, action_dict=action_dict)
            if isinstance(rows, list) and rows:
                self.save(rows, project_id=project_id, instance=instance_name)
                all_rows.extend(rows)
        return all_rows


def _format_ip_addresses(ip_addresses: Any) -> str:
    entries = ip_addresses if isinstance(ip_addresses, list) else []
    formatted: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("ip_address") or "").strip()
        if not address:
            continue
        address_type = str(entry.get("type") or "").strip()
        formatted.append(f"{address_type}: {address}" if address_type else address)
    return "; ".join(formatted)


class CloudSqlConnectionsResource:
    TABLE_NAME = "cloudsql_instances"
    COLUMNS = [
        "name",
        "region",
        "connection_name",
        "ip_addresses_output",
    ]

    def __init__(self, session) -> None:
        self.session = session

    def list(self, *, project_id: str, instance_names: list[str] | None = None) -> list[dict[str, Any]]:
        rows = get_cached_rows(
            self.session,
            self.TABLE_NAME,
            project_id=project_id,
            columns=[
                "name",
                "region",
                "connection_name",
                "ip_addresses",
            ],
        ) or []
        rows = [
            {
                **row,
                "ip_addresses_output": _format_ip_addresses(row.get("ip_addresses")),
            }
            for row in rows
        ]
        if instance_names:
            allowed = set(instance_names)
            rows = [row for row in rows if str(row.get("name") or "").strip() in allowed]
        return rows


class CloudSqlConfigsResource:
    TABLE_NAME = "cloudsql_instances"
    COLUMNS = [
        "name",
        "database_version",
        "region",
        "state",
        "ip_addresses_output",
    ]

    def __init__(self, session) -> None:
        self.session = session

    def list(self, *, project_id: str, instance_names: list[str] | None = None) -> list[dict[str, Any]]:
        rows = get_cached_rows(
            self.session,
            self.TABLE_NAME,
            project_id=project_id,
            columns=[
                "name",
                "database_version",
                "region",
                "state",
                "ip_addresses",
                "connection_name",
                "settings_tier",
                "settings_activation_policy",
                "settings_ip_configuration_ipv4_enabled",
                "settings_ip_configuration_require_ssl",
                "settings_ip_configuration_authorized_networks",
            ],
        ) or []
        rows = [
            {
                **row,
                "ip_addresses_output": _format_ip_addresses(row.get("ip_addresses")),
            }
            for row in rows
        ]
        if not instance_names:
            return rows
        allowed = set(instance_names)
        return [row for row in rows if str(row.get("name") or "").strip() in allowed]
