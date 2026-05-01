from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    resolve_regions_from_module_data,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


def _normalize_environment_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = str(row.get("name") or "").strip()
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("environment_id", extract_path_tail(name, default=name))
    return row


def _format_section(title: str, values: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title)]
    if not values:
        lines.append("(none)")
        return lines
    for key in sorted(values):
        lines.append(f"{key}={values[key]}")
    return lines


def _software_config_text(row: dict[str, Any]) -> str:
    config = row.get("config") if isinstance(row, dict) else None
    config = config if isinstance(config, dict) else {}
    software_config = config.get("software_config") if isinstance(config, dict) else None
    software_config = software_config if isinstance(software_config, dict) else {}

    airflow_config_overrides = software_config.get("airflow_config_overrides")
    airflow_config_overrides = airflow_config_overrides if isinstance(airflow_config_overrides, dict) else {}
    env_variables = software_config.get("env_variables")
    env_variables = env_variables if isinstance(env_variables, dict) else {}

    sections = [
        _format_section("Airflow Config Overrides", airflow_config_overrides),
        [""],
        _format_section("Environment Variables", env_variables),
    ]
    return "\n".join(line for section in sections for line in section)


class ComposerEnvironmentsResource:
    TABLE_NAME = "cloudcomposer_environments"
    COLUMNS = ["location", "environment_id", "name", "state", "config_gke_cluster", "config_airflow_uri"]
    SERVICE_LABEL = "Cloud Composer"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud.orchestration.airflow import service_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Composer enumeration requires the `google-cloud-orchestration-airflow` package."
            ) from exc
        self._service_v1 = service_v1
        self.client = service_v1.EnvironmentsClient(credentials=session.credentials)

    def _download_path(self, *, project_id: str, filename: str) -> Path:
        if hasattr(self.session, "get_download_save_path"):
            return Path(
                self.session.get_download_save_path(
                    service_name="cloudcomposer",
                    filename=filename,
                    project_id=project_id,
                )
            )
        fallback = Path.cwd() / "gcpwn_output" / "downloads" / "cloudcomposer" / project_id
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / compact_filename_component(filename)

    def list(self, *, project_id: str, location: str):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._service_v1.ListEnvironmentsRequest(parent=parent)
            return [_normalize_environment_row(resource_to_dict(env)) for env in self.client.list_environments(request=request)]
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="composer.environments.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._service_v1.GetEnvironmentRequest(name=resource_id)
            return _normalize_environment_row(resource_to_dict(self.client.get_environment(request=request)))
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="composer.environments.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            normalized_row = _normalize_environment_row(dict(row or {}))
            name = str(normalized_row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                normalized_row,
                defaults={"project_id": project_id, "location": location or extract_location_from_resource_name(name)},
                extra_builder=lambda _obj, raw: {
                    "environment_id": str(raw.get("environment_id") or "").strip() or extract_path_tail(raw.get("name", "")),
                    "state": raw.get("state") or "",
                },
            )

    def download_environment_configs(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        normalized_row = _normalize_environment_row(dict(row or {}))
        environment_id = str(normalized_row.get("environment_id") or "").strip()
        if not environment_id:
            return None
        destination = self._download_path(
            project_id=project_id,
            filename=compact_filename_component(f"{environment_id}_configs.txt"),
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_software_config_text(normalized_row), encoding="utf-8")
        return destination
