from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_path_segment,
    extract_project_id_from_resource,
    resolve_regions_from_module_data,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_lines(value: Any, *, indent: int = 0) -> list[str]:
    prefix = " " * max(0, int(indent))
    if isinstance(value, dict):
        if not value:
            return [prefix + "{}"]
        lines: list[str] = []
        for key, item in value.items():
            key_text = json.dumps(str(key), ensure_ascii=False)
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key_text}:")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}{key_text}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [prefix + "[]"]
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(prefix + "-")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [prefix + _yaml_scalar(value)]


def _to_yaml_text(payload: Any) -> str:
    return "\n".join(_yaml_lines(payload)) + "\n"


def _extract_revision_env_snapshot(revision_row: dict[str, Any], *, project_id: str) -> dict[str, Any]:
    revision_name = str(revision_row.get("name") or "").strip()
    location = extract_location_from_resource_name(revision_name)
    service_id = extract_path_segment(revision_name, "services")
    revision_id = extract_path_segment(revision_name, "revisions") or extract_path_tail(revision_name, default="revision")

    container_rows = revision_row.get("containers")
    if not isinstance(container_rows, list):
        template = revision_row.get("template")
        if isinstance(template, dict):
            nested = template.get("containers")
            container_rows = nested if isinstance(nested, list) else []
        else:
            container_rows = []

    containers: list[dict[str, Any]] = []
    for idx, container in enumerate(container_rows):
        if not isinstance(container, dict):
            continue
        env_rows = container.get("env")
        if not isinstance(env_rows, list):
            env_rows = []

        env_entries: list[dict[str, Any]] = []
        for env in env_rows:
            if not isinstance(env, dict):
                continue
            entry: dict[str, Any] = {}
            env_name = str(env.get("name") or "").strip()
            if env_name:
                entry["name"] = env_name
            if "value" in env:
                entry["value"] = env.get("value")
            value_source = env.get("value_source")
            if value_source is None:
                value_source = env.get("valueSource")
            if value_source not in (None, "", {}):
                entry["value_source"] = value_source
            if entry:
                env_entries.append(entry)

        if not env_entries:
            continue
        containers.append(
            {
                "name": str(container.get("name") or "").strip() or f"container-{idx}",
                "image": str(container.get("image") or "").strip(),
                "env": env_entries,
            }
        )

    return {
        "kind": "CloudRunRevisionEnvSnapshot",
        "project_id": str(project_id or "").strip(),
        "location": location,
        "service_id": service_id,
        "revision_id": revision_id,
        "revision_name": revision_name,
        "containers": containers,
    }


class _CloudRunBaseResource:
    SERVICE_LABEL = "Cloud Run"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import run_v2  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Run enumeration requires the `google-cloud-run` package."
            ) from exc
        self._run_v2 = run_v2

    def _project_id_for(self, row_or_name: Any) -> str:
        return extract_project_id_from_resource(
            row_or_name,
            fallback_project=getattr(self.session, "project_id", ""),
        )

class CloudRunServicesResource(_CloudRunBaseResource):
    TABLE_NAME = "cloudrun_services"
    COLUMNS = ["location", "service_id", "name", "url", "ingress", "latest_ready_revision"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "run.services.list"
    GET_PERMISSION = "run.services.get"
    TEST_IAM_API_NAME = "run.services.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.services.")

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._run_v2.ServicesClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(service) for service in self.client.list_services(parent=parent)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.services.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_service(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=self._project_id_for(resource_id),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.services.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label=self.SERVICE_LABEL,
            project_id=self._project_id_for(resource_id) or None,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=self._project_id_for(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, services: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for svc in services or []:
            name = str(svc.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                svc,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {
                    "service_id": extract_path_tail(raw.get("name", "")),
                    "url": raw.get("uri") or "",
                    "ingress": raw.get("ingress") or "",
                    "latest_ready_revision": raw.get("latest_ready_revision") or "",
                },
            )


class CloudRunRevisionsResource(_CloudRunBaseResource):
    ACTION_RESOURCE_TYPE = "revisions"
    LIST_PERMISSION = "run.revisions.list"
    GET_PERMISSION = "run.revisions.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._run_v2.RevisionsClient(credentials=session.credentials)

    def list(self, *, service_name: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        if not service_name:
            return []
        try:
            rows = [resource_to_dict(revision) for revision in self.client.list_revisions(parent=service_name)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=self._project_id_for(service_name),
                resource_type="services",
                resource_label=service_name,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.services.revisions.list",
                resource_name=service_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_revision(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=self._project_id_for(resource_id),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.services.revisions.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def download_env_yaml(self, *, revision_row: dict[str, Any], project_id: str) -> Path | None:
        if not isinstance(revision_row, dict) or not revision_row:
            return None
        revision_name = str(revision_row.get("name") or "").strip()
        if not revision_name:
            return None
        snapshot = _extract_revision_env_snapshot(revision_row, project_id=project_id)
        if not list(snapshot.get("containers") or []):
            return None
        filename = compact_filename_component(
            f"{snapshot.get('location')}_{snapshot.get('service_id')}_{snapshot.get('revision_id')}_env.yaml"
        )
        destination = self.session.get_download_save_path(
            service_name="cloudrun",
            project_id=project_id,
            subdirs=["revisions"],
            filename=filename,
        )
        destination.write_text(_to_yaml_text(snapshot), encoding="utf-8")
        return destination


class CloudRunJobsResource(_CloudRunBaseResource):
    TABLE_NAME = "cloudrun_jobs"
    COLUMNS = ["location", "job_id", "name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "run.jobs.list"
    GET_PERMISSION = "run.jobs.get"
    TEST_IAM_API_NAME = "run.jobs.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.jobs.")

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._run_v2.JobsClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(job) for job in self.client.list_jobs(parent=parent)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.jobs.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_job(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=self._project_id_for(resource_id),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="run.projects.locations.jobs.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label=self.SERVICE_LABEL,
            project_id=self._project_id_for(resource_id) or None,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=self._project_id_for(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, jobs: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for job in jobs or []:
            name = str(job.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                job,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {
                    "job_id": extract_path_tail(raw.get("name", "")),
                },
            )
