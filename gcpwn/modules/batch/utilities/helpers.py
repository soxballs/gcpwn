from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_path_tail, extract_project_id_from_resource, resolve_regions_args
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error
resolve_locations = resolve_regions_args


class BatchJobsResource:
    TABLE_NAME = "batch_jobs"
    COLUMNS = ["location", "job_id", "name", "uid", "create_time", "status_state"]
    SERVICE_LABEL = "Batch"
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "batch.jobs.list"
    GET_PERMISSION = "batch.jobs.get"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import batch_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Batch enumeration requires the `google-cloud-batch` package with `batch_v1` support."
            ) from exc
        self._batch = batch_v1
        self.client = batch_v1.BatchServiceClient(credentials=session.credentials)

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
                api_name="batch.projects.locations.jobs.list",
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
                project_id = extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", ""))
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="batch.projects.locations.jobs.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, jobs: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for job in jobs or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                job,
                defaults={"project_id": project_id, "location": location},
                extra_builder=lambda _obj, raw: {
                    "job_id": extract_path_tail(raw.get("name", "")),
                    "status_state": (((raw.get("status") or {}) if isinstance(raw.get("status"), dict) else {}).get("state") if isinstance(raw.get("status"), dict) else "") or raw.get("status_state") or "",
                },
            )
