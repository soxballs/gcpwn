from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Iterable

from google.cloud import tasks_v2

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


def _http_auth_details(http_request: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(http_request, dict):
        return False, "no"
    oidc_token = http_request.get("oidc_token")
    if isinstance(oidc_token, dict) and oidc_token:
        email = str(oidc_token.get("service_account_email") or "").strip()
        audience = str(oidc_token.get("audience") or "").strip()
        detail = "yes (OIDC token)"
        if email:
            detail += f", service_account_email={email}"
        if audience:
            detail += f", audience={audience}"
        return True, detail
    oauth_token = http_request.get("oauth_token")
    if isinstance(oauth_token, dict) and oauth_token:
        email = str(oauth_token.get("service_account_email") or "").strip()
        scope = str(oauth_token.get("scope") or "").strip()
        detail = "yes (OAuth token)"
        if email:
            detail += f", service_account_email={email}"
        if scope:
            detail += f", scope={scope}"
        return True, detail
    headers = http_request.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "authorization" and str(value or "").strip():
                return True, "yes (explicit Authorization header)"
    return False, "no"


def _decode_http_body(body_value: Any) -> tuple[str, str]:
    text = str(body_value or "").strip()
    if not text:
        return "", "empty"
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:
        return text, "plain"
    try:
        return decoded.decode("utf-8"), "utf-8"
    except Exception:
        return text, "base64"


def _http_request_sample_text(task_row: dict[str, Any]) -> str:
    http_request = (task_row or {}).get("http_request")
    if not isinstance(http_request, dict):
        return ""

    task_name = str(task_row.get("name") or "").strip()
    queue_name = ""
    queue_project = extract_path_segment(task_name, "projects")
    queue_location = extract_path_segment(task_name, "locations")
    queue_id = extract_path_segment(task_name, "queues")
    if queue_project and queue_location and queue_id:
        queue_name = f"projects/{queue_project}/locations/{queue_location}/queues/{queue_id}"

    method = str(http_request.get("http_method") or "POST").strip()
    url = str(http_request.get("url") or "").strip()
    headers = http_request.get("headers") if isinstance(http_request.get("headers"), dict) else {}
    auth_required, auth_detail = _http_auth_details(http_request)
    body_text, body_format = _decode_http_body(http_request.get("body"))

    lines = [
        f"task_name: {task_name}",
        f"queue_name: {queue_name}",
        f"http_method: {method}",
        f"url: {url}",
        f"auth_required: {'yes' if auth_required else 'no'}",
        f"auth_detail: {auth_detail}",
        "",
        "headers:",
    ]
    if headers:
        for key in sorted(headers):
            lines.append(f"{key}: {headers[key]}")
    else:
        lines.append("(none)")
    lines.extend(
        [
            "",
            f"body_encoding: {body_format}",
            "body:",
            body_text if body_text else "(empty)",
        ]
    )
    return "\n".join(lines) + "\n"


def _resolve_download_path(session, *, project_id: str, filename: str, output: str | None = None) -> Path:
    if output:
        return Path(output).expanduser() / filename
    if hasattr(session, "get_download_save_path"):
        return Path(
            session.get_download_save_path(
                service_name="cloudtasks",
                filename=filename,
                project_id=project_id,
            )
        )
    fallback = Path.cwd() / "gcpwn_output" / "downloads" / "cloudtasks" / project_id / filename
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


def resolve_locations(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


class CloudTasksQueuesResource:
    TABLE_NAME = "cloudtasks_queues"
    COLUMNS = ["location", "queue_id", "name", "state"]
    SERVICE_LABEL = "Cloud Tasks"
    ACTION_RESOURCE_TYPE = "queues"
    LIST_PERMISSION = "cloudtasks.queues.list"
    GET_PERMISSION = "cloudtasks.queues.get"
    TEST_IAM_API_NAME = "cloudtasks.queues.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudtasks.queues.",
        exclude_permissions=(
            "cloudtasks.queues.create",
            "cloudtasks.queues.list",
        ),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = tasks_v2.CloudTasksClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = tasks_v2.ListQueuesRequest(parent=parent)
            rows = [resource_to_dict(queue) for queue in self.client.list_queues(request=request)]
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
                api_name="cloudtasks.queues.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = tasks_v2.GetQueueRequest(name=resource_id)
            row = resource_to_dict(self.client.get_queue(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudtasks.queues.get",
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
            project_id=extract_project_id_from_resource(
                resource_id,
                fallback_project=getattr(self.session, "project_id", None),
            ),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(
                    resource_id,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": location or extract_location_from_resource_name(name),
                },
                extra_builder=lambda _obj, raw: {
                    "queue_id": extract_path_tail(raw.get("name", "")),
                },
            )


class CloudTasksTasksResource:
    TABLE_NAME = "cloudtasks_tasks"
    COLUMNS = [
        "location",
        "queue_id",
        "task_id",
        "name",
        "dispatch_type",
        "schedule_time",
        "create_time",
        "dispatch_deadline",
        "http_method",
        "url",
        "auth_required",
    ]
    SERVICE_LABEL = "Cloud Tasks"
    ACTION_RESOURCE_TYPE = "tasks"
    LIST_PERMISSION = "cloudtasks.tasks.list"
    GET_PERMISSION = "cloudtasks.tasks.get"
    SUPPORTS_GET = True

    def __init__(self, session) -> None:
        self.session = session
        self.client = tasks_v2.CloudTasksClient(credentials=session.credentials)

    def list(
        self,
        *,
        queue_name: str,
        full_view: bool = False,
        action_dict=None,
    ) -> list[dict[str, Any]] | str | None:
        if not queue_name:
            return []
        try:
            request = tasks_v2.ListTasksRequest(
                parent=queue_name,
                response_view=tasks_v2.Task.View.FULL if full_view else tasks_v2.Task.View.BASIC,
            )
            rows = [resource_to_dict(task) for task in self.client.list_tasks(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(
                    queue_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="queues",
                resource_label=queue_name,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudtasks.tasks.list",
                resource_name=queue_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, full_view: bool = True, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = tasks_v2.GetTaskRequest(
                name=resource_id,
                response_view=tasks_v2.Task.View.FULL if full_view else tasks_v2.Task.View.BASIC,
            )
            row = resource_to_dict(self.client.get_task(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudtasks.tasks.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(name),
                },
                extra_builder=lambda _obj, raw: {
                    "queue_id": extract_path_segment(str(raw.get("name", "") or ""), "queues"),
                    "task_id": extract_path_tail(raw.get("name", "")),
                    "dispatch_type": (
                        "http"
                        if isinstance(raw.get("http_request"), dict) and raw.get("http_request")
                        else "app_engine"
                        if isinstance(raw.get("app_engine_http_request"), dict) and raw.get("app_engine_http_request")
                        else ""
                    ),
                    "http_method": (
                        ((raw.get("http_request") or {}) if isinstance(raw.get("http_request"), dict) else {}).get("http_method")
                        or ""
                    ),
                    "url": (
                        ((raw.get("http_request") or {}) if isinstance(raw.get("http_request"), dict) else {}).get("url")
                        or ""
                    ),
                    "auth_required": "yes" if _http_auth_details((raw.get("http_request") or {}))[0] else "no",
                },
            )

    def download_http_request_samples(
        self,
        *,
        task_rows: Iterable[dict[str, Any]],
        project_id: str,
        output: str | None = None,
    ) -> list[str]:
        written_paths: list[str] = []
        for row in task_rows or []:
            if not isinstance(row, dict):
                continue
            http_request = row.get("http_request")
            if not isinstance(http_request, dict) or not http_request:
                continue
            name = str(row.get("name") or "").strip()
            task_id = extract_path_segment(name, "tasks") or "task"
            queue_id = extract_path_segment(name, "queues") or "queue"
            location = extract_path_segment(name, "locations") or "location"
            filename = f"{location}_{queue_id}_{task_id}_http_request.txt"
            destination = _resolve_download_path(
                self.session,
                project_id=project_id,
                filename=filename,
                output=output,
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(_http_request_sample_text(row), encoding="utf-8")
            written_paths.append(str(destination))
        return written_paths
