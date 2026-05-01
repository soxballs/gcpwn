from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_service_account_email,
    extract_path_tail,
    extract_path_segment,
    extract_project_id_from_resource,
    resolve_regions_from_module_data,
    resource_name_from_value,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


def _normalize_connection_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = resource_name_from_value(row, "name")
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("connection_id", extract_path_segment(name, "connections"))
    return row


def _normalize_trigger_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    resource_name = resource_name_from_value(row, "resource_name")
    if resource_name:
        row.setdefault("location", extract_location_from_resource_name(resource_name))
        row.setdefault("trigger_id", extract_path_segment(resource_name, "triggers"))
    elif row.get("id"):
        row.setdefault("trigger_id", str(row.get("id") or "").strip())
    return row


def _normalize_build_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = resource_name_from_value(row, "name")
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("build_id", extract_path_segment(name, "builds"))
    elif row.get("id"):
        row.setdefault("build_id", str(row.get("id") or "").strip())
    service_account = row.get("service_account")
    normalized_service_account = _normalize_service_account_value(service_account)
    if normalized_service_account:
        row["service_account"] = normalized_service_account
    return row


def _normalize_service_account_value(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "/serviceAccounts/" in text or text.startswith("projects/"):
        return extract_service_account_email(text) or text
    return text


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _format_key_value_section(title: str, values: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title)]
    if not values:
        lines.append("(none)")
        return lines

    for key in sorted(values):
        lines.append(f"{key}={values[key]}")
    return lines


def _build_env_summary_text(row: dict[str, Any]) -> str:
    substitutions = row.get("substitutions")
    substitutions = substitutions if isinstance(substitutions, dict) else {}
    user_substitutions = {
        str(key).strip(): value
        for key, value in substitutions.items()
        if str(key).strip().startswith("_")
    }
    built_in_substitutions = {
        str(key).strip(): value
        for key, value in substitutions.items()
        if str(key).strip() and not str(key).strip().startswith("_")
    }

    env_lines = ["Environment Variables", "=" * len("Environment Variables")]
    has_environment = False

    options = row.get("options")
    options = options if isinstance(options, dict) else {}
    global_env = _string_list(options.get("env"))
    global_secret_env = _string_list(options.get("secret_env"))
    if global_env or global_secret_env:
        has_environment = True
        env_lines.append("[Global]")
        env_lines.extend(global_env or ["env: (none)"])
        if global_secret_env:
            env_lines.append("")
            env_lines.append("secret_env:")
            env_lines.extend(global_secret_env)
        env_lines.append("")

    steps = row.get("steps")
    if isinstance(steps, list):
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            step_env = _string_list(step.get("env"))
            step_secret_env = _string_list(step.get("secret_env"))
            if not step_env and not step_secret_env:
                continue
            has_environment = True
            step_name = str(step.get("name") or "").strip() or "(unnamed)"
            env_lines.append(f"[Step {index}] {step_name}")
            env_lines.extend(step_env or ["env: (none)"])
            if step_secret_env:
                env_lines.append("")
                env_lines.append("secret_env:")
                env_lines.extend(step_secret_env)
            env_lines.append("")

    if not has_environment:
        env_lines.append("(none)")
    elif env_lines and env_lines[-1] == "":
        env_lines.pop()

    sections = [
        _format_key_value_section("User Substitutions", user_substitutions),
        [""],
        _format_key_value_section("Built-in Substitutions", built_in_substitutions),
        [""],
        env_lines,
    ]
    return "\n".join(line for section in sections for line in section)


def _build_step_arguments_text(row: dict[str, Any]) -> str:
    lines = ["Arguments By Step", "=" * len("Arguments By Step")]
    steps = row.get("steps")
    if not isinstance(steps, list) or not steps:
        lines.append("(none)")
        return "\n".join(lines)

    has_arguments = False
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        step_name = str(step.get("name") or "").strip() or "(unnamed)"
        lines.append(f"Step {index}: {step_name}")
        lines.append("-" * len(lines[-1]))
        script = str(step.get("script") or "").strip()
        entrypoint = str(step.get("entrypoint") or "").strip()
        arguments = _string_list(step.get("args"))
        command_parts = ([entrypoint] if entrypoint else []) + arguments
        if script:
            has_arguments = True
            lines.append(script)
        elif command_parts:
            has_arguments = True
            lines.append(shlex.join(command_parts))
        else:
            lines.append("(none)")
        if index != len(steps):
            lines.append("")

    if not has_arguments:
        return "\n".join(["Arguments By Step", "=" * len("Arguments By Step"), "(none)"])
    return "\n".join(lines)


class _CloudBuildBaseResource:
    SERVICE_LABEL = "Cloud Build"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud.devtools import cloudbuild_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Build enumeration requires the `google-cloud-build` package."
            ) from exc
        self._cloudbuild_v1 = cloudbuild_v1
        self.client = cloudbuild_v1.CloudBuildClient(credentials=session.credentials)

        # v2 RepositoryManagerClient is part of the same official SDK family.
        # We treat it as a hard dependency when connections are used.
        from google.cloud.devtools import cloudbuild_v2  # type: ignore

        self._cloudbuild_v2 = cloudbuild_v2
        self.repository_manager_client = cloudbuild_v2.RepositoryManagerClient(credentials=session.credentials)

    def _download_path(self, *, project_id: str, filename: str) -> Path:
        if hasattr(self.session, "get_download_save_path"):
            return Path(
                self.session.get_download_save_path(
                    service_name="cloudbuild",
                    filename=filename,
                    project_id=project_id,
                )
            )
        fallback = Path.cwd() / "gcpwn_output" / "downloads" / "cloudbuild" / project_id
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / compact_filename_component(filename)


class CloudBuildConnectionsResource(_CloudBuildBaseResource):
    TABLE_NAME = "cloudbuild_connections"
    ACTION_RESOURCE_TYPE = "connections"
    LIST_PERMISSION = "cloudbuild.connections.list"
    GET_PERMISSION = "cloudbuild.connections.get"
    TEST_IAM_API_NAME = "cloudbuild.connections.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("cloudbuild.connections.")
    COLUMNS = ["location", "connection_id", "name", "disabled"]

    def __init__(self, session) -> None:
        super().__init__(session)

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [
                _normalize_connection_row(resource_to_dict(connection))
                for connection in self.repository_manager_client.list_connections(
                    request=self._cloudbuild_v2.ListConnectionsRequest(parent=parent)
                )
            ]
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
                api_name=self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str, action_dict=None) -> dict[str, Any] | None:
        if not name:
            return None
        try:
            row = resource_to_dict(
                self.repository_manager_client.get_connection(
                    request=self._cloudbuild_v2.GetConnectionRequest(name=name)
                )
            )
            row = _normalize_connection_row(row)
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(
                        name,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(row.get("name") or name).strip(),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, name: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.repository_manager_client,
            resource_name=name,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label=self.SERVICE_LABEL,
            project_id=extract_project_id_from_resource(
                name,
                fallback_project=getattr(self.session, "project_id", ""),
            ) or None,
        )
        if permissions and action_dict is not None:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(
                    name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=str(name or "").strip(),
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": location or extract_location_from_resource_name(name),
                },
                extra_builder=lambda _obj, raw: {
                    "connection_id": str(raw.get("connection_id") or "").strip()
                    or extract_path_segment(str(raw.get("name", "")).strip(), "connections"),
                },
            )


class CloudBuildTriggersResource(_CloudBuildBaseResource):
    TABLE_NAME = "cloudbuild_triggers"
    ACTION_RESOURCE_TYPE = "triggers"
    # Cloud Build trigger methods require Cloud Build build permissions.
    # Ref: REST docs for projects.triggers.list/get call out cloudbuild.builds.list/get.
    LIST_PERMISSION = "cloudbuild.builds.list"
    GET_PERMISSION = "cloudbuild.builds.get"
    COLUMNS = ["location", "name", "disabled", "service_account"]

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._cloudbuild_v1.ListBuildTriggersRequest(project_id=project_id, parent=parent)
            rows = [_normalize_trigger_row(resource_to_dict(trigger)) for trigger in self.client.list_build_triggers(request=request)]
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
                api_name=self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, project_id: str, trigger_id: str, action_dict=None) -> dict[str, Any] | None:
        if not trigger_id:
            return None
        try:
            request = self._cloudbuild_v1.GetBuildTriggerRequest(project_id=project_id, trigger_id=trigger_id)
            row = _normalize_trigger_row(resource_to_dict(self.client.get_build_trigger(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(row.get("id") or row.get("name") or trigger_id).strip(),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=trigger_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    @staticmethod
    def _resource_id_from_row(row: Any) -> str:
        if isinstance(row, str):
            token = str(row).strip()
            if token.startswith("projects/"):
                return extract_path_segment(token, "triggers")
            if "/" in token:
                return extract_path_tail(token, default=token)
            return token
        if isinstance(row, dict):
            return (
                str(row.get("id") or row.get("trigger_id") or "").strip()
                or extract_path_segment(resource_name_from_value(row, "resource_name"), "triggers")
            )
        return str(getattr(row, "id", "") or getattr(row, "trigger_id", "") or "").strip()

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(
                        resource_name_from_value(row, "resource_name")
                    ),
                },
                extra_builder=lambda _obj, raw: {
                    "trigger_id": raw.get("trigger_id")
                    or raw.get("id")
                    or extract_path_segment(
                        resource_name_from_value(raw, "resource_name"),
                        "triggers",
                    )
                    or "",
                    "service_account": raw.get("service_account") or "",
                },
            )


class CloudBuildBuildsResource(_CloudBuildBaseResource):
    TABLE_NAME = "cloudbuild_builds"
    ACTION_RESOURCE_TYPE = "builds"
    LIST_PERMISSION = "cloudbuild.builds.list"
    GET_PERMISSION = "cloudbuild.builds.get"
    COLUMNS = ["location", "build_id", "status", "service_account", "images"]

    def list(self, *, project_id: str, location: str, page_size: int = 50, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._cloudbuild_v1.ListBuildsRequest(
                project_id=project_id,
                parent=parent,
                page_size=int(page_size or 50),
            )
            rows = [_normalize_build_row(resource_to_dict(build)) for build in self.client.list_builds(request=request)]
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
                api_name=self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, project_id: str, build_id: str, action_dict=None) -> dict[str, Any] | None:
        if not build_id:
            return None
        try:
            row = _normalize_build_row(resource_to_dict(self.client.get_build(project_id=project_id, id=build_id)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(row.get("id") or row.get("name") or build_id).strip(),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=build_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    @staticmethod
    def _resource_id_from_row(row: Any) -> str:
        if isinstance(row, str):
            token = str(row).strip()
            if token.startswith("projects/"):
                return extract_path_segment(token, "builds")
            if "/" in token:
                return extract_path_tail(token, default=token)
            return token
        if isinstance(row, dict):
            return (
                str(row.get("id") or row.get("build_id") or "").strip()
                or extract_path_segment(resource_name_from_value(row, "name"), "builds")
            )
        return str(getattr(row, "id", "") or getattr(row, "build_id", "") or "").strip()

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(resource_name_from_value(row, "name")),
                },
                extra_builder=lambda _obj, raw: {
                    "build_id": raw.get("build_id")
                    or raw.get("id")
                    or extract_path_segment(resource_name_from_value(raw, "name"), "builds")
                    or "",
                    "create_time": raw.get("create_time") or "",
                    "finish_time": raw.get("finish_time") or "",
                    "log_url": raw.get("log_url") or "",
                    "service_account": raw.get("service_account") or "",
                },
            )

    def download_build_env_summary(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        normalized_row = _normalize_build_row(dict(row or {}))
        build_id = self._resource_id_from_row(normalized_row)
        if not build_id:
            return None
        location = str(normalized_row.get("location") or "").strip() or "global"
        destination = self._download_path(
            project_id=project_id,
            filename=compact_filename_component(f"{location}_{build_id}_env_summary"),
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_build_env_summary_text(normalized_row), encoding="utf-8")
        return destination

    def download_build_step_arguments(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        normalized_row = _normalize_build_row(dict(row or {}))
        build_id = self._resource_id_from_row(normalized_row)
        if not build_id:
            return None
        location = str(normalized_row.get("location") or "").strip() or "global"
        destination = self._download_path(
            project_id=project_id,
            filename=compact_filename_component(f"{location}_{build_id}_step_arguments"),
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_build_step_arguments_text(normalized_row), encoding="utf-8")
        return destination
