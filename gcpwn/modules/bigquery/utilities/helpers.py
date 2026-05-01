from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from google.api_core.exceptions import Forbidden, NotFound
from google.cloud import bigquery

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service, handle_discovery_error
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    bigquery_routine_iam_resource_name,
    bigquery_table_iam_resource_name,
    normalize_bigquery_resource_id,
    split_bigquery_dataset_id,
    split_bigquery_routine_id,
    split_bigquery_table_id,
)
from gcpwn.core.utils.persistence import save_to_table, to_snake_key
from gcpwn.core.utils.serialization import resource_to_dict


def _normalize_payload_keys(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_payload_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_payload_keys(item) for item in value]
    return value


def _payload_from_resource(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return _normalize_payload_keys(dict(value))

    payload = resource_to_dict(value)
    if payload:
        return _normalize_payload_keys(payload)

    to_api_repr = getattr(value, "to_api_repr", None)
    if callable(to_api_repr):
        try:
            payload = to_api_repr()
            if isinstance(payload, dict):
                return _normalize_payload_keys(payload)
        except Exception:
            pass

    properties = getattr(value, "_properties", None)
    if isinstance(properties, dict):
        return _normalize_payload_keys(dict(properties))

    try:
        return _normalize_payload_keys(dict(vars(value)))
    except Exception:
        return {}


class _BigQueryBaseResource:
    SERVICE_LABEL = "BigQuery"

    def __init__(self, session) -> None:
        self.session = session
        self.client = bigquery.Client(project=session.project_id, credentials=session.credentials)
        self._discovery_service = None

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(self.session.credentials, "bigquery", "v2")
        return self._discovery_service

    def _call_test_iam_permissions(self, *, resource_name: str, request_builder, api_name: str) -> list[str]:
        normalized_resource_name = str(resource_name or "").strip()
        if not normalized_resource_name:
            return []
        try:
            request = request_builder(self._get_discovery_service(), normalized_resource_name)
            response = request.execute()
            return [
                str(permission).strip()
                for permission in ((response or {}).get("permissions") or [])
                if str(permission).strip()
            ]
        except Exception as exc:
            handle_discovery_error(
                self.session,
                api_name,
                normalized_resource_name,
                exc,
                service_label="BigQuery",
            )
            return []

    def _download_path(self, *, project_id: str, subdirs: list[str], filename: str) -> Path:
        if hasattr(self.session, "get_download_save_path"):
            return Path(
                self.session.get_download_save_path(
                    service_name="bigquery",
                    filename=filename,
                    project_id=project_id,
                    subdirs=subdirs,
                )
            )
        fallback = Path.cwd() / "gcpwn_output" / "downloads" / "bigquery" / project_id
        for subdir in subdirs:
            fallback = fallback / str(subdir)
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / filename


class BigQueryDatasetsResource(_BigQueryBaseResource):
    TABLE_NAME = "bigquery_datasets"
    ACTION_RESOURCE_TYPE = "datasets"
    LIST_PERMISSION = "bigquery.datasets.list"
    GET_PERMISSION = "bigquery.datasets.get"
    COLUMNS = ["full_dataset_id", "location", "friendly_name"]

    def list(self, *, project_id: str, action_dict=None) -> list[Any]:
        try:
            rows = list(self.client.list_datasets(project=project_id))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied(self.LIST_PERMISSION, project_id=project_id)
        except Exception as exc:
            UtilityTools.print_500(project_id, self.LIST_PERMISSION, exc)
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_dataset(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id = split_bigquery_dataset_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def _resource_id_from_row(self, row: Any) -> str:
        if isinstance(row, str):
            return normalize_bigquery_resource_id(row)
        if isinstance(row, dict):
            full_dataset_id = str(row.get("full_dataset_id") or "").strip()
            if full_dataset_id:
                return normalize_bigquery_resource_id(full_dataset_id)
            project_id = str(row.get("project_id") or getattr(self.session, "project_id", "") or "").strip()
            dataset_id = str(row.get("dataset_id") or "").strip()
            if project_id and dataset_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
            dataset_reference = row.get("dataset_reference") or {}
            if isinstance(dataset_reference, dict):
                project_id = str(dataset_reference.get("project_id") or "").strip()
                dataset_id = str(dataset_reference.get("dataset_id") or "").strip()
                if project_id and dataset_id:
                    return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
            return ""

        full_dataset_id = str(getattr(row, "full_dataset_id", "") or "").strip()
        if full_dataset_id:
            return normalize_bigquery_resource_id(full_dataset_id)
        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            if project_id and dataset_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
        project_id = str(getattr(row, "project", "") or getattr(self.session, "project_id", "") or "").strip()
        dataset_id = str(getattr(row, "dataset_id", "") or "").strip()
        if project_id and dataset_id:
            return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
        return normalize_bigquery_resource_id(dataset_id)

    def save(self, datasets: Iterable[Any]) -> None:
        for dataset in datasets or []:
            resource_id = self._resource_id_from_row(dataset)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                dataset,
                extras={"full_dataset_id": resource_id},
            )


class BigQueryTablesResource(_BigQueryBaseResource):
    TABLE_NAME = "bigquery_tables"
    ACTION_RESOURCE_TYPE = "tables"
    LIST_PERMISSION = "bigquery.tables.list"
    GET_PERMISSION = "bigquery.tables.get"
    DOWNLOAD_PERMISSION = "bigquery.tables.getData"
    TEST_IAM_API_NAME = "bigquery.tables.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "bigquery.tables.",
        exclude_permissions=(
            "bigquery.tables.create",
            "bigquery.tables.list",
        ),
    )
    COLUMNS = ["full_table_id", "table_type", "num_rows", "num_bytes"]

    def list(self, *, dataset_id: str, action_dict=None) -> list[Any]:
        try:
            project_id, resolved_dataset_id = split_bigquery_dataset_id(
                dataset_id, fallback_project=getattr(self.session, "project_id", "")
            )
            # Avoid passing "project:dataset" as dataset_id (client will treat it as the datasetId and error).
            dataset_ref = bigquery.DatasetReference(project_id, resolved_dataset_id)
            rows = list(self.client.list_tables(dataset_ref))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied(self.LIST_PERMISSION, resource_name=dataset_id)
        except NotFound:
            UtilityTools.print_404_resource(dataset_id)
        except Exception as exc:
            UtilityTools.print_500(dataset_id, self.LIST_PERMISSION, exc)
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_table(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id, _table_id = split_bigquery_table_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        iam_resource = bigquery_table_iam_resource_name(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )
        if not iam_resource:
            return []
        permissions = self._call_test_iam_permissions(
            resource_name=iam_resource,
            api_name=self.TEST_IAM_API_NAME,
            request_builder=lambda service, resource_name: service.tables().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.TEST_IAM_PERMISSIONS)},
            ),
        )
        if permissions:
            project_id, _dataset_id, _table_id = split_bigquery_table_id(
                resource_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=self._resource_id_from_row(resource_id),
            )
        return permissions

    def _resource_id_from_row(self, row: Any) -> str:
        if isinstance(row, str):
            return normalize_bigquery_resource_id(row)
        if isinstance(row, dict):
            full_table_id = str(row.get("full_table_id") or "").strip()
            if full_table_id:
                return normalize_bigquery_resource_id(full_table_id)
            table_reference = row.get("table_reference") or {}
            if isinstance(table_reference, dict):
                project_id = str(table_reference.get("project_id") or "").strip()
                dataset_id = str(table_reference.get("dataset_id") or "").strip()
                table_id = str(table_reference.get("table_id") or "").strip()
                if project_id and dataset_id and table_id:
                    return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}.{table_id}")
            return ""

        full_table_id = str(getattr(row, "full_table_id", "") or "").strip()
        if full_table_id:
            return normalize_bigquery_resource_id(full_table_id)
        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            table_id = str(getattr(reference, "table_id", "") or "").strip()
            if project_id and dataset_id and table_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}.{table_id}")
        project_id = str(getattr(row, "project", "") or "").strip()
        dataset_id = str(getattr(row, "dataset_id", "") or "").strip()
        table_id = str(getattr(row, "table_id", "") or "").strip()
        return normalize_bigquery_resource_id(".".join(part for part in [project_id, dataset_id, table_id] if part))

    def save(self, tables: Iterable[Any]) -> None:
        for table in tables or []:
            resource_id = self._resource_id_from_row(table)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                table,
                extras={"full_table_id": resource_id},
            )

    def download_table_data(self, *, row: Any, project_id: str, action_dict=None) -> Path | None:
        resolved_id = self._resource_id_from_row(row)
        if not resolved_id:
            return None

        table = row
        if not hasattr(table, "schema"):
            table = self.get(resource_id=resolved_id, action_dict=action_dict)
            if table is None:
                return None

        resolved_id = self._resource_id_from_row(table)
        if not resolved_id:
            return None

        resolved_project, dataset_id, table_id = split_bigquery_table_id(
            resolved_id,
            fallback_project=project_id,
        )
        destination = self._download_path(
            project_id=project_id,
            subdirs=["tables", f"{resolved_project}_{dataset_id}"],
            filename=f"{table_id}.jsonl",
        )

        try:
            with destination.open("w", encoding="utf-8", newline="\n") as handle:
                row_iter = self.client.list_rows(table)
                # Record this once per download attempt (also covers empty tables).
                record_permissions(
                    action_dict,
                    permissions=self.DOWNLOAD_PERMISSION,
                    project_id=resolved_project,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resolved_id,
                )
                for table_row in row_iter:
                    handle.write(json.dumps(dict(table_row.items()), ensure_ascii=False, default=str))
                    handle.write("\n")
            return destination
        except Forbidden:
            UtilityTools.print_403_api_denied(self.DOWNLOAD_PERMISSION, resource_name=resolved_id)
        except NotFound:
            UtilityTools.print_404_resource(resolved_id)
        except Exception as exc:
            UtilityTools.print_500(resolved_id, self.DOWNLOAD_PERMISSION, exc)
        return None


class BigQueryRoutinesResource(_BigQueryBaseResource):
    TABLE_NAME = "bigquery_routines"
    ACTION_RESOURCE_TYPE = "routines"
    LIST_PERMISSION = "bigquery.routines.list"
    GET_PERMISSION = "bigquery.routines.get"
    TEST_IAM_API_NAME = "bigquery.routines.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigquery.routines.")
    COLUMNS = ["full_routine_id", "routine_type", "language", "creation_time", "last_modified_time"]

    def list(self, *, dataset_id: str, action_dict=None) -> list[Any] | str | None:
        try:
            project_id, resolved_dataset_id = split_bigquery_dataset_id(
                dataset_id, fallback_project=getattr(self.session, "project_id", "")
            )
            dataset_ref = bigquery.DatasetReference(project_id, resolved_dataset_id)
            rows = list(self.client.list_routines(dataset_ref))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied(self.LIST_PERMISSION, resource_name=dataset_id)
        except NotFound:
            UtilityTools.print_404_resource(dataset_id)
        except Exception as exc:
            UtilityTools.print_500(dataset_id, self.LIST_PERMISSION, exc)
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_routine(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id, _routine_id = split_bigquery_routine_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        iam_resource = bigquery_routine_iam_resource_name(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )
        if not iam_resource:
            return []
        permissions = self._call_test_iam_permissions(
            resource_name=iam_resource,
            api_name=self.TEST_IAM_API_NAME,
            request_builder=lambda service, resource_name: service.routines().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.TEST_IAM_PERMISSIONS)},
            ),
        )
        if permissions:
            project_id, _dataset_id, _routine_id = split_bigquery_routine_id(
                resource_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=self._resource_id_from_row(resource_id),
            )
        return permissions

    def _resource_id_from_row(self, row: Any) -> str:
        if isinstance(row, str):
            return str(row).strip()
        if isinstance(row, dict):
            full_routine_id = str(row.get("full_routine_id") or "").strip()
            if full_routine_id:
                return full_routine_id
            reference = row.get("routine_reference") or {}
            if isinstance(reference, dict):
                project_id = str(reference.get("project_id") or "").strip()
                dataset_id = str(reference.get("dataset_id") or "").strip()
                routine_id = str(reference.get("routine_id") or "").strip()
                if project_id and dataset_id and routine_id:
                    return f"{project_id}.{dataset_id}.{routine_id}"
            project_id = str(row.get("project_id") or getattr(self.session, "project_id", "") or "").strip()
            dataset_id = str(row.get("dataset_id") or "").strip()
            routine_id = str(row.get("routine_id") or "").strip()
            if project_id and dataset_id and routine_id:
                return f"{project_id}.{dataset_id}.{routine_id}"
            return ""

        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            routine_id = str(getattr(reference, "routine_id", "") or "").strip()
            if project_id and dataset_id and routine_id:
                return f"{project_id}.{dataset_id}.{routine_id}"

        payload = _payload_from_resource(row)
        if payload:
            return self._resource_id_from_row(payload)
        return ""

    def save(self, rows: Iterable[Any]) -> None:
        for row in rows or []:
            resource_id = self._resource_id_from_row(row)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                extras={"full_routine_id": resource_id},
                extra_builder=lambda _obj, _raw, resource_id=resource_id: {
                    "project_id": split_bigquery_routine_id(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    )[0],
                    "dataset_id": split_bigquery_routine_id(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    )[1],
                    "routine_id": split_bigquery_routine_id(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    )[2],
                },
            )
