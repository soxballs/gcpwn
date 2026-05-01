from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import (
    build_discovery_service,
    handle_discovery_error,
    paged_list,
)
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.persistence import save_to_table, to_snake_key
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_csv_file_args
from gcpwn.core.utils.service_runtime import handle_service_error


class FirestoreDatabasesResource:
    TABLE_NAME = "firestore_databases"
    COLUMNS = ["database_id", "name", "location_id", "type", "concurrency_mode", "delete_protection_state"]
    LIST_PERMISSION = "datastore.databases.getMetadata"
    GET_PERMISSION = "datastore.databases.getMetadata"
    ACTION_RESOURCE_TYPE = "databases"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import firestore_admin_v1  # type: ignore
            from google.cloud import firestore_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Firestore enumeration requires the `google-cloud-firestore` package."
            ) from exc
        # Keep data-plane client available for future document-level expansion.
        self.firestore_client_cls = firestore_v1.Client
        self.admin_client = firestore_admin_v1.FirestoreAdminClient(credentials=session.credentials)

    def manual_targets(self, *, database_ids: str | None = None, database_file: str | None = None) -> list[str]:
        return [_normalize_database_id(value) for value in parse_csv_file_args(database_ids, database_file) if _normalize_database_id(value)]

    def resolve_cached_targets(self, *, project_id: str) -> list[str]:
        rows = get_cached_rows(self.session, self.TABLE_NAME, project_id=project_id, columns=["database_id", "name"]) or []
        targets: list[str] = []
        seen: set[str] = set()
        for row in rows:
            candidate = _normalize_database_id(row.get("database_id") or row.get("name"))
            if candidate and candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)
        return targets

    def list(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}"
        try:
            response = self.admin_client.list_databases(parent=parent)
            databases = getattr(response, "databases", response)
            rows = [resource_to_dict(db) for db in (databases or [])]
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
                api_name="firestore.projects.databases.list",
                resource_name=parent,
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, project_id: str, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        normalized_name = _database_name(project_id, resource_id)
        try:
            row = resource_to_dict(self.admin_client.get_database(name=normalized_name))
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_name,
            )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="firestore.projects.databases.get",
                resource_name=normalized_name,
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, databases: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for db in databases or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                db,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "database_id": extract_path_tail(raw.get("name", "")),
                },
            )


def _normalize_keys(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


class FirestoreRulesResource:
    TABLE_NAME = "firestore_rules"
    COLUMNS = ["database_id", "release_name", "ruleset_name", "attachment_point", "services", "create_time"]
    LIST_RELEASES_PERMISSION = "firebaserules.releases.list"
    LIST_RULESETS_PERMISSION = "firebaserules.rulesets.list"
    GET_RULESET_PERMISSION = "firebaserules.rulesets.get"
    ACTION_RESOURCE_TYPE = "databases"
    SERVICE_LABEL = "Firebase Rules"

    def __init__(self, session) -> None:
        self.session = session
        self.service = build_discovery_service(session.credentials, "firebaserules", "v1")

    def list_releases(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}"
        try:
            rows = paged_list(
                lambda page_token: self.service.projects().releases().list(
                    name=parent,
                    pageToken=page_token,
                    pageSize=100,
                ),
                items_key="releases",
            )
            rows = [_normalize_keys(row) for row in rows or [] if isinstance(row, dict)]
            record_permissions(
                action_dict,
                permissions=self.LIST_RELEASES_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_discovery_error(
                self.session,
                "firebaserules.releases.list",
                parent,
                exc,
                service_label=self.SERVICE_LABEL,
            )

    def list_rulesets(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}"
        try:
            rows = paged_list(
                lambda page_token: self.service.projects().rulesets().list(
                    name=parent,
                    pageToken=page_token,
                    pageSize=100,
                ),
                items_key="rulesets",
            )
            rows = [_normalize_keys(row) for row in rows or [] if isinstance(row, dict)]
            record_permissions(
                action_dict,
                permissions=self.LIST_RULESETS_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_discovery_error(
                self.session,
                "firebaserules.rulesets.list",
                parent,
                exc,
                service_label=self.SERVICE_LABEL,
            )

    def get_ruleset(self, *, project_id: str, ruleset_name: str, action_dict=None) -> dict[str, Any] | None:
        if not ruleset_name:
            return None
        try:
            row = self.service.projects().rulesets().get(name=ruleset_name).execute()
            return _normalize_keys(row) if isinstance(row, dict) else None
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                "firebaserules.rulesets.get",
                ruleset_name,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return result if isinstance(result, dict) else None

    def enumerate(
        self,
        *,
        project_id: str,
        include_get: bool = False,
        database_ids: list[str] | None = None,
        scope_actions=None,
        api_actions=None,
    ) -> list[dict[str, Any]]:
        releases = self.list_releases(project_id=project_id, action_dict=scope_actions)
        if releases in ("Not Enabled", None):
            return []

        rulesets = self.list_rulesets(project_id=project_id, action_dict=scope_actions)
        if rulesets in ("Not Enabled", None):
            return []

        ruleset_lookup = {
            str(row.get("name") or "").strip(): dict(row)
            for row in rulesets or []
            if isinstance(row, dict) and str(row.get("name") or "").strip()
        }
        allowed_databases = {_normalize_database_id(value) for value in (database_ids or []) if _normalize_database_id(value)}
        detailed_cache: dict[str, dict[str, Any]] = {}
        output: list[dict[str, Any]] = []

        for release in releases or []:
            if not isinstance(release, dict):
                continue
            release_name = str(release.get("name") or "").strip()
            ruleset_name = str(release.get("ruleset_name") or "").strip()
            ruleset = dict(ruleset_lookup.get(ruleset_name, {}))
            if include_get and ruleset_name:
                if ruleset_name not in detailed_cache:
                    detailed_cache[ruleset_name] = self.get_ruleset(
                        project_id=project_id,
                        ruleset_name=ruleset_name,
                    ) or {}
                if detailed_cache[ruleset_name]:
                    ruleset = detailed_cache[ruleset_name]

            if not _is_firestore_rules_release(release, ruleset):
                continue

            database_id = _database_id_from_rules_payload(release, ruleset)
            if include_get and ruleset_name and ruleset:
                record_permissions(
                    api_actions,
                    permissions=self.GET_RULESET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=database_id or ruleset_name,
                )
            if allowed_databases and database_id not in allowed_databases:
                continue

            services = _rules_services(ruleset)
            output.append(
                {
                    "database_id": database_id,
                    "release_name": release_name,
                    "ruleset_name": ruleset_name,
                    "attachment_point": _rules_attachment_point(ruleset),
                    "services": services,
                    "create_time": str(ruleset.get("create_time") or "").strip(),
                    "source_files": _rules_source_files(ruleset) if include_get else [],
                }
            )
        return output

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class FirestoreCollectionsResource:
    TABLE_NAME = "firestore_collections"
    COLUMNS = ["database_id", "collection_id", "collection_path"]
    LIST_PERMISSION = "datastore.entities.list"
    DOWNLOAD_PERMISSION = "datastore.entities.list"
    ACTION_RESOURCE_TYPE = "databases"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import firestore_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Firestore collection enumeration requires the `google-cloud-firestore` package."
            ) from exc
        self.firestore_client_cls = firestore_v1.Client

    def _client(self, *, project_id: str, database_id: str):
        return self.firestore_client_cls(
            project=project_id,
            credentials=self.session.credentials,
            database=_normalize_database_id(database_id),
        )

    def list(self, *, project_id: str, database_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        normalized_database_id = _normalize_database_id(database_id)
        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            rows = []
            for collection_ref in client.collections():
                collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
                    getattr(collection_ref, "id", "") or ""
                ).strip()
                collection_id = str(getattr(collection_ref, "id", "") or "").strip() or extract_path_tail(collection_path)
                rows.append(
                    {
                        "database_id": normalized_database_id,
                        "collection_id": collection_id,
                        "collection_path": collection_path,
                    }
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_database_id,
            )
            return rows
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection enumeration for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return None
            return handle_service_error(
                exc,
                api_name="firestore.collections.list",
                resource_name=_database_name(project_id, normalized_database_id),
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    def download_collection_documents(
        self,
        *,
        project_id: str,
        database_id: str,
        collection_path: str,
        limit: int = 0,
        action_dict=None,
    ) -> Path | None:
        normalized_database_id = _normalize_database_id(database_id)
        normalized_collection_path = str(collection_path or "").strip()
        if not normalized_collection_path:
            return None

        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            destination = self._download_path(
                project_id=project_id,
                filename=f"{_safe_filename_token(normalized_database_id)}_{_safe_filename_token(normalized_collection_path)}_contents.txt",
            )
            visited: set[str] = set()
            with destination.open("w", encoding="utf-8", newline="\n") as handle:
                self._write_collection_recursive(
                    handle=handle,
                    collection_ref=client.collection(normalized_collection_path),
                    limit=limit,
                    visited=visited,
                )
            record_permissions(
                action_dict,
                permissions=self.DOWNLOAD_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_database_id,
            )
            return destination
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection download for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return None
            handle_service_error(
                exc,
                api_name="firestore.documents.list",
                resource_name=f"{_database_name(project_id, normalized_database_id)}:{normalized_collection_path}",
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )
            return None

    def download_database_documents(
        self,
        *,
        project_id: str,
        database_id: str,
        limit: int = 0,
        action_dict=None,
    ) -> list[Path]:
        normalized_database_id = _normalize_database_id(database_id)
        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            destinations: list[Path] = []
            for collection_ref in client.collections():
                collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
                    getattr(collection_ref, "id", "") or ""
                ).strip()
                if not collection_path:
                    continue
                destination = self.download_collection_documents(
                    project_id=project_id,
                    database_id=normalized_database_id,
                    collection_path=collection_path,
                    limit=limit,
                    action_dict=action_dict,
                )
                if destination is not None:
                    destinations.append(destination)
            return destinations
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection download for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return []
            handle_service_error(
                exc,
                api_name="firestore.documents.list",
                resource_name=_database_name(project_id, normalized_database_id),
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )
            return []

    def _write_collection_recursive(self, *, handle, collection_ref, limit: int, visited: set[str]) -> None:
        collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
            getattr(collection_ref, "id", "") or ""
        ).strip()
        if not collection_path or collection_path in visited:
            return
        visited.add(collection_path)

        query = collection_ref.limit(limit) if limit > 0 else collection_ref
        for snapshot in query.stream():
            payload = {
                "collection_path": collection_path,
                "document_id": str(getattr(snapshot, "id", "") or "").strip(),
                "document_path": str(getattr(getattr(snapshot, "reference", None), "path", "") or "").strip(),
                "data": snapshot.to_dict() if getattr(snapshot, "exists", True) else None,
            }
            handle.write(json.dumps(payload, ensure_ascii=False, default=str))
            handle.write("\n")
            for child_collection in getattr(snapshot.reference, "collections")():
                self._write_collection_recursive(
                    handle=handle,
                    collection_ref=child_collection,
                    limit=limit,
                    visited=visited,
                )

    def _download_path(self, *, project_id: str, filename: str) -> Path:
        if hasattr(self.session, "get_download_save_path"):
            return Path(
                self.session.get_download_save_path(
                    service_name="firestore",
                    filename=filename,
                    project_id=project_id,
                    subdirs=["collections"],
                )
            )
        fallback = Path.cwd() / "gcpwn_output" / "downloads" / "firestore" / project_id / "collections"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback / filename


def _normalize_database_id(value: Any) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if "/databases/" in token:
        token = token.partition("/databases/")[2]
    return token.strip("/")


def _database_name(project_id: str, database_id: Any) -> str:
    normalized_database_id = _normalize_database_id(database_id)
    return f"projects/{project_id}/databases/{normalized_database_id}" if normalized_database_id else ""


def _rules_services(ruleset: dict[str, Any]) -> list[str]:
    metadata = ruleset.get("metadata") or {}
    if not isinstance(metadata, dict):
        return []
    values = metadata.get("services") or []
    return [str(value).strip() for value in values if str(value).strip()]


def _rules_attachment_point(ruleset: dict[str, Any]) -> str:
    return str(ruleset.get("attachment_point") or "").strip()


def _rules_source_files(ruleset: dict[str, Any]) -> list[dict[str, Any]]:
    source = ruleset.get("source") or {}
    if not isinstance(source, dict):
        return []
    files = source.get("files") or []
    return [dict(entry) for entry in files if isinstance(entry, dict)]


def _is_firestore_rules_release(release: dict[str, Any], ruleset: dict[str, Any]) -> bool:
    release_name = str(release.get("name") or "").strip()
    attachment_point = _rules_attachment_point(ruleset)
    services = _rules_services(ruleset)
    return (
        "cloud.firestore" in services
        or "firestore.googleapis.com" in attachment_point
        or "/releases/cloud.firestore" in release_name
    )


def _database_id_from_rules_payload(release: dict[str, Any], ruleset: dict[str, Any]) -> str:
    attachment_point = _rules_attachment_point(ruleset)
    match = re.search(r"/databases/([^/]+)$", attachment_point)
    if match:
        return _normalize_database_id(match.group(1))

    release_name = str(release.get("name") or "").strip()
    release_prefix = "/releases/cloud.firestore"
    if release_prefix in release_name:
        suffix = release_name.split(release_prefix, 1)[1].strip("/")
        return _normalize_database_id(suffix or "(default)")
    return ""


def _safe_filename_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    token = token.strip("._")
    return token or "unknown"


def _is_datastore_mode_collection_unsupported(exc: Exception) -> bool:
    message = str(exc or "")
    return (
        "Cloud Firestore API is not available for Firestore in Datastore Mode database" in message
        or "Firestore in Datastore Mode database" in message
    )
