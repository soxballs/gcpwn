from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service, handle_discovery_error
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_from_module_data,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def _safe_path_parts(relative_path: str) -> list[str]:
    parts: list[str] = []
    for part in Path(str(relative_path or "")).parts:
        token = str(part).strip()
        if not token or token in {".", "..", "/"}:
            continue
        parts.append(token)
    return parts


def _flatten_filename_parts(parts: list[str]) -> str:
    tokens = [str(part).strip().replace("/", "_") for part in (parts or []) if str(part).strip()]
    return "_".join(tokens)


def _file_payload_from_openapi_document(document: Any) -> dict[str, Any]:
    payload = resource_to_dict(document)
    file_payload = payload.get("document")
    if isinstance(file_payload, dict):
        return file_payload
    source_payload = payload.get("document") or payload.get("source_contents")
    if isinstance(source_payload, dict):
        return source_payload
    file_attr = getattr(document, "document", None)
    if file_attr is not None:
        return resource_to_dict(file_attr)
    return {}


def _decode_file_contents(contents: Any) -> bytes:
    if isinstance(contents, bytes):
        return contents
    if isinstance(contents, str):
        token = contents
        if not token:
            return b""
        try:
            return base64.b64decode(token.strip(), validate=True)
        except Exception:
            return token.encode("utf-8")
    return str(contents or "").encode("utf-8")


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


class _ApiGatewayBaseResource:
    SERVICE_LABEL = "API Gateway"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    ACTION_RESOURCE_TYPE = ""
    test_iam_permissions_starting_list: tuple[str, ...] = ()
    test_iam_permissions_api_name = ""

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import apigateway_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "API Gateway enumeration requires the `google-cloud-api-gateway` package."
            ) from exc
        self._apigateway_v1 = apigateway_v1
        self.client = apigateway_v1.ApiGatewayServiceClient(credentials=session.credentials)
        self._discovery_service = None

    def _request(self, callback):
        return callback()

    def resource_name(self, row: Any) -> str:
        payload = resource_to_dict(row)
        return field_from_row(row, payload, "name")

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(
                getattr(self.session, "credentials", None),
                "apigateway",
                "v1",
                scopes=(self.CLOUD_PLATFORM_SCOPE,),
            )
        return self._discovery_service

    def _call_test_iam_permissions(self, *, name: str, request_builder) -> list[str]:
        normalized_name = str(name or "").strip()
        if not normalized_name:
            return []
        try:
            request = request_builder(self._get_discovery_service(), normalized_name)
            response = request.execute()
            return [
                str(permission).strip()
                for permission in ((response or {}).get("permissions") or [])
                if str(permission).strip()
            ]
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                self.test_iam_permissions_api_name,
                normalized_name,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return [] if result in (None, "Not Enabled") else list(result or [])

    def _record_test_iam_permissions(self, *, name: str, permissions: list[str], action_dict=None) -> list[str]:
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


class ApiGatewayGatewaysResource(_ApiGatewayBaseResource):
    TABLE_NAME = "apigateway_gateways"
    ACTION_RESOURCE_TYPE = "gateways"
    LIST_API_NAME = "apigateway.gateways.list"
    GET_API_NAME = "apigateway.gateways.get"
    test_iam_permissions_api_name = "apigateway.gateways.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.gateways.createTagBinding",
        "apigateway.gateways.delete",
        "apigateway.gateways.deleteTagBinding",
        "apigateway.gateways.get",
        "apigateway.gateways.getIamPolicy",
        "apigateway.gateways.listEffectiveTags",
        "apigateway.gateways.listTagBindings",
        "apigateway.gateways.setIamPolicy",
        "apigateway.gateways.update",
    )
    COLUMNS = [
        "name",
        "default_hostname",
        "state",
    ]

    def test_iam_permissions(self, *, name: str, action_dict=None) -> list[str]:
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().gateways().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._apigateway_v1.ListGatewaysRequest(parent=parent)
            rows = [resource_to_dict(gateway) for gateway in self._request(lambda: self.client.list_gateways(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str, action_dict=None):
        try:
            request = self._apigateway_v1.GetGatewayRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_gateway(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class ApiGatewayApisResource(_ApiGatewayBaseResource):
    TABLE_NAME = "apigateway_apis"
    ACTION_RESOURCE_TYPE = "apis"
    LIST_API_NAME = "apigateway.apis.list"
    GET_API_NAME = "apigateway.apis.get"
    test_iam_permissions_api_name = "apigateway.apis.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.apis.createTagBinding",
        "apigateway.apis.delete",
        "apigateway.apis.deleteTagBinding",
        "apigateway.apis.get",
        "apigateway.apis.getIamPolicy",
        "apigateway.apis.listEffectiveTags",
        "apigateway.apis.listTagBindings",
        "apigateway.apis.setIamPolicy",
        "apigateway.apis.update",
    )
    COLUMNS = [
        "name",
        "managed_service",
        "state",
    ]

    def test_iam_permissions(self, *, name: str, action_dict=None) -> list[str]:
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().apis().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, project_id: str, action_dict=None):
        parent = f"projects/{project_id}/locations/global"
        try:
            request = self._apigateway_v1.ListApisRequest(parent=parent)
            rows = [resource_to_dict(api) for api in self._request(lambda: self.client.list_apis(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str, action_dict=None):
        try:
            request = self._apigateway_v1.GetApiRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_api(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class ApiGatewayConfigsResource(_ApiGatewayBaseResource):
    TABLE_NAME = "apigateway_api_configs"
    ACTION_RESOURCE_TYPE = "configs"
    LIST_API_NAME = "apigateway.apiconfigs.list"
    GET_API_NAME = "apigateway.apiconfigs.get"
    test_iam_permissions_api_name = "apigateway.apiconfigs.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.apiconfigs.delete",
        "apigateway.apiconfigs.get",
        "apigateway.apiconfigs.getIamPolicy",
        "apigateway.apiconfigs.setIamPolicy",
        "apigateway.apiconfigs.update",
    )
    COLUMNS = [
        "name",
        "gateway_service_account",
        "service_config_id",
        "state"
    ]

    def test_iam_permissions(self, *, name: str, action_dict=None) -> list[str]:
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().apis().configs().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, api_name: str, action_dict=None):
        try:
            request = self._apigateway_v1.ListApiConfigsRequest(parent=api_name)
            rows = [resource_to_dict(config) for config in self._request(lambda: self.client.list_api_configs(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    api_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=api_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str, action_dict=None):
        try:
            view_enum = getattr(self._apigateway_v1.GetApiConfigRequest, "ConfigView", None)
            full_view = getattr(view_enum, "FULL", "FULL")
            request = self._apigateway_v1.GetApiConfigRequest(name=name, view=full_view)
            row = resource_to_dict(self._request(lambda: self.client.get_api_config(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def download_openapi_documents(self, *, row: dict[str, Any], project_id: str) -> list[Path]:
        payload = resource_to_dict(row)
        config_name = str(payload.get("name") or "").strip()
        api_name = str(payload.get("api_name") or "").strip()
        if not api_name:
            config_project = extract_path_segment(config_name, "projects")
            config_location = extract_path_segment(config_name, "locations")
            config_api_id = extract_path_segment(config_name, "apis")
            if config_project and config_location and config_api_id:
                api_name = f"projects/{config_project}/locations/{config_location}/apis/{config_api_id}"
        api_simple = extract_path_tail(api_name, default=api_name) or "unknown-api"
        config_simple = extract_path_tail(config_name, default=config_name) or "unknown-config"
        downloaded_paths: list[Path] = []

        openapi_documents = payload.get("openapi_documents")
        for index, document in enumerate(openapi_documents or [], start=1):
            file_payload = _file_payload_from_openapi_document(document)
            relative_parts = _safe_path_parts(str(file_payload.get("path") or file_payload.get("file_path") or ""))
            relative_name = _flatten_filename_parts(relative_parts) or f"openapi_document_{index}.yaml"
            filename = f"{api_simple}_{config_simple}_{relative_name}"
            subdirs = ["api_configs"]
            destination = self.session.get_download_save_path(
                service_name="apigateway",
                filename=filename,
                project_id=project_id,
                subdirs=subdirs,
            )
            contents = _decode_file_contents(
                file_payload.get("contents")
                or file_payload.get("data")
                or file_payload.get("source_contents")
            )
            destination.write_bytes(contents)
            downloaded_paths.append(destination)

        return downloaded_paths

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, api_name: str) -> None:
        for row in rows or []:
            raw_name = str(row.get("name") or "").strip()
            config_project = extract_path_segment(raw_name, "projects")
            config_location = extract_path_segment(raw_name, "locations")
            config_api_id = extract_path_segment(raw_name, "apis")
            inferred_api_name = (
                f"projects/{config_project}/locations/{config_location}/apis/{config_api_id}"
                if config_project and config_location and config_api_id
                else str(api_name or "").strip()
            )
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "api_name": api_name},
                extra_builder=lambda _obj, raw: {
                    "api_name": str(raw.get("api_name") or "").strip() or inferred_api_name,
                },
            )
