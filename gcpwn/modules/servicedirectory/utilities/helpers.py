from __future__ import annotations

from typing import Any, Iterable

from google.api_core.exceptions import Forbidden, NotFound
from google.cloud import servicedirectory_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_from_module_data,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.service_runtime import is_api_disabled_error


class ServiceDirectoryNamespacesResource:
    TABLE_NAME = "servicedirectory_namespaces"
    COLUMNS = ["location_id", "namespace_id", "name", "labels"]
    ACTION_RESOURCE_TYPE = "namespaces"
    LIST_PERMISSION = "servicedirectory.namespaces.list"
    GET_PERMISSION = "servicedirectory.namespaces.get"
    TEST_IAM_API_NAME = "servicedirectory.namespaces.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "servicedirectory.namespaces.",
        exclude_permissions=(
            "servicedirectory.namespaces.create",
            "servicedirectory.namespaces.list"
        ),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = servicedirectory_v1.RegistrationServiceClient(credentials=session.credentials)

    def list(self, *, parent: str, project_id: str, location_id: str, action_dict=None) -> list[Any] | str | None:
        _ = (project_id, location_id)
        try:
            rows = list(self.client.list_namespaces(request={"parent": parent}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as exc:
            if is_api_disabled_error(exc):
                UtilityTools.print_403_api_disabled("Service Directory", self.session.project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied("servicedirectory.namespaces.list", resource_name=parent)
        except Exception as exc:
            UtilityTools.print_500(parent, "servicedirectory.namespaces.list", exc)
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_namespace(request={"name": resource_id})
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
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Forbidden as exc:
            if is_api_disabled_error(exc):
                UtilityTools.print_403_api_disabled("Service Directory", self.session.project_id)
                return None
            UtilityTools.print_403_api_denied("servicedirectory.namespaces.get", resource_name=resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, "servicedirectory.namespaces.get", exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Service Directory",
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

    def save(self, namespaces: Iterable[Any], *, project_id: str, location_id: str) -> None:
        for namespace in namespaces or []:
            save_to_table(
                self.session,
                "servicedirectory_namespaces",
                namespace,
                defaults={"project_id": project_id, "location_id": location_id},
                extra_builder=lambda _obj, raw: {
                    "namespace_id": extract_path_tail(raw.get("name", "")),
                },
            )


class ServiceDirectoryServicesResource:
    TABLE_NAME = "servicedirectory_services"
    COLUMNS = ["location_id", "service_id", "name", "namespace_name", "labels"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "servicedirectory.services.list"
    GET_PERMISSION = "servicedirectory.services.get"
    TEST_IAM_API_NAME = "servicedirectory.services.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "servicedirectory.services.",
        exclude_permissions=(
            "servicedirectory.services.create",
            "servicedirectory.services.list"
        ),
    )


    def __init__(self, session) -> None:
        self.session = session
        self.client = servicedirectory_v1.RegistrationServiceClient(credentials=session.credentials)

    def list(self, *, parent: str, project_id: str, location_id: str, action_dict=None) -> list[Any] | str | None:
        _ = (project_id, location_id)
        try:
            rows = list(self.client.list_services(request={"parent": parent}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type="namespaces",
                resource_label=parent,
            )
            return rows
        except Forbidden as exc:
            if is_api_disabled_error(exc):
                return "Not Enabled"
            UtilityTools.print_403_api_denied("servicedirectory.services.list", resource_name=parent)
        except Exception as exc:
            UtilityTools.print_500(parent, "servicedirectory.services.list", exc)
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_service(request={"name": resource_id})
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
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Forbidden as exc:
            if is_api_disabled_error(exc):
                UtilityTools.print_403_api_disabled("Service Directory", self.session.project_id)
                return None
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Service Directory",
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

    def save(self, services: Iterable[Any], *, project_id: str, location_id: str, namespace_name: str) -> None:
        for service in services or []:
            save_to_table(
                self.session,
                "servicedirectory_services",
                service,
                defaults={"project_id": project_id, "location_id": location_id, "namespace_name": namespace_name},
                extra_builder=lambda _obj, raw: {
                    "service_id": extract_path_tail(raw.get("name", "")),
                },
            )


class ServiceDirectoryEndpointsResource:
    TABLE_NAME = "servicedirectory_endpoints"
    COLUMNS = ["location_id", "endpoint_id", "name", "service_name", "address", "port", "network"]

    def __init__(self, session) -> None:
        self.session = session
        self.client = servicedirectory_v1.RegistrationServiceClient(credentials=session.credentials)

    def list(self, *, parent: str, project_id: str, location_id: str) -> list[Any] | str | None:
        _ = (project_id, location_id)
        try:
            return list(self.client.list_endpoints(request={"parent": parent}))
        except Forbidden as exc:
            if is_api_disabled_error(exc):
                return "Not Enabled"
            UtilityTools.print_403_api_denied("servicedirectory.endpoints.list", resource_name=parent)
        except Exception as exc:
            UtilityTools.print_500(parent, "servicedirectory.endpoints.list", exc)
        return []

    def save(self, endpoints: Iterable[Any], *, project_id: str, location_id: str, service_name: str) -> None:
        for endpoint in endpoints or []:
            save_to_table(
                self.session,
                "servicedirectory_endpoints",
                endpoint,
                defaults={"project_id": project_id, "location_id": location_id, "service_name": service_name},
                extra_builder=lambda _obj, raw: {
                    "endpoint_id": extract_path_tail(raw.get("name", "")),
                },
            )


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)
