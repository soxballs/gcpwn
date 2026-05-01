from __future__ import annotations

from typing import Any, Iterable

from google.api_core.exceptions import Forbidden, NotFound
from google.cloud.bigtable_admin_v2.overlay.services.bigtable_table_admin import BigtableTableAdminClient
from google.cloud.bigtable_admin_v2.services.bigtable_instance_admin import BigtableInstanceAdminClient

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_tail, extract_project_id_from_resource
from gcpwn.core.utils.persistence import save_to_table


class BigtableInstancesResource:
    TABLE_NAME = "bigtable_instances"
    COLUMNS = ["instance_id", "name", "display_name", "state", "type", "labels"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "bigtable.instances.list"
    GET_PERMISSION = "bigtable.instances.get"
    TEST_IAM_API_NAME = "bigtable.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigtable.instances.")

    def __init__(self, session) -> None:
        self.session = session
        self.client = BigtableInstanceAdminClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        parent = f"projects/{project_id}"
        try:
            resp = self.client.list_instances(parent=parent)
            rows = list(getattr(resp, "instances", []) or [])
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied("bigtable.instances.list", project_id=project_id)
        except Exception as exc:
            UtilityTools.print_500(project_id, "bigtable.instances.list", exc)
        return []

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_instance(name=resource_id)
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
        except Forbidden:
            UtilityTools.print_403_api_denied("bigtable.instances.get", resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, "bigtable.instances.get", exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Cloud Bigtable",
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

    def save(self, instances: Iterable[Any], *, project_id: str) -> None:
        for instance in instances or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                instance,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "instance_id": extract_path_tail(raw.get("name", "")),
                },
            )


class BigtableTablesResource:
    TABLE_NAME = "bigtable_tables"
    COLUMNS = ["table_id", "name", "granularity", "deletion_protection"]
    ACTION_RESOURCE_TYPE = "tables"
    LIST_PERMISSION = "bigtable.tables.list"
    GET_PERMISSION = "bigtable.tables.get"
    TEST_IAM_API_NAME = "bigtable.tables.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigtable.tables.")

    def __init__(self, session) -> None:
        self.session = session
        self.client = BigtableTableAdminClient(credentials=session.credentials)

    def list(self, *, instance_name: str, action_dict=None):
        try:
            rows = list(self.client.list_tables(parent=instance_name))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(
                    instance_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="instances",
                resource_label=instance_name,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied("bigtable.tables.list", resource_name=instance_name)
        except Exception as exc:
            UtilityTools.print_500(instance_name, "bigtable.tables.list", exc)
        return []

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_table(name=resource_id)
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
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Cloud Bigtable",
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

    def save(self, tables: Iterable[Any], *, project_id: str, instance_name: str) -> None:
        for table in tables or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                table,
                defaults={"project_id": project_id, "instance_name": instance_name},
                extra_builder=lambda _obj, raw: {
                    "table_id": extract_path_tail(raw.get("name", "")),
                },
            )


class BigtableBackupsResource:
    TABLE_NAME = "bigtable_backups"
    COLUMNS = ["backup_id", "name", "source_table", "state", "expire_time", "start_time", "end_time", "size_bytes"]
    ACTION_RESOURCE_TYPE = "backups"
    LIST_PERMISSION = "bigtable.backups.list"
    GET_PERMISSION = "bigtable.backups.get"

    def __init__(self, session) -> None:
        self.session = session
        self.client = BigtableTableAdminClient(credentials=session.credentials)

    def list(self, *, instance_name: str, action_dict=None):
        # Backups are scoped to clusters; "-" lets the API enumerate across all clusters in the instance.
        parent = f"{str(instance_name).rstrip('/')}/clusters/-"
        try:
            rows = list(self.client.list_backups(parent=parent))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(
                    instance_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="instances",
                resource_label=instance_name,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied(self.LIST_PERMISSION, resource_name=parent)
        except Exception as exc:
            UtilityTools.print_500(parent, self.LIST_PERMISSION, exc)
        return []

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_backup(name=resource_id)
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
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, backups: Iterable[Any], *, project_id: str, instance_name: str) -> None:
        for backup in backups or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                backup,
                defaults={"project_id": project_id, "instance_name": instance_name},
                extra_builder=lambda _obj, raw: {
                    "backup_id": extract_path_tail(raw.get("name", "")),
                },
            )


class BigtableAuthorizedViewsResource:
    TABLE_NAME = "bigtable_authorized_views"
    COLUMNS = ["authorized_view_id", "name", "table_name", "deletion_protection"]
    ACTION_RESOURCE_TYPE = "authorized_views"
    LIST_PERMISSION = "bigtable.authorizedViews.list"
    GET_PERMISSION = "bigtable.authorizedViews.get"

    def __init__(self, session) -> None:
        self.session = session
        self.client = BigtableTableAdminClient(credentials=session.credentials)

    def list(self, *, table_name: str, action_dict=None):
        parent = str(table_name or "").strip()
        if not parent:
            return []
        try:
            rows = list(self.client.list_authorized_views(parent=parent))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="tables",
                resource_label=parent,
            )
            return rows
        except Forbidden:
            UtilityTools.print_403_api_denied(self.LIST_PERMISSION, resource_name=parent)
        except Exception as exc:
            UtilityTools.print_500(parent, self.LIST_PERMISSION, exc)
        return []

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_authorized_view(name=resource_id)
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
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, views: Iterable[Any], *, project_id: str, table_name: str) -> None:
        for view in views or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                view,
                defaults={"project_id": project_id, "table_name": table_name},
                extra_builder=lambda _obj, raw: {
                    "authorized_view_id": extract_path_tail(raw.get("name", "")),
                },
            )
