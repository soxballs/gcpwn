from __future__ import annotations

from typing import Any, Iterable

from google.api_core.exceptions import Forbidden, NotFound
from google.cloud import pubsub_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, resource_name_from_value
from gcpwn.core.utils.persistence import save_to_table


class PubSubTopicsResource:
    TABLE_NAME = "pubsub_topics"
    ACTION_RESOURCE_TYPE = "topics"
    LIST_PERMISSION = "pubsub.topics.list"
    GET_PERMISSION = "pubsub.topics.get"
    TEST_IAM_API_NAME = "pubsub.topics.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.topics.",
        exclude_permissions=("pubsub.topics.create","pubsub.topics.list"),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = pubsub_v1.PublisherClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        project_path = f"projects/{project_id}"
        try:
            rows = list(self.client.list_topics(request={"project": project_path}))
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

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_topic(request={"topic": resource_id})
            project_id = extract_path_segment(resource_name_from_value(row, "name"), "projects")
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, topics: Iterable[Any]) -> None:
        for topic in topics or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                topic,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_path_segment(str(raw.get("name", "") or ""), "projects"),
                    "topic_id": extract_path_tail(raw.get("name", "")),
                },
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Pub/Sub",
            project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions


class PubSubSubscriptionsResource:
    TABLE_NAME = "pubsub_subscriptions"
    ACTION_RESOURCE_TYPE = "subscriptions"
    LIST_PERMISSION = "pubsub.subscriptions.list"
    GET_PERMISSION = "pubsub.subscriptions.get"
    TEST_IAM_API_NAME = "pubsub.subscriptions.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.subscriptions.",
        exclude_permissions=("pubsub.subscriptions.create","pubsub.subscriptions.list"),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = pubsub_v1.SubscriberClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        project_path = f"projects/{project_id}"
        try:
            rows = list(self.client.list_subscriptions(request={"project": project_path}))
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

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_subscription(request={"subscription": resource_id})
            project_id = extract_path_segment(resource_name_from_value(row, "name"), "projects")
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, subscriptions: Iterable[Any]) -> None:
        for subscription in subscriptions or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                subscription,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_path_segment(str(raw.get("name", "") or ""), "projects"),
                    "subscription_id": extract_path_tail(raw.get("name", "")),
                },
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Pub/Sub",
            project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions


class PubSubSchemasResource:
    TABLE_NAME = "pubsub_schemas"
    ACTION_RESOURCE_TYPE = "schemas"
    LIST_PERMISSION = "pubsub.schemas.list"
    GET_PERMISSION = "pubsub.schemas.get"
    TEST_IAM_API_NAME = "pubsub.schemas.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.schemas.",
        exclude_permissions=("pubsub.schemas.create","pubsub.schemas.list","pubsub.schemas.validate"),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = pubsub_v1.SchemaServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        parent = f"projects/{project_id}"
        try:
            rows = list(self.client.list_schemas(request={"parent": parent}))
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

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_schema(request={"name": resource_id})
            project_id = extract_path_segment(resource_name_from_value(row, "name"), "projects")
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, schemas: Iterable[Any]) -> None:
        for schema in schemas or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                schema,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_path_segment(str(raw.get("name", "") or ""), "projects"),
                    "schema_id": extract_path_tail(raw.get("name", "")),
                    "type": raw.get("type") or raw.get("type_") or "",
                    "definition": raw.get("definition") or "",
                },
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Pub/Sub",
            project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions


class PubSubSnapshotsResource:
    TABLE_NAME = "pubsub_snapshots"
    ACTION_RESOURCE_TYPE = "snapshots"
    LIST_PERMISSION = "pubsub.snapshots.list"
    GET_PERMISSION = "pubsub.snapshots.get"
    TEST_IAM_API_NAME = "pubsub.snapshots.testIamPermissions"

    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.snapshots.",
        exclude_permissions=("pubsub.snapshots.create","pubsub.snapshots.list"),
    )

    def __init__(self, session) -> None:
        self.session = session
        self.client = pubsub_v1.SubscriberClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        project_path = f"projects/{project_id}"
        try:
            rows = list(self.client.list_snapshots(request={"project": project_path}))
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

    def get(self, *, resource_id: str, action_dict=None):
        try:
            row = self.client.get_snapshot(request={"snapshot": resource_id})
            project_id = extract_path_segment(resource_name_from_value(row, "name"), "projects")
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return row
        except Forbidden:
            UtilityTools.print_403_api_denied(self.GET_PERMISSION, resource_name=resource_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as exc:
            UtilityTools.print_500(resource_id, self.GET_PERMISSION, exc)
        return None

    def save(self, snapshots: Iterable[Any]) -> None:
        for snapshot in snapshots or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                snapshot,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_path_segment(str(raw.get("name", "") or ""), "projects"),
                    "snapshot_id": extract_path_tail(raw.get("name", "")),
                },
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Pub/Sub",
            project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_path_segment(resource_name_from_value(resource_id, "name"), "projects"),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions
