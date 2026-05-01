from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_location_from_resource_name, extract_path_tail, extract_project_id_from_resource
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


class _AgentPlatformBaseResource:
    SERVICE_LABEL = "aiplatform"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import aiplatform_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "aiplatform enumeration requires the `google-cloud-aiplatform` package."
            ) from exc
        self._aiplatform_v1 = aiplatform_v1

class AgentPlatformEndpointsResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_endpoints"
    COLUMNS = ["location", "endpoint_id", "name", "display_name", "create_time", "update_time"]
    LIST_PERMISSION = "aiplatform.endpoints.list"
    GET_PERMISSION = "aiplatform.endpoints.get"
    ACTION_RESOURCE_TYPE = "endpoints"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.EndpointServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(endpoint) for endpoint in self.client.list_endpoints(parent=parent)]
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
                api_name="aiplatform.endpoints.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_endpoint(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.endpoints.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"endpoint_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformDatasetsResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_datasets"
    COLUMNS = ["location", "dataset_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "datasets"
    LIST_PERMISSION = "aiplatform.datasets.list"
    GET_PERMISSION = "aiplatform.datasets.get"
    TEST_IAM_API_NAME = "aiplatform.datasets.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.datasets.",
        exclude_permissions=(
            "aiplatform.datasets.add",
            "aiplatform.datasets.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.DatasetServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(dataset) for dataset in self.client.list_datasets(parent=parent)]
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
                api_name="aiplatform.datasets.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_dataset(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.datasets.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"dataset_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformModelsResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_models"
    COLUMNS = ["location", "model_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "models"
    LIST_PERMISSION = "aiplatform.models.list"
    GET_PERMISSION = "aiplatform.models.get"
    TEST_IAM_API_NAME = "aiplatform.models.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.models.",
        exclude_permissions=(
            "aiplatform.models.add",
            "aiplatform.models.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.ModelServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(model) for model in self.client.list_models(parent=parent)]
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
                api_name="aiplatform.models.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_model(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.models.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"model_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformFeaturestoresResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_featurestores"
    COLUMNS = ["location", "featurestore_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "featurestores"
    LIST_PERMISSION = "aiplatform.featurestores.list"
    GET_PERMISSION = "aiplatform.featurestores.get"
    TEST_IAM_API_NAME = "aiplatform.featurestores.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.featurestores.",
        exclude_permissions=(
            "aiplatform.featurestores.add",
            "aiplatform.featurestores.list"
        ),
    )


    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.FeaturestoreServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(featurestore) for featurestore in self.client.list_featurestores(parent=parent)]
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
                api_name="aiplatform.featurestores.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_featurestore(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.featurestores.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"featurestore_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformEntityTypesResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_entity_types"
    COLUMNS = ["location", "entity_type_id", "name", "featurestore_name", "labels"]
    ACTION_RESOURCE_TYPE = "entityTypes"
    LIST_PERMISSION = "aiplatform.entityTypes.list"
    GET_PERMISSION = "aiplatform.entityTypes.get"
    TEST_IAM_API_NAME = "aiplatform.entityTypes.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.entityTypes.",
        exclude_permissions=(
            "aiplatform.entityTypes.add",
            "aiplatform.entityTypes.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.FeaturestoreServiceClient(credentials=session.credentials)

    def list(self, *, parent: str, action_dict=None):
        try:
            rows = [resource_to_dict(entity_type) for entity_type in self.client.list_entity_types(parent=parent)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(parent, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=parent,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.entityTypes.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_entity_type(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.entityTypes.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, featurestore_name: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": location if location and location != "-" else extract_location_from_resource_name(name),
                    "featurestore_name": featurestore_name,
                },
                extra_builder=lambda _obj, raw: {"entity_type_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformFeatureGroupsResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_feature_groups"
    COLUMNS = ["location", "feature_group_id", "name", "display_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureGroups"
    LIST_PERMISSION = "aiplatform.featureGroups.list"
    GET_PERMISSION = "aiplatform.featureGroups.get"
    TEST_IAM_API_NAME = "aiplatform.featureGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.featureGroups.",
        exclude_permissions=(
            "aiplatform.featureGroups.add",
            "aiplatform.featureGroups.list"
        ),
    )


    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.FeatureRegistryServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(feature_group) for feature_group in self.client.list_feature_groups(parent=parent)]
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
                api_name="aiplatform.featureGroups.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_feature_group(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.featureGroups.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"feature_group_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformFeatureOnlineStoresResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_feature_online_stores"
    COLUMNS = ["location", "feature_online_store_id", "name", "display_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureOnlineStores"
    LIST_PERMISSION = "aiplatform.featureOnlineStores.list"
    GET_PERMISSION = "aiplatform.featureOnlineStores.get"
    TEST_IAM_API_NAME = "aiplatform.featureOnlineStores.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.featureOnlineStores.",
        exclude_permissions=(
            "aiplatform.featureOnlineStores.add",
            "aiplatform.featureOnlineStores.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        from google.cloud.aiplatform_v1.services import feature_online_store_admin_service  # type: ignore

        self.client = feature_online_store_admin_service.FeatureOnlineStoreAdminServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [
                resource_to_dict(feature_online_store)
                for feature_online_store in self.client.list_feature_online_stores(parent=parent)
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
                api_name="aiplatform.featureOnlineStores.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_feature_online_store(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.featureOnlineStores.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"feature_online_store_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformFeatureViewsResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_feature_views"
    COLUMNS = ["location", "feature_view_id", "name", "feature_online_store_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureViews"
    LIST_PERMISSION = "aiplatform.featureViews.list"
    GET_PERMISSION = "aiplatform.featureViews.get"
    TEST_IAM_API_NAME = "aiplatform.featureViews.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.featureViews.",
        exclude_permissions=(
            "aiplatform.featureViews.add",
            "aiplatform.featureViews.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        from google.cloud.aiplatform_v1.services import feature_online_store_admin_service  # type: ignore

        self.client = feature_online_store_admin_service.FeatureOnlineStoreAdminServiceClient(credentials=session.credentials)

    def list(self, *, parent: str, action_dict=None):
        try:
            rows = [resource_to_dict(feature_view) for feature_view in self.client.list_feature_views(parent=parent)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(parent, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=parent,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.featureViews.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_feature_view(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.featureViews.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, feature_online_store_name: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": location if location and location != "-" else extract_location_from_resource_name(name),
                    "feature_online_store_name": feature_online_store_name,
                },
                extra_builder=lambda _obj, raw: {"feature_view_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformReasoningEnginesResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_reasoning_engines"
    COLUMNS = ["location", "reasoning_engine_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "reasoningEngines"
    LIST_PERMISSION = "aiplatform.reasoningEngines.list"
    GET_PERMISSION = "aiplatform.reasoningEngines.get"
    TEST_IAM_API_NAME = "aiplatform.reasoningEngines.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.reasoningEngines.",
        exclude_permissions=(
            "aiplatform.reasoningEngines.add",
            "aiplatform.reasoningEngines.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.ReasoningEngineServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(reasoning_engine) for reasoning_engine in self.client.list_reasoning_engines(parent=parent)]
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
                api_name="aiplatform.reasoningEngines.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_reasoning_engine(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.reasoningEngines.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"reasoning_engine_id": extract_path_tail(raw.get("name", ""))},
            )


class AgentPlatformNotebookRuntimeTemplatesResource(_AgentPlatformBaseResource):
    TABLE_NAME = "agentplatform_notebook_runtime_templates"
    COLUMNS = ["location", "notebook_runtime_template_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "notebookRuntimeTemplates"
    LIST_PERMISSION = "aiplatform.notebookRuntimeTemplates.list"
    GET_PERMISSION = "aiplatform.notebookRuntimeTemplates.get"
    TEST_IAM_API_NAME = "aiplatform.notebookRuntimeTemplates.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "aiplatform.notebookRuntimeTemplates.",
        exclude_permissions=(
            "aiplatform.notebookRuntimeTemplates.add",
            "aiplatform.notebookRuntimeTemplates.list"
        ),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._aiplatform_v1.NotebookServiceClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(template) for template in self.client.list_notebook_runtime_templates(parent=parent)]
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
                api_name="aiplatform.notebookRuntimeTemplates.list",
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_notebook_runtime_template(name=resource_id))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="aiplatform.notebookRuntimeTemplates.get",
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
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "")).strip()
            resolved_location = location if location and location != "-" else extract_location_from_resource_name(name)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": resolved_location},
                extra_builder=lambda _obj, raw: {"notebook_runtime_template_id": extract_path_tail(raw.get("name", ""))},
            )
