from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_from_module_data,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


class _KmsBaseResource:
    SERVICE_LABEL = "Cloud KMS"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import kms_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud KMS enumeration requires the `google-cloud-kms` package."
            ) from exc
        self.client = kms_v1.KeyManagementServiceClient(credentials=session.credentials)


class KmsKeyRingsResource(_KmsBaseResource):
    TABLE_NAME = "kms_keyrings"
    COLUMNS = ["location", "keyring_id", "name", "create_time"]
    ACTION_RESOURCE_TYPE = "keyrings"
    LIST_PERMISSION = "cloudkms.keyRings.list"
    TEST_IAM_API_NAME = "cloudkms.keyRings.testIamPermissions"

    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudkms.keyRings.",
        exclude_permissions=("cloudkms.keyRings.create","cloudkms.keyRings.list"),
    )

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [resource_to_dict(item) for item in self.client.list_key_rings(parent=parent)]
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
                api_name="cloudkms.projects.locations.keyRings.list",
                resource_name=parent,
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
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location},
                extra_builder=lambda _obj, raw: {
                    "keyring_id": extract_path_tail(raw.get("name", "")),
                },
            )


class KmsCryptoKeysResource(_KmsBaseResource):
    TABLE_NAME = "kms_keys"
    COLUMNS = ["location", "key_id", "name", "purpose", "primary_state", "next_rotation_time"]
    ACTION_RESOURCE_TYPE = "keys"
    LIST_PERMISSION = "cloudkms.cryptoKeys.list"
    GET_PERMISSION = "cloudkms.cryptoKeys.get"
    TEST_IAM_API_NAME = "cloudkms.cryptoKeys.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudkms.cryptoKeys.",
        exclude_permissions=("cloudkms.cryptoKeys.create","cloudkms.cryptoKeys.list"),
    )

    def list(self, *, keyring_name: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            rows = [resource_to_dict(item) for item in self.client.list_crypto_keys(parent=keyring_name)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=extract_project_id_from_resource(
                    keyring_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="keyrings",
                resource_label=keyring_name,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudkms.cryptoKeys.list",
                resource_name=keyring_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = resource_to_dict(self.client.get_crypto_key(name=resource_id))
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
                api_name="cloudkms.cryptoKeys.get",
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

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, keyring_name: str) -> None:
        location = extract_location_from_resource_name(keyring_name)
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location, "keyring_name": keyring_name},
                extra_builder=lambda _obj, raw: {
                    "key_id": extract_path_tail(raw.get("name", "")),
                    "primary_state": (raw.get("primary") or {}).get("state") if isinstance(raw.get("primary"), dict) else "",
                },
            )


class KmsCryptoKeyVersionsResource(_KmsBaseResource):
    TABLE_NAME = "kms_key_versions"
    COLUMNS = ["location", "version_id", "name", "state", "create_time", "destroy_time"]

    def list(self, *, key_name: str) -> list[dict[str, Any]] | str | None:
        try:
            return [resource_to_dict(item) for item in self.client.list_crypto_key_versions(parent=key_name)]
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudkms.cryptoKeyVersions.list",
                resource_name=key_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            return resource_to_dict(self.client.get_crypto_key_version(name=resource_id))
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="cloudkms.cryptoKeyVersions.get",
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, key_name: str) -> None:
        location = extract_location_from_resource_name(key_name)
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location, "key_name": key_name},
                extra_builder=lambda _obj, raw: {
                    "version_id": extract_path_tail(raw.get("name", "")),
                },
            )
