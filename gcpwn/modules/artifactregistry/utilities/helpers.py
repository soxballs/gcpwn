from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, unquote

from gcpwn.core.output_paths import compact_filename_component

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_location_from_resource_name
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.module_helpers import extract_project_id_from_resource
from gcpwn.core.utils.module_helpers import resolve_regions_from_module_data
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def resolve_regions(session, args) -> list[str]:
    return resolve_regions_from_module_data(session, args, module_file=__file__)


def _normalize_repository_row(row: dict[str, Any]) -> dict[str, Any]:
    # The Repository proto uses `format`, but the generated Python field name is `format_`.
    # Our DB mapping and enum logic standardize on `format`.
    if not isinstance(row, dict):
        return {}
    if "format" not in row and "format_" in row:
        row["format"] = row.get("format_")
    return row


class _ArtifactRegistryBaseResource:
    SERVICE_LABEL = "Artifact Registry"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    ACTION_RESOURCE_TYPE = ""
    LIST_API_NAME = ""
    GET_API_NAME = ""
    TEST_IAM_PERMISSIONS: tuple[str, ...] = ()
    TEST_IAM_API_NAME = ""

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import artifactregistry_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Artifact Registry enumeration requires the `google-cloud-artifact-registry` package."
            ) from exc
        self._artifactregistry_v1 = artifactregistry_v1
        self.client = artifactregistry_v1.ArtifactRegistryClient(credentials=session.credentials)

    def resource_name(self, row: Any) -> str:
        payload = resource_to_dict(row)
        return field_from_row(row, payload, "name")

    def _request(self, callback):
        return callback()

    def _ensure_scoped_credentials(self, credentials):
        if credentials is None:
            return None
        try:
            import google.auth.credentials

            return google.auth.credentials.with_scopes_if_required(
                credentials,
                (self.CLOUD_PLATFORM_SCOPE,),
            )
        except Exception:
            try:
                return credentials.with_scopes([self.CLOUD_PLATFORM_SCOPE])  # type: ignore[attr-defined]
            except Exception:
                return credentials

    def test_iam_permissions(self, *, name: str, action_dict=None) -> list[str]:
        from gcpwn.core.utils.iam_permissions import call_test_iam_permissions

        permissions = call_test_iam_permissions(
            client=self.client,
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


class ArtifactRegistryRepositoriesResource(_ArtifactRegistryBaseResource):
    TABLE_NAME = "artifactregistry_repositories"
    ACTION_RESOURCE_TYPE = "repositories"
    LIST_API_NAME = "artifactregistry.repositories.list"
    GET_API_NAME = "artifactregistry.repositories.get"
    TEST_IAM_API_NAME = "artifactregistry.repositories.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "artifactregistry.repositories.",
        exclude_permissions=(
            "artifactregistry.repositories.create",
            "artifactregistry.repositories.list",
        ),
    )
    COLUMNS = ["location", "repository_id", "format_", "name"]

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._artifactregistry_v1.ListRepositoriesRequest(parent=parent)
            rows = [_normalize_repository_row(resource_to_dict(repo)) for repo in self._request(lambda: self.client.list_repositories(request=request))]
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

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetRepositoryRequest(name=resource_id)
            row = _normalize_repository_row(resource_to_dict(self._request(lambda: self.client.get_repository(request=request))))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
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
                extra_builder=lambda _obj, raw: {
                    "repository_id": extract_path_tail(raw.get("name", "")),
                    "format": raw.get("format") or raw.get("format_") or "",
                },
            )


class ArtifactRegistryPackagesResource(_ArtifactRegistryBaseResource):
    TABLE_NAME = "artifactregistry_packages"
    ACTION_RESOURCE_TYPE = "packages"
    LIST_API_NAME = "artifactregistry.packages.list"
    GET_API_NAME = "artifactregistry.packages.get"
    COLUMNS = ["location", "repository", "package_id"]

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListPackagesRequest(parent=parent)
            items = [resource_to_dict(pkg) for pkg in self._request(lambda: self.client.list_packages(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetPackageRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_package(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, repository: str) -> None:
        location = extract_location_from_resource_name(repository)
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location, "repository": repository},
                extra_builder=lambda _obj, raw: {
                    "package_id": extract_path_tail(raw.get("name", "")),
                },
            )


class ArtifactRegistryVersionsResource(_ArtifactRegistryBaseResource):
    TABLE_NAME = "artifactregistry_versions"
    ACTION_RESOURCE_TYPE = "versions"
    LIST_API_NAME = "artifactregistry.versions.list"
    GET_API_NAME = "artifactregistry.versions.get"
    COLUMNS = ["location", "package", "version_id", "name"]

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListVersionsRequest(parent=parent)
            items = [resource_to_dict(version) for version in self._request(lambda: self.client.list_versions(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetVersionRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_version(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, package: str) -> None:
        location = extract_location_from_resource_name(package)
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location, "package": package},
                extra_builder=lambda _obj, raw: {
                    "version_id": extract_path_tail(raw.get("name", "")),
                },
            )


class ArtifactRegistryDockerImagesResource(_ArtifactRegistryBaseResource):
    ACTION_RESOURCE_TYPE = "docker_images"
    LIST_API_NAME = "artifactregistry.dockerImages.list"
    GET_API_NAME = "artifactregistry.dockerImages.get"

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListDockerImagesRequest(parent=parent)
            items = [
                resource_to_dict(image)
                for image in self._request(lambda: self.client.list_docker_images(request=request))
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetDockerImageRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_docker_image(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )


class ArtifactRegistryPythonPackagesResource(_ArtifactRegistryBaseResource):
    ACTION_RESOURCE_TYPE = "python_packages"
    LIST_API_NAME = "artifactregistry.pythonPackages.list"
    GET_API_NAME = "artifactregistry.pythonPackages.get"

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListPythonPackagesRequest(parent=parent)
            items = [
                resource_to_dict(package)
                for package in self._request(lambda: self.client.list_python_packages(request=request))
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetPythonPackageRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_python_package(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )


class ArtifactRegistryNpmPackagesResource(_ArtifactRegistryBaseResource):
    ACTION_RESOURCE_TYPE = "npm_packages"
    LIST_API_NAME = "artifactregistry.npmPackages.list"
    GET_API_NAME = "artifactregistry.npmPackages.get"

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListNpmPackagesRequest(parent=parent)
            items = [
                resource_to_dict(package)
                for package in self._request(lambda: self.client.list_npm_packages(request=request))
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetNpmPackageRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_npm_package(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )


class ArtifactRegistryMavenArtifactsResource(_ArtifactRegistryBaseResource):
    ACTION_RESOURCE_TYPE = "maven_artifacts"
    LIST_API_NAME = "artifactregistry.mavenArtifacts.list"
    GET_API_NAME = "artifactregistry.mavenArtifacts.get"

    def list(self, *, parent: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListMavenArtifactsRequest(parent=parent)
            items = [
                resource_to_dict(artifact)
                for artifact in self._request(lambda: self.client.list_maven_artifacts(request=request))
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._artifactregistry_v1.GetMavenArtifactRequest(name=resource_id)
            row = resource_to_dict(self._request(lambda: self.client.get_maven_artifact(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        resource_id,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )


class ArtifactRegistryFilesResource(_ArtifactRegistryBaseResource):
    ACTION_RESOURCE_TYPE = "repositories"
    LIST_API_NAME = "artifactregistry.files.list"
    DOWNLOAD_API_NAME = "artifactregistry.repositories.downloadArtifacts"

    def list(
        self,
        *,
        parent: str,
        filter_text: str = "",
        limit: int = 0,
        action_dict=None,
    ) -> list[dict[str, Any]] | str | None:
        try:
            request = self._artifactregistry_v1.ListFilesRequest(parent=parent, filter=filter_text or "")
            items = [resource_to_dict(file_row) for file_row in self._request(lambda: self.client.list_files(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    parent,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return items[:limit] if limit and limit > 0 else items
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def list_by_owner(self, *, parent: str, owner: str, limit: int = 0, action_dict=None) -> list[dict[str, Any]] | str | None:
        normalized_owner = str(owner or "").strip()
        filter_text = f'owner="{normalized_owner}"' if normalized_owner else ""
        return self.list(parent=parent, filter_text=filter_text, limit=limit, action_dict=action_dict)

    def download(
        self,
        *,
        file_name: str,
        project_id: str,
        download_subdir: str = "Files",
        action_dict=None,
    ) -> Path | None:
        normalized_name = str(file_name or "").strip()
        if not normalized_name or "/files/" not in normalized_name:
            return None

        try:
            import google.auth.transport.requests
            import requests
        except Exception as exc:  # pragma: no cover
            handle_service_error(
                exc,
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return None

        credentials = self._ensure_scoped_credentials(getattr(self.session, "credentials", None))
        if credentials is None:
            return None

        repository_name, _, raw_file_id = normalized_name.partition("/files/")
        normalized_file_id = unquote(raw_file_id)
        encoded_file_id = quote(normalized_file_id, safe="")

        request_session = requests.Session()
        auth_request = google.auth.transport.requests.Request(session=request_session)

        def _refresh_access_token() -> str:
            if hasattr(credentials, "refresh"):
                credentials.refresh(auth_request)
            refreshed = str(getattr(credentials, "token", "") or "").strip()
            if refreshed and hasattr(self.session, "access_token"):
                self.session.access_token = refreshed
            return refreshed

        def _submit(access_token: str):
            return request_session.get(
                f"https://artifactregistry.googleapis.com/download/v1/{repository_name}/files/{encoded_file_id}:download?alt=media",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=120,
                stream=True,
            )

        try:
            access_token = str(
                getattr(credentials, "token", "")
                or getattr(self.session, "access_token", "")
                or ""
            ).strip()
            if not access_token:
                access_token = _refresh_access_token()
            if not access_token:
                raise RuntimeError("Unable to acquire an access token for Artifact Registry downloads.")
            response = _submit(access_token)
            if response.status_code == 401:
                refreshed_token = _refresh_access_token()
                if not refreshed_token:
                    raise RuntimeError("Unable to refresh an access token for Artifact Registry downloads.")
                response = _submit(refreshed_token)
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return None

        if response.status_code == 403:
            handle_service_error(
                RuntimeError(response.text),
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
                return_not_enabled=False,
            )
            return None
        if response.status_code == 404:
            handle_service_error(
                RuntimeError(response.text),
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
                return_not_enabled=False,
                not_found_label=normalized_name,
            )
            return None
        if not response.ok:
            handle_service_error(
                RuntimeError(response.text),
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
                return_not_enabled=False,
            )
            return None

        location = extract_location_from_resource_name(repository_name)
        repository_id = extract_path_tail(repository_name, default=repository_name)
        relative_name = normalized_file_id.replace("/", "_") or "artifact"
        destination = Path(
            self.session.get_download_save_path(
                service_name="artifactregistry",
                project_id=project_id,
                subdirs=[str(download_subdir or "Files").strip() or "Files"],
                filename=compact_filename_component(f"{location}_{repository_id}_{relative_name}"),
            )
        )
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                handle.write(chunk)

        if action_dict is not None:
            record_permissions(
                action_dict,
                permissions=self.DOWNLOAD_API_NAME,
                project_id=extract_project_id_from_resource(
                    normalized_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="repositories",
                resource_label=repository_name,
            )
        return destination
