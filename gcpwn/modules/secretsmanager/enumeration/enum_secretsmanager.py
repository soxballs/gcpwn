from __future__ import annotations

import argparse
from collections import defaultdict

from google.cloud.secretmanager_v1.types import Secret

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.service_runtime import parse_component_args, parse_csv_file_args, resolve_selected_components
from gcpwn.modules.secretsmanager.utilities.helpers import HashableSecret, SecretVersionsResource, SecretsResource


COMPONENTS = [
    ("secrets", "Enumerate secret metadata"),
    ("versions", "Enumerate secret versions"),
    ("values", "Attempt to access secret values"),
]


def _summary_for_empty(project_id: str, primary_resource: str) -> None:
    print(f"[*] No {primary_resource} found in project {project_id}.")


def _parse_range(range_str):
    if not range_str:
        return []
    numbers = []
    for part in range_str.split(","):
        token = part.strip()
        if not token:
            continue
        if token == "latest":
            numbers.append(token)
        elif "-" in token:
            start, end = token.split("-", 1)
            numbers.extend(range(int(start), int(end) + 1))
        else:
            numbers.append(int(token))
    return numbers


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        secret_group = parser.add_mutually_exclusive_group(required=False)
        secret_group.add_argument("--secret-names", type=str, help="Secrets in format projects/<project_number>/secrets/<secret_name>")
        secret_group.add_argument("--secret-names-file", type=str, help="File containing secret resource names")
        parser.add_argument("--version-range", type=_parse_range, help="Version range like 1-5,7,latest")

    return parse_component_args(
        user_args,
        description="Enumerate Secret Manager resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on secrets and versions"},
            "download": {"help": "Download secret values to local files"},
        },
    )


def _resource_name(value) -> str:
    if isinstance(value, str):
        return value
    return str((value or {}).get("name") or "")


def run_module(user_args, session):
    args = _parse_args(user_args)
    secret_name_inputs = parse_csv_file_args(
        getattr(args, "secret_names", None),
        getattr(args, "secret_names_file", None),
    )
    if secret_name_inputs:
        args.secrets = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    secrets_resource = SecretsResource(session)
    versions_resource = SecretVersionsResource(session)
    resource_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    secret_api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    secret_iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    secrets = defaultdict(dict)
    download_paths_by_project: dict[str, list[str]] = defaultdict(list)
    requested_secret_names = bool(secret_name_inputs)
    secret_list_failed = False
    secret_names_discovered = False
    enumerate_secret_resources = (
        selected.get("secrets", False) or selected.get("versions", False) or selected.get("values", False)
    )

    if secret_name_inputs:
        print(f"[*] Using provided secret names for project {project_id}.")
        for secret_name in secret_name_inputs:
            secrets[project_id][HashableSecret(Secret(name=secret_name), validated=False)] = {}
        secret_names_discovered = bool(secret_name_inputs)
    elif enumerate_secret_resources:
        print(f"[*] Enumerating Secret Names in project {project_id}...")
        found = secrets_resource.list(project_id=project_id, action_dict=resource_actions)
        if found not in ("Not Enabled", None):
            secrets_resource.save(found, project_id=project_id)
            found_count = len(found)
            secret_names_discovered = found_count > 0
            for secret in found:
                secrets[project_id][HashableSecret(secret)] = {}
        else:
            secret_list_failed = True

    if (
        enumerate_secret_resources
        and not requested_secret_names
        and not secret_list_failed
        and not secret_names_discovered
    ):
        _summary_for_empty(project_id, "Secret Names")

    for target_project_id, secret_dict in secrets.items():
        if not secret_dict:
            continue
        for secret in list(secret_dict):
            name = secret.name
            if selected.get("versions", False) or selected.get("values", False):
                short_secret_name = extract_path_tail(name, default=name)
                print(f"[*] Enumerating Versions for secret {short_secret_name} in project {target_project_id}.")
            if selected.get("secrets", False) and args.get:
                secret_get = secrets_resource.get(resource_id=name, action_dict=secret_api_actions)
                if secret_get and secret_get != 404:
                    secrets_resource.save([secret_get], project_id=target_project_id)
                    secret.validated = True

            if args.iam and selected.get("secrets", False):
                perms = secrets_resource.test_iam_permissions(resource_id=name, action_dict=secret_iam_actions)
                for permission in perms:
                    secret.validated = True

            if not (selected.get("versions", False) or selected.get("values", False)):
                continue

            versions = [f"{name}/versions/{version}" for version in args.version_range] if args.version_range else versions_resource.list(secret_name=name)
            if versions in (None, 404):
                continue

            if selected.get("versions", False) and not args.version_range and versions:
                for version in versions:
                    version_name = _resource_name(version)
                    if version_name:
                        secret_dict[secret][extract_path_tail(version_name, default=version_name)] = None
                    versions_resource.save([version], project_id=target_project_id)

            for version in versions:
                version_name = _resource_name(version)
                if not version_name:
                    continue
                version_id = extract_path_tail(version_name, default=version_name)

                if selected.get("versions", False) and args.get:
                    version_get = versions_resource.get(resource_id=version_name, action_dict=secret_api_actions)
                    if version_get and version_get != 404:
                        versions_resource.save([version_get], project_id=target_project_id)
                        secret_dict[secret][version_id] = None

                if args.iam and (selected.get("versions", False) or selected.get("values", False)):
                    perms = versions_resource.test_iam_permissions(resource_id=version_name, action_dict=secret_iam_actions)
                    for permission in perms:
                        secret_dict[secret][version_id] = None

                if selected.get("values", False) or args.download:
                    value = versions_resource.access_value(resource_id=version_name, action_dict=secret_api_actions)
                    if value:
                        if selected.get("values", False):
                            decoded = value.payload.data.decode("utf-8", errors="replace")
                            secret_dict[secret][version_id] = decoded
                        session.insert_data(
                            "secretsmanager_secretversions",
                            {
                                "primary_keys_to_match": {"name": version_name},
                                "data_to_insert": {"secret_value": value.payload.data},
                            },
                            update_only=True,
                        )
                        if args.download:
                            download_path = versions_resource.download(
                                project_id=target_project_id,
                                secret_name=short_secret_name,
                                version=version_id,
                                payload=value.payload.data,
                            )
                            if download_path:
                                download_paths_by_project[target_project_id].append(str(download_path))

        if has_recorded_actions(resource_actions):
            session.insert_actions(resource_actions, target_project_id, column_name="secret_actions_allowed")
        if has_recorded_actions(secret_api_actions):
            session.insert_actions(secret_api_actions, target_project_id, column_name="secret_actions_allowed")
        if has_recorded_actions(secret_iam_actions):
            session.insert_actions(
                secret_iam_actions,
                target_project_id,
                column_name="secret_actions_allowed",
                evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
            )

    for target_project_id, secret_dict in secrets.items():
        final = {}
        for secret, versions in secret_dict.items():
            if secret.validated or not (args.secret_names or args.secret_names_file):
                short_name = extract_path_tail(secret.name, default=secret.name)
                final[HashableSecret(Secret(name=short_name), validated=True)] = [f"{version}: {value}" for version, value in versions.items()]
        UtilityTools.summary_wrapup(
            target_project_id,
            "Secret Manager",
            final,
            ["name", "expire_time"],
            primary_resource="Secret Names",
            secondary_title_name="versions: <secrets>",
            )
        for download_path in download_paths_by_project.get(target_project_id, []):
            print(f"[*] Wrote Secret Manager value to {download_path}")
        if args.download:
            downloaded_count = len(download_paths_by_project.get(target_project_id, []))
            if downloaded_count:
                print(f"[*] Downloaded {downloaded_count} secret value file(s) for project {target_project_id}.")
            else:
                print(f"[*] No secret values were downloaded for project {target_project_id}.")

    return 1
