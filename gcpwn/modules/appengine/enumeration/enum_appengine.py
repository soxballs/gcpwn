from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, name_from_input
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_component_args, parse_csv_file_args, resolve_selected_components
from gcpwn.modules.appengine.utilities.helpers import (
    AppEngineAppsResource,
    AppEngineInstancesResource,
    AppEngineServicesResource,
    AppEngineVersionsResource,
    row_names,
)


COMPONENTS = [
    ("app", "Enumerate App Engine application"),
    ("services", "Enumerate App Engine services"),
    ("versions", "Enumerate App Engine versions (per service)"),
    ("instances", "Enumerate App Engine instances (per version)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--app-name",
            required=False,
            help="Application name as `apps/PROJECT_ID` or plain `PROJECT_ID`.",
        )
        parser.add_argument(
            "--service-ids",
            required=False,
            help=(
                "Service IDs in comma-separated format. Accepts short IDs like `default` "
                "or full names like `apps/PROJECT_ID/services/SERVICE_ID`."
            ),
        )
        parser.add_argument(
            "--service-ids-file",
            required=False,
            help="File containing service IDs, one per line or comma-separated, using the same formats as --service-ids.",
        )
        parser.add_argument(
            "--version-ids",
            required=False,
            help=(
                "Version IDs in comma-separated format. Accepts `SERVICE_ID/VERSION_ID` "
                "pairs like `default/v1` or full names like "
                "`apps/PROJECT_ID/services/SERVICE_ID/versions/VERSION_ID`."
            ),
        )
        parser.add_argument(
            "--version-ids-file",
            required=False,
            help="File containing version IDs, one per line or comma-separated, using the same formats as --version-ids.",
        )
        parser.add_argument(
            "--instance-ids",
            required=False,
            help=(
                "Instance IDs in comma-separated format. Accepts "
                "`SERVICE_ID/VERSION_ID/INSTANCE_ID` triples or full names like "
                "`apps/PROJECT_ID/services/SERVICE_ID/versions/VERSION_ID/instances/INSTANCE_ID`."
            ),
        )
        parser.add_argument(
            "--instance-ids-file",
            required=False,
            help="File containing instance IDs, one per line or comma-separated, using the same formats as --instance-ids.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate App Engine resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )

def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id

    app_name_arg = str(getattr(args, "app_name", "") or "").strip()
    service_ids = parse_csv_file_args(getattr(args, "service_ids", None), getattr(args, "service_ids_file", None))
    version_ids = parse_csv_file_args(getattr(args, "version_ids", None), getattr(args, "version_ids_file", None))
    instance_ids = parse_csv_file_args(getattr(args, "instance_ids", None), getattr(args, "instance_ids_file", None))

    if app_name_arg:
        args.app = True
    if service_ids:
        args.services = True
    if version_ids:
        args.versions = True
    if instance_ids:
        args.instances = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    try:
        app_name = name_from_input(
            app_name_arg or project_id,
            project_id=project_id,
            template=("apps", 0),
            passthrough_prefixes=("apps/",),
            error_message="Invalid app name format. Use PROJECT_ID or apps/PROJECT_ID.",
        )
        service_names = [
            name_from_input(
                service_id,
                project_id=project_id,
                template=("apps", "{project_id}", "services", 0),
                passthrough_prefixes=("apps/",),
                error_message="Invalid service ID format. Use SERVICE_ID or apps/PROJECT_ID/services/SERVICE_ID.",
            )
            for service_id in service_ids
        ]
        version_names = [
            name_from_input(
                version_id,
                project_id=project_id,
                template=("apps", "{project_id}", "services", 0, "versions", 1),
                passthrough_prefixes=("apps/",),
                error_message=(
                    "Invalid version ID format. Use SERVICE_ID/VERSION_ID or "
                    "apps/PROJECT_ID/services/SERVICE_ID/versions/VERSION_ID."
                ),
            )
            for version_id in version_ids
        ]
        instance_names = [
            name_from_input(
                instance_id,
                project_id=project_id,
                template=("apps", "{project_id}", "services", 0, "versions", 1, "instances", 2),
                passthrough_prefixes=("apps/",),
                error_message=(
                    "Invalid instance ID format. Use SERVICE_ID/VERSION_ID/INSTANCE_ID or "
                    "apps/PROJECT_ID/services/SERVICE_ID/versions/VERSION_ID/instances/INSTANCE_ID."
                ),
            )
            for instance_id in instance_ids
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    try:
        app_resource = AppEngineAppsResource(session)
        services_resource = AppEngineServicesResource(session)
        versions_resource = AppEngineVersionsResource(session)
        instances_resource = AppEngineInstancesResource(session)
    except RuntimeError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    services_rows: list[dict] = []
    versions_rows: list[dict] = []

    if selected.get("app", False):
        manual_app_requested = bool(app_name_arg)
        row = None

        if manual_app_requested and args.get:
            row = app_resource.get(name=app_name, action_dict=api_actions)
        elif not manual_app_requested:
            row = app_resource.get(project_id=project_id, action_dict=api_actions)

        if isinstance(row, dict) and row:
            app_resource.save(row, project_id=project_id)

        show_app_summary = bool(row) or not manual_app_requested
        if show_app_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "App Engine Application",
                [row] if row else [],
                app_resource.COLUMNS,
                primary_resource="App",
                primary_sort_key="location_id",
            )
        elif args.get:
            print("[*] No App Engine application found for the supplied --app-name.")
        else:
            print("[*] Manual --app-name supplied without --get; skipping application summary.")

    if selected.get("services", False):
        manual_services_requested = bool(service_names)
        services_rows = []

        if manual_services_requested and args.get:
            for name in service_names:
                row = services_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    services_rows.append(row)
        elif not manual_services_requested:
            listed = services_resource.list(project_id=project_id, action_dict=scope_actions)
            if listed not in ("Not Enabled", None):
                services_rows = listed or []
            if services_rows and args.get:
                services_rows = hydrate_get_request_rows(
                    services_rows,
                    lambda _row, payload: services_resource.get(
                        name=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if services_rows:
            services_resource.save(services_rows, project_id=project_id)

        show_services_summary = bool(services_rows) or not manual_services_requested
        if show_services_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "App Engine Services",
                services_rows,
                services_resource.COLUMNS,
                primary_resource="Services",
                primary_sort_key="service_id",
            )
        elif args.get:
            print("[*] No App Engine services found for the supplied --service-ids.")
        else:
            print("[*] Manual --service-ids supplied without --get; skipping services summary.")

    if selected.get("versions", False):
        manual_versions_requested = bool(version_names)
        manual_service_parents_requested = bool(service_names)
        versions_rows = []
        parent_service_names = list(service_names)

        if manual_versions_requested and args.get:
            for name in version_names:
                row = versions_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    versions_rows.append(row)
        elif not manual_versions_requested:
            if not parent_service_names:
                parent_service_names = row_names(services_rows)
            if not parent_service_names and not selected.get("services", False):
                cached_services = get_cached_rows(
                    session,
                    services_resource.TABLE_NAME,
                    project_id=project_id,
                    columns=["name"],
                ) or []
                parent_service_names = row_names(cached_services)
            if not parent_service_names:
                print("[*] No App Engine service parent data available for version enumeration. Run this module with --services or supply --service-ids.")
            else:
                for service_name in parent_service_names:
                    service_id = extract_path_tail(service_name, default=str(service_name or "").strip())
                    listed = versions_resource.list(
                        project_id=project_id,
                        service_id=service_id,
                        action_dict=scope_actions,
                    )
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    versions_resource.save(listed, project_id=project_id, service_name=service_name)
                    versions_rows.extend(listed)
                if args.get and versions_rows:
                    versions_rows = hydrate_get_request_rows(
                        versions_rows,
                        lambda _row, payload: versions_resource.get(
                            name=str(payload.get("name") or "").strip(),
                            action_dict=api_actions,
                        ),
                    )

        if versions_rows:
            for row in versions_rows:
                row_name = str(row.get("name") or "").strip()
                row_project = extract_path_segment(row_name, "apps")
                row_service = extract_path_segment(row_name, "services")
                service_name = (
                    f"apps/{row_project}/services/{row_service}"
                    if row_project and row_service
                    else row_name.partition("/versions/")[0]
                )
                versions_resource.save([row], project_id=project_id, service_name=service_name)

        show_versions_summary = bool(versions_rows) or (not manual_versions_requested and bool(parent_service_names))
        if show_versions_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "App Engine Versions",
                versions_rows,
                versions_resource.COLUMNS,
                primary_resource="Versions",
                primary_sort_key="version_id",
            )
        elif manual_versions_requested and args.get:
            print("[*] No App Engine versions found for the supplied --version-ids.")
        elif manual_versions_requested:
            print("[*] Manual --version-ids supplied without --get; skipping versions summary.")
        elif manual_service_parents_requested:
            print("[*] No App Engine versions found for the supplied --service-ids.")

    if selected.get("instances", False):
        all_instances: list[dict] = []
        manual_instances_requested = bool(instance_names)
        manual_version_parents_requested = bool(version_names)
        parent_version_names = list(version_names)

        if manual_instances_requested and args.get:
            for name in instance_names:
                row = instances_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    all_instances.append(row)
        elif not manual_instances_requested:
            if not parent_version_names:
                parent_version_names = row_names(versions_rows)
            if not parent_version_names and not selected.get("versions", False):
                cached_versions = get_cached_rows(
                    session,
                    versions_resource.TABLE_NAME,
                    project_id=project_id,
                    columns=["name", "version_id", "service_name", "runtime", "env", "serving_status", "create_time"],
                ) or []
                parent_version_names = row_names(cached_versions)
            if not parent_version_names:
                print("[*] No App Engine version parent data available for instance enumeration. Run this module with --versions or supply --version-ids.")
            else:
                for version_name in parent_version_names:
                    service_id = extract_path_segment(version_name, "services")
                    version_id = extract_path_segment(version_name, "versions")
                    if not service_id or not version_id:
                        continue
                    listed = instances_resource.list(
                        project_id=project_id,
                        service_id=service_id,
                        version_id=version_id,
                        action_dict=scope_actions,
                    )
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    if args.get:
                        listed = hydrate_get_request_rows(
                            listed,
                            lambda _row, payload: instances_resource.get(
                                name=str(payload.get("name") or "").strip(),
                                action_dict=api_actions,
                            ),
                        )
                    all_instances.extend(listed)

        if all_instances:
            for row in all_instances:
                row_name = str(row.get("name") or "").strip()
                row_project = extract_path_segment(row_name, "apps")
                row_service = extract_path_segment(row_name, "services")
                row_version = extract_path_segment(row_name, "versions")
                version_name = (
                    f"apps/{row_project}/services/{row_service}/versions/{row_version}"
                    if row_project and row_service and row_version
                    else row_name.partition("/instances/")[0]
                )
                instances_resource.save([row], project_id=project_id, version_name=version_name)

        show_instances_summary = bool(all_instances) or (not manual_instances_requested and bool(parent_version_names))
        if show_instances_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "App Engine Instances",
                all_instances,
                instances_resource.COLUMNS,
                primary_resource="Instances",
                primary_sort_key="instance_id",
            )
        elif manual_instances_requested and args.get:
            print("[*] No App Engine instances found for the supplied --instance-ids.")
        elif manual_instances_requested:
            print("[*] Manual --instance-ids supplied without --get; skipping instances summary.")
        elif manual_version_parents_requested:
            print("[*] No App Engine instances found for the supplied --version-ids.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="appengine_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="appengine_actions_allowed")

    return 1
