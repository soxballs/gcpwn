from __future__ import annotations

import argparse
import math
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import parse_component_args, resolve_selected_components
from gcpwn.modules.resourcemanager.utilities.helpers import (
    DEFAULT_TEST_IAM_BATCH_SIZE,
    FailedPermissionReportWriter,
    RESOURCE_MANAGER_BATCH_CALLS_PER_WINDOW,
    RESOURCE_MANAGER_BATCH_WINDOW_SECONDS,
    FAILED_PERMISSION_RECORD_BATCH_SIZE,
    RESOURCE_MANAGER_FAILED_PERMISSION_CALLS_PER_WINDOW,
    RESOURCE_MANAGER_FAILED_PERMISSION_WINDOW_SECONDS,
    ResourceManagerFoldersResource,
    ResourceManagerOrganizationsResource,
    ResourceManagerProjectsResource,
    build_hierarchy_tree,
    merge_failed_permissions,
    resolve_missing_hierarchy_parents,
    write_failed_permission_reports,
)


COMPONENTS = [
    ("organizations", "Search organizations"),
    ("folders", "Search folders"),
    ("projects", "Search projects"),
]

SUMMARY_COLUMNS = ["name", "display_name", "parent", "r_type", "project_id", "r_state"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--all-permissions",
            action="store_true",
            help="Check the larger TestIamPermissions catalog for each selected resource",
        )
        parser.add_argument(
            "--no-recursive",
            action="store_true",
            help="Skip recursive list calls from discovered organizations/folders",
        )
        parser.add_argument(
            "--record-failed-permissions",
            action="store_true",
            help="Force one-permission TestIamPermissions checks and write reusable failed-permission lists to scripts/",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Resource Manager organizations, folders, and projects",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on each selected resource"},
            "get": {"help": "Fetch per-resource details and resolve missing parent display names"},
        },
    )


def _dedupe_summary_rows(rows):
    deduped = []
    seen = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("r_type") or "").strip(), str(row.get("name") or "").strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        deduped.append(dict(row))
    return deduped


def _collect_resource_rows(resource, *, args, action_dict, failed_permission_writer=None):
    rows = resource.search(debug=args.debug)
    if rows == "Not Enabled":
        return {"rows": [], "not_enabled": True}
    if not isinstance(rows, list):
        return {"rows": [], "not_enabled": False}

    detailed_rows = rows
    if args.get:
        detailed_rows = hydrate_get_request_rows(
            rows,
            lambda raw_row, payload: resource.get(
                name=resource.resource_name(payload) or (str(raw_row).strip() if isinstance(raw_row, str) else ""),
                debug=args.debug,
                quiet_not_found=False,
            ),
        )
    if detailed_rows:
        resource.save(detailed_rows)

    failed_permissions = {} if args.record_failed_permissions else None
    if args.iam:
        permission_catalog = resource.load_permissions(all_permissions=args.all_permissions)
        batch_size = FAILED_PERMISSION_RECORD_BATCH_SIZE if args.record_failed_permissions else DEFAULT_TEST_IAM_BATCH_SIZE
        for row in detailed_rows:
            resource_name = resource.resource_name(row)
            if not resource_name:
                continue
            if args.all_permissions and permission_catalog:
                total_permissions = len(permission_catalog)
                total_calls = math.ceil(total_permissions / batch_size)
                if args.record_failed_permissions:
                    calls_per_window = RESOURCE_MANAGER_FAILED_PERMISSION_CALLS_PER_WINDOW
                    window_seconds = RESOURCE_MANAGER_FAILED_PERMISSION_WINDOW_SECONDS
                else:
                    calls_per_window = RESOURCE_MANAGER_BATCH_CALLS_PER_WINDOW
                    window_seconds = RESOURCE_MANAGER_BATCH_WINDOW_SECONDS
                rate_calls_per_min = (calls_per_window * 60.0) / float(window_seconds)
                pause_windows = max(0, total_calls - 1) // max(1, calls_per_window)
                approx_eta_minutes = (pause_windows * window_seconds) / 60.0
                if args.record_failed_permissions:
                    print(
                        f"[*] Checking {total_permissions} permissions for {resource_name}; "
                        f"batch_size={FAILED_PERMISSION_RECORD_BATCH_SIZE}, "
                        f"rate≈{rate_calls_per_min:.2f} calls/min "
                        f"({calls_per_window} calls/{window_seconds}s), "
                        f"total_calls={total_calls}, ETA≈{approx_eta_minutes:.1f} min"
                    )
                else:
                    print(
                        f"[*] Checking {total_permissions} permissions for {resource_name}; "
                        f"batch_size={batch_size}, "
                        f"rate≈{rate_calls_per_min:.2f} calls/min "
                        f"({calls_per_window} calls/{window_seconds}s), "
                        f"total_calls={total_calls}, ETA≈{approx_eta_minutes:.1f} min"
                    )
            permissions = resource.test_iam_permissions(
                resource_name=resource_name,
                permissions=permission_catalog,
                debug=args.debug,
                batch_size=batch_size,
                failed_permissions=failed_permissions,
                show_permission_progress=args.record_failed_permissions,
                failed_permission_writer=failed_permission_writer,
            )
            resource.record_permissions(action_dict, row, permissions)

    return {"rows": detailed_rows, "not_enabled": False, "failed_permissions": failed_permissions or {}}


def run_module(user_args, session):
    args = _parse_args(user_args)
    if args.record_failed_permissions and not args.iam:
        args.iam = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id

    organizations_resource = ResourceManagerOrganizationsResource(session)
    folders_resource = ResourceManagerFoldersResource(session)
    projects_resource = ResourceManagerProjectsResource(session)

    resources_by_component = {
        "organizations": organizations_resource,
        "folders": folders_resource,
        "projects": projects_resource,
    }

    action_dict = {
        "organization_permissions": defaultdict(set),
        "folder_permissions": defaultdict(set),
        "project_permissions": defaultdict(set),
    }
    summary_rows = []
    collected_rows = {component_key: [] for component_key, _help_text in COMPONENTS}
    resource_manager_disabled = False
    failed_permissions = {}
    failed_permission_writer = FailedPermissionReportWriter() if args.record_failed_permissions else None

    for component_key, help_text in COMPONENTS:
        if not selected.get(component_key, False):
            continue
        print(f"[*] {help_text}")
        result = _collect_resource_rows(
            resources_by_component[component_key],
            args=args,
            action_dict=action_dict,
            failed_permission_writer=failed_permission_writer,
        )
        resource_manager_disabled = bool(resource_manager_disabled or result["not_enabled"])
        collected_rows[component_key] = list(result["rows"] or [])
        summary_rows.extend(resources_by_component[component_key].summary_rows(result["rows"] or []))
        merge_failed_permissions(failed_permissions, result.get("failed_permissions") or {})

    recursion_roots = [
        organizations_resource.resource_name(row)
        for row in collected_rows.get("organizations", [])
        if organizations_resource.resource_name(row)
    ]
    if not recursion_roots:
        recursion_roots = [
            folders_resource.resource_name(row)
            for row in collected_rows.get("folders", [])
            if folders_resource.resource_name(row)
        ]

    if not args.no_recursive and recursion_roots and not resource_manager_disabled:
        print("[*] Getting remaining projects/folders via recursive list calls")
        tree_rows = build_hierarchy_tree(
            projects_resource=projects_resource,
            folders_resource=folders_resource,
            parent_ids=recursion_roots,
            debug=args.debug,
        )
        if selected.get("projects", False):
            summary_rows.extend(projects_resource.summary_rows(tree_rows.get("projects", [])))
        if selected.get("folders", False):
            summary_rows.extend(folders_resource.summary_rows(tree_rows.get("folders", [])))

    if args.get:
        print("[*] Resolving missing parent folders/orgs via direct get calls")
        resolved = resolve_missing_hierarchy_parents(
            session,
            folders_resource=folders_resource,
            organizations_resource=organizations_resource,
            debug=args.debug,
        )
        if selected.get("folders", False):
            summary_rows.extend(folders_resource.summary_rows(resolved.get("folders", [])))
        if selected.get("organizations", False):
            summary_rows.extend(organizations_resource.summary_rows(resolved.get("organizations", [])))

    summary_rows = _dedupe_summary_rows(summary_rows)
    if not summary_rows:
        print(
            "[-] No organizations, projects, or folders were identified. "
            "You might be restricted from Resource Manager enumeration."
        )

    session.sync_projects()
    if args.iam:
        session.insert_actions(
            action_dict,
            project_id,
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )
    if args.record_failed_permissions:
        written_reports = write_failed_permission_reports(failed_permissions)
        if written_reports:
            print("[*] Wrote failed permission reports:")
            for resource_type in sorted(written_reports.keys()):
                debug_path = written_reports[resource_type]
                clean_list_path = str(debug_path).removesuffix(".txt") + "_list.txt"
                print(f"    - {resource_type}: {debug_path}")
                print(f"      clean list: {clean_list_path}")
        else:
            print("[*] No failed permissions were recorded.")

    UtilityTools.summary_wrapup(
        project_id,
        "Resource Orgs/Folders/Projects",
        summary_rows,
        SUMMARY_COLUMNS,
        primary_resource="Orgs/Folders/Projects",
        primary_sort_key="r_type",
    )
    return 1
