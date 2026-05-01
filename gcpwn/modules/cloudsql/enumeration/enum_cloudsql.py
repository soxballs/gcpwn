from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import (
    parse_component_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.cloudsql.utilities.helpers import (
    CloudSqlConnectionsResource,
    CloudSqlConfigsResource,
    CloudSqlDatabasesResource,
    CloudSqlInstancesResource,
    CloudSqlUsersResource,
)


COMPONENTS = [
    ("instances", "Enumerate Cloud SQL instances"),
    ("connections", "Summarize Cloud SQL connection details"),
    ("configs", "Summarize cached Cloud SQL instance configuration fields"),
    ("databases", "Enumerate Cloud SQL databases (per instance)"),
    ("users", "Enumerate Cloud SQL users (per instance)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--instance-names",
            type=str,
            required=False,
            help="Instance names in comma-separated format using Cloud SQL instance IDs.",
        )
        parser.add_argument(
            "--instance-names-file",
            type=str,
            required=False,
            help="File containing instance names, one per line or comma-separated, using the same formats as --instance-names.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud SQL resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )
def run_module(user_args, session):
    args = _parse_args(user_args)
    if args.instance_names or args.instance_names_file:
        args.instances = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id

    instances_resource = CloudSqlInstancesResource(session)
    connections_resource = CloudSqlConnectionsResource(session)
    configs_resource = CloudSqlConfigsResource(session)
    db_resource = CloudSqlDatabasesResource(session)
    users_resource = CloudSqlUsersResource(session)
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    manual_instance_names = instances_resource.manual_targets(
        instance_names=getattr(args, "instance_names", None),
        instance_file=getattr(args, "instance_names_file", None),
    )
    instance_result = {"rows": [], "manual_requested": bool(manual_instance_names), "target_names": list(manual_instance_names)}

    if selected.get("instances", False):
        instance_result = instances_resource.enumerate(
            project_id=project_id,
            instance_names=manual_instance_names,
            include_get=args.get,
            scope_actions=scope_actions,
            api_actions=api_actions,
        )
        instances = instance_result["rows"]
        show_instance_summary = bool(instances) or not instance_result["manual_requested"]
        if show_instance_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud SQL Instances",
                instances,
                instances_resource.COLUMNS,
                primary_resource="Instances",
                primary_sort_key="name",
                )
        elif args.get:
            print("[*] No Cloud SQL instances found for the supplied --instance-names.")
        else:
            print("[*] Manual --instance-names supplied without --get; skipping instance summary.")

    targets = list(instance_result["target_names"])
    if (
        selected.get("connections", False)
        or selected.get("configs", False)
        or selected.get("databases", False)
        or selected.get("users", False)
    ) and not targets and not selected.get("instances", False):
        targets = instances_resource.resolve_cached_targets(project_id=project_id)

    if selected.get("connections", False) or selected.get("configs", False):
        if manual_instance_names and args.get and not instance_result["rows"]:
            fetched_rows = [
                row
                for row in (
                    instances_resource.get(project_id=project_id, resource_id=name, action_dict=api_actions)
                    for name in manual_instance_names
                )
                if row
            ]
            if fetched_rows:
                instances_resource.save(fetched_rows, project_id=project_id)

    if selected.get("connections", False):
        connection_rows = connections_resource.list(project_id=project_id, instance_names=targets or manual_instance_names)
        UtilityTools.summary_wrapup(
            project_id,
            "Cloud SQL Connections",
            connection_rows,
            connections_resource.COLUMNS,
            primary_resource="Connections",
            primary_sort_key="region",
        )

    if selected.get("configs", False):
        config_rows = configs_resource.list(project_id=project_id, instance_names=targets or manual_instance_names)
        UtilityTools.summary_wrapup(
            project_id,
            "Cloud SQL Instance Configs",
            config_rows,
            configs_resource.COLUMNS,
            primary_resource="Instances",
            primary_sort_key="region",
            )

    if selected.get("databases", False):
        if not targets:
            print_missing_dependency(
                component_name="Cloud SQL databases",
                dependency_name="Instances",
                module_name="enum_cloudsql",
                manual_flags=["--instance-names", "--instance-names-file"],
            )
        else:
            all_dbs = db_resource.enumerate(project_id=project_id, instance_names=targets, action_dict=api_actions)
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud SQL Databases",
                all_dbs,
                db_resource.COLUMNS,
                primary_resource="Databases",
                primary_sort_key="instance",
                )

    if selected.get("users", False):
        if not targets:
            print_missing_dependency(
                component_name="Cloud SQL users",
                dependency_name="Instances",
                module_name="enum_cloudsql",
                manual_flags=["--instance-names", "--instance-names-file"],
            )
        else:
            all_users = users_resource.enumerate(project_id=project_id, instance_names=targets, action_dict=api_actions)
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud SQL Users",
                all_users,
                users_resource.COLUMNS,
                primary_resource="Users",
                primary_sort_key="instance",
                )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="cloudsql_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="cloudsql_actions_allowed")

    return 1
