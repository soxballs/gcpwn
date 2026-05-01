from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_component_args, resolve_selected_components
from gcpwn.modules.bigtable.utilities.helpers import (
    BigtableAuthorizedViewsResource,
    BigtableBackupsResource,
    BigtableInstancesResource,
    BigtableTablesResource,
)


COMPONENTS = [
    ("instances", "Enumerate Bigtable instances"),
    ("tables", "Enumerate Bigtable tables (per instance)"),
    ("authorized_views", "Enumerate Bigtable authorized views (per table)"),
    ("backups", "Enumerate Bigtable backups (per instance)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        _ = parser

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Bigtable resources (read-only)",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Bigtable instances and tables"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    instances_resource = BigtableInstancesResource(session)
    tables_resource = BigtableTablesResource(session)
    backups_resource = BigtableBackupsResource(session)
    views_resource = BigtableAuthorizedViewsResource(session)

    instances = []
    if selected.get("instances", False):
        instances = instances_resource.list(project_id=project_id, action_dict=scope_actions) or []
        if args.get and instances:
            enriched = []
            for inst in instances:
                name = inst.get("name") if isinstance(inst, dict) else getattr(inst, "name", "")
                enriched.append(instances_resource.get(resource_id=name, action_dict=api_actions) or inst)
            instances = enriched
        if instances:
            instances_resource.save(instances, project_id=project_id)
            if args.iam:
                for inst in instances:
                    name = inst.get("name") if isinstance(inst, dict) else getattr(inst, "name", "")
                    if name:
                        instances_resource.test_iam_permissions(resource_id=str(name), action_dict=iam_actions)
    elif (
        selected.get("tables", False)
        or selected.get("authorized_views", False)
        or selected.get("backups", False)
    ) and not selected.get("instances", False):
        instances = get_cached_rows(
            session,
            instances_resource.TABLE_NAME,
            project_id=project_id,
            columns=["name", "instance_id", "display_name", "state", "type", "labels"],
        ) or []

    if selected.get("instances", False):
        UtilityTools.summary_wrapup(
            project_id,
            "Bigtable Instances",
            instances,
            instances_resource.COLUMNS,
            primary_resource="Instances",
            primary_sort_key="instance_id",
            )

    instance_names = []
    for inst in instances or []:
        name = inst.get("name") if isinstance(inst, dict) else getattr(inst, "name", "")
        if name:
            instance_names.append(str(name))

    all_tables = []
    if selected.get("tables", False):
        if not instance_names:
            print("[*] No cached instance parent data available for Bigtable table enumeration. Run this module with --instances.")
        else:
            for instance_name in instance_names:
                tables = tables_resource.list(instance_name=instance_name, action_dict=scope_actions) or []
                if tables:
                    if args.get:
                        tables = [
                            tables_resource.get(
                                resource_id=(table.get("name") if isinstance(table, dict) else getattr(table, "name", "")),
                                action_dict=api_actions,
                            )
                            or table
                            for table in tables
                        ]
                    if args.iam:
                        for table in tables:
                            name = table.get("name") if isinstance(table, dict) else getattr(table, "name", "")
                            if name:
                                tables_resource.test_iam_permissions(resource_id=str(name), action_dict=iam_actions)
                    tables_resource.save(tables, project_id=project_id, instance_name=instance_name)
                    all_tables.extend(tables)
            UtilityTools.summary_wrapup(
                project_id,
                "Bigtable Tables",
                all_tables,
                tables_resource.COLUMNS,
                primary_resource="Tables",
                primary_sort_key="table_id",
                )

    if selected.get("backups", False):
        if not instance_names:
            print("[*] No cached instance parent data available for Bigtable backup enumeration. Run this module with --instances.")
        else:
            all_backups = []
            for instance_name in instance_names:
                backups = backups_resource.list(instance_name=instance_name, action_dict=scope_actions) or []
                if backups:
                    if args.get:
                        backups = [
                            backups_resource.get(
                                resource_id=(backup.get("name") if isinstance(backup, dict) else getattr(backup, "name", "")),
                                action_dict=api_actions,
                            )
                            or backup
                            for backup in backups
                        ]
                    backups_resource.save(backups, project_id=project_id, instance_name=instance_name)
                    all_backups.extend(backups)
            UtilityTools.summary_wrapup(
                project_id,
                "Bigtable Backups",
                all_backups,
                backups_resource.COLUMNS,
                primary_resource="Backups",
                primary_sort_key="backup_id",
            )

    if selected.get("authorized_views", False):
        table_source = all_tables
        if not table_source:
            table_source = get_cached_rows(
                session,
                tables_resource.TABLE_NAME,
                project_id=project_id,
                columns=["name", "table_id", "instance_name", "granularity", "deletion_protection"],
            ) or []

        table_names: list[str] = []
        for table in table_source:
            name = table.get("name") if isinstance(table, dict) else getattr(table, "name", "")
            if name:
                table_names.append(str(name))

        if not table_names:
            print("[*] No cached table parent data available for Bigtable authorized view enumeration. Run this module with --tables.")
        else:
            all_views = []
            for table_name in table_names:
                views = views_resource.list(table_name=table_name, action_dict=scope_actions) or []
                if views:
                    if args.get:
                        views = [
                            views_resource.get(
                                resource_id=(view.get("name") if isinstance(view, dict) else getattr(view, "name", "")),
                                action_dict=api_actions,
                            )
                            or view
                            for view in views
                        ]
                    views_resource.save(views, project_id=project_id, table_name=table_name)
                    all_views.extend(views)
            UtilityTools.summary_wrapup(
                project_id,
                "Bigtable Authorized Views",
                all_views,
                views_resource.COLUMNS,
                primary_resource="Authorized Views",
                primary_sort_key="authorized_view_id",
            )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="bigtable_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="bigtable_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="bigtable_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
