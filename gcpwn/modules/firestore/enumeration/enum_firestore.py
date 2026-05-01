from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import parse_component_args, print_missing_dependency, resolve_selected_components
from gcpwn.modules.firestore.utilities.helpers import (
    FirestoreCollectionsResource,
    FirestoreDatabasesResource,
    FirestoreRulesResource,
)


COMPONENTS = [
    ("databases", "Enumerate Firestore databases"),
    ("rules", "Enumerate Firestore security rules metadata"),
    ("collections", "Enumerate top-level Firestore collections"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--database-ids",
            type=str,
            required=False,
            help="Firestore database IDs in comma-separated format (for example `(default)` or a named database ID).",
        )
        parser.add_argument(
            "--database-ids-file",
            type=str,
            required=False,
            help="File containing Firestore database IDs, one per line or comma-separated.",
        )
        parser.add_argument(
            "--download-limit",
            type=int,
            default=0,
            help="Limit documents downloaded per collection. 0 means unlimited.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Firestore resources (read-only)",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download_limit", 0) < 0:
        UtilityTools.print_error("--download-limit must be 0 or greater.")
        return -1

    if args.download:
        args.collections = True
    if args.database_ids or args.database_ids_file:
        args.databases = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id

    db_resource = FirestoreDatabasesResource(session)
    rules_resource = FirestoreRulesResource(session)
    collections_resource = FirestoreCollectionsResource(session)
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    manual_database_ids = db_resource.manual_targets(
        database_ids=getattr(args, "database_ids", None),
        database_file=getattr(args, "database_ids_file", None),
    )
    target_database_ids: list[str] = list(manual_database_ids)
    database_rows: list[dict] = []

    if selected.get("databases", False):
        if manual_database_ids and args.get:
            database_rows = [
                row
                for row in (
                    db_resource.get(project_id=project_id, resource_id=database_id, action_dict=api_actions)
                    for database_id in manual_database_ids
                )
                if row
            ]
        elif manual_database_ids:
            database_rows = []
        else:
            listed = db_resource.list(project_id=project_id, action_dict=scope_actions)
            if listed not in ("Not Enabled", None):
                database_rows = listed or []
            if args.get and database_rows:
                database_rows = [
                    db_resource.get(project_id=project_id, resource_id=row.get("name", ""), action_dict=api_actions) or row
                    for row in database_rows
                ]
        if database_rows:
            db_resource.save(database_rows, project_id=project_id)
        if not target_database_ids:
            target_database_ids = db_resource.resolve_cached_targets(project_id=project_id) or [
                str(row.get("database_id") or "").strip()
                for row in database_rows
                if str(row.get("database_id") or "").strip()
            ]

        show_database_summary = bool(database_rows) or not manual_database_ids
        if show_database_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Firestore Databases",
                database_rows,
                db_resource.COLUMNS,
                primary_resource="Databases",
                primary_sort_key="database_id",
                )
        if manual_database_ids and not database_rows:
            if args.get:
                print("[*] No Firestore databases found for the supplied --database-ids.")
            else:
                print("[*] Manual --database-ids supplied without --get; skipping database summary.")

    if (
        selected.get("rules", False) or selected.get("collections", False)
    ) and not target_database_ids:
        target_database_ids = db_resource.resolve_cached_targets(project_id=project_id)
        if not target_database_ids:
            listed = db_resource.list(project_id=project_id, action_dict=scope_actions)
            if isinstance(listed, list) and listed:
                db_resource.save(listed, project_id=project_id)
                target_database_ids = [
                    str(row.get("database_id") or "").strip()
                    for row in listed
                    if str(row.get("database_id") or "").strip()
                ]

    if selected.get("rules", False):
        rules_rows = rules_resource.enumerate(
            project_id=project_id,
            include_get=args.get,
            database_ids=target_database_ids,
            scope_actions=scope_actions,
            api_actions=api_actions,
        )
        if rules_rows:
            rules_resource.save(rules_rows, project_id=project_id)
        UtilityTools.summary_wrapup(
            project_id,
            "Firestore Rules",
            rules_rows,
            rules_resource.COLUMNS,
            primary_resource="Rules",
            primary_sort_key="database_id",
            )

    if selected.get("collections", False):
        if not target_database_ids:
            print_missing_dependency(
                component_name="Firestore collections",
                dependency_name="Databases",
                module_name="enum_firestore",
                manual_flags=["--database-ids", "--database-ids-file"],
            )
        else:
            collection_rows: list[dict] = []
            for database_id in target_database_ids:
                rows = collections_resource.list(
                    project_id=project_id,
                    database_id=database_id,
                    action_dict=api_actions,
                )
                if not isinstance(rows, list) or not rows:
                    continue
                collections_resource.save(rows, project_id=project_id)
                collection_rows.extend(rows)

            UtilityTools.summary_wrapup(
                project_id,
                "Firestore Collections",
                collection_rows,
                collections_resource.COLUMNS,
                primary_resource="Collections",
                primary_sort_key="database_id",
                )

            if args.download:
                for database_id in target_database_ids:
                    collections_resource.download_database_documents(
                        project_id=project_id,
                        database_id=database_id,
                        limit=args.download_limit,
                        action_dict=api_actions,
                    )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="firestore_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="firestore_actions_allowed")

    return 1
