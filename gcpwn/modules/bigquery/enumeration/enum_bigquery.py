from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import (
    parse_component_args,
    parse_csv_arg,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.bigquery.utilities.helpers import BigQueryDatasetsResource, BigQueryRoutinesResource, BigQueryTablesResource


COMPONENTS = [
    ("datasets", "Enumerate BigQuery datasets"),
    ("tables", "Enumerate BigQuery tables"),
    ("routines", "Enumerate BigQuery routines"),
]

DOWNLOAD_SCOPE_ALIASES = {
    "table": "table",
}
ALL_DOWNLOAD_SCOPES = ["table"]


def _parse_download_scopes(raw_value: str | None) -> list[str]:
    if raw_value is None:
        return []
    tokens = [str(token).strip().lower() for token in parse_csv_arg(raw_value) if str(token).strip()]
    if not tokens:
        return list(ALL_DOWNLOAD_SCOPES)

    normalized: list[str] = []
    for token in tokens:
        mapped = DOWNLOAD_SCOPE_ALIASES.get(token)
        if mapped is None:
            raise ValueError(
                "Invalid BigQuery download scope. Supported values: "
                + ", ".join(sorted(set(DOWNLOAD_SCOPE_ALIASES)))
            )
        if mapped not in normalized:
            normalized.append(mapped)
    return normalized


def _limit_items(items: list[str], limit: int) -> list[str]:
    if limit <= 0:
        return list(items)
    return list(items[:limit])


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--dataset-ids", type=str, help="Dataset IDs in comma-separated format using `project.dataset`.")
        parser.add_argument("--dataset-ids-file", type=str, help="File containing dataset IDs, one per line or comma-separated, using the same formats as --dataset-ids.")
        parser.add_argument("--table-ids", type=str, help="Table IDs in comma-separated format using `project.dataset.table`.")
        parser.add_argument("--table-ids-file", type=str, help="File containing table IDs, one per line or comma-separated, using the same formats as --table-ids.")
        parser.add_argument("--routine-ids", type=str, help="Routine IDs in comma-separated format using `project.dataset.routine`.")
        parser.add_argument("--routine-ids-file", type=str, help="File containing routine IDs, one per line or comma-separated, using the same formats as --routine-ids.")
        parser.add_argument(
            "--download",
            nargs="?",
            const="table",
            default=None,
            help="Download BigQuery table data. Optional CSV scopes: table.",
        )
        parser.add_argument(
            "--download-limit",
            type=int,
            default=0,
            help="Limit downloaded resources per parent. For table downloads, this caps tables per dataset. 0 means unlimited.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate BigQuery resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on tables and routines"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    try:
        download_scopes = _parse_download_scopes(getattr(args, "download", None))
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    if getattr(args, "download_limit", 0) < 0:
        UtilityTools.print_error("--download-limit must be 0 or greater.")
        return -1

    dataset_ids = parse_csv_file_args(args.dataset_ids, getattr(args, "dataset_ids_file", None))
    table_ids = parse_csv_file_args(args.table_ids, getattr(args, "table_ids_file", None))
    routine_ids = parse_csv_file_args(args.routine_ids, getattr(args, "routine_ids_file", None))

    if dataset_ids:
        args.datasets = True
    if table_ids:
        args.tables = True
    if routine_ids:
        args.routines = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    dataset_resource = BigQueryDatasetsResource(session)
    table_resource = BigQueryTablesResource(session)
    routine_resource = BigQueryRoutinesResource(session)

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    datasets: list = []
    tables: list = []
    routines: list = []
    dataset_refs: list[str] = list(dataset_ids)
    tables_by_dataset: dict[str, list] = defaultdict(list)
    routines_by_dataset: dict[str, list] = defaultdict(list)

    if selected.get("datasets", False):
        manual_dataset_ids_requested = bool(dataset_ids)

        if manual_dataset_ids_requested and args.get:
            datasets = [
                dataset
                for dataset_id in dataset_ids
                for dataset in [dataset_resource.get(resource_id=dataset_id, action_dict=api_actions)]
                if dataset
            ]
        elif not manual_dataset_ids_requested:
            datasets = dataset_resource.list(project_id=project_id, action_dict=scope_actions) or []
            if args.get and datasets:
                detailed_datasets = []
                for dataset in datasets:
                    resource_id = dataset_resource._resource_id_from_row(dataset)
                    detailed = dataset_resource.get(resource_id=resource_id, action_dict=api_actions) if resource_id else None
                    detailed_datasets.append(detailed or dataset)
                datasets = detailed_datasets

        if datasets:
            dataset_resource.save(datasets)

        if not dataset_refs:
            dataset_refs = [
                dataset_resource._resource_id_from_row(dataset)
                for dataset in datasets
                if dataset_resource._resource_id_from_row(dataset)
            ]

        show_dataset_summary = bool(datasets) or not manual_dataset_ids_requested
        if show_dataset_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "BigQuery Datasets",
                datasets,
                dataset_resource.COLUMNS,
                primary_resource="Datasets",
                primary_sort_key="full_dataset_id",
            )
        elif args.get:
            print("[*] No BigQuery datasets found for the supplied --dataset-ids.")
        else:
            print("[*] Manual --dataset-ids supplied without --get; skipping dataset summary.")

    if selected.get("tables", False):
        manual_table_ids_requested = bool(table_ids)

        if manual_table_ids_requested:
            if args.get:
                tables = [
                    table
                    for table_id in table_ids
                    for table in [table_resource.get(resource_id=table_id, action_dict=api_actions)]
                    if table
                ]
        else:
            table_parent_refs = dataset_ids or dataset_refs
            if not table_parent_refs:
                print_missing_dependency(
                    component_name="BigQuery tables",
                    dependency_name="Datasets",
                    module_name="enum_bigquery",
                    manual_flags=["--dataset-ids"],
                )
            else:
                for dataset_id in table_parent_refs:
                    listed = table_resource.list(dataset_id=dataset_id, action_dict=scope_actions) or []
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    if args.get:
                        detailed_tables = []
                        for table in listed:
                            resource_id = table_resource._resource_id_from_row(table)
                            detailed = table_resource.get(resource_id=resource_id, action_dict=api_actions) if resource_id else None
                            detailed_tables.append(detailed or table)
                        listed = detailed_tables
                    tables_by_dataset[dataset_id].extend(listed)
                    tables.extend(listed)

        if tables:
            table_resource.save(tables)

        if args.iam:
            table_targets = table_ids if manual_table_ids_requested else [
                table_resource._resource_id_from_row(table)
                for table in tables
                if table_resource._resource_id_from_row(table)
            ]
            for table_id in table_targets:
                table_resource.test_iam_permissions(resource_id=table_id, action_dict=iam_actions)

        show_table_summary = bool(tables) or (not manual_table_ids_requested and bool(dataset_ids or dataset_refs))
        if show_table_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "BigQuery Tables",
                tables,
                table_resource.COLUMNS,
                primary_resource="Tables",
                primary_sort_key="full_table_id",
            )
        elif manual_table_ids_requested and args.get:
            print("[*] No BigQuery tables found for the supplied --table-ids.")
        elif manual_table_ids_requested:
            print("[*] Manual --table-ids supplied without --get; skipping table summary.")

    if selected.get("routines", False):
        manual_routine_ids_requested = bool(routine_ids)

        if manual_routine_ids_requested:
            if args.get:
                routines = [
                    routine
                    for routine_id in routine_ids
                    for routine in [routine_resource.get(resource_id=routine_id, action_dict=api_actions)]
                    if routine
                ]
        else:
            routine_parent_refs = dataset_ids or dataset_refs
            if not routine_parent_refs:
                print_missing_dependency(
                    component_name="BigQuery routines",
                    dependency_name="Datasets",
                    module_name="enum_bigquery",
                    manual_flags=["--dataset-ids"],
                )
            else:
                for dataset_id in routine_parent_refs:
                    listed = routine_resource.list(dataset_id=dataset_id, action_dict=scope_actions) or []
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    if args.get:
                        detailed_routines = []
                        for routine in listed:
                            resource_id = routine_resource._resource_id_from_row(routine)
                            detailed = routine_resource.get(resource_id=resource_id, action_dict=api_actions) if resource_id else None
                            detailed_routines.append(detailed or routine)
                        listed = detailed_routines
                    routines_by_dataset[dataset_id].extend(listed)
                    routines.extend(listed)

        if routines:
            routine_resource.save(routines)

        if args.iam:
            routine_targets = routine_ids if manual_routine_ids_requested else [
                routine_resource._resource_id_from_row(routine)
                for routine in routines
                if routine_resource._resource_id_from_row(routine)
            ]
            for routine_id in routine_targets:
                routine_resource.test_iam_permissions(resource_id=routine_id, action_dict=iam_actions)

        show_routine_summary = bool(routines) or (not manual_routine_ids_requested and bool(dataset_ids or dataset_refs))
        if show_routine_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "BigQuery Routines",
                routines,
                routine_resource.COLUMNS,
                primary_resource="Routines",
                primary_sort_key="full_routine_id",
            )
        elif manual_routine_ids_requested and args.get:
            print("[*] No BigQuery routines found for the supplied --routine-ids.")
        elif manual_routine_ids_requested:
            print("[*] Manual --routine-ids supplied without --get; skipping routine summary.")

    if download_scopes:
        downloaded_paths: list[str] = []
        download_count = 0
        table_download_parents = dataset_ids or dataset_refs
        if not table_ids and not table_download_parents:
            print("[*] No BigQuery dataset parent data available for table downloads.")
        elif "table" in download_scopes:
            if table_ids:
                for table_id in _limit_items(table_ids, int(getattr(args, "download_limit", 0) or 0)):
                    table = table_resource.get(resource_id=table_id, action_dict=api_actions)
                    if table is None:
                        continue
                    download_path = table_resource.download_table_data(row=table, project_id=project_id, action_dict=api_actions)
                    if download_path is None:
                        continue
                    downloaded_paths.append(str(download_path))
                    download_count += 1
            else:
                for dataset_id in table_download_parents:
                    candidate_rows = list(tables_by_dataset.get(dataset_id, []))
                    if not candidate_rows:
                        listed = table_resource.list(dataset_id=dataset_id, action_dict=scope_actions) or []
                        if listed in ("Not Enabled", None) or not listed:
                            continue
                        candidate_rows = list(listed)
                        tables_by_dataset[dataset_id].extend(candidate_rows)
                    for table in candidate_rows[: int(getattr(args, "download_limit", 0) or 0) or None]:
                        resource_id = table_resource._resource_id_from_row(table)
                        full_table = table_resource.get(resource_id=resource_id, action_dict=api_actions) if resource_id else None
                        download_path = table_resource.download_table_data(
                            row=full_table or table,
                            project_id=project_id,
                            action_dict=api_actions,
                        )
                        if download_path is None:
                            continue
                        downloaded_paths.append(str(download_path))
                        download_count += 1

        for download_path in downloaded_paths:
            print(f"[*] Wrote BigQuery table data to {download_path}")
        if download_count:
            print(f"[*] Downloaded {download_count} BigQuery table data file(s) for project {project_id}.")
        elif table_ids or table_download_parents:
            print(f"[*] No BigQuery table data was downloaded for project {project_id}.")
        else:
            print(f"[*] No BigQuery table data targets matched the requested download scopes for project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="bigquery_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="bigquery_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="bigquery_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )
    return 1
