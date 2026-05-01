from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import parse_component_args, parse_csv_file_args, resolve_selected_components
from gcpwn.modules.storagetransfer.utilities.helpers import StorageTransferJobsResource


COMPONENTS = [
    ("transfer_jobs", "Enumerate Storage Transfer jobs"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--transfer-job-ids",
            type=str,
            required=False,
            help=(
                "Transfer job IDs in comma-separated format. Accepts short IDs like "
                "`my-transfer-job` or full names like "
                "`projects/PROJECT_ID/transferJobs/my-transfer-job`."
            ),
        )
        parser.add_argument(
            "--transfer-job-ids-file",
            type=str,
            required=False,
            help="File containing transfer job IDs, one per line or comma-separated, using the same formats as --transfer-job-ids.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Storage Transfer resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
        standard_arg_overrides={
            "download": {"help": "Reserved for future transfer job content downloads"},
        },
    )


def _normalize_transfer_job_name(project_id: str, raw_value: str) -> str:
    text = str(raw_value or "").strip()
    if not text:
        return ""
    if text.startswith("projects/"):
        return text
    if text.startswith("transferJobs/"):
        return f"projects/{project_id}/{text}"
    if text.startswith("transferjobs/"):
        return f"projects/{project_id}/transferJobs/{extract_path_tail(text, default=text)}"
    return f"projects/{project_id}/transferJobs/{text}"


def _resolve_transfer_job_names(project_id: str, raw_values: list[str]) -> list[str]:
    resolved: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        normalized = _normalize_transfer_job_name(project_id, raw)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        resolved.append(normalized)
    return resolved


def _hydrate_jobs(resource, *, rows, action_dict):
    return [
        row
        for row in hydrate_get_request_rows(
            rows,
            lambda _row, payload: resource.get(
                project_id=resource.session.project_id,
                resource_id=str(payload.get("name") if isinstance(payload, dict) else str(_row or "").strip()),
                action_dict=action_dict,
            ),
        )
        if row
    ]


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id

    manual_job_names = _resolve_transfer_job_names(
        project_id,
        parse_csv_file_args(
            getattr(args, "transfer_job_ids", None),
            getattr(args, "transfer_job_ids_file", None),
        ),
    )
    if manual_job_names:
        args.transfer_jobs = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("transfer_jobs", False):
        return 1

    transfer_resource = StorageTransferJobsResource(session)
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }

    manual_jobs_requested = bool(manual_job_names)
    jobs: list[dict] = []

    try:
        if manual_jobs_requested and args.get:
            for job_name in manual_job_names:
                row = transfer_resource.get(
                    project_id=project_id,
                    resource_id=job_name,
                    action_dict=scope_actions,
                )
                if isinstance(row, dict) and row:
                    jobs.append(row)
        elif manual_jobs_requested:
            jobs = [{"name": job_name} for job_name in manual_job_names]
        else:
            rows = transfer_resource.list(project_id=project_id, action_dict=scope_actions) or []
            if isinstance(rows, list):
                if args.get:
                    rows = _hydrate_jobs(transfer_resource, rows=rows, action_dict=scope_actions)
                jobs = [row for row in rows if row]

        if jobs and args.download:
            print("[*] Transfer job download is not yet implemented for this module.")
    except ValueError as exc:
        print(f"[X] {exc}")
        return -1

    if jobs:
        transfer_resource.save(jobs, project_id=project_id)

    show_job_summary = bool(jobs) or not manual_jobs_requested
    if show_job_summary:
        UtilityTools.summary_wrapup(
            project_id,
            "Storage Transfer Jobs",
            jobs,
            transfer_resource.COLUMNS,
            primary_resource="Transfer Jobs",
            primary_sort_key="name",
        )
        if not jobs:
            print(f"[*] No Storage Transfer jobs found in project {project_id}.")
    elif args.get:
        print("[*] No Storage Transfer jobs found for the supplied --transfer-job-ids.")
    else:
        print("[*] Manual --transfer-job-ids supplied without --get; skipping transfer job summary.")

    if any(bool(value) for value in scope_actions.values()):
        session.insert_actions(scope_actions, project_id)

    return 1
