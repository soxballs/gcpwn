from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import parse_component_args, parse_csv_file_args, resolve_selected_components
from gcpwn.modules.apikeys.utilities.helpers import (
    ApiKeysKeysResource,
    attach_key_strings,
    get_key_rows,
    key_row_names,
)


COMPONENTS = [
    ("keys", "Enumerate API Keys"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--key-ids",
            required=False,
            help=(
                "Key IDs in comma-separated format. Accepts short IDs like "
                "`my-key` or full names like "
                "`projects/PROJECT_ID/locations/global/keys/KEY_ID`."
            ),
        )
        parser.add_argument(
            "--key-ids-file",
            required=False,
            help="File containing key IDs, one per line or comma-separated, using the same formats as --key-ids.",
        )
        parser.add_argument(
            "--include-key-string",
            action="store_true",
            required=False,
            help="Include API key strings (sensitive) when available for enumerated or manually targeted keys.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate API Keys surfaces",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    key_ids = parse_csv_file_args(getattr(args, "key_ids", None), getattr(args, "key_ids_file", None))
    if key_ids:
        args.keys = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("keys", False):
        return 1

    try:
        resource = ApiKeysKeysResource(session)
    except RuntimeError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    key_names = [resource.key_name(project_id=project_id, key_id=key_id) for key_id in key_ids]
    manual_keys_requested = bool(key_names)
    include_key_string_requested = bool(args.include_key_string or args.download)

    # API Keys follows the same split as API Gateway:
    # - `scope_actions` holds project-scoped list permissions such as `apikeys.keys.list`
    # - `api_actions` holds resource-scoped direct API successes such as
    #   `apikeys.keys.get` / `apikeys.keys.getKeyString` under:
    #   {project_id: {permission_name: {resource_type: {resource_label}}}}
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    downloaded_paths: list[str] = []
    download_message = ""

    rows: list[dict] = []

    if manual_keys_requested and args.get:
        rows = get_key_rows(resource, key_names, api_actions)
    elif not manual_keys_requested:
        rows = resource.list(project_id=project_id, location="global", action_dict=scope_actions) or []
        if not isinstance(rows, list):
            rows = []
        if args.get:
            rows = hydrate_get_request_rows(
                rows,
                lambda _row, payload: resource.get(
                    name=str(payload.get("name") or "").strip(),
                    action_dict=api_actions,
                ),
            )

    if include_key_string_requested:
        key_string_targets = key_names if manual_keys_requested else key_row_names(resource, rows)
        rows = attach_key_strings(
            resource,
            key_string_targets,
            rows,
            api_actions,
            require_key_string=bool(manual_keys_requested and not args.get),
        )

    if rows:
        resource.save(rows, project_id=project_id, location="global")

    if args.download:
        download_count = 0
        for row in rows:
            download_path = resource.download_key_string(row=row, project_id=project_id)
            if download_path is None:
                continue
            downloaded_paths.append(str(download_path))
            download_count += 1
        if download_count:
            download_message = f"[*] Downloaded {download_count} API key content file(s) for project {project_id}."
        elif rows:
            download_message = f"[*] No API key content was present on the retrieved keys for project {project_id}."
        else:
            download_message = f"[*] No API keys were available to download content from in project {project_id}."

    show_key_summary = bool(rows) or not manual_keys_requested
    if show_key_summary:
        UtilityTools.summary_wrapup(
            project_id,
            "API Keys",
            rows,
            resource.COLUMNS,
            primary_resource="Keys",
            primary_sort_key="display_name",
        )
    elif manual_keys_requested and args.get:
        print("[*] No API Keys found for the supplied --key-ids.")
    elif manual_keys_requested and include_key_string_requested:
        print("[*] No API key content was returned for the supplied --key-ids.")
    else:
        print("[*] Manual --key-ids supplied without --get, --include-key-string, or --download; skipping key summary.")

    if args.download:
        for download_path in downloaded_paths:
            print(f"[*] Wrote API key content to {download_path}")
        if download_message:
            print(download_message)

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="apikeys_actions_allowed")

    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="apikeys_actions_allowed")

    return 1
