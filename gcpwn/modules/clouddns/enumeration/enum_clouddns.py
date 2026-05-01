from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.clouddns.utilities.helpers import CloudDnsManagedZonesResource, CloudDnsRecordSetsResource


COMPONENTS = [
    ("zones", "Enumerate Cloud DNS managed zones"),
    ("record_sets", "Enumerate Cloud DNS record sets (per managed zone)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        zone_group = parser.add_mutually_exclusive_group(required=False)
        zone_group.add_argument("--zone-names", type=str, help="Zone names in comma-separated format.")
        zone_group.add_argument(
            "--zone-names-file",
            type=str,
            help="File with zone names, one per line or comma-separated, using the same formats as --zone-names.",
        )
        parser.add_argument("--record-type", type=str, required=False, help="Filter record sets by type (e.g. A, CNAME, TXT)")
    
    return parse_component_args(
        user_args,
        description="Enumerate Cloud DNS resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on managed zones"},
            "download": {"help": "Write record sets to per-zone CSV-style text files"},
        },
    )


def _manual_zone_names(args) -> list[str]:
    return parse_csv_file_args(getattr(args, "zone_names", None), getattr(args, "zone_names_file", None))


def _zone_type_label(row: dict[str, str] | object) -> str:
    visibility = ""
    if isinstance(row, dict):
        visibility = str(row.get("visibility") or "").strip()
    else:
        visibility = str(getattr(row, "visibility", "") or "").strip()
    lowered = visibility.lower()
    if lowered == "public":
        return "Public"
    if lowered == "private":
        return "Private"
    return visibility.title() if visibility else ""


def _zone_summary_rows(rows: list[dict]) -> list[dict]:
    return [
        {
            **dict(row),
            "type": _zone_type_label(row),
        }
        for row in (rows or [])
    ]


def run_module(user_args, session):
    args = _parse_args(user_args)
    if args.zone_names or args.zone_names_file:
        args.zones = True
    if args.download:
        args.record_sets = True
        if not (args.zone_names or args.zone_names_file):
            args.zones = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    project_id = session.project_id
    zones_resource = CloudDnsManagedZonesResource(session)
    records_resource = CloudDnsRecordSetsResource(session)

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    downloaded_paths: list[str] = []

    manual_zone_names = _manual_zone_names(args)
    discovered_zone_names: list[str] = list(manual_zone_names)

    if selected.get("zones", False):
        manual_zones_requested = bool(manual_zone_names)
        listed = []
        if manual_zones_requested and args.get:
            listed = [
                zones_resource.get(project_id=project_id, resource_id=name, action_dict=api_actions)
                for name in manual_zone_names
            ]
            listed = [zone for zone in listed if zone]
        elif not manual_zones_requested:
            listed = zones_resource.list(project_id=project_id, action_dict=scope_actions)
            if isinstance(listed, list) and args.get:
                listed = hydrate_get_request_rows(
                    listed,
                    lambda row, payload: zones_resource.get(
                        project_id=project_id,
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if listed in ("Not Enabled", None):
            listed = []

        if listed:
            zone_names_from_rows = [
                str(zone.get("name") or "").strip()
                for zone in listed
                if isinstance(zone, dict) and str(zone.get("name") or "").strip()
            ]
            discovered_zone_names = zone_names_from_rows or discovered_zone_names
            zones_resource.save(listed, project_id=project_id)

        if args.iam:
            for zone_name in discovered_zone_names:
                zones_resource.test_iam_permissions(
                    project_id=project_id,
                    resource_id=zone_name,
                    action_dict=iam_actions,
                )

        show_zone_summary = bool(listed) or not manual_zones_requested
        
        if show_zone_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud DNS Managed Zones",
                _zone_summary_rows(listed),
                ["name", "dns_name", "type", "description"],
                primary_resource="Zones",
                primary_sort_key="dns_name",
            )
        elif args.get:
            print("[*] No Cloud DNS managed zones found for the supplied --zone-names.")
        else:
            print("[*] Manual --zone-names supplied without --get; skipping zone summary.")

    if selected.get("record_sets", False):
        zone_target_names: list[str] = []
        if discovered_zone_names:
            zone_target_names = list(discovered_zone_names)
        elif manual_zone_names:
            zone_target_names = list(manual_zone_names)
        elif not selected.get("zones", False):
            cached = get_cached_rows(session, zones_resource.TABLE_NAME, project_id=project_id, columns=["name"])
            if cached:
                zone_target_names = [str(row["name"]).strip() for row in cached if row.get("name")]

        if not zone_target_names:
            print_missing_dependency(
                component_name="record sets",
                dependency_name="Cloud DNS zones",
                module_name="enum_clouddns",
                manual_flags=("--zone-names", "--zone-names-file"),
            )
            if has_recorded_actions(scope_actions):
                session.insert_actions(scope_actions, project_id, column_name="clouddns_actions_allowed")
            if has_recorded_actions(api_actions):
                session.insert_actions(api_actions, project_id, column_name="clouddns_actions_allowed")
            if has_recorded_actions(iam_actions):
                session.insert_actions(
                    iam_actions,
                    project_id,
                    column_name="clouddns_actions_allowed",
                    evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
                )
            return 1

        all_records = []
        client = zones_resource.build_client(project_id)
        listed_by_zone = parallel_map(
            zone_target_names,
            lambda zone_name: (
                zone_name,
                records_resource.list(
                    project_id=project_id,
                    zone=client.zone(zone_name),
                    record_type=args.record_type,
                    action_dict=api_actions,
                ),
            ),
            threads=getattr(args, "threads", 3),
        )
        for zone_name, listed in listed_by_zone:
            if listed in ("Not Enabled", None):
                continue
            if listed:
                records_resource.save(listed, project_id=project_id, zone=client.zone(zone_name))
                if args.download:
                    download_path = records_resource.download_record_sets(
                        project_id=project_id,
                        zone_name=zone_name,
                        records=listed,
                    )
                    if download_path is not None:
                        downloaded_paths.append(str(download_path))
                all_records.extend(listed)

        UtilityTools.summary_wrapup(
            project_id,
            "Cloud DNS Record Sets",
            all_records,
            ["zone_name", "name", "type", "ttl", "rrdatas"],
            primary_resource="Record Sets",
            primary_sort_key="zone_name",
        )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="clouddns_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="clouddns_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="clouddns_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    for download_path in downloaded_paths:
        print(f"[*] Wrote Cloud DNS record sets to {download_path}")
    if args.download:
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud DNS record-set file(s) for project {project_id}.")
        else:
            print(f"[*] No Cloud DNS record sets were available to download for project {project_id}.")

    return 1
