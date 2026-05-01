from __future__ import annotations

import argparse

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import (
    parse_component_args,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.cloudstorage.utilities.helpers import (
    CloudStorageBlobsResource,
    CloudStorageBucketsResource,
    CloudStorageHmacKeysResource,
)


COMPONENTS = [
    ("hmac_keys", "Enumerate Cloud Storage HMAC keys"),
    ("buckets", "Enumerate Cloud Storage buckets"),
    ("blobs", "Enumerate Cloud Storage blobs"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        exclusive_bucket_group = parser.add_mutually_exclusive_group(required=False)
        exclusive_bucket_group.add_argument("--bucket-names", type=str, help="Bucket names in comma-separated format")
        exclusive_bucket_group.add_argument("--bucket-names-file", type=str, help="File containing bucket names, one per line")

        exclusive_blob_group = parser.add_mutually_exclusive_group(required=False)
        exclusive_blob_group.add_argument("--blob-names", type=str, help="Blob names in comma-separated format")
        exclusive_blob_group.add_argument("--blob-names-file", type=str, help="File containing blob names, one per line")

        exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
        exclusive_access_key_group.add_argument("--access-keys", type=str)
        exclusive_access_key_group.add_argument("--access-keys-file", type=str)

        parser.add_argument("--output", type=str, required=False, help="Output folder for downloaded files")
        parser.add_argument("--file-size", type=int, required=False, help="Blob size filter in bytes")
        parser.add_argument("--good-regex", type=str, required=False, help="Regex filter for blob downloads")
        parser.add_argument("--time-limit", type=str, required=False, help="Per-bucket time limit in seconds")
        parser.add_argument("--access-id", type=str, help="HMAC access ID")
        parser.add_argument("--hmac-secret", type=str, help="HMAC secret")
        parser.add_argument("--threads", type=int, default=1, help="Number of download worker threads")
        parser.add_argument("--list-hmac-secrets", action="store_true", help="List saved HMAC secrets")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Storage resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={
            "download": {"help": "Attempt to download enumerated blobs"},
            "iam": {"help": "Run bucket TestIamPermissions checks"},
        },
    )


def run_module(user_args, session, dependency=False):
    args = _parse_args(user_args)
    if bool(args.access_id) ^ bool(args.hmac_secret):
        print("[X] --access-id and --hmac-secret must be supplied together.")
        return -1

    bucket_name_inputs = parse_csv_file_args(getattr(args, "bucket_names", None), getattr(args, "bucket_names_file", None))
    blob_name_inputs = parse_csv_file_args(getattr(args, "blob_names", None), getattr(args, "blob_names_file", None))
    access_key_inputs = parse_csv_file_args(getattr(args, "access_keys", None), getattr(args, "access_keys_file", None))

    hmac_resource = CloudStorageHmacKeysResource(session)
    buckets_resource = CloudStorageBucketsResource(session)
    blobs_resource = CloudStorageBlobsResource(session)
    project_id = session.project_id
    access_mode = "hmac" if args.access_id and args.hmac_secret else "standard"
    hmac_action_crednames = (
        hmac_resource.resolve_action_crednames(project_id=project_id, access_id=args.access_id)
        if access_mode == "hmac"
        else None
    )

    if access_key_inputs:
        args.hmac_keys = True
    if bucket_name_inputs:
        args.buckets = True
    if blob_name_inputs:
        args.blobs = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    if args.list_hmac_secrets:
        hmac_secrets = hmac_resource.list_saved_secrets()
        if hmac_secrets:
            print("[*] The following HMAC keys have saved secrets:")
            for secret in hmac_secrets:
                print(f"   - {secret['secret']} \n      - {secret['access_id']} @ {secret['service_account_email']}")
        return 1

    discovered_bucket_targets = []

    if selected.get("hmac_keys", False):
        all_hmacs, resource_actions = hmac_resource.enumerate(
            project_id=project_id,
            access_key_inputs=access_key_inputs,
            include_get=args.get,
        )

        for hmac_project_id, hmac_objects in all_hmacs.items():
            if resource_actions:
                session.insert_actions(resource_actions, hmac_project_id, column_name="storage_actions_allowed")
            validated_hmacs = [item for item in hmac_objects if getattr(item, "validated", True)]
            UtilityTools.summary_wrapup(
                hmac_project_id,
                "Cloud Storage HMAC Keys",
                list(validated_hmacs),
                ["access_id", "secret", "state", "service_account_email"],
                primary_resource="HMAC Keys",
                primary_sort_key="service_account_email",
            )

    if selected.get("buckets", False):
        bucket_result = buckets_resource.enumerate(
            project_id=project_id,
            include_get=args.get,
            include_iam=args.iam,
            access_mode=access_mode,
            access_id=args.access_id,
            hmac_secret=args.hmac_secret,
            bucket_names=args.bucket_names,
            bucket_file=args.bucket_names_file,
        )

        validated_buckets = bucket_result["validated_buckets"]
        discovered_bucket_targets = bucket_result["bucket_targets"]
        manual_buckets_requested = bucket_result["manual_requested"]

        if bucket_result["scope_actions"]:
            session.insert_actions(
                bucket_result["scope_actions"],
                project_id,
                column_name="storage_actions_allowed",
                credname_override=hmac_action_crednames if access_mode == "hmac" else None,
            )
        if bucket_result["api_actions"]:
            session.insert_actions(
                bucket_result["api_actions"],
                project_id,
                column_name="storage_actions_allowed",
                credname_override=hmac_action_crednames if access_mode == "hmac" else None,
            )
        if bucket_result["iam_actions"]:
            session.insert_actions(
                bucket_result["iam_actions"],
                project_id,
                column_name="storage_actions_allowed",
                evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
                credname_override=hmac_action_crednames if access_mode == "hmac" else None,
            )

        show_bucket_summary = bool(validated_buckets) or not manual_buckets_requested
        if show_bucket_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud Storage Buckets",
                validated_buckets,
                ["name", "location"],
                primary_resource="Buckets",
                secondary_title_name="blobs",
            )
        elif args.get:
            print("[*] No Cloud Storage buckets found for the supplied --bucket-names.")
        else:
            print("[*] Manual --bucket-names supplied without --get; skipping bucket summary.")

    if selected.get("blobs", False):
        if bucket_name_inputs:
            blob_bucket_targets = buckets_resource.manual_targets(
                project_id=project_id,
                bucket_names=args.bucket_names,
                bucket_file=args.bucket_names_file,
            )
        elif discovered_bucket_targets:
            blob_bucket_targets = discovered_bucket_targets
        else:
            blob_bucket_targets = blobs_resource.resolve_cached_buckets(project_id=project_id)

        if not blob_bucket_targets:
            print_missing_dependency(
                component_name="Cloud Storage blobs",
                dependency_name="Buckets",
                module_name="enum_cloudstorage",
                manual_flags=["--bucket-names", "--bucket-names-file"],
            )
            return 1

        bucket_blob_map, blob_actions = blobs_resource.enumerate(
            project_id=project_id,
            bucket_targets=blob_bucket_targets,
            blob_name_inputs=blob_name_inputs,
            download=args.download,
            output=args.output,
            good_regex=args.good_regex,
            file_size=args.file_size,
            time_limit=args.time_limit,
            threads=args.threads,
            access_mode=access_mode,
            access_id=args.access_id,
            hmac_secret=args.hmac_secret,
        )

        if blob_actions:
            session.insert_actions(
                blob_actions,
                project_id,
                column_name="storage_actions_allowed",
                credname_override=hmac_action_crednames if access_mode == "hmac" else None,
            )
        if not dependency:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud Storage Blobs",
                bucket_blob_map,
                ["name", "location"],
                primary_resource="Buckets",
                secondary_title_name="blobs",
            )

    return 1
