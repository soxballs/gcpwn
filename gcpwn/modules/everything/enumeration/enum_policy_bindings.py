from __future__ import annotations

import argparse
import importlib

from gcpwn.modules.everything.utilities.iam_policy_bindings import IAMPolicyBindingsResource

SERVICE_FLAG_TO_GROUP = {
    "resource_manager": "resource_manager",
    "storage": "storage",
    "bigquery": "bigquery",
    "functions": "functions",
    "compute": "compute",
    "service_accounts": "service_accounts",
    "secrets": "secrets",
    "cloud_run": "cloudrun",
    "cloud_tasks": "cloudtasks",
    "artifact_registry": "artifactregistry",
    "cloud_kms": "kms",
    "pubsub": "pubsub",
    "service_directory": "servicedirectory",
}


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate IAM allow-policy bindings across cached resources", allow_abbrev=False)
    parser.add_argument(
        "--ensure-tree",
        action="store_true",
        help="If Resource Manager hierarchy is missing, run enum_resources automatically before policy-binding collection.",
    )
    parser.add_argument("--resource-manager", dest="resource_manager", action="store_true", help="Enumerate org/folder/project IAM policies")
    parser.add_argument("--storage", action="store_true", help="Enumerate Cloud Storage bucket IAM policies")
    parser.add_argument("--bigquery", action="store_true", help="Enumerate BigQuery dataset IAM policies")
    parser.add_argument("--functions", action="store_true", help="Enumerate Cloud Functions IAM policies")
    parser.add_argument("--compute", action="store_true", help="Enumerate Compute Engine instance IAM policies")
    parser.add_argument("--service-accounts", dest="service_accounts", action="store_true", help="Enumerate service account IAM policies")
    parser.add_argument("--secrets", action="store_true", help="Enumerate Secret Manager IAM policies")
    parser.add_argument("--cloud-run", dest="cloud_run", action="store_true", help="Enumerate Cloud Run service/job IAM policies")
    parser.add_argument("--cloud-tasks", dest="cloud_tasks", action="store_true", help="Enumerate Cloud Tasks queue IAM policies")
    parser.add_argument("--artifact-registry", dest="artifact_registry", action="store_true", help="Enumerate Artifact Registry repository IAM policies")
    parser.add_argument("--cloud-kms", dest="cloud_kms", action="store_true", help="Enumerate Cloud KMS keyring/cryptokey IAM policies")
    parser.add_argument("--pubsub", action="store_true", help="Enumerate Pub/Sub topic/subscription/snapshot/schema IAM policies")
    parser.add_argument("--service-directory", dest="service_directory", action="store_true", help="Enumerate Service Directory namespace/service IAM policies")
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Verbose low-level debug logging.")
    return parser.parse_args(user_args)


def _selected_service_groups(args) -> set[str] | None:
    selected = {
        group
        for flag, group in SERVICE_FLAG_TO_GROUP.items()
        if bool(getattr(args, flag, False))
    }
    return selected or None


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected_groups = _selected_service_groups(args)

    setattr(session, "debug", bool(args.debug))

    should_ensure_tree = bool(args.ensure_tree) or selected_groups is None or "resource_manager" in selected_groups
    if should_ensure_tree:
        tree = session.get_data("abstract_tree_hierarchy", columns=["name"], conditions='type IN ("org","folder","project")') or []
        if not tree:
            try:
                module = importlib.import_module("gcpwn.modules.resourcemanager.enumeration.enum_resources")
                module_args = ["-v"] if getattr(args, "debug", False) else []
                module.run_module(module_args, session)
            except Exception:
                pass

    print("[*] Starting IAM policy binding enumeration")
    if selected_groups:
        print(f"[*] Service filter: {', '.join(sorted(selected_groups))}")
    print("[*] Capturing raw allow-policy JSON and normalized bindings for cached resources")
    if not getattr(args, "debug", False):
        print("[*] Tip: add --debug for low-level API traces")

    IAMPolicyBindingsResource(session).run(
        save_raw_policies=True,
        services=selected_groups,
    )
    return 1

