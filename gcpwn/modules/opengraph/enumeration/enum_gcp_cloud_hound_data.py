from __future__ import annotations

import argparse
import json
import os
import time
from urllib.parse import urlparse, urlunparse

from gcpwn.core.console import UtilityTools
from gcpwn.modules.opengraph.utilities.iam_bindings_single_multi_permission_graph_builder import (
    build_iam_bindings_multi_permission_graph,
)
from gcpwn.modules.opengraph.utilities.iam_bindings_prepare_builder import (
    build_iam_bindings_prepare,
)
from gcpwn.modules.opengraph.utilities.iam_bindings_single_permission_graph_builder import (
    build_iam_bindings_single_permissions,
)
from gcpwn.modules.opengraph.utilities.iam_inferred_permissions_graph_builder import (
    build_iam_inferred_permissions_graph,
)
from gcpwn.modules.opengraph.utilities.final_allowlist_trim_builder import apply_final_allowlist_trims
from gcpwn.modules.opengraph.utilities.principal_builder import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.resource_expansion_builder import build_resource_expansion_graph
from gcpwn.modules.opengraph.utilities.helpers.context import OpenGraphBuildContext, OpenGraphBuildOptions
from gcpwn.modules.opengraph.utilities.helpers.core_helpers import (
    edge_to_opengraph,
    node_to_opengraph,
    persist_opengraph,
)


def push_custom_node_attributes(
    *,
    custom_nodes_url: str,
    custom_nodes_token: str,
):
    token = (custom_nodes_token or "").strip()
    url = (custom_nodes_url or "").strip()
    if not url:
        url = str(os.getenv("GCPWN_CUSTOM_NODES_URL") or "").strip() or "http://127.0.0.1:8080"
    if not token:
        print("[*] Skipping custom-nodes push: token not provided.")
        return {"ok": False, "reason": "missing_token"}

    try:
        import requests
    except Exception:
        print("[*] Skipping custom-nodes push: requests is not installed.")
        return {"ok": False, "reason": "requests_missing"}

    from gcpwn.modules.opengraph.utilities.helpers.constants import CUSTOM_NODE_TYPES

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"custom_types": dict(CUSTOM_NODE_TYPES or {})}

    try:
        parsed = urlparse(url)
        candidate_urls: list[str] = []
        if parsed.scheme and parsed.netloc:
            original_path = str(parsed.path or "").strip()
            if original_path and original_path != "/":
                normalized_path = original_path if original_path.startswith("/") else f"/{original_path}"
                candidate_urls.append(urlunparse((parsed.scheme, parsed.netloc, normalized_path, "", "", "")))
            else:
                candidate_urls.extend(
                    [
                        urlunparse((parsed.scheme, parsed.netloc, "/api/v2/custom-nodes", "", "", "")),
                        urlunparse((parsed.scheme, parsed.netloc, "/api/v2/custom-node-types", "", "", "")),
                    ]
                )
        else:
            candidate_urls.append(url)

        candidate_urls = list(dict.fromkeys(candidate_urls))
        method_order = ("PUT", "POST", "PATCH")
        attempts: list[tuple[str, str, int, str]] = []
        for candidate_url in candidate_urls:
            for method in method_order:
                resp = requests.request(
                    method,
                    candidate_url,
                    headers=headers,
                    json=payload,
                    verify=False,
                    timeout=10,
                )
                status_code = int(resp.status_code)
                response_text = str(resp.text or "")
                attempts.append((method, candidate_url, status_code, response_text))
                if 200 <= status_code < 300:
                    print(f"[*] custom-nodes push complete: {status_code} ({method} {candidate_url})")
                    return {
                        "ok": True,
                        "status_code": status_code,
                        "method": method,
                        "url": candidate_url,
                    }

        last_method, last_url, last_status, last_body = attempts[-1]
        attempted_signatures = ", ".join(f"{method} {target_url}" for method, target_url, _status, _body in attempts)
        print(
            f"[*] custom-nodes push failed: {last_status} ({last_method} {last_url}) "
            f"{str(last_body or '')[:300]}"
        )
        return {
            "ok": False,
            "reason": "http_error",
            "status_code": last_status,
            "method": last_method,
            "url": last_url,
            "body": str(last_body or "")[:300],
            "attempted": attempted_signatures,
        }
    except Exception as exc:
        print("custom-nodes request failed", f"{type(exc).__name__}: {exc}")
        return {"ok": False, "reason": "request_failed", "error": f"{type(exc).__name__}: {exc}"}


def export_opengraph_json(nodes_in_memory, edges_in_memory, *, debug: bool = False):
    UtilityTools.dlog(
        debug,
        "export: loaded graph objects",
        nodes=len(nodes_in_memory or []),
        edges=len(edges_in_memory or []),
    )

    nodes = [node_to_opengraph(r) for r in (nodes_in_memory or [])]
    edges = [edge_to_opengraph(r) for r in (edges_in_memory or [])]

    nodes = sorted(nodes, key=lambda n: str(n["id"] or ""))
    edges = sorted(
        edges,
        key=lambda e: (
            str(e["start"]["value"] or ""),
            str(e["end"]["value"] or ""),
            str(e["kind"] or ""),
        ),
    )

    UtilityTools.dlog(debug, "export: final graph", unique_nodes=len(nodes), unique_edges=len(edges))
    payload = {
        "metadata": {
            "source_kind": "GCPBase",
        },
        "graph": {"nodes": nodes, "edges": edges},
        "summary": {"nodes": len(nodes), "edges": len(edges)},
    }
    return payload


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Build GCP OpenGraph data offline from cached SQLite tables",
        allow_abbrev=False,
    )

    # Logging
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")

    # Output / persistence
    parser.add_argument("--out", required=False, help="Optional JSON export path for the generated graph")
    parser.add_argument("--reset", action="store_true", help="Delete existing OpenGraph rows for this workspace before rebuilding")

    # IAM graph behavior
    parser.add_argument("--include-all", action="store_true", help="Include generic IAM binding edges (not only dangerous built-in edges)")
    parser.add_argument("--expand-inherited", action="store_true", help="Expand inherited IAM bindings from org/folder down to child folders/projects")
    parser.add_argument(
        "--cond-eval",
        action="store_true",
        help="Run IAM conditional workflow in pass-through mode (currently no-op filtering)",
    )

    # Step selection
    parser.add_argument("--groups", action="store_true", help="Run users/groups mapping step")
    parser.add_argument("--iam-bindings", action="store_true", help="Run IAM bindings graph step")
    parser.add_argument("--inferred-permissions", action="store_true", help="Run inferred credential-permissions graph step")
    parser.add_argument("--resource-expansion", action="store_true", help="Run resource expansion graph step")

    # Optional custom-node sync
    parser.add_argument(
        "--push-custom-node-attributes-url",
        default=os.getenv("GCPWN_CUSTOM_NODES_URL") or None,
        required=False,
        help=(
            "Optional BloodHound custom-node-types endpoint URL. "
            "If omitted, set GCPWN_CUSTOM_NODES_URL. Typical local endpoint: "
            "http://127.0.0.1:8080/api/v2/custom-nodes"
        ),
    )
    parser.add_argument(
        "--push-custom-node-attributes-token",
        required=False,
        help="Optional bearer token used to push custom node types.",
    )

    return parser.parse_args(user_args)


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_all_steps = not any([args.groups, args.iam_bindings, args.inferred_permissions, args.resource_expansion])
    if args.cond_eval:
        print("[*] --cond-eval enabled in pass-through mode; condition filters currently return input scopes unchanged.")

    raw_allow_bindings = session.get_data("iam_allow_policies") or []
    if args.iam_bindings and not raw_allow_bindings:
        print("[X] No IAM policy data was found in SQLite (iam_allow_policies). Run enum_policy_bindings first.")
        return -1
    if run_all_steps and not raw_allow_bindings:
        print("[*] No IAM policy data was found in SQLite (iam_allow_policies). Skipping IAM bindings step.")

    context = OpenGraphBuildContext(
        session=session,
        options=OpenGraphBuildOptions(
            include_all=args.include_all,
            expand_inheritance=args.expand_inherited,
            conditional_evaluation=bool(args.cond_eval),
            debug=args.debug,
        ),
    )

    UtilityTools.dlog(
        args.debug,
        "opengraph explicit steps selected",
        groups=bool(args.groups),
        iam_bindings=bool(args.iam_bindings),
        inferred_permissions=bool(args.inferred_permissions),
        resource_expansion=bool(args.resource_expansion),
    )
    UtilityTools.dlog(args.debug, "opengraph run all steps", enabled=run_all_steps)
    current_step = 0

    step_plan: list[tuple[bool, str, str]] = [
        (run_all_steps or args.groups, "users_groups", "Users/Groups graph"),
        (
            (run_all_steps or args.iam_bindings) and bool(raw_allow_bindings),
            "iam_bindings",
            "IAM bindings graph",
        ),
        (run_all_steps or args.inferred_permissions, "inferred_permissions", "Inferred permissions graph"),
        (run_all_steps or args.resource_expansion, "resource_expansion", "Resource expansion graph"),
    ]
    for should_run, step, step_title in step_plan:
        if not should_run:
            continue
        current_step += 1
        before_nodes, before_edges = context.counts()
        print(f"[*] Step {current_step}: {step} ({step_title})")
        if step == "users_groups":
            step_stats = build_users_groups_graph(context) or {}
        elif step == "iam_bindings":
            build_iam_bindings_prepare(context)
            binding_coverage = dict(context.get_artifact("binding_permission_map_coverage") or {})
            unsupported_rules = list(binding_coverage.get("unsupported_rules") or [])
            unmapped_permissions = list(binding_coverage.get("unmapped_permissions") or [])
            if unsupported_rules:
                print(
                    "[!] IAM binding rule coverage warning: some dangerous-edge rules reference permissions that are "
                    "not mapped in og_permission_to_roles_map.json. Those rules will be skipped for IAM-binding graphing."
                )
                if unmapped_permissions:
                    print(f"    Unmapped permissions: {', '.join(sorted(set(str(p) for p in unmapped_permissions if str(p))))}")
                for record in unsupported_rules:
                    rule_name = str(record.get("rule_name") or "").strip() or "<unknown_rule>"
                    rule_variant = str(record.get("rule_variant_id") or "").strip()
                    missing = [str(permission or "").strip() for permission in (record.get("missing_permissions") or []) if str(permission or "").strip()]
                    label = f"{rule_name} ({rule_variant})" if rule_variant else rule_name
                    print(f"    Skipping rule {label}: unmapped permissions -> {', '.join(missing)}")
            step_stats = build_iam_bindings_single_permissions(context) or {}
            advanced_step_stats = build_iam_bindings_multi_permission_graph(context) or {}
            step_stats.update({f"advanced_{key}": value for key, value in dict(advanced_step_stats).items()})
        elif step == "inferred_permissions":
            step_stats = build_iam_inferred_permissions_graph(context) or {}
        elif step == "resource_expansion":
            step_stats = build_resource_expansion_graph(context) or {}
        else:
            step_stats = {}

        context.record_step(step, step_stats)
        after_nodes, after_edges = context.counts()
        print(
            f"[*] Completed {step}: +{max(0, after_nodes - before_nodes)} nodes, "
            f"+{max(0, after_edges - before_edges)} edges"
        )
        UtilityTools.dlog(args.debug, "opengraph step stats", step=step, stats=step_stats)

    nodes = list(context.builder.node_map.values())
    edges = list(context.builder.edge_map.values())
    nodes, edges, trim_stats = apply_final_allowlist_trims(
        nodes,
        edges,
        include_all=bool(args.include_all),
    )
    prune_stats = trim_stats.get("service_account_binding_islands") or {}
    if prune_stats.get("nodes_removed", 0) or prune_stats.get("edges_removed", 0):
        print(
            "[*] Pruned isolated service-account IAM-binding islands "
            f"(pairs={prune_stats['pairs_removed']}, key_islands={prune_stats.get('key_islands_removed', 0)}, "
            f"nodes={prune_stats['nodes_removed']}, edges={prune_stats['edges_removed']})."
        )
    implied_prune_stats = trim_stats.get("orphan_implied_bindings") or {}
    if implied_prune_stats.get("implied_bindings_removed", 0):
        print(
            "[*] Pruned orphan implied-IAM-binding nodes "
            f"(implied_bindings={implied_prune_stats['implied_bindings_removed']}, "
            f"nodes={implied_prune_stats['nodes_removed']}, edges={implied_prune_stats['edges_removed']})."
        )
    isolated_sa_prune_stats = trim_stats.get("isolated_service_accounts") or {}
    if isolated_sa_prune_stats.get("isolated_service_accounts_removed", 0):
        print(
            "[*] Pruned isolated service-account nodes "
            f"(service_accounts={isolated_sa_prune_stats['isolated_service_accounts_removed']}, "
            f"nodes={isolated_sa_prune_stats['nodes_removed']}, "
            f"edges={isolated_sa_prune_stats['edges_removed']})."
        )

    persist_opengraph(session, nodes, edges, clear_existing=args.reset)

    output_path = str(
        session.resolve_output_path(
            requested_path=args.out,
            service_name="reports",
            filename=f"opengraph_{int(time.time())}.json",
            subdirs=["snapshots"],
            target="export",
        )
    )
    payload = export_opengraph_json(
        nodes,
        edges,
        debug=args.debug,
    )
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    exported_path = output_path

    if args.push_custom_node_attributes_url or args.push_custom_node_attributes_token:
        push_custom_node_attributes(
            custom_nodes_url=str(args.push_custom_node_attributes_url or ""),
            custom_nodes_token=str(args.push_custom_node_attributes_token or ""),
        )

    print(f"[*] OpenGraph generation complete. Nodes: {len(nodes)} | Edges: {len(edges)}")
    print(f"[*] Saved graph JSON to {exported_path}")
    return 1
