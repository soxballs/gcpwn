from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, parse_json_value
from gcpwn.modules.opengraph.utilities.helpers.core_helpers import (
    gcp_resource_node_type,
    principal_member_properties,
    principal_node_id,
    principal_type,
    resource_display_label,
    resource_leaf_name,
    resource_location_token,
    resource_node_id,
)


def _normalize_graph_scalar(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    text = str(value).strip()
    if not text:
        return None
    return text


def _row_resourcedata_payload(
    row: dict[str, Any],
    *,
    skip_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Build nested row payload to later export as flattened `resourcedata.*`."""
    output: dict[str, Any] = {}
    if not isinstance(row, dict):
        return output

    effective_skip_keys = {str(key or "").strip() for key in (skip_keys or set())}
    for raw_key, raw_value in row.items():
        key = str(raw_key or "").strip()
        if not key or key in effective_skip_keys or key.startswith("resourcedata."):
            continue
        parsed = parse_json_value(raw_value, default=None)
        if key == "raw_json" and isinstance(parsed, dict):
            # Unwrap raw_json object payloads into top-level resourcedata keys
            # so exports read as resourcedata.<field> instead of
            # resourcedata.raw_json.<field>.
            for child_key, child_value in parsed.items():
                child_token = str(child_key or "").strip()
                if not child_token or child_token in output:
                    continue
                output[child_token] = child_value
            continue
        if isinstance(parsed, (dict, list)):
            output[key] = parsed
            continue
        normalized = _normalize_graph_scalar(raw_value)
        if normalized is not None:
            output[key] = normalized
    return output


def _compute_instance_resourcedata_payload(row: dict[str, Any]) -> dict[str, Any]:
    """
    Preserve cached `cloudcompute_instances` row data as nested `resourcedata`
    so export-time flattening can emit `resourcedata.*` keys.
    """
    return _row_resourcedata_payload(row, skip_keys={"workspace_id"})


def _normalize_resource_type(token: str) -> str:
    lowered = str(token or "").strip().lower().replace("_", "-").replace(" ", "-")
    return {
        "organization": "org",
        "organizations": "org",
        "folders": "folder",
        "projects": "project",
        "service-accounts": "service-account",
        "saaccounts": "service-account",
        "functions": "cloudfunction",
        "keyrings": "kmskeyring",
        "keys": "kmscryptokey",
        "repositories": "artifactregistryrepo",
        "topics": "pubsubtopic",
        "subscriptions": "pubsubsubscription",
        "snapshots": "pubsubsnapshot",
        "schemas": "pubsubschema",
        "namespaces": "servicedirectorynamespace",
        "queues": "cloudtasksqueue",
        "services": "cloudrunservice",
        "jobs": "cloudrunjob",
    }.get(lowered, lowered)


def _compute_instance_resource_name(row: dict[str, Any]) -> str:
    project_id = str(row.get("project_id") or "").strip()
    name = str(row.get("name") or "").strip()
    zone = str(row.get("zone") or "").strip()
    zone = extract_path_tail(zone)
    if project_id and name and zone:
        return f"projects/{project_id}/zones/{zone}/instances/{name}"
    self_link = str(row.get("self_link") or "").strip()
    if self_link:
        return self_link
    return name


def _extract_compute_instance_service_accounts(row: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    candidates.append(parse_json_value(row.get("service_accounts"), default=None))
    raw_json = parse_json_value(row.get("raw_json"), default=None)
    if isinstance(raw_json, dict):
        candidates.append(raw_json.get("service_accounts"))

    emails: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, list):
            continue
        for item in candidate:
            if isinstance(item, str):
                email = item.strip().lower()
                if "@" in email:
                    emails.add(email)
                continue
            if isinstance(item, dict):
                email = str(item.get("email") or "").strip().lower()
                if "@" in email:
                    emails.add(email)
    return sorted(emails)


def _project_scope_name(project_id: str, project_scope_by_project_id: dict[str, str]) -> str:
    token = str(project_id or "").strip()
    if not token:
        return ""
    mapped = str(project_scope_by_project_id.get(token) or "").strip()
    if mapped:
        return mapped
    return token if token.startswith("projects/") else f"projects/{token}"


# "Relevant services" for default project->resource topology mode.
_DEFAULT_PROJECT_EDGE_RESOURCE_TYPES = frozenset(
    {
        "computeinstance",
        "cloudfunction",
        "cloudrunservice",
        "cloudrunjob",
        "bucket",
        "secrets",
        "cloudtasksqueue",
        "artifactregistryrepo",
        "service-account",
    }
)

_RESOURCE_ENRICHMENT_SKIP_TABLES = frozenset(
    {
        "iam_allow_policies",
        "iam_unauth_permissions",
        "iam_roles",
        "iam_group_memberships",
        "workspace_users",
        "workspace_groups",
        "workspace_group_memberships",
        "member_permissions_summary",
        "opengraph_nodes",
        "opengraph_edges",
    }
)
_RESOURCE_ENRICHMENT_NAME_COLUMNS = ("resource_name", "name", "self_link")


def _merge_nested_payload_missing(destination: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    merged = dict(destination or {})
    for key, value in (source or {}).items():
        if key not in merged:
            if value not in (None, "", [], {}):
                merged[key] = value
            continue
        existing_child = merged.get(key)
        if isinstance(existing_child, dict) and isinstance(value, dict):
            merged[key] = _merge_nested_payload_missing(existing_child, value)
    return merged


def _resource_name_aliases(value: str) -> set[str]:
    token = str(value or "").strip()
    if not token:
        return set()
    aliases = {token}
    tail = extract_path_tail(token, default="")
    if tail:
        aliases.add(tail)
    if "/buckets/" in token:
        bucket_tail = token.split("/buckets/", 1)[1].strip()
        if bucket_tail:
            aliases.add(bucket_tail)
    return {alias for alias in aliases if str(alias or "").strip()}


def _resource_enrichment_payloads_by_name(
    context,
    *,
    target_resource_names: set[str],
    candidate_project_by_name: dict[str, str],
) -> dict[str, dict[str, Any]]:
    if not target_resource_names:
        return {}

    alias_to_targets: dict[str, set[str]] = {}
    for resource_name in target_resource_names:
        for alias_token in _resource_name_aliases(resource_name):
            alias_to_targets.setdefault(alias_token, set()).add(resource_name)

    output: dict[str, dict[str, Any]] = {}
    for table_name in context.service_table_names():
        table_token = str(table_name or "").strip()
        if (
            not table_token
            or table_token in _RESOURCE_ENRICHMENT_SKIP_TABLES
            or table_token.startswith("opengraph_")
        ):
            continue
        table_columns = {str(col or "").strip().lower() for col in context.service_table_columns(table_token)}
        if "workspace_id" not in table_columns:
            continue
        name_columns = [column for column in _RESOURCE_ENRICHMENT_NAME_COLUMNS if column in table_columns]
        if not name_columns:
            continue

        for row in context.service_rows(table_token):
            row_dict = dict(row or {})
            row_project_id = str(row_dict.get("project_id") or "").strip()
            matched_names: set[str] = set()
            for column in name_columns:
                token = str(row_dict.get(column) or "").strip()
                if not token:
                    continue
                if token in target_resource_names:
                    matched_names.add(token)
                for alias_token in _resource_name_aliases(token):
                    alias_matches = alias_to_targets.get(alias_token, set())
                    if not alias_matches:
                        continue
                    if row_project_id:
                        alias_matches = {
                            name
                            for name in alias_matches
                            if str(candidate_project_by_name.get(name) or "").strip() == row_project_id
                        }
                    if len(alias_matches) == 1:
                        matched_names.update(alias_matches)
            if not matched_names:
                continue

            row_payload = _row_resourcedata_payload(row_dict, skip_keys={"workspace_id"})
            if not row_payload:
                continue
            for resource_name in matched_names:
                existing = output.setdefault(resource_name, {})
                output[resource_name] = _merge_nested_payload_missing(existing, row_payload)

    return output


def _collect_project_resource_candidates(
    *,
    indexes,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None,
    cloudfunctions_functions_rows: Iterable[dict[str, Any]] | None,
    cloudrun_services_rows: Iterable[dict[str, Any]] | None,
    cloudrun_jobs_rows: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Build candidate resources used for project -> resource topology edges.

    Sources:
    1) `scope_resource_indexes.allow_resources` (IAM-discovered resources)
    2) explicit cached service tables for high-value runtime services
       (compute instances, cloud functions, cloud run services/jobs)
    """
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for row in indexes.allow_resources or []:
        project_id = str(row.get("project_id") or "").strip()
        resource_name = str(row.get("resource_name") or "").strip()
        resource_type = _normalize_resource_type(str(row.get("resource_type") or ""))
        if not project_id or not resource_name or not resource_type:
            continue
        key = (project_id, resource_type, resource_name)
        if key in seen:
            continue
        seen.add(key)
        region = resource_location_token(resource_name)
        candidates.append(
            {
                "project_id": project_id,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "display_name": str(row.get("display_name") or "").strip() or extract_path_tail(resource_name, default=resource_name),
                "region": region,
                "status": str(row.get("status") or row.get("state") or "").strip().upper(),
                "source": "iam_allow_policies",
                "resourcedata": _row_resourcedata_payload(dict(row), skip_keys={"workspace_id"}),
            }
        )

    def _append_explicit_rows(rows: Iterable[dict[str, Any]], *, resource_type: str, name_builder) -> None:
        for row in rows or []:
            project_id = str(row.get("project_id") or "").strip()
            resource_name = str(name_builder(row) or "").strip()
            if not project_id or not resource_name:
                continue
            normalized_type = _normalize_resource_type(resource_type)
            key = (project_id, normalized_type, resource_name)
            if key in seen:
                continue
            seen.add(key)
            region = (
                str(row.get("region_val") or row.get("region") or row.get("location") or "").strip()
                or resource_location_token(resource_name)
            )
            candidates.append(
                {
                    "project_id": project_id,
                    "resource_type": normalized_type,
                    "resource_name": resource_name,
                    "display_name": extract_path_tail(resource_name, default=resource_name),
                    "region": region,
                    "status": str(row.get("status") or row.get("state") or "").strip().upper(),
                    "source": "service_cache",
                    "resourcedata": _row_resourcedata_payload(dict(row), skip_keys={"workspace_id"}),
                }
            )

    _append_explicit_rows(
        cloudcompute_instances_rows,
        resource_type="computeinstance",
        name_builder=lambda row: _compute_instance_resource_name(row),
    )
    _append_explicit_rows(
        cloudfunctions_functions_rows,
        resource_type="cloudfunction",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        cloudrun_services_rows,
        resource_type="cloudrunservice",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        cloudrun_jobs_rows,
        resource_type="cloudrunjob",
        name_builder=lambda row: row.get("name"),
    )

    return candidates


def _add_project_resource_membership_edges(
    context,
    *,
    candidates: list[dict[str, Any]],
    indexes,
    resource_enrichment_by_name: dict[str, dict[str, Any]] | None = None,
) -> int:
    """
    Add:
      project -> EXISTS_IN_PROJECT -> resource

    Mode behavior:
    - default: emit only "relevant services" (compute/function/run + selected high-value services)
    - include_all: emit for every known resource candidate
    """
    include_all = bool(getattr(context.options, "include_all", False))
    edges_added = 0
    enrichment_by_name = dict(resource_enrichment_by_name or {})

    for resource in candidates:
        project_id = str(resource.get("project_id") or "").strip()
        resource_type = _normalize_resource_type(str(resource.get("resource_type") or ""))
        resource_name = str(resource.get("resource_name") or "").strip()
        if not project_id or not resource_type or not resource_name:
            continue
        if resource_type in {"org", "folder", "project"}:
            continue
        should_emit_membership_edge = bool(include_all or resource_type in _DEFAULT_PROJECT_EDGE_RESOURCE_TYPES)

        resource_node = resource_node_id(resource_name)
        resource_label = resource_leaf_name(resource_name) or str(resource.get("display_name") or "").strip() or resource_name
        resource_region = str(resource.get("region") or "").strip() or resource_location_token(resource_name)
        resource_status = str(resource.get("status") or resource.get("state") or "").strip().upper()
        resource_resourcedata = resource.get("resourcedata") if isinstance(resource.get("resourcedata"), dict) else {}
        enriched_payload = enrichment_by_name.get(resource_name)
        if isinstance(enriched_payload, dict) and enriched_payload:
            resource_resourcedata = _merge_nested_payload_missing(resource_resourcedata, enriched_payload)
            if not resource_status:
                resource_status = (
                    str(resource_resourcedata.get("status") or "").strip()
                    or str(resource_resourcedata.get("state") or "").strip()
                    or str(resource_resourcedata.get("primary_state") or "").strip()
                ).upper()
        context.builder.add_node(
            resource_node,
            gcp_resource_node_type(resource_type),
            name=resource_label,
            display_name=resource_label,
            resource_name=resource_name,
            region=resource_region,
            project_id=project_id,
            resource_type=resource_type,
            status=resource_status or None,
            source=str(resource.get("source") or "resource_expansion"),
            resourcedata=resource_resourcedata or None,
        )

        if not should_emit_membership_edge:
            continue

        project_scope_name = _project_scope_name(project_id, indexes.project_scope_by_project_id)
        if not project_scope_name or resource_name == project_scope_name:
            continue

        project_node_id = resource_node_id(project_scope_name)
        project_label = resource_display_label(
            project_scope_name,
            resource_type="project",
            project_id=project_id,
        )
        context.builder.add_node(
            project_node_id,
            gcp_resource_node_type("project"),
            name=project_label,
            display_name=project_label,
            resource_name=project_scope_name,
            project_id=project_id,
            resource_type="project",
            source="resource_expansion",
        )

        edge_key = (project_node_id, "EXISTS_IN_PROJECT", resource_node)
        if edge_key in context.builder.edge_map:
            continue
        context.builder.add_edge(
            project_node_id,
            resource_node,
            "EXISTS_IN_PROJECT",
            source="resource_expansion",
            project_id=project_id,
            resource_type=resource_type,
            membership_mode="include_all" if include_all else "default",
        )
        edges_added += 1

    return edges_added


def _add_compute_executes_with_edges(
    context,
    *,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None,
) -> int:
    """
    Add:
      compute_instance -> EXECUTES_WITH -> serviceAccount:<email>
    """
    edges_added = 0
    for row in cloudcompute_instances_rows or []:
        project_id = str(row.get("project_id") or "").strip()
        instance_name = _compute_instance_resource_name(row)
        if not project_id or not instance_name:
            continue
        instance_label = resource_leaf_name(instance_name) or instance_name
        instance_region = str(row.get("region_val") or row.get("region") or row.get("location") or "").strip() or resource_location_token(instance_name)
        instance_status = str(row.get("status") or row.get("state") or "").strip().upper()
        instance_resourcedata = _compute_instance_resourcedata_payload(row)

        instance_node_id = resource_node_id(instance_name)
        context.builder.add_node(
            instance_node_id,
            gcp_resource_node_type("computeinstance"),
            name=instance_label,
            display_name=instance_label,
            resource_name=instance_name,
            region=instance_region,
            project_id=project_id,
            resource_type="computeinstance",
            status=instance_status or None,
            source="cloudcompute_instances",
            resourcedata=instance_resourcedata or None,
        )

        for email in _extract_compute_instance_service_accounts(row):
            member = f"serviceAccount:{email}"
            principal_id = principal_node_id(member)
            if not principal_id:
                continue
            context.builder.add_node(
                principal_id,
                principal_type(member),
                **principal_member_properties(member),
                source="cloudcompute_instances",
            )

            edge_key = (instance_node_id, "EXECUTES_WITH", principal_id)
            if edge_key in context.builder.edge_map:
                continue
            context.builder.add_edge(
                instance_node_id,
                principal_id,
                "EXECUTES_WITH",
                source="cloudcompute_instances",
                project_id=project_id,
                instance_resource=instance_name,
                service_account_email=email,
            )
            edges_added += 1
    return edges_added


def build_resource_expansion_graph(context) -> dict[str, int | bool]:
    """
    Expand graph with additional derived resource nodes.

    Current pass:
    - GCPServiceAccount nodes from `iam_service_accounts`
    - GCPServiceAccountKey nodes from `iam_sa_keys`
    - key -> service account relationship edges
    - project -> resource topology edges (EXISTS_IN_PROJECT)
    - compute instance -> attached service account edges (EXECUTES_WITH)
    """

    before_nodes, before_edges = context.counts()
    iam_service_accounts_rows = context.rows("iam_service_accounts")
    iam_sa_keys_rows = context.rows("iam_sa_keys")
    cloudcompute_instances_rows = context.rows("cloudcompute_instances")
    cloudfunctions_functions_rows = context.rows("cloudfunctions_functions")
    cloudrun_services_rows = context.rows("cloudrun_services")
    cloudrun_jobs_rows = context.rows("cloudrun_jobs")
    scope_resource_indexes = context.scope_resource_indexes()

    sa_nodes_added = 0
    for row in iam_service_accounts_rows:
        principal_type_token = str(row.get("type") or "").strip().lower()
        if "service" not in principal_type_token:
            continue
        email = str(row.get("email") or "").strip()
        if not email:
            continue
        member = f"serviceAccount:{email}"
        node_id = principal_node_id(member)
        existed = node_id in context.builder.node_map
        props = dict(principal_member_properties(member))
        row_name = str(row.get("name") or "").strip()
        row_display_name = str(row.get("display_name") or "").strip()
        if row_name:
            props["name"] = row_name
        if row_display_name:
            props["display_name"] = row_display_name
        context.builder.add_node(
            node_id,
            principal_type(member),
            **props,
            source="iam_service_accounts",
        )
        if not existed:
            sa_nodes_added += 1

    key_nodes_added = 0
    key_edges_added = 0
    for row in iam_sa_keys_rows:
        key_name = str(row.get("name") or "").strip()
        if not key_name:
            continue
        service_account_email = extract_path_segment(key_name, "serviceAccounts")
        key_id = extract_path_segment(key_name, "keys")
        if not service_account_email or not key_id:
            continue

        key_node_id = f"service_account_key:{key_name}"
        key_existed = key_node_id in context.builder.node_map
        context.builder.add_node(
            key_node_id,
            "GCPServiceAccountKey",
            name=key_id,
            display_name=key_id,
            resource_name=key_name,
            key_id=key_id,
            service_account_email=service_account_email,
            disabled=row.get("disabled"),
            key_type=row.get("key_type"),
            key_origin=row.get("key_origin"),
            valid_after_time=row.get("valid_after_time"),
            valid_before_time=row.get("valid_before_time"),
            source="iam_sa_keys",
        )
        if not key_existed:
            key_nodes_added += 1

        service_account_member = f"serviceAccount:{service_account_email}"
        service_account_id = principal_node_id(service_account_member)
        sa_props = principal_member_properties(service_account_member)
        context.builder.add_node(
            service_account_id,
            principal_type(service_account_member),
            **sa_props,
            source="iam_sa_keys",
        )

        edge_key = (key_node_id, "GCP_SERVICE_ACCOUNT_KEY_FOR", service_account_id)
        edge_existed = edge_key in context.builder.edge_map
        context.builder.add_edge(
            key_node_id,
            service_account_id,
            "GCP_SERVICE_ACCOUNT_KEY_FOR",
            source="iam_sa_keys",
            key_name=key_name,
            key_id=key_id,
            service_account_email=service_account_email,
        )
        if not edge_existed:
            key_edges_added += 1

    project_resource_candidates = _collect_project_resource_candidates(
        indexes=scope_resource_indexes,
        cloudcompute_instances_rows=cloudcompute_instances_rows,
        cloudfunctions_functions_rows=cloudfunctions_functions_rows,
        cloudrun_services_rows=cloudrun_services_rows,
        cloudrun_jobs_rows=cloudrun_jobs_rows,
    )
    candidate_resource_names = {
        str(candidate.get("resource_name") or "").strip()
        for candidate in project_resource_candidates
        if str(candidate.get("resource_name") or "").strip()
    }
    candidate_project_by_name = {
        str(candidate.get("resource_name") or "").strip(): str(candidate.get("project_id") or "").strip()
        for candidate in project_resource_candidates
        if str(candidate.get("resource_name") or "").strip()
    }
    resource_enrichment_by_name = _resource_enrichment_payloads_by_name(
        context,
        target_resource_names=candidate_resource_names,
        candidate_project_by_name=candidate_project_by_name,
    )

    project_membership_edges_added = _add_project_resource_membership_edges(
        context,
        candidates=project_resource_candidates,
        indexes=scope_resource_indexes,
        resource_enrichment_by_name=resource_enrichment_by_name,
    )
    compute_executes_with_edges_added = _add_compute_executes_with_edges(
        context,
        cloudcompute_instances_rows=cloudcompute_instances_rows,
    )

    after_nodes, after_edges = context.counts()
    return {
        "service_account_nodes_added": sa_nodes_added,
        "service_account_key_nodes_added": key_nodes_added,
        "service_account_key_edges_added": key_edges_added,
        "project_resource_edges_added": project_membership_edges_added,
        "compute_executes_with_edges_added": compute_executes_with_edges_added,
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
