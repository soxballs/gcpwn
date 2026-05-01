from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import load_mapping_data, parse_string_list
from gcpwn.modules.opengraph.utilities.helpers.constants import load_privilege_escalation_rules
from gcpwn.modules.opengraph.utilities.helpers.core_helpers import principal_node_id
from gcpwn.modules.opengraph.utilities.helpers.iam_conditionals import ConditionOption, StatementConditionalsEngine
from gcpwn.modules.opengraph.utilities.helpers.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    ScopeResourceIndexes,
    _canonical_scope_type,
    _normalized_token_frozenset,
    _normalized_rule,
    _requirement_permissions,
    _scope_leaf,
    binding_scope_token,
    expand_multi_permission_rules,
    expand_single_permission_rules,
)


DEFAULT_PERMISSION_ROLE_MAP_FILE = "og_permission_to_roles_map.json"


def _load_permission_to_roles() -> dict[str, list[str]]:
    try:
        payload = load_mapping_data(DEFAULT_PERMISSION_ROLE_MAP_FILE, kind="json")
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(permission or "").strip(): [str(role or "").strip() for role in (roles or []) if str(role or "").strip()]
        for permission, roles in payload.items()
        if str(permission or "").strip() and isinstance(roles, list)
    }


def _normalized_binding_rules_by_family() -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    single_rules_raw, multi_rules_raw, _collapsed_rules = load_privilege_escalation_rules()
    single_rules = tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_single_permission_rules(single_rules_raw).items()
        if isinstance(raw_rule, dict)
    )
    multi_rules = tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_multi_permission_rules(multi_rules_raw).items()
        if isinstance(raw_rule, dict)
    )
    return single_rules, multi_rules


def _binding_rule_permission_map_coverage(
    *,
    permission_to_roles: dict[str, list[str]] | None,
    single_rules: Iterable[dict[str, Any]],
    multi_rules: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    known_permissions = {
        str(permission or "").strip()
        for permission in (permission_to_roles or {}).keys()
        if str(permission or "").strip()
    }
    unsupported_rule_names: set[str] = set()
    unmapped_permissions: set[str] = set()
    unsupported_rules: list[dict[str, Any]] = []

    def _collect_rule(rule: dict[str, Any], *, family: str) -> None:
        required_permissions = sorted(
            {
                str(permission or "").strip()
                for permission in _requirement_permissions(rule)
                if str(permission or "").strip()
            }
        )
        if not required_permissions:
            return
        missing_permissions = [permission for permission in required_permissions if permission not in known_permissions]
        if not missing_permissions:
            return
        rule_name = str(rule.get("name") or "").strip() or str(rule.get("edge_type") or "").strip() or "<unnamed_rule>"
        unsupported_rule_names.add(rule_name)
        unmapped_permissions.update(missing_permissions)
        record = {
            "family": family,
            "rule_name": rule_name,
            "edge_type": str(rule.get("edge_type") or "").strip() or rule_name,
            "missing_permissions": missing_permissions,
            "required_permissions": required_permissions,
        }
        variant_id = str(rule.get("rule_variant_id") or "").strip()
        if variant_id:
            record["rule_variant_id"] = variant_id
        unsupported_rules.append(record)

    for rule in single_rules or ():
        if isinstance(rule, dict):
            _collect_rule(rule, family="single")
    for rule in multi_rules or ():
        if isinstance(rule, dict):
            _collect_rule(rule, family="multi")

    return {
        "known_permission_count": len(known_permissions),
        "unsupported_rule_count": len(unsupported_rules),
        "unsupported_rule_names": sorted(unsupported_rule_names),
        "unmapped_permissions": sorted(unmapped_permissions),
        "unsupported_rules": unsupported_rules,
    }


def _condition_hash(condition: Any) -> str:
    if not condition:
        return ""
    if isinstance(condition, dict):
        expression = str(condition.get("expression") or "").strip()
        if expression:
            return hashlib.sha1(expression.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
        payload = json.dumps(condition, sort_keys=True, ensure_ascii=False)
    else:
        payload = str(condition)
    if not payload:
        return ""
    return hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]


def _binding_composite_id(
    *,
    role_name: str,
    attached_scope_token: str,
    source_scope_token: str = "",
    condition_hash: str,
) -> str:
    binding_composite_id = f"iambinding:{role_name}@{attached_scope_token}"
    # Keep inherited fan-out rows distinct from direct rows at the same effective
    # scope so direct + inherited bindings do not collapse into a single binding node.
    if source_scope_token and source_scope_token != attached_scope_token:
        binding_composite_id = f"{binding_composite_id}#src:{source_scope_token}"
    if condition_hash:
        binding_composite_id = f"{binding_composite_id}#cond:{condition_hash}"
    return binding_composite_id


def _descendants(children_by_parent: dict[str, list[str]], root: str) -> list[str]:
    root_name = str(root or "").strip()
    if not root_name:
        return []
    output: list[str] = []
    seen = {root_name}
    queue: deque[str] = deque(children_by_parent.get(root_name, []))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        output.append(current)
        for child in children_by_parent.get(current, []):
            if child not in seen:
                queue.append(child)
    return output


def _invert_permission_to_roles(permission_to_roles: dict[str, list[str]] | None) -> dict[str, set[str]]:
    output: dict[str, set[str]] = defaultdict(set)
    for permission, roles in (permission_to_roles or {}).items():
        permission_token = str(permission or "").strip()
        if not permission_token or not isinstance(roles, list):
            continue
        for role in roles:
            role_token = str(role or "").strip()
            if role_token:
                output[role_token].add(permission_token)
    return output


def _custom_role_permissions(iam_roles_rows: Iterable[dict[str, Any]] | None) -> dict[str, set[str]]:
    output: dict[str, set[str]] = {}
    for row in iam_roles_rows or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        permissions = set(parse_string_list(row.get("included_permissions"), fallback_to_single=True))
        if permissions:
            output[name] = permissions
    return output


def _build_scope_and_resource_indexes(
    *,
    hierarchy_data: dict[str, Any] | None,
    flattened_member_rows: Iterable[dict[str, Any]] | None = None,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None = None,
) -> ScopeResourceIndexes:
    """Build reusable scope/resource indexes from hierarchy + flattened IAM member rows."""
    hierarchy = hierarchy_data or {}
    scope_project_by_name = hierarchy.get("scope_project_by_name") or {}
    scope_display_by_name = hierarchy.get("scope_display_by_name") or {}
    scope_type_by_name = hierarchy.get("scope_type_by_name") or {}
    known_project_ids = {
        str(project_id or "").strip()
        for project_id in (hierarchy.get("known_project_ids") or set())
        if str(project_id or "").strip()
    }
    project_id_by_scope_name: dict[str, str] = {}
    project_scope_by_project_id: dict[str, str] = {}

    for scope_name, scope_type in scope_type_by_name.items():
        token = str(scope_name or "").strip()
        if not token or _canonical_scope_type(str(scope_type or ""), token) != "project":
            continue
        project_id = str(scope_project_by_name.get(token) or "").strip() or _scope_leaf(token)
        if not project_id:
            continue
        known_project_ids.add(project_id)
        project_id_by_scope_name[token] = project_id
        project_scope_by_project_id[project_id] = token

    allow_resources: list[dict[str, str]] = []
    seen_resources: set[tuple[str, str, str]] = set()
    for row in flattened_member_rows or []:
        resource_name = str(row.get("name") or "").strip()
        if not resource_name:
            continue
        resource_type = _canonical_scope_type(str(row.get("type") or "").strip(), resource_name)
        resolved_project_id = str(row.get("project_id") or "").strip()
        if resource_type == "project":
            resolved_project_id = (
                resolved_project_id or project_id_by_scope_name.get(resource_name, "") or _scope_leaf(resource_name)
            )
            if resolved_project_id:
                known_project_ids.add(resolved_project_id)
                project_scope_by_project_id.setdefault(resolved_project_id, resource_name)
                project_id_by_scope_name.setdefault(resource_name, resolved_project_id)
        resource_key_tuple = (resource_name, resource_type, resolved_project_id)
        if resource_key_tuple in seen_resources:
            continue
        seen_resources.add(resource_key_tuple)
        allow_resources.append(
            {
                "resource_name": resource_name,
                "resource_type": resource_type,
                "display_name": str(row.get("display_name") or "").strip()
                or str(scope_display_by_name.get(resource_name) or ""),
                "project_id": resolved_project_id,
            }
        )

    # Enrich compute instance resources with runtime status from cached
    # cloudcompute_instances rows so rule selectors can reason about
    # start/reset viability by instance state.
    compute_status_by_resource_name: dict[str, str] = {}
    for row in cloudcompute_instances_rows or []:
        project_id = str(row.get("project_id") or "").strip()
        instance_name = str(row.get("name") or "").strip()
        zone = str(row.get("zone") or "").strip()
        if "/" in zone:
            zone = _scope_leaf(zone)
        status = str(row.get("status") or row.get("state") or "").strip().upper()
        if not status:
            continue
        if project_id and instance_name and zone:
            full_name = f"projects/{project_id}/zones/{zone}/instances/{instance_name}"
            compute_status_by_resource_name[full_name] = status
        if instance_name:
            compute_status_by_resource_name.setdefault(instance_name, status)

    # Ensure compute instances from runtime enumeration are available as
    # selector targets even when no per-instance IAM policy rows were cached.
    for row in cloudcompute_instances_rows or []:
        project_id = str(row.get("project_id") or "").strip()
        instance_name = str(row.get("name") or "").strip()
        zone = str(row.get("zone") or "").strip()
        if "/" in zone:
            zone = _scope_leaf(zone)
        if not (project_id and instance_name):
            continue
        resource_name = f"projects/{project_id}/zones/{zone}/instances/{instance_name}" if zone else instance_name
        resource_key_tuple = (resource_name, "computeinstance", project_id)
        if resource_key_tuple in seen_resources:
            continue
        seen_resources.add(resource_key_tuple)
        allow_resources.append(
            {
                "resource_name": resource_name,
                "resource_type": "computeinstance",
                "display_name": instance_name,
                "project_id": project_id,
            }
        )

    for resource in allow_resources:
        if str(resource.get("resource_type") or "").strip().lower() != "computeinstance":
            continue
        resource_name = str(resource.get("resource_name") or "").strip()
        if not resource_name:
            continue
        status = compute_status_by_resource_name.get(resource_name)
        if not status and "/" in resource_name:
            status = compute_status_by_resource_name.get(_scope_leaf(resource_name))
        if status:
            resource["status"] = status

    allow_resources_by_project: dict[str, list[dict[str, str]]] = defaultdict(list)
    allow_resources_by_project_type: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for resource in allow_resources:
        project_key = str(resource.get("project_id") or "").strip()
        if not project_key:
            continue
        resource_type = str(resource.get("resource_type") or "").strip().lower()
        allow_resources_by_project[project_key].append(resource)
        if resource_type:
            allow_resources_by_project_type[project_key][resource_type].append(resource)

    return ScopeResourceIndexes(
        project_scope_by_project_id=project_scope_by_project_id,
        project_id_by_scope_name=project_id_by_scope_name,
        known_project_ids=known_project_ids,
        allow_resources=allow_resources,
        allow_resources_by_project={k: list(v) for k, v in allow_resources_by_project.items()},
        allow_resources_by_project_type={
            project_id: {resource_type: list(resources) for resource_type, resources in type_map.items()}
            for project_id, type_map in allow_resources_by_project_type.items()
        },
    )


def build_iam_bindings_prepare(
    context,
) -> list[BindingPlusScopeEntry]:
    """
    Build normalized IAM binding+scope entries used by all IAM graph passes.

    Input sources:
    - simplified hierarchy IAM bindings (`member_binding_index`)
    - custom role definitions (`iam_custom_roles`)
    - hierarchy/scope indexes from context

    What this does:
    - expands each IAM binding into typed objects (one object per principal+role+effective scope)
    - resolves role -> permission sets (predefined map + custom role permissions)
    - fans out inherited scope coverage (org/folder -> descendants) when enabled
    - applies conditional option expansion/narrowing metadata when enabled

    Output:
    - list[BindingPlusScopeEntry] where each row has principal, role, permissions,
      source/attached/effective scope metadata, inheritance flags, and condition metadata
    - writes that list into context artifact `resolved_bindings_composite`
    """
    scope_resource_indexes = context.scope_resource_indexes()
    simplified_base = context.simplified_hierarchy_permissions(include_inferred_permissions=False)
    member_binding_index = simplified_base.get("member_binding_index") or {}
    expand_inheritance = bool(context.options.expand_inheritance)
    conditional_evaluation = bool(context.options.conditional_evaluation)
    iam_roles_rows = context.rows("iam_custom_roles")

    permission_to_roles = _load_permission_to_roles()
    role_to_permissions = _invert_permission_to_roles(permission_to_roles)

    for role_name, perms in _custom_role_permissions(iam_roles_rows).items():
        role_to_permissions.setdefault(role_name, set()).update(perms)

    normalized_single_rules, normalized_multi_rules = _normalized_binding_rules_by_family()
    binding_permission_coverage = _binding_rule_permission_map_coverage(
        permission_to_roles=permission_to_roles,
        single_rules=normalized_single_rules,
        multi_rules=normalized_multi_rules,
    )
    context.set_artifact("binding_permission_map_coverage", binding_permission_coverage)
    context.set_artifact(
        "binding_unsupported_rule_names",
        list(binding_permission_coverage.get("unsupported_rule_names") or []),
    )
    context.set_artifact(
        "binding_unmapped_permissions",
        list(binding_permission_coverage.get("unmapped_permissions") or []),
    )

    hierarchy = context.hierarchy_data() or {}
    scope_type_by_name = hierarchy.get("scope_type_by_name") or {}
    scope_display_by_name = hierarchy.get("scope_display_by_name") or {}
    conditionals = StatementConditionalsEngine(enabled=conditional_evaluation)
    entries: list[BindingPlusScopeEntry] = []
    children_by_parent = hierarchy.get("children_by_parent") or {}
    default_condition_option = ConditionOption(
        option_id="default",
        expression="",
        narrowed_prefixes=[],
        narrowed_equals=[],
        narrowed_services=[],
        narrowed_resource_types=[],
        unresolved=False,
        filter_summary="",
    )

    def _append_binding(
        *,
        member: str,
        role_name: str,
        attached_scope_name: str,
        attached_scope_type: str,
        project_id: str,
        condition: Any | None,
        expanded_from_convenience_member: str = "",
    ) -> None:
        """Expand one IAM binding into one or more binding-composite entries."""
        member_token = str(member or "").strip()
        role_token = str(role_name or "").strip()
        attached_scope = str(attached_scope_name or "").strip()
        if not member_token or not role_token or not attached_scope:
            return

        attached_type = _canonical_scope_type(attached_scope_type, attached_scope)
        principal_id = principal_node_id(member_token)
        if not principal_id:
            return

        expanded_from = str(expanded_from_convenience_member or "").strip()
        condition_dict = condition if isinstance(condition, dict) else None
        condition_expr = str(condition_dict.get("expression") or "").strip() if condition_dict else ""
        cond_hash = _condition_hash(condition_dict)
        attached_scope_ref = binding_scope_token(attached_type, attached_scope, project_id=project_id)
        role_permissions = frozenset(role_to_permissions.get(role_token, ()))
        common_entry_fields = {
            "principal_id": principal_id,
            "principal_member": member_token,
            "expanded_from_convenience_member": expanded_from,
            "role_name": role_token,
            "permissions": role_permissions,
            "source_scope_name": attached_scope,
            "source_scope_type": attached_type,
            "source_scope_display": str(scope_display_by_name.get(attached_scope) or attached_scope_ref),
            "source": "iam_allow_policies",
            "conditional": bool(cond_hash),
            "condition_expr_raw": condition_expr,
            "condition_hash": cond_hash,
            "condition_summary": condition_expr[:240] if condition_expr else "",
        }

        effective_scopes = [attached_scope]
        if expand_inheritance and attached_type in {"org", "folder"}:
            effective_scopes.extend(_descendants(children_by_parent, attached_scope))

        option_list: list[ConditionOption] = (
            conditionals.evaluate_options(condition_dict)
            if conditional_evaluation
            else [default_condition_option]
        )

        project_id_by_scope = scope_resource_indexes.project_id_by_scope_name
        for option in option_list:
            option_id = str(option.option_id or "default")
            option_summary = str(option.filter_summary or "")
            option_services = _normalized_token_frozenset(option.narrowed_services)
            option_resource_types = _normalized_token_frozenset(option.narrowed_resource_types)
            option_name_prefixes = _normalized_token_frozenset(option.narrowed_prefixes)
            option_name_equals = _normalized_token_frozenset(option.narrowed_equals)
            option_scopes = (
                conditionals.narrow_with_option(effective_scopes, option)
                if conditional_evaluation
                else effective_scopes
            )

            for effective_scope in option_scopes:
                effective_scope_type = scope_type_by_name.get(effective_scope, attached_type)
                effective_scope_display = scope_display_by_name.get(effective_scope) or _scope_leaf(effective_scope)
                entry_project_id = project_id_by_scope.get(effective_scope, project_id)
                emitted_scope_ref = binding_scope_token(
                    effective_scope_type,
                    effective_scope,
                    project_id=str(entry_project_id or ""),
                )
                entries.append(
                    BindingPlusScopeEntry(
                        **common_entry_fields,
                        binding_composite_id=_binding_composite_id(
                            role_name=role_token,
                            attached_scope_token=emitted_scope_ref,
                            source_scope_token=attached_scope_ref,
                            condition_hash=cond_hash,
                        ),
                        attached_scope_name=effective_scope,
                        attached_scope_type=effective_scope_type,
                        attached_scope_display=effective_scope_display,
                        effective_scope_name=effective_scope,
                        effective_scope_type=effective_scope_type,
                        effective_scope_display=effective_scope_display,
                        project_id=str(entry_project_id or ""),
                        inherited=bool(effective_scope != attached_scope),
                        condition_option_id=option_id,
                        condition_option_summary=option_summary,
                        condition_services=option_services,
                        condition_resource_types=option_resource_types,
                        condition_name_prefixes=option_name_prefixes,
                        condition_name_equals=option_name_equals,
                    )
                )

    for member_key, resource_map in sorted(
        (member_binding_index or {}).items(),
        key=lambda item: str(item[0] or ""),
    ):
        member_token = principal_node_id(str(member_key or "").strip())
        if not member_token:
            continue

        for _resource_key, payload in sorted(
            (resource_map or {}).items(),
            key=lambda item: str(item[0] or ""),
        ):
            for raw_record in (payload.get("direct_binding_records") or []) + (payload.get("convenience_binding_records") or []):
                role_name = str(raw_record.get("role_name") or "").strip()
                attached_scope_type = str(raw_record.get("attached_scope_type") or "").strip()
                attached_scope_name = str(raw_record.get("attached_scope_name") or "").strip()
                project_id = str(raw_record.get("project_id") or "").strip()
                condition = raw_record.get("condition") if isinstance(raw_record.get("condition"), dict) else None
                if not role_name or not attached_scope_name:
                    continue
                _append_binding(
                    member=member_token,
                    role_name=role_name,
                    attached_scope_name=attached_scope_name,
                    attached_scope_type=attached_scope_type,
                    project_id=project_id,
                    condition=condition,
                    expanded_from_convenience_member=str(raw_record.get("derived_from") or "").strip(),
                )

    context.set_artifact("resolved_bindings_composite", entries)
    return entries
