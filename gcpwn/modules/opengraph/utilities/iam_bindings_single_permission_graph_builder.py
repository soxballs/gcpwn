from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.constants import (
    load_privilege_escalation_rules,
)
from gcpwn.modules.opengraph.utilities.helpers.iam_bindings_shared_helpers import (
    _emit_iam_binding_edges_from_entries,
    _normalized_rule,
    expand_single_permission_rules,
)


def _single_dangerous_rules() -> tuple[dict[str, object], ...]:
    single_rules_raw, _multi_rules_raw, _collapsed_rules = load_privilege_escalation_rules()
    return tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_single_permission_rules(single_rules_raw).items()
        if isinstance(raw_rule, dict)
    )


def build_iam_bindings_single_permissions(
    context,
) -> dict[str, int | bool]:
    """Emit single-permission IAM rule edges from pre-resolved binding+scope composite rows."""

    before_nodes, before_edges = context.counts()
    resolved_binding_scope_entries = context.get_artifact("resolved_bindings_composite") or ()
    if not isinstance(resolved_binding_scope_entries, list):
        resolved_binding_scope_entries = list(resolved_binding_scope_entries)
    unsupported_rule_names = {
        str(rule_name or "").strip()
        for rule_name in (context.get_artifact("binding_unsupported_rule_names") or [])
        if str(rule_name or "").strip()
    }
    single_rules = tuple(
        rule
        for rule in _single_dangerous_rules()
        if str(rule.get("name") or "").strip() not in unsupported_rule_names
    )
    binding_result = _emit_iam_binding_edges_from_entries(
        context,
        entries=resolved_binding_scope_entries,
        include_all=bool(context.options.include_all),
        dangerous_rules=single_rules,
        pass_name="base",
    )
    # Base aggregation + normalized binding contexts are consumed by the advanced pass.
    context.set_artifact("iam_bindings_base_state", binding_result.get("aggregation") or {})
    context.set_artifact("iam_bindings_base_runtime", binding_result.get("runtime") or {})
    after_nodes, after_edges = context.counts()
    return {
        "include_all": bool(context.options.include_all),
        "expand_inheritance": bool(context.options.expand_inheritance),
        "conditional_evaluation": bool(context.options.conditional_evaluation),
        "dangerous_rule_mode": str(binding_result.get("dangerous_rule_mode") or "base"),
        "dangerous_edges_emitted": int(binding_result.get("dangerous_edges_emitted", 0)),
        "combo_bindings_emitted": int(binding_result.get("combo_bindings_emitted", 0)),
        "bindings_composite_total": int(binding_result.get("bindings_composite_total", 0)),
        "bindings_composite_emitted": int(binding_result.get("bindings_composite_emitted", 0)),
        "bindings_total": int(binding_result.get("bindings_total", 0)),
        "bindings_emitted": int(binding_result.get("bindings_emitted", 0)),
        "entries_total": int(binding_result.get("entries_total", 0)),
        "rules_total": int(binding_result.get("rules_total", 0)),
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
