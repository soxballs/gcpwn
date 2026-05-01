from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.constants import load_privilege_escalation_rules
from gcpwn.modules.opengraph.utilities.helpers.iam_bindings_shared_helpers import (
    _emit_iam_binding_edges_from_entries,
    _normalized_rule,
    expand_multi_permission_rules,
)


def _multi_permission_dangerous_rules() -> tuple[dict[str, object], ...]:
    _single_rules_raw, multi_rules_raw, _collapsed_rules = load_privilege_escalation_rules()
    return tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_multi_permission_rules(multi_rules_raw).items()
        if isinstance(raw_rule, dict)
    )


def build_iam_bindings_multi_permission_graph(
    context,
) -> dict[str, int | bool | str]:
    """Emit multi-permission/combo IAM rule edges from pre-resolved bindings composite rows."""

    before_nodes, before_edges = context.counts()
    base_state_present = bool(context.get_artifact("iam_bindings_base_state"))
    resolved_bindings_composite = list(context.get_artifact("resolved_bindings_composite") or [])
    reused_base_entries = bool(resolved_bindings_composite)
    unsupported_rule_names = {
        str(rule_name or "").strip()
        for rule_name in (context.get_artifact("binding_unsupported_rule_names") or [])
        if str(rule_name or "").strip()
    }
    multi_rules = tuple(
        rule
        for rule in _multi_permission_dangerous_rules()
        if str(rule.get("name") or "").strip() not in unsupported_rule_names
    )

    if not multi_rules:
        return {
            "dangerous_rule_mode": "advanced",
            "base_state_present": base_state_present,
            "reused_base_entries": reused_base_entries,
            "dangerous_edges_emitted": 0,
            "combo_bindings_emitted": 0,
            "bindings_total": 0,
            "bindings_emitted": 0,
            "entries_total": 0,
            "rules_total": 0,
            "nodes_added": 0,
            "edges_added": 0,
            "total_nodes": before_nodes,
            "total_edges": before_edges,
        }

    binding_result = _emit_iam_binding_edges_from_entries(
        context,
        entries=resolved_bindings_composite,
        include_all=False,
        dangerous_rules=multi_rules,
        pass_name="advanced",
    )
    context.set_artifact("iam_bindings_advanced_state", binding_result.get("aggregation") or {})
    context.set_artifact("iam_bindings_advanced_runtime", binding_result.get("runtime") or {})

    after_nodes, after_edges = context.counts()
    return {
        "dangerous_rule_mode": str(binding_result.get("dangerous_rule_mode") or "advanced"),
        "base_state_present": base_state_present,
        "reused_base_entries": reused_base_entries,
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
