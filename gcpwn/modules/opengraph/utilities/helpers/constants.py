from __future__ import annotations

from typing import Any

from gcpwn.core.utils.module_helpers import load_mapping_data

def _fa_icon(name: str, color: str) -> dict:
    return {"icon": {"type": "font-awesome", "name": name, "color": color}}


CUSTOM_NODE_TYPES = {
    # Principals
    "GCPAllUsers": _fa_icon("users", "#8E24AA"),
    "GCPAllAuthenticatedUsers": _fa_icon("user-check", "#5E35B1"),
    "GoogleUser": _fa_icon("user", "#43A047"),
    "GoogleGroup": _fa_icon("users", "#FB8C00"),
    "GCPServiceAccount": _fa_icon("id-badge", "#1E88E5"),
    "GCPDomainPrincipal": _fa_icon("globe", "#607D8B"),
    "GCPConvenienceMember": _fa_icon("user-tag", "#7B1FA2"),
    "GCPPrincipal": _fa_icon("user-shield", "#546E7A"),

    # Graph internals
    "GCPIamBinding": _fa_icon("id-card", "#546E7A"),
    "GCPIamGrant": _fa_icon("id-card", "#546E7A"),
    "GCPIamSimpleBinding": _fa_icon("id-card", "#455A64"),
    "GCPIamMultiBinding": _fa_icon("layer-group", "#37474F"),
    "GCPIamCapability": _fa_icon("wand-magic-sparkles", "#6A1B9A"),
    "GCPResource": _fa_icon("cube", "#90A4AE"),
    "GCPUnknown": _fa_icon("circle-question", "#90A4AE"),

    # Hierarchy / scope resources
    "GCPOrganization": _fa_icon("building", "#6D4C41"),
    "GCPFolder": _fa_icon("folder", "#8D6E63"),
    "GCPProject": _fa_icon("folder-open", "#5D4037"),

    # GCP resources
    "GCPBucket": _fa_icon("box-open", "#F57C00"),
    "GCPCloudFunction": _fa_icon("bolt", "#FF7043"),
    "GCPComputeInstance": _fa_icon("server", "#1E88E5"),
    "GCPCloudSQLInstance": _fa_icon("database", "#1976D2"),
    "GCPServiceAccountResource": _fa_icon("id-badge", "#1E88E5"),
    "GCPArtifactRegistryRepo": _fa_icon("boxes-stacked", "#8E24AA"),
    "GCPBigQueryDataset": _fa_icon("database", "#1A73E8"),
    "GCPBigQueryTable": _fa_icon("table", "#1A73E8"),
    "GCPBigQueryRoutine": _fa_icon("code", "#1A73E8"),
    "GCPSpannerInstance": _fa_icon("database", "#0B57D0"),
    "GCPSpannerDatabase": _fa_icon("table", "#0B57D0"),
    "GCPCloudRunService": _fa_icon("play", "#00ACC1"),
    "GCPCloudRunJob": _fa_icon("gears", "#00ACC1"),
    "GCPCloudTasksQueue": _fa_icon("list-check", "#5E35B1"),
    "GCPServiceDirectoryNamespace": _fa_icon("folder-open", "#6A1B9A"),
    "GCPServiceDirectoryService": _fa_icon("compass", "#6A1B9A"),
    "GCPPubSubTopic": _fa_icon("bullhorn", "#8E24AA"),
    "GCPPubSubSubscription": _fa_icon("bell", "#8E24AA"),
    "GCPPubSubSchema": _fa_icon("file-code", "#8E24AA"),
    "GCPPubSubSnapshot": _fa_icon("camera", "#8E24AA"),

    # Secrets / KMS
    "GCPSecret": _fa_icon("lock", "#00695C"),
    "GCPKmsKeyRing": _fa_icon("key", "#00796B"),
    "GCPKmsCryptoKey": _fa_icon("key", "#00796B"),
    "GCPKmsCryptoKeyVersion": _fa_icon("key", "#00796B"),
    # Compatibility aliases for legacy node-type casing
    "GCPKmskey": _fa_icon("key", "#00796B"),

    # Expansion helpers
    "GCPServiceAccountKey": _fa_icon("key", "#F9A825"),
}


# IAM dangerous (privilege escalation/lateral movement) edge rules are loaded
# from a dedicated data file so contributors can add paths without editing code.
_PRIVILEGE_ESCALATION_RULES_MAPPING_FILE = "og_privilege_escalation_paths.json"


def _as_rule_mapping(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for raw_name, raw_rule in value.items():
        name = str(raw_name or "").strip()
        if not name or not isinstance(raw_rule, dict):
            continue
        output[name] = dict(raw_rule)
    return output


def _as_collapsed_role_mapping(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, str]] = {}
    for raw_role, raw_rule in value.items():
        role_name = str(raw_role or "").strip()
        if not role_name or not isinstance(raw_rule, dict):
            continue
        edge_type = str(raw_rule.get("edge_type") or "").strip()
        if not edge_type:
            continue
        output[role_name] = {
            "edge_type": edge_type,
            "description": str(raw_rule.get("description") or "").strip(),
        }
    return output


def _load_privilege_escalation_rules() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    payload = load_mapping_data(_PRIVILEGE_ESCALATION_RULES_MAPPING_FILE, kind="json")
    if not isinstance(payload, dict):
        return {}, {}, {}
    return (
        _as_rule_mapping(payload.get("single_permission_rules")),
        _as_rule_mapping(payload.get("multi_permission_rules")),
        _as_collapsed_role_mapping(payload.get("collapsed_role_edges")),
    )


def load_privilege_escalation_rules() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """
    Load privilege-escalation rule mappings from disk.

    Callers that need hot-reload behavior in long-lived CLI sessions should
    use this helper instead of relying on module-import-time globals.
    """
    return _load_privilege_escalation_rules()


(
    DANGEROUS_EDGE_RULES_SINGLE_PERMISSION,
    DANGEROUS_EDGE_RULES_MULTI_PERMISSIONS,
    COLLAPSED_DANGEROUS_ROLE_EDGE_RULES,
) = _load_privilege_escalation_rules()
