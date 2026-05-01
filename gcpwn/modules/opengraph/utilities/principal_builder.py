from __future__ import annotations

from typing import Any, Iterable

from gcpwn.modules.opengraph.utilities.helpers.core_helpers import (
    OpenGraphBuilder,
    is_convenience_member,
    principal_member_properties,
    principal_node_id,
    principal_type,
)


def _add_workspace_principal_nodes(
    builder: OpenGraphBuilder,
    *,
    rows: Iterable[dict[str, Any]] | None,
    member_prefix: str,
    node_type: str,
    source: str,
    extra_fields: dict[str, str],
) -> None:
    # Shared Google Workspace principal-node seeding helper.
    # Expected row examples:
    # - user row:  {"email":"alice@example.com","display_name":"Alice","user_id":"123","customer_id":"C..."}
    # - group row: {"email":"eng@example.com","display_name":"Engineering","description":"...","customer_id":"C..."}
    #
    # `extra_fields` maps destination node property -> source row key.
    # Example: {"google_workspace_customer_id": "customer_id"}
    for row in rows or []:
        email = str(row.get("email") or "").strip().lower()
        if not email:
            continue
        member = f"{member_prefix}:{email}"
        node_id = principal_node_id(member)
        if not node_id:
            continue
        props = principal_member_properties(member)
        row_display_name = str(row.get("display_name") or "").strip()
        if row_display_name:
            props["display_name"] = row_display_name
            props["name"] = row_display_name

        extras = {dst: row.get(src) for dst, src in (extra_fields or {}).items()}
        builder.add_node(
            node_id,
            node_type,
            **props,
            source=source,
            **extras,
        )


def _add_workspace_nodes(
    builder: OpenGraphBuilder,
    *,
    workspace_users: Iterable[dict[str, Any]] | None,
    workspace_groups: Iterable[dict[str, Any]] | None,
) -> None:
    # Seed high-confidence identity nodes from Google Workspace inventory first.
    # This allows later IAM-derived principal nodes to merge into richer user/group nodes
    # instead of remaining generic principal-only objects.
    _add_workspace_principal_nodes(
        builder,
        rows=workspace_users,
        member_prefix="user",
        node_type="GoogleUser",
        source="workspace_users",
        extra_fields={
            "user_id": "user_id",
            "google_workspace_customer_id": "customer_id",
        },
    )
    _add_workspace_principal_nodes(
        builder,
        rows=workspace_groups,
        member_prefix="group",
        node_type="GoogleGroup",
        source="workspace_groups",
        extra_fields={
            "description": "description",
            "google_workspace_customer_id": "customer_id",
        },
    )


def _typed_member_token(raw_member: str, *, member_type: str = "") -> str:
    token = str(raw_member or "").strip()
    if not token:
        return ""
    if ":" in token:
        return principal_node_id(token)

    lower_type = str(member_type or "").strip().lower()
    if lower_type in {"user", "group", "domain"}:
        return principal_node_id(f"{lower_type}:{token}")
    if lower_type == "service_account":
        return principal_node_id(f"serviceAccount:{token}")
    if lower_type in {"all_users", "allusers"}:
        return "allUsers"
    if lower_type in {"all_authenticated_users", "allauthenticatedusers"}:
        return "allAuthenticatedUsers"
    if token.endswith(".gserviceaccount.com"):
        return principal_node_id(f"serviceAccount:{token}")
    if "@" in token:
        return principal_node_id(f"user:{token}")
    return principal_node_id(token)


def _normalize_group_membership_rows(rows: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in rows or []:
        group_member = _typed_member_token(
            str(row.get("group_member") or "").strip(),
            member_type="group",
        )
        member = _typed_member_token(
            str(row.get("member") or "").strip(),
            member_type=str(row.get("member_type") or "").strip(),
        )
        if not group_member or not member:
            continue
        normalized.append(
            {
                **row,
                "group_member": group_member,
                "member": member,
                "source": str(row.get("source") or "").strip() or "workspace_group_memberships",
            }
        )
    return normalized


def _add_group_membership_edges(builder: OpenGraphBuilder, group_memberships: Iterable[dict[str, Any]] | None) -> None:
    # Add explicit group membership edges from normalized membership rows.
    # Row shape (after in-builder normalization):
    # {"group_member":"group:eng@example.com","member":"user:alice@example.com","source":"..."}
    for row in group_memberships or []:
        source = str(row.get("source") or "").strip() or "group_memberships"
        group = str(row.get("group_member") or "").strip()
        member = str(row.get("member") or "").strip()
        if not group or not member or is_convenience_member(member):
            continue

        # Ensure source/destination principal nodes exist before adding edge.
        builder.add_node(member, principal_type(member), **principal_member_properties(member))
        builder.add_node(group, principal_type(group), **principal_member_properties(group))
        builder.add_edge(
            member,
            group,
            "GOOGLE_MEMBER_OF",
            source=source,
        )


def _add_iam_member_nodes(builder: OpenGraphBuilder, members: Iterable[str] | None) -> None:
    # Add principals observed in IAM bindings.
    # `members` typically comes from simplified["member_binding_index"].keys(), e.g.
    # ["user:alice@example.com", "group:eng@example.com", "domain:example.com", "allUsers"].
    #
    # Skip convenience members for now (projectOwner/projectEditor/projectViewer),
    # and skip nodes already present (often seeded via Workspace data).
    normalized_members = sorted(
        {
            principal_node_id(str(token or "").strip())
            for token in members or []
            if str(token or "").strip()
        }
    )
    for member in normalized_members:
        if not member or is_convenience_member(member) or member in builder.node_map:
            continue
        builder.add_node(member, principal_type(member), source="iam_members", **principal_member_properties(member))


def _member_email(member: str) -> str:
    # Extract email-ish identity tokens from principal strings.
    # Deleted principals are already filtered by principal_node_id().
    # Examples:
    # - user:alice@example.com                -> alice@example.com
    # - allUsers                               -> ""
    token = principal_node_id(member)
    if ":" not in token:
        return ""
    _prefix, value = token.split(":", 1)
    email = value.split("?", 1)[0].strip().lower()
    return email if "@" in email else ""


def _add_domain_wide_membership_edges(builder: OpenGraphBuilder) -> None:
    # Add inferred user/group/serviceAccount -> domain:<suffix> edges
    # only when the destination domain node already exists.
    #
    # Example:
    # - source principal: user:alice@example.com
    # - inferred edge: user:alice@example.com -[DOMAIN_MEMBER_OF]-> domain:example.com
    domain_node_ids = {
        str(token or "").strip()
        for token in builder.node_map.keys()
        if str(token or "").strip().startswith("domain:")
    }
    if not domain_node_ids:
        return

    for src_id, node in builder.node_map.items():
        props = dict(node.properties or {})
        email = str(props.get("email") or "").strip().lower()
        if not email:
            email = _member_email(str(props.get("member") or src_id).strip())
        if "@" not in email:
            continue

        domain = email.split("@", 1)[1].strip().lower()
        if not domain:
            continue
        dst_id = principal_node_id(f"domain:{domain}")
        if dst_id not in domain_node_ids or dst_id == src_id:
            continue

        builder.add_edge(
            src_id,
            dst_id,
            "DOMAIN_MEMBER_OF",
            source="domain_wide_memberships",
            membership_scope="domain",
        )


def build_users_groups_graph(context) -> dict[str, int | bool]:
    before_nodes, before_edges = context.counts()
    builder = context.builder

    simplified_base = context.simplified_hierarchy_permissions(include_inferred_permissions=False)
    member_binding_index = dict(simplified_base.get("member_binding_index") or {})
    iam_members = sorted(member_binding_index.keys())

    # Input contracts used here:
    # - context.rows("workspace_users"):  Workspace users
    # - context.rows("workspace_groups"): Workspace groups
    # - simplified.member_binding_index:  IAM-derived member keys from allow policy parsing
    # - context.rows("group_memberships"): workspace membership rows

    # 1) Seed workspace users/groups
    _add_workspace_nodes(
        builder,
        workspace_users=context.rows("workspace_users"),
        workspace_groups=context.rows("workspace_groups"),
    )

    # 2) Fill in any remaining IAM principals
    _add_iam_member_nodes(builder, iam_members)

    # 3) Add explicit group membership edges
    _add_group_membership_edges(builder, _normalize_group_membership_rows(context.rows("group_memberships")))

    # 4) Add inferred domain membership edges when domain nodes exist
    _add_domain_wide_membership_edges(builder)

    after_nodes, after_edges = context.counts()
    return {
        "include_memberships": True,
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
