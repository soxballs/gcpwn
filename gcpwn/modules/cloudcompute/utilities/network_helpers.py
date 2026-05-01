from __future__ import annotations

from typing import Any, Iterable

from google.cloud import compute_v1

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def _global_resource_label(project_id: str, collection: str, resource_id: str) -> str:
    return f"projects/{project_id}/global/{collection}/{resource_id}"


def _regional_resource_label(project_id: str, region: str, collection: str, resource_id: str) -> str:
    return f"projects/{project_id}/regions/{region}/{collection}/{resource_id}"


def _router_nat_label(project_id: str, region: str, router_name: str, nat_name: str) -> str:
    return f"projects/{project_id}/regions/{region}/routers/{router_name}/nats/{nat_name}"


def _record_list_permission(action_dict, *, permission: str, project_id: str) -> None:
    record_permissions(
        action_dict,
        permissions=permission,
        scope_key="project_permissions",
        scope_label=project_id,
    )


def _record_resource_permission(
    action_dict,
    *,
    permission: str,
    project_id: str,
    resource_type: str,
    resource_label: str,
) -> None:
    record_permissions(
        action_dict,
        permissions=permission,
        project_id=project_id,
        resource_type=resource_type,
        resource_label=resource_label,
    )


def _stringify_sequence(values: Any) -> str:
    if values is None:
        return ""
    if isinstance(values, str):
        return values
    rendered = [str(value).strip() for value in values or [] if str(value).strip()]
    return ", ".join(rendered)


def _format_firewall_rule_entries(entries: Any) -> str:
    output: list[str] = []
    for entry in entries or []:
        protocol = str(getattr(entry, "IP_protocol", "") or getattr(entry, "ip_protocol", "") or "").strip()
        ports = [str(port).strip() for port in getattr(entry, "ports", None) or [] if str(port).strip()]
        if protocol and ports:
            output.append(f"{protocol}:{','.join(ports)}")
        elif protocol:
            output.append(protocol)
        elif ports:
            output.append(",".join(ports))
    return ", ".join(output)


def _compute_test_iam_permissions(
    *,
    client,
    project_id: str,
    api_name: str,
    resource_label: str,
    permissions: tuple[str, ...],
    region: str | None = None,
    resource_id: str,
) -> list[str]:
    return call_test_iam_permissions(
        client=client,
        resource_name=resource_label,
        permissions=permissions,
        api_name=api_name,
        service_label="Compute",
        project_id=project_id,
        request_builder=lambda _resource_name, granted_permissions: list(granted_permissions),
        caller=lambda granted_permissions: client.test_iam_permissions(
            project=project_id,
            region=region,
            resource=resource_id,
            test_permissions_request_resource={"permissions": list(granted_permissions)},
        ),
    )


class _VpcBaseResource:
    SERVICE_LABEL = "Compute"
    ACTION_RESOURCE_TYPE = ""
    LIST_API_NAME = ""
    GET_API_NAME = ""
    SUPPORTS_GET = True
    SUPPORTS_IAM = False
    TEST_IAM_API_NAME = ""
    TEST_IAM_PERMISSIONS: tuple[str, ...] = ()

    def __init__(self, session) -> None:
        self.session = session

    def _handle_error(self, exc: Exception, *, api_name: str, resource_name: str, project_id: str) -> str | None:
        return handle_service_error(
            exc,
            api_name=api_name,
            resource_name=resource_name,
            service_label=self.SERVICE_LABEL,
            project_id=project_id,
        )

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        raise NotImplementedError


class VpcNetworksResource(_VpcBaseResource):
    TABLE_NAME = "vpc_networks"
    COLUMNS = ["name", "auto_create_subnetworks", "routing_mode", "peerings"]
    ACTION_RESOURCE_TYPE = "networks"
    LIST_API_NAME = "compute.networks.list"
    GET_API_NAME = "compute.networks.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.NetworksClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        network = field_from_row(row, payload, "name")
        return {"network": network, "resource_id": network}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, network: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, network=network)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "networks", network),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=network, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class VpcSubnetworksResource(_VpcBaseResource):
    TABLE_NAME = "vpc_subnetworks"
    COLUMNS = ["name", "region", "network", "ip_cidr_range", "purpose"]
    ACTION_RESOURCE_TYPE = "subnetworks"
    LIST_API_NAME = "compute.subnetworks.list"
    GET_API_NAME = "compute.subnetworks.get"
    SUPPORTS_IAM = True
    TEST_IAM_API_NAME = "compute.subnetworks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.subnetworks.",
        exclude_permissions=("compute.subnetworks.create","compute.subnetworks.list"),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.SubnetworksClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        subnetwork = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "subnetwork": subnetwork,
            "resource_id": subnetwork,
        }

    def list(self, *, project_id: str, action_dict=None):
        out = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                out.extend(list(getattr(scoped, "subnetworks", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return out
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, subnetwork: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, subnetwork=subnetwork)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "subnetworks", subnetwork),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=subnetwork, project_id=project_id)
        return None

    def test_iam_permissions(self, *, project_id: str, region: str, subnetwork: str, action_dict=None) -> list[str]:
        if not region or not subnetwork:
            return []
        resource_label = _regional_resource_label(project_id, region, "subnetworks", subnetwork)
        permissions = _compute_test_iam_permissions(
            client=self.client,
            project_id=project_id,
            api_name=self.TEST_IAM_API_NAME,
            resource_label=resource_label,
            permissions=self.TEST_IAM_PERMISSIONS,
            region=region,
            resource_id=subnetwork,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
        return permissions

    def get_iam_permissions(self, *, project_id: str, region: str, subnetwork: str, action_dict=None) -> list[str]:
        return self.test_iam_permissions(
            project_id=project_id,
            region=region,
            subnetwork=subnetwork,
            action_dict=action_dict,
        )

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_tail(str(raw.get("region", "") or "")),
                },
            )


class VpcFirewallsResource(_VpcBaseResource):
    TABLE_NAME = "vpc_firewalls"
    COLUMNS = ["name", "network", "direction", "priority", "disabled", "source_ranges", "target_tags", "allowed", "denied"]
    ACTION_RESOURCE_TYPE = "firewalls"
    LIST_API_NAME = "compute.firewalls.list"
    GET_API_NAME = "compute.firewalls.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.FirewallsClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        firewall = field_from_row(row, payload, "name")
        return {"firewall": firewall, "resource_id": firewall}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, firewall: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, firewall=firewall)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "firewalls", firewall),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=firewall, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def normalize_summary_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for row in rows or []:
            payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
            normalized.append(
                {
                    "name": field_from_row(row, payload, "name"),
                    "network": extract_path_tail(field_from_row(row, payload, "network")),
                    "direction": field_from_row(row, payload, "direction"),
                    "priority": field_from_row(row, payload, "priority"),
                    "disabled": field_from_row(row, payload, "disabled"),
                    "source_ranges": _stringify_sequence(field_from_row(row, payload, "source_ranges", "sourceRanges")),
                    "target_tags": _stringify_sequence(field_from_row(row, payload, "target_tags", "targetTags")),
                    "allowed": _format_firewall_rule_entries(field_from_row(row, payload, "allowed")),
                    "denied": _format_firewall_rule_entries(field_from_row(row, payload, "denied")),
                }
            )
        return normalized


class VpcRoutesResource(_VpcBaseResource):
    TABLE_NAME = "vpc_routes"
    COLUMNS = ["name", "network", "dest_range", "next_hop_ip", "next_hop_instance", "next_hop_vpn_tunnel", "priority"]
    ACTION_RESOURCE_TYPE = "routes"
    LIST_API_NAME = "compute.routes.list"
    GET_API_NAME = "compute.routes.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.RoutesClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        route = field_from_row(row, payload, "name")
        return {"route": route, "resource_id": route}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, route: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, route=route)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "routes", route),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=route, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class VpcRoutersResource(_VpcBaseResource):
    TABLE_NAME = "vpc_routers"
    COLUMNS = ["name", "region", "network", "bgp"]
    ACTION_RESOURCE_TYPE = "routers"
    LIST_API_NAME = "compute.routers.list"
    GET_API_NAME = "compute.routers.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.RoutersClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        router = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "router": router,
            "resource_id": router,
        }

    def list(self, *, project_id: str, action_dict=None):
        rows: list[Any] = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, "routers", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, router: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, router=router)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "routers", router),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=router, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_segment(
                        raw.get("region", "") or raw.get("self_link") or raw.get("selfLink") or "",
                        "regions",
                    ),
                },
            )


class VpcRouterNatsResource(_VpcBaseResource):
    TABLE_NAME = "vpc_router_nats"
    COLUMNS = ["router_name", "region", "name", "nat_ip_allocate_option", "source_subnetwork_ip_ranges_to_nat", "nat_ips", "log_config"]
    SUPPORTS_GET = False

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.RoutersClient(credentials=session.credentials)

    def list_for_router(self, *, project_id: str, region: str, router_name: str, action_dict=None):
        try:
            router = self.client.get(project=project_id, region=region, router=router_name)
            _record_resource_permission(
                action_dict,
                permission="compute.routers.get",
                project_id=project_id,
                resource_type="routers",
                resource_label=_regional_resource_label(project_id, region, "routers", router_name),
            )
            return list(getattr(router, "nats", None) or [])
        except Exception as exc:
            self._handle_error(exc, api_name="compute.routers.get", resource_name=router_name, project_id=project_id)
        return []

    def save(self, rows: Iterable[Any], *, project_id: str, region: str, router_name: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "region": region, "router_name": router_name},
            )


class VpcVpnTunnelsResource(_VpcBaseResource):
    TABLE_NAME = "vpc_vpn_tunnels"
    COLUMNS = ["name", "region", "status", "target_vpn_gateway", "vpn_gateway", "router", "peer_ip", "ike_version"]
    ACTION_RESOURCE_TYPE = "vpn_tunnels"
    LIST_API_NAME = "compute.vpnTunnels.list"
    GET_API_NAME = "compute.vpnTunnels.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.VpnTunnelsClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        vpn_tunnel = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "vpn_tunnel": vpn_tunnel,
            "resource_id": vpn_tunnel,
        }

    def list(self, *, project_id: str, action_dict=None):
        rows: list[Any] = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, "vpn_tunnels", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, vpn_tunnel: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, vpn_tunnel=vpn_tunnel)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "vpnTunnels", vpn_tunnel),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=vpn_tunnel, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_segment(
                        raw.get("region", "") or raw.get("self_link") or raw.get("selfLink") or "",
                        "regions",
                    ),
                },
            )


class VpcVpnGatewaysResource(_VpcBaseResource):
    TABLE_NAME = "vpc_vpn_gateways"
    COLUMNS = ["name", "region", "network"]
    ACTION_RESOURCE_TYPE = "vpn_gateways"
    LIST_API_NAME = "compute.vpnGateways.list"
    GET_API_NAME = "compute.vpnGateways.get"
    SUPPORTS_IAM = True
    TEST_IAM_API_NAME = "compute.vpnGateways.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("compute.vpnGateways.")

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.VpnGatewaysClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        vpn_gateway = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "vpn_gateway": vpn_gateway,
            "resource_id": vpn_gateway,
        }

    def list(self, *, project_id: str, action_dict=None):
        rows: list[Any] = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, "vpn_gateways", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, vpn_gateway: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, vpn_gateway=vpn_gateway)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "vpnGateways", vpn_gateway),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=vpn_gateway, project_id=project_id)
        return None

    def test_iam_permissions(self, *, project_id: str, region: str, vpn_gateway: str, action_dict=None) -> list[str]:
        if not region or not vpn_gateway:
            return []
        resource_label = _regional_resource_label(project_id, region, "vpnGateways", vpn_gateway)
        permissions = _compute_test_iam_permissions(
            client=self.client,
            project_id=project_id,
            api_name=self.TEST_IAM_API_NAME,
            resource_label=resource_label,
            permissions=self.TEST_IAM_PERMISSIONS,
            region=region,
            resource_id=vpn_gateway,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
        return permissions

    def get_iam_permissions(self, *, project_id: str, region: str, vpn_gateway: str, action_dict=None) -> list[str]:
        return self.test_iam_permissions(
            project_id=project_id,
            region=region,
            vpn_gateway=vpn_gateway,
            action_dict=action_dict,
        )

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_segment(
                        raw.get("region", "") or raw.get("self_link") or raw.get("selfLink") or "",
                        "regions",
                    ),
                },
            )


class VpcTargetVpnGatewaysResource(_VpcBaseResource):
    TABLE_NAME = "vpc_target_vpn_gateways"
    COLUMNS = ["name", "region", "network"]
    ACTION_RESOURCE_TYPE = "target_vpn_gateways"
    LIST_API_NAME = "compute.targetVpnGateways.list"
    GET_API_NAME = "compute.targetVpnGateways.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.TargetVpnGatewaysClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        target_vpn_gateway = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "target_vpn_gateway": target_vpn_gateway,
            "resource_id": target_vpn_gateway,
        }

    def list(self, *, project_id: str, action_dict=None):
        rows: list[Any] = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, "target_vpn_gateways", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, target_vpn_gateway: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, target_vpn_gateway=target_vpn_gateway)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "targetVpnGateways", target_vpn_gateway),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=target_vpn_gateway, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_segment(
                        raw.get("region", "") or raw.get("self_link") or raw.get("selfLink") or "",
                        "regions",
                    ),
                },
            )
