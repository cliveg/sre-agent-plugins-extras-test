"""Azure-only specialist projections adapted from the credited Network Desk procedures."""

from __future__ import annotations

import sys
from pathlib import Path

import configuration_profile as configuration
import evidence_files as ef


LEGACY = Path(__file__).resolve().parents[2] / "azure-network-health-assessment"
sys.path.insert(0, str(LEGACY))
import network_health as nh


VERSION = "1.0.0"
FIELDS: dict[str, dict[str, tuple[str, type]]] = {
    "reference-firewalls": {
        "provisioningState": ("properties.provisioningState", str),
        "skuName": ("sku.name", str), "skuTier": ("sku.tier", str),
        "firewallPolicyId": ("properties.firewallPolicy.id", str),
        "virtualHubId": ("properties.virtualHub.id", str),
        "basePolicyId": ("properties.basePolicy.id", str),
        "threatIntelMode": ("properties.threatIntelMode", str),
        "dnsProxyEnabled": ("properties.dnsSettings.enableProxy", bool),
        "networkRuleCollectionCount": ("array_length(properties.networkRuleCollections)", int),
        "applicationRuleCollectionCount": ("array_length(properties.applicationRuleCollections)", int),
        "natRuleCollectionCount": ("array_length(properties.natRuleCollections)", int),
        "ruleCollectionGroupCount": ("array_length(properties.ruleCollectionGroups)", int),
    },
    "reference-hybrid": {
        "provisioningState": ("properties.provisioningState", str),
        "skuName": ("sku.name", str), "skuTier": ("sku.tier", str),
        "gatewayType": ("properties.gatewayType", str), "vpnType": ("properties.vpnType", str),
        "enableBgp": ("properties.enableBgp", bool), "activeActive": ("properties.activeActive", bool),
        "connectionStatus": ("properties.connectionStatus", str),
        "serviceProviderProvisioningState": ("properties.serviceProviderProvisioningState", str),
        "peeringCount": ("array_length(properties.peerings)", int),
        "virtualHubId": ("properties.virtualHub.id", str),
        "gateway1Id": ("properties.virtualNetworkGateway1.id", str),
        "gateway2Id": ("properties.virtualNetworkGateway2.id", str),
        "localGatewayId": ("properties.localNetworkGateway2.id", str),
    },
    "reference-monitoring": {
        "provisioningState": ("properties.provisioningState", str),
        "enabled": ("properties.enabled", bool),
        "targetResourceId": ("properties.targetResourceId", str),
        "storageId": ("properties.storageId", str),
        "workspaceResourceId": ("properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceResourceId", str),
        "trafficAnalyticsEnabled": ("properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled", bool),
        "retentionEnabled": ("properties.retentionPolicy.enabled", bool),
        "retentionDays": ("properties.retentionPolicy.days", int),
        "testConfigurationCount": ("array_length(properties.testConfigurations)", int),
        "testGroupCount": ("array_length(properties.testGroups)", int),
        "endpointCount": ("array_length(properties.endpoints)", int),
    },
    "reference-public-ips": {
        "provisioningState": ("properties.provisioningState", str),
        "ipConfigurationId": ("properties.ipConfiguration.id", str),
        "natGatewayId": ("properties.natGateway.id", str),
        "allocationMethod": ("properties.publicIPAllocationMethod", str),
        "ipVersion": ("properties.publicIPAddressVersion", str),
        "ipAddressKnown": ("bag_has_key(properties,'ipAddress')", bool),
        "ipAddressPresent": ("isnotempty(properties.ipAddress)", bool),
    },
}
TYPES = {
    "reference-firewalls": ("microsoft.network/azurefirewalls", "microsoft.network/firewallpolicies"),
    "reference-hybrid": (
        "microsoft.network/virtualnetworkgateways", "microsoft.network/connections",
        "microsoft.network/expressroutecircuits", "microsoft.network/virtualwans",
        "microsoft.network/virtualhubs", "microsoft.network/vpngateways",
        "microsoft.network/expressroutegateways", "microsoft.network/vpnsites",
    ),
    "reference-monitoring": (
        "microsoft.network/networkwatchers/flowlogs", "microsoft.network/networkwatchers/connectionmonitors",
    ),
    "reference-public-ips": ("microsoft.network/publicipaddresses",),
}


def catalog() -> ef.Record:
    base = nh.catalog("1.8.0")
    operations = []
    for name, fields in FIELDS.items():
        query = (
            "Resources | where type in~ (" + ",".join("'" + value + "'" for value in TYPES[name]) + ")"
            " | project id,name,type,subscriptionId,resourceGroup,location,parentId='',properties=bag_pack("
            + ",".join("'" + field + "'," + expression for field, (expression, _) in fields.items())
            + ") | order by id asc"
        )
        operations.append({
            "operationId": name, "operationVersion": VERSION, "kind": "graph",
            "entityType": TYPES[name][0], "entityTypes": list(TYPES[name]), "query": query,
        })
    return {**base, "catalogVersion": "1.9.0", "operations": [*ef.records(base["operations"]), *operations]}


def select_row(row: ef.Record, operation: ef.Record, subscription: str) -> ef.Record:
    name = ef.text(operation["operationId"])
    if name not in FIELDS:
        return nh.select_row(row, operation, subscription)
    resource_type = ef.text(row["type"]).lower()
    if resource_type not in TYPES[name] or ef.canonical_uuid(ef.text(row["subscriptionId"])) != subscription:
        raise ValueError("Specialist row type/subscription differs from the reviewed profile")
    identifier = configuration.resource_id(row["id"], subscription, resource_type)
    properties = ef.obj(row["properties"])
    selected = {}
    for field, (_, kind) in FIELDS[name].items():
        if field not in properties:
            continue
        value = properties[field]
        if value is not None and (type(value) is not kind or kind is int and ef.integer(value) < 0):
            raise ValueError("Specialist property shape differs from the reviewed projection")
        selected[field] = value
    result = {
        "id": identifier, "type": resource_type, "name": ef.text(row["name"]),
        "subscriptionId": subscription, "resourceGroup": row.get("resourceGroup"),
        "location": row.get("location"), "parentId": row.get("parentId", ""), "properties": selected,
    }
    if any(value is not None and not isinstance(value, str) for value in (
        result["resourceGroup"], result["location"], result["parentId"],
    )):
        raise ValueError("Specialist resource metadata has an unsupported shape")
    return result


def core_input(document: ef.Record) -> ef.Record:
    base = nh.catalog("1.8.0")
    names = {ef.text(row["operationId"]) for row in ef.records(base["operations"])}
    return {
        **document, "inputVersion": "0.9.0", "queryCatalogVersion": "1.8.0",
        "collections": [row for row in ef.records(document["collections"]) if row["operationId"] in names],
    }
