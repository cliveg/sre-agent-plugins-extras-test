"""Restricted Increment 1: selected reads, factual normalization, checks and reports."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4
from urllib.parse import parse_qsl, urlsplit

from jsonschema import Draft202012Validator, ValidationError

from runtime import canonical_uuid, validate_document


Record = dict[str, object]
HERE = Path(__file__).resolve().parent
VERSION = "0.13.0"
CONTRACT_VERSION = "0.2.0"
REPORT_FILES = ("observed-network.json", "assessment.json", "network-assessment.md", "network-evidence.md")
LEGACY_CHECK_VERSIONS = {
    "NET-ADDR-001": "1.0.0", "NET-PEER-001": "1.0.0", "NET-NSG-001": "1.0.0",
    "NET-ROUTE-001": "1.0.0", "NET-ROUTE-002": "1.0.0", "NET-COVERAGE-001": "1.0.0",
}
LEGACY_DEFERRED = [
    "Private Endpoints", "Private DNS", "Azure Firewall", "VPN", "ExpressRoute",
    "vWAN", "NAT Gateway", "load balancers", "Application Gateway", "telemetry",
    "effective routes", "effective NSG rules", "IaC", "architecture documents",
]
DEFERRED = [
    *[value for value in LEGACY_DEFERRED if value not in ("Private Endpoints", "Private DNS")],
    "Private DNS records/resolution/forwarding", "Private endpoint effective connectivity",
    "Target service public-network access",
]
RESOURCE_PATTERN = re.compile(r"^/subscriptions/([a-f0-9-]{36})(?:/|$)", re.I)
GROUP_PATTERN = re.compile(r"^(/subscriptions/[^/]+/resourcegroups/([^/]+))(?:/|$)", re.I)
FIELDS = {
    "vnet-dns-settings": ("dnsServers", "dnsServersKnown"),
    "dns-resolvers": ("virtualNetworkId", "provisioningState"),
    "dns-rulesets": ("outboundEndpointIds", "provisioningState"),
    "dns-inbound-endpoints": ("inboundSubnetIds", "inboundIpAddresses", "ipConfigurationCount", "provisioningState"),
    "dns-outbound-endpoints": ("subnetId", "provisioningState"),
    "dns-forwarding-rules": ("domainName", "forwardingRuleState", "targetDnsServerIPs", "targetDnsServerPorts", "targetDnsServersKnown", "provisioningState"),
    "dns-ruleset-links": ("virtualNetworkId", "provisioningState"),
    "repeated-zone-record-metadata": ("reportedRecordSetCount", "selectedRecordSetCount",
        "aRecordSetCount", "aaaaRecordSetCount", "cnameRecordSetCount", "mxRecordSetCount",
        "ptrRecordSetCount", "soaRecordSetCount", "srvRecordSetCount", "txtRecordSetCount",
        "unknownTypeCount", "unknownTtlCount", "minTtl", "maxTtl"),
    "private-link-services": (),
    "subscription-context": (),
    "vnets": ("addressPrefixes", "subnetCount", "peeringCount"),
    "subnets": ("addressPrefix", "addressPrefixes", "networkSecurityGroupId",
                "networkSecurityGroupKnown", "routeTableId", "routeTableKnown"),
    "peerings": ("remoteVNetId", "peeringState", "provisioningState",
                 "allowVirtualNetworkAccess", "allowForwardedTraffic",
                 "allowGatewayTransit", "useRemoteGateways"),
    "route-tables": ("routeCount", "disableBgpRoutePropagation"),
    "routes": ("addressPrefix", "nextHopType", "nextHopIpAddress"),
    "nsgs": ("customRuleCount", "defaultRuleCount"),
    "nsg-rules": ("isDefault", "priority", "direction", "access", "protocol",
                  "sourceAddressPrefix", "sourceAddressPrefixes",
                  "destinationAddressPrefix", "destinationAddressPrefixes",
                  "sourcePortRange", "sourcePortRanges",
                  "destinationPortRange", "destinationPortRanges"),
    "ip-attachments": ("subnetId", "workloadId", "privateIPAddress", "ipConfigurationCount"),
    "private-endpoints": ("subnetId", "provisioningState", "automaticConnectionCount", "manualConnectionCount"),
    "private-endpoint-connections": ("connectionKind", "privateLinkServiceId", "groupIds", "connectionStatus", "provisioningState"),
    "private-dns-zones": ("provisioningState", "virtualNetworkLinkCount"),
    "private-dns-links": ("virtualNetworkId", "registrationEnabled", "virtualNetworkLinkState", "provisioningState"),
    "private-dns-groups": ("privateDnsZoneIds", "provisioningState"),
}
PRIVATE_OPERATIONS = {
    "private-endpoints", "private-endpoint-connections", "private-dns-zones", "private-dns-links", "private-dns-groups",
}
DNS_PATH_OPERATIONS = {"vnet-dns-settings", "dns-resolvers", "dns-rulesets", "dns-inbound-endpoints",
                       "dns-outbound-endpoints", "dns-forwarding-rules", "dns-ruleset-links"}
DNS_ARM_CHILD_KINDS = {"dns-inbound-endpoints", "dns-outbound-endpoints", "dns-forwarding-rules", "dns-ruleset-links"}
SERVICE_ARM_KIND = "service-arm-access"
NSP_CHILD_KINDS = {"nsp-profiles", "nsp-associations", "nsp-rules"}
NSP_KINDS = {"nsp-arm-root", *NSP_CHILD_KINDS}
ARM_ROOT_KINDS = {"dns-arm-root", "nsp-arm-root"}
ARM_CHILD_KINDS = DNS_ARM_CHILD_KINDS | NSP_CHILD_KINDS
CHILD_KINDS = {"private-dns-groups", "private-dns-record-metadata", SERVICE_ARM_KIND, *ARM_CHILD_KINDS}
BOOLEAN_FIELDS = {
    "networkSecurityGroupKnown", "routeTableKnown", "allowVirtualNetworkAccess",
    "allowForwardedTraffic", "allowGatewayTransit", "useRemoteGateways",
    "disableBgpRoutePropagation", "isDefault", "registrationEnabled", "dnsServersKnown", "targetDnsServersKnown",
}
DATA_HANDLING = {
    "sourceSensitivity": "customer-internal",
    "redactionState": "allowlisted-properties-only",
    "resourceIdentifierHandling": "preserved-in-access-controlled-engineering-artifacts",
    "rawResponsesPersisted": False,
    "retentionDecision": "prototype-run-only-no-external-publication",
    "omittedSensitiveProperties": ["tags", "descriptions", "credentials", "nonAllowlistedProperties"],
}
SERVICE_ACCESS_TYPES = (
    "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults",
    "microsoft.containerregistry/registries",
)
SERVICE_ACCESS_FIELDS = (
    "publicNetworkAccess", "firewallDefaultAction", "trustedServiceBypass",
    "ipRuleCount", "virtualNetworkRuleCount", "resourceAccessRuleCount",
)
SERVICE_ARM_PROFILES = {
    "storage-service-arm": (SERVICE_ACCESS_TYPES[0], "2023-05-01", "networkAcls", "networkAcls.bypass"),
    "vault-service-arm": (SERVICE_ACCESS_TYPES[1], "2023-07-01", "networkAcls", "networkAcls.bypass"),
    "registry-service-arm": (SERVICE_ACCESS_TYPES[2], "2023-07-01", "networkRuleSet", "networkRuleBypassOptions"),
}
NSP_SELECTOR_FIELDS = {
    "addressPrefixCount": "addressPrefixes", "fqdnCount": "fullyQualifiedDomainNames",
    "subscriptionSelectorCount": "subscriptions", "serviceTagCount": "serviceTags",
    "emailSelectorCount": "emailAddresses", "phoneSelectorCount": "phoneNumbers",
}
NSP_FIELDS = {
    "nsp-perimeters": ("provisioningState",),
    "nsp-profiles": ("provisioningState",),
    "nsp-associations": ("provisioningState", "privateLinkResourceId", "profileId", "accessMode", "hasProvisioningIssues"),
    "nsp-rules": ("provisioningState", "direction", *NSP_SELECTOR_FIELDS),
}


def obj(value: object) -> Record:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ValueError("Expected an object with string keys")
    return value


def array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("Expected an array")
    return value


def text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a string")
    return value


def records(value: object) -> list[Record]:
    return [obj(item) for item in array(value)]


def load(path: Path) -> Record:
    return obj(json.loads(path.read_text(encoding="utf-8")))


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def stable(prefix: str, *parts: object) -> str:
    return prefix + "-" + digest(parts)[:24]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("Expected an integer")
    return value


def service_arm_operations() -> list[Record]:
    operations: list[Record] = []
    for operation_id, (resource_type, api_version, rule_path, bypass_path) in SERVICE_ARM_PROFILES.items():
        fields = [
            "publicNetworkAccess:properties.publicNetworkAccess",
            "firewallDefaultAction:properties." + rule_path + ".defaultAction",
            "trustedServiceBypass:properties." + bypass_path,
        ]
        for field, path in (("ipRuleCount", "ipRules"), ("virtualNetworkRuleCount", "virtualNetworkRules"),
                            ("resourceAccessRuleCount", "resourceAccessRules")):
            supported = field != "resourceAccessRuleCount" or resource_type == SERVICE_ACCESS_TYPES[0]
            expression = "properties." + rule_path + "." + path
            fields.extend([
                field + (":length(" + expression + " || `[]`)" if supported else ":`null`"),
                field + "Known:" + (expression + "!=`null`" if supported else "`false`"),
            ])
        operations.append({
            "operationId": operation_id, "operationVersion": "1.0.0",
            "kind": SERVICE_ARM_KIND, "entityType": "service-arm-access-settings",
            "parentOperation": "private-link-services", "parentEntityType": resource_type,
            "apiVersion": api_version,
            "query": "{count:`1`,data:[{id:id,name:name,type:type,location:location,properties:{"
                     + ",".join(fields) + "}}]}",
        })
    return operations


def nsp_operations() -> list[Record]:
    root = "microsoft.network/networksecurityperimeters"
    rules = ["provisioningState:properties.provisioningState", "direction:properties.direction"]
    for field, path in NSP_SELECTOR_FIELDS.items():
        rules.extend([field + ":length(properties." + path + " || `[]`)",
                      field + "Known:properties." + path + "!=`null`"])
    descriptions = [
        ("nsp-perimeters", "nsp-arm-root", root, None, None, "provisioningState:properties.provisioningState"),
        ("nsp-profiles", "nsp-profiles", root + "/profiles", "nsp-perimeters", "profiles",
         "provisioningState:properties.provisioningState"),
        ("nsp-associations", "nsp-associations", root + "/resourceassociations", "nsp-perimeters", "resourceAssociations",
         "provisioningState:properties.provisioningState,privateLinkResourceId:properties.privateLinkResource.id,"
         "profileId:properties.profile.id,accessMode:properties.accessMode,hasProvisioningIssues:properties.hasProvisioningIssues"),
        ("nsp-rules", "nsp-rules", root + "/profiles/accessrules", "nsp-profiles", "accessRules", ",".join(rules)),
    ]
    return [{
        "operationId": op_id, "operationVersion": "1.0.0", "kind": kind, "entityType": entity_type,
        "apiVersion": "2024-07-01", "armPagination": True,
        **({"parentOperation": parent, "childSegment": segment} if parent is not None else {}),
        "query": "{count:length(value),nextLink:nextLink,data:value[:2000].{id:id,name:name,type:type,location:location,properties:{"
                 + projection + "}}}",
    } for op_id, kind, entity_type, parent, segment, projection in descriptions]


@lru_cache(maxsize=9)
def catalog(version: str = "1.0.0") -> Record:
    if version == "1.8.0":
        previous = catalog("1.7.0")
        return {**previous, "catalogVersion": version,
                "operations": [*records(previous["operations"]), *nsp_operations()]}
    if version == "1.7.0":
        previous = catalog("1.6.0")
        return {**previous, "catalogVersion": version,
                "operations": [*records(previous["operations"]), *service_arm_operations()]}
    if version == "1.6.0":
        previous = catalog("1.5.0")
        query = (
            "Resources | where type in~ (" + ",".join("'" + text(value) + "'" for value in
                array(next(op for op in records(previous["operations"]) if op["operationId"] == "private-link-services")["entityTypes"]))
            + ") | project id, name, type, subscriptionId, resourceGroup, location, parentId='', "
            "properties=iff(type in~ (" + ",".join("'" + value + "'" for value in SERVICE_ACCESS_TYPES)
            + "),bag_pack('publicNetworkAccess',properties.publicNetworkAccess,"
            "'firewallDefaultAction',iff(type =~ 'microsoft.containerregistry/registries',properties.networkRuleSet.defaultAction,properties.networkAcls.defaultAction),"
            "'trustedServiceBypass',iff(type =~ 'microsoft.containerregistry/registries',properties.networkRuleBypassOptions,properties.networkAcls.bypass),"
            "'ipRuleCount',iff(type =~ 'microsoft.containerregistry/registries',array_length(properties.networkRuleSet.ipRules),array_length(properties.networkAcls.ipRules)),"
            "'virtualNetworkRuleCount',iff(type =~ 'microsoft.containerregistry/registries',array_length(properties.networkRuleSet.virtualNetworkRules),array_length(properties.networkAcls.virtualNetworkRules)),"
            "'resourceAccessRuleCount',iff(type =~ 'microsoft.storage/storageaccounts',array_length(properties.networkAcls.resourceAccessRules),int(null))),dynamic({})) | order by id asc"
        )
        return {**previous, "catalogVersion": version, "operations": [
            {**op, "operationVersion": "1.1.0", "query": query}
            if op["operationId"] == "private-link-services" else op
            for op in records(previous["operations"])
        ]}
    data = load(HERE / "acquisition.json")
    operations = records(data["operations"])
    if {text(op["operationId"]) for op in operations} != set(FIELDS):
        raise ValueError("Acquisition catalog does not match the restricted increment")
    if version in ("1.0.0", "1.1.0"):
        return {**data, "catalogVersion": version, "operations": [
            op for op in operations if op["operationId"] not in ("private-link-services", "repeated-zone-record-metadata", *DNS_PATH_OPERATIONS)
            and (version == "1.1.0" or op["operationId"] not in PRIVATE_OPERATIONS)
        ]}
    if version not in ("1.2.0", "1.3.0", "1.4.0", "1.5.0") or data["catalogVersion"] != "1.4.0":
        raise ValueError("Unsupported acquisition catalog version")
    mapping = load(HERE / "private-dns-services.json")
    resource_types = sorted({text(row["resourceType"]) for row in records(mapping["services"])})
    if not resource_types or any(not re.fullmatch(r"microsoft\.[a-z0-9]+/[a-z0-9]+", value) for value in resource_types):
        raise ValueError("Service mapping contains unsupported resource-type syntax")
    query = (
        "Resources | where type in~ (" + ",".join("'" + value + "'" for value in resource_types)
        + ") | project id, name, type, subscriptionId, resourceGroup, location, parentId='', properties=dynamic({}) | order by id asc"
    )
    service_op = next(op for op in operations if op["operationId"] == "private-link-services")
    result = {
        **data, "catalogVersion": version, "serviceCatalogSha256": digest(mapping),
        "operations": [op for op in operations if op is not service_op and op["operationId"] != "repeated-zone-record-metadata"
                       and op["operationId"] not in DNS_PATH_OPERATIONS]
        + [{**service_op, "query": query, "entityTypes": resource_types}]
        + ([op for op in operations if op["operationId"] == "repeated-zone-record-metadata"] if version in ("1.3.0", "1.4.0", "1.5.0") else [])
        + ([op for op in operations if op["operationId"] in DNS_PATH_OPERATIONS] if version in ("1.4.0", "1.5.0") else []),
    }
    if version == "1.5.0":
        result["operations"] = [
            {**op, "operationVersion": "1.1.0", "armPagination": True,
             "query": text(op["query"]).replace("hasContinuation:nextLink!=`null`", "nextLink:nextLink")}
            if op["kind"] == "dns-arm-root" or op["kind"] in DNS_ARM_CHILD_KINDS else op
            for op in records(result["operations"])
        ]
    return result


def arm_cursor(parent_index: int, url: str | None) -> str:
    return base64.urlsafe_b64encode(json.dumps([parent_index, url], separators=(",", ":")).encode()).decode()


def read_arm_cursor(token: str | None) -> tuple[int, str | None]:
    if token is None:
        return 0, None
    if len(token) > 12000:
        raise ValueError("ARM continuation checkpoint exceeds its budget")
    try:
        values = array(json.loads(base64.b64decode(token, altchars=b"-_", validate=True)))
        if len(values) != 2 or type(values[0]) is not int or not 0 <= values[0] <= 100:
            raise ValueError("Invalid ARM parent cursor")
        url = text(values[1]) if values[1] is not None else None
        if arm_cursor(values[0], url) != token:
            raise ValueError("Noncanonical ARM cursor")
        return values[0], url
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid ARM continuation checkpoint") from exc


def validated_arm_url(url: str, expected_path: str, api_version: str = "2022-07-01") -> str:
    if not 1 <= len(url) <= 8192 or re.search(r"[\s\\]", url) or re.search(r"%(?![0-9a-fA-F]{2})", url):
        raise ValueError("Invalid ARM continuation URL syntax")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "management.azure.com" or parsed.fragment or (
        parsed.path.lower() != expected_path.lower() or "%" in parsed.path
        or any(part in (".", "..") for part in parsed.path.split("/"))
    ):
        raise ValueError("ARM continuation exceeds approved origin/resource path")
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    keys = [key.lower() for key, _ in pairs]
    allowed_keys = {"api-version", "$skiptoken", "skiptoken", *(["$top"] if api_version == "2024-07-01" else [])}
    if len(keys) != len(set(keys)) or not set(keys) <= allowed_keys or (
        keys.count("api-version") != 1 or sum(key in ("$skiptoken", "skiptoken") for key in keys) != 1
        or any(not value or len(value) > 4096 or re.search(r"[\x00-\x20\x7f]", value) for _, value in pairs)
        or any(value != api_version for key, value in pairs if key.lower() == "api-version")
        or any(not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= 20
               for key, value in pairs if key.lower() == "$top")
    ):
        raise ValueError("ARM continuation query differs from approved API/token parameters")
    return url


def request_token(command: list[str]) -> str | None:
    if command[:4] == ["az", "rest", "--method", "get"]:
        url = command[command.index("--url") + 1]
        return arm_cursor(0, url) if any(key.lower() in ("$skiptoken", "skiptoken") for key, _ in parse_qsl(urlsplit(url).query)) else None
    return command[command.index("--skip-token") + 1] if "--skip-token" in command else None


def dns_scopes(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    if not 1 <= len(values) <= 20:
        raise ValueError("DNS-hosting scope requires 1 to 20 explicitly approved subscriptions")
    canonical = [canonical_uuid(value) for value in values]
    if len(set(canonical)) != len(canonical):
        raise ValueError("Duplicate DNS-hosting subscriptions")
    return sorted(canonical)


def collection_plan(configuration: Record, subscription: str, dns_subscriptions: list[str] | None) -> list[tuple[Record, str]]:
    operations = records(configuration["operations"])
    metadata = [op for op in operations if op["kind"] == "private-dns-record-metadata"]
    return [(op, subscription) for op in operations if op not in metadata] + [
        (op, host) for host in dns_subscriptions or [] if host != subscription
        for op in operations if op["operationId"] in ("private-dns-zones", "private-dns-links")
    ] + [(op, host) for host in sorted({subscription, *(dns_subscriptions or [])}) for op in metadata]


def child_kind(command: list[str]) -> str | None:
    if command[:4] == ["az", "rest", "--method", "get"]:
        try:
            url = command[command.index("--url") + 1]
        except (ValueError, IndexError):
            return None
        path = urlsplit(url).path.lower()
        if "/providers/microsoft.network/networksecurityperimeters" in path:
            for kind, segment in (("nsp-profiles", "profiles"), ("nsp-associations", "resourceassociations"),
                                  ("nsp-rules", "accessrules")):
                if path.endswith("/" + segment):
                    return kind
            return "nsp-arm-root"
        if any(re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/" +
                           re.escape(resource_type) + r"/[^/]+", urlsplit(url).path, re.I)
               for resource_type in SERVICE_ACCESS_TYPES):
            return SERVICE_ARM_KIND
        for kind, segment in (("dns-inbound-endpoints", "inboundEndpoints"), ("dns-outbound-endpoints", "outboundEndpoints"),
                              ("dns-forwarding-rules", "forwardingRules"), ("dns-ruleset-links", "virtualNetworkLinks")):
            if urlsplit(url).path.lower().endswith("/" + segment.lower()):
                return kind
        return "dns-arm-root"
    if command[:5] == ["az", "network", "private-endpoint", "dns-zone-group", "list"]:
        return "private-dns-groups"
    if command[:5] == ["az", "network", "private-dns", "record-set", "list"]:
        return "private-dns-record-metadata"
    return None


def command_target(command: list[str], subscription: str) -> Record | None:
    kind = child_kind(command)
    if kind is None:
        return None
    if kind in ARM_ROOT_KINDS:
        return None
    if kind == SERVICE_ARM_KIND:
        path = urlsplit(command[command.index("--url") + 1]).path
        return {"id": path, "subscriptionId": subscription,
                "type": path.lower().split("/providers/", 1)[1].rsplit("/", 1)[0]}
    if kind in ARM_CHILD_KINDS:
        url = command[command.index("--url") + 1]
        parent_id = url.removeprefix("https://management.azure.com").split("?", 1)[0].rsplit("/", 1)[0]
        return {"subscriptionId": subscription, "id": parent_id}
    return {
        "subscriptionId": subscription, "resourceGroup": command[command.index("--resource-group") + 1],
        "name": command[command.index("--zone-name" if kind == "private-dns-record-metadata" else "--endpoint-name") + 1],
    }


def repeated_zone_parents(collections: list[Record], subscription: str) -> list[Record]:
    zones = [row for c in collections if c["operationId"] == "private-dns-zones" for row in records(c["rows"])]
    counts = Counter(text(row["name"]).lower().rstrip(".") for row in zones)
    return sorted(
        [row for row in zones if row["subscriptionId"] == subscription and counts[text(row["name"]).lower().rstrip(".")] > 1],
        key=lambda row: text(row["id"]).lower(),
    )


def record_metadata_row(payload: Record, parent: Record, operation: Record) -> tuple[Record, list[str]]:
    items = records(payload["data"])
    if len(items) > 2000:
        raise ValueError("Record metadata exceeds approved selection budget")
    issues: list[str] = []
    reported = payload.get("count")
    if type(reported) is not int or reported < 0:
        reported = None
        issues.append("RecordSetTotalUnavailable")
    elif reported != len(items):
        issues.append("RecordSetSelectionIncomplete")
    counts = {kind: 0 for kind in ("a", "aaaa", "cname", "mx", "ptr", "soa", "srv", "txt")}
    ttls: list[int] = []
    unknown_type, unknown_ttl = 0, 0
    for item in items:
        resource_type = item.get("type")
        kind = resource_type.lower().removeprefix("microsoft.network/privatednszones/") if isinstance(resource_type, str) else ""
        if not isinstance(resource_type, str) or not resource_type.lower().startswith("microsoft.network/privatednszones/") or kind not in counts:
            unknown_type += 1
        else:
            counts[kind] += 1
        ttl = item.get("ttl")
        if type(ttl) is int and 0 <= ttl <= 2147483647:
            ttls.append(ttl)
        else:
            unknown_ttl += 1
    if unknown_type or unknown_ttl:
        issues.append("RecordSetMetadataUnavailable")
    return {
        "id": text(parent["id"]) + "/observedRecordMetadata/summary", "name": "summary",
        "type": operation["entityType"], "subscriptionId": parent["subscriptionId"],
        "resourceGroup": parent["resourceGroup"], "location": None, "parentId": parent["id"],
        "properties": {
            "reportedRecordSetCount": reported, "selectedRecordSetCount": len(items),
            **{kind + "RecordSetCount": count for kind, count in counts.items()},
            "unknownTypeCount": unknown_type, "unknownTtlCount": unknown_ttl,
            "minTtl": min(ttls) if ttls else None, "maxTtl": max(ttls) if ttls else None,
        },
    }, issues


def collection_id(run_id: str, operation_id: object, requested: str, workload: str) -> str:
    return stable("collection", run_id, operation_id) if requested == workload else stable("collection", run_id, operation_id, requested)


class ReadResponse(NamedTuple):
    payload: Record
    execution_id: str | None = None


class ReadFailure(Exception):
    def __init__(self, code: str, status: str = "failed") -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def cli_reader(command: list[str]) -> ReadResponse:
    executable = shutil.which("az")
    if executable is None:
        raise ReadFailure("AzureCliUnavailable", "unavailable")
    env = {
        **os.environ,
        "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
        "AZURE_CORE_COLLECT_TELEMETRY": "no",
    }
    try:
        result = subprocess.run(
            [executable, *command[1:]], capture_output=True, text=True,
            timeout=120, check=False, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReadFailure("ReadTimeout", "unavailable") from exc
    if result.returncode:
        error = result.stderr.lower()
        if "forbidden" in error or "authorizationfailed" in error:
            raise ReadFailure("PermissionDenied", "permissionDenied")
        if "not recognized" in error or "extension" in error and "install" in error:
            raise ReadFailure("ReadCapabilityUnavailable", "unsupported")
        raise ReadFailure("AzureReadFailed")
    try:
        return ReadResponse(obj(json.loads(result.stdout)))
    except ValueError as exc:
        raise ReadFailure("InvalidReadResponse") from exc


def command_for(op: Record, subscription: str, page_size: int, token: str | None, target: Record | None = None) -> list[str]:
    if op["kind"] == SERVICE_ARM_KIND:
        if target is None or target["subscriptionId"] != subscription or text(target["type"]).lower() != op["parentEntityType"]:
            raise ValueError("Service ARM read requires its approved in-scope collected service parent")
        path = text(target["id"])
        if not re.fullmatch(r"/subscriptions/" + re.escape(subscription)
                           + r"/resourcegroups/[^/?#%\\\s]+/providers/" + re.escape(text(op["parentEntityType"]))
                           + r"/[^/?#%\\\s]+", path, re.I):
            raise ValueError("Service ARM parent differs from the approved resource path")
        return ["az", "rest", "--method", "get", "--url",
                "https://management.azure.com" + path + "?api-version=" + text(op["apiVersion"]),
                "--subscription", subscription, "--query", text(op["query"]), "-o", "json"]
    if op["kind"] in ARM_ROOT_KINDS or op["kind"] in ARM_CHILD_KINDS:
        if op["kind"] in ARM_ROOT_KINDS:
            path = "/subscriptions/" + subscription + "/providers/" + text(op["entityType"])
        else:
            if target is None or target["subscriptionId"] != subscription:
                raise ValueError("NSP child list requires an explicitly scoped collected parent" if op["kind"] in NSP_CHILD_KINDS
                                 else "DNS child list requires an explicitly scoped collected parent")
            path = text(target["id"]) + "/" + text(op["childSegment"])
            expected_parent = (
                "networksecurityperimeters" + (r"/[^/?#%\\]+/profiles" if op["parentOperation"] == "nsp-profiles" else "")
                if op["kind"] in NSP_CHILD_KINDS else
                "dnsresolvers" if op["parentOperation"] == "dns-resolvers" else "dnsforwardingrulesets"
            )
            if not re.fullmatch(r"/subscriptions/" + re.escape(subscription)
                               + r"/resourcegroups/[^/?#%\\]+/providers/microsoft.network/" + expected_parent + r"/[^/?#%\\]+",
                               text(target["id"]), re.I):
                raise ValueError("NSP child parent ID differs from approved resource path" if op["kind"] in NSP_CHILD_KINDS
                                 else "DNS child parent ID differs from approved resource path")
        api_version = text(op.get("apiVersion", "2022-07-01"))
        url = "https://management.azure.com" + path + "?api-version=" + api_version
        if token is not None and op.get("armPagination"):
            _, continuation = read_arm_cursor(token)
            if continuation is not None:
                url = validated_arm_url(continuation, path, api_version)
        return ["az", "rest", "--method", "get", "--url", url, "--subscription", subscription,
                "--query", text(op["query"]), "-o", "json"]
    if op["kind"] == "account":
        return [
            "az", "account", "show", "--subscription", subscription,
            "--query", "{subscriptionId:id}", "-o", "json",
        ]
    if op["kind"] == "private-dns-groups":
        if target is None or target["subscriptionId"] != subscription:
            raise ValueError("Private DNS group read requires an in-scope collected endpoint parent")
        return [
            "az", "network", "private-endpoint", "dns-zone-group", "list",
            "--resource-group", text(target["resourceGroup"]), "--endpoint-name", text(target["name"]),
            "--subscription", subscription, "--query", text(op["query"]), "-o", "json",
        ]
    if op["kind"] == "private-dns-record-metadata":
        if target is None or target["subscriptionId"] != subscription:
            raise ValueError("Record metadata read requires an explicitly scoped collected repeated-zone parent")
        return [
            "az", "network", "private-dns", "record-set", "list",
            "--resource-group", text(target["resourceGroup"]), "--zone-name", text(target["name"]),
            "--subscription", subscription, "--query", text(op["query"]), "-o", "json",
        ]
    command = [
        "az", "graph", "query", "--subscriptions", subscription,
        "--first", str(page_size), "-q", text(op["query"]), "-o", "json",
    ]
    if token:
        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", token):
            raise ReadFailure("UnsupportedContinuationToken", "partial")
        command.extend(["--skip-token", token])
    return command


def operation_matches_kind(operation: Record, kind: str | None, target: Record | None) -> bool:
    if kind is None:
        return operation["kind"] not in CHILD_KINDS and operation["kind"] not in ARM_ROOT_KINDS
    return operation["kind"] == kind and (
        kind != SERVICE_ARM_KIND or target is not None and target["type"] == operation["parentEntityType"]
    )


def matches_command(command: list[str], subscription: str, page_size: int) -> bool:
    kind = child_kind(command)
    try:
        token = request_token(command)
        target = command_target(command, subscription)
    except (ValueError, IndexError):
        return False
    try:
        return any(
            command == command_for(op, subscription, page_size, token, target)
            for op in [*records(catalog("1.4.0")["operations"]), *records(catalog("1.5.0")["operations"]),
                       *records(catalog("1.6.0")["operations"]), *records(catalog("1.7.0")["operations"]),
                       *records(catalog("1.8.0")["operations"])]
            if operation_matches_kind(op, kind, target)
        )
    except (ValueError, ReadFailure):
        return False


def select_row(row: Record, operation: Record, subscription: str) -> Record:
    operation_id = text(operation["operationId"])
    if operation_id == "subscription-context":
        if canonical_uuid(text(row["subscriptionId"])) != subscription:
            raise ValueError("Returned subscription scope mismatch")
        return {
            "id": "/subscriptions/" + subscription, "name": subscription,
            "type": operation["entityType"], "subscriptionId": subscription,
            "resourceGroup": None, "location": None, "parentId": "", "properties": {},
        }
    resource_id = text(row["id"])
    match = RESOURCE_PATTERN.match(resource_id)
    if not match or canonical_uuid(match.group(1)) != subscription:
        raise ValueError("Returned resource scope mismatch")
    resource_type = text(row["type"]).lower()
    if resource_type not in operation.get("entityTypes", [operation["entityType"]]):
        raise ValueError("Unexpected resource type in restricted collection")
    if canonical_uuid(text(row["subscriptionId"])) != subscription:
        raise ValueError("Returned row subscription mismatch")
    props = obj(row["properties"])
    selected: Record = {}
    fields = NSP_FIELDS[operation_id] if operation_id in NSP_FIELDS else SERVICE_ACCESS_FIELDS if operation["kind"] == SERVICE_ARM_KIND or (
        operation_id == "private-link-services" and operation["operationVersion"] == "1.1.0"
        and resource_type in SERVICE_ACCESS_TYPES
    ) else FIELDS[operation_id]
    for key in fields:
        value = props.get(key)
        if key in BOOLEAN_FIELDS and type(value) is int and value in (0, 1):
            value = bool(value)
        selected[key] = value
    candidate = {
        "id": resource_id, "name": text(row["name"]), "type": resource_type,
        "subscriptionId": subscription, "resourceGroup": row.get("resourceGroup"),
        "location": row.get("location"), "parentId": row.get("parentId", ""),
        "properties": selected,
    }
    if any(candidate[key] is not None and not isinstance(candidate[key], str)
           for key in ("resourceGroup", "location", "parentId")):
        raise ValueError("Invalid selected resource metadata")
    validate_configuration(selected)
    if operation["kind"] == SERVICE_ARM_KIND and (
        resource_id.lower() != text(candidate["parentId"]).lower() + "/observedarmserviceaccess/summary"
        or candidate["name"] != "summary"
    ):
        raise ValueError("Service ARM configuration object identity differs from its parent")
    if operation_id == "vnet-dns-settings" and (
        resource_id != text(candidate["parentId"]) + "/observedDnsSettings/summary" or candidate["name"] != "summary"
    ):
        raise ValueError("VNet DNS configuration object identity differs from its parent")
    if operation_id == "dns-forwarding-rules":
        ips, ports = selected["targetDnsServerIPs"], selected["targetDnsServerPorts"]
        if isinstance(ips, list) and isinstance(ports, list) and len(ips) != len(ports):
            raise ValueError("Forwarding target address/port positions differ")
    if operation_id == "repeated-zone-record-metadata":
        if resource_id != text(candidate["parentId"]) + "/observedRecordMetadata/summary" or candidate["name"] != "summary":
            raise ValueError("Metadata summary identity differs from its zone parent")
        selected_count = integer(selected["selectedRecordSetCount"])
        if sum(integer(selected[kind + "RecordSetCount"]) for kind in ("a", "aaaa", "cname", "mx", "ptr", "soa", "srv", "txt")) + integer(selected["unknownTypeCount"]) != selected_count:
            raise ValueError("Metadata type counts differ from selected record-set count")
        if integer(selected["unknownTtlCount"]) > selected_count:
            raise ValueError("Metadata TTL coverage exceeds selected count")
        min_ttl, max_ttl = selected["minTtl"], selected["maxTtl"]
        if (min_ttl is None) != (max_ttl is None) or (
            min_ttl is not None and integer(min_ttl) > integer(max_ttl)
        ) or (selected_count == selected["unknownTtlCount"]) != (min_ttl is None):
            raise ValueError("Metadata TTL range differs from available selected values")
    return candidate


@lru_cache(maxsize=1)
def configuration_validator() -> Draft202012Validator:
    schema = load(HERE / "common.schema.json")
    definition = obj(obj(schema["$defs"])["configuration"])
    return Draft202012Validator(definition)


def validate_configuration(properties: Record) -> None:
    configuration_validator().validate(properties)


def collect(
    subscription_id: str,
    run_id: str,
    reader: Callable[[list[str]], ReadResponse] = cli_reader,
    source: str = "azure-cli",
    page_size: int | None = None,
    clock: Callable[[], str] = utc_now,
    progress: Record | None = None,
    save_progress: Callable[[Record], None] | None = None,
    include_private: bool = False,
    include_dns_planning: bool = False,
    dns_subscriptions: list[str] | None = None,
    include_record_metadata: bool = False,
    include_dns_paths: bool = False,
    include_service_access: bool = False,
    include_service_arm: bool = False,
    include_nsp: bool = False,
    acquisition: Record | None = None,
    row_selector: Callable[[Record, Record, str], Record] = select_row,
) -> Record:
    subscription = canonical_uuid(subscription_id)
    run_id = canonical_uuid(run_id)
    dns_subscriptions = dns_scopes(dns_subscriptions)
    include_service_arm = include_service_arm or include_nsp
    include_service_access = include_service_access or include_service_arm
    include_dns_paths = include_dns_paths or include_service_access
    if dns_subscriptions is not None and not (include_dns_planning or include_record_metadata or include_dns_paths):
        raise ValueError("DNS-hosting subscriptions require DNS planning mode")
    include_record_metadata = include_record_metadata or include_dns_paths
    include_dns_planning = include_dns_planning or include_record_metadata
    include_private = include_private or include_dns_planning
    configuration = acquisition if acquisition is not None else catalog("1.8.0" if include_nsp else "1.7.0" if include_service_arm else "1.6.0" if include_service_access else "1.5.0" if include_dns_paths else "1.3.0" if include_record_metadata else "1.2.0" if include_dns_planning else "1.1.0" if include_private else "1.0.0")
    page_size = page_size if page_size is not None else integer(configuration["pageSize"])
    if not 1 <= page_size <= 1000:
        raise ValueError("Page size must be between 1 and 1000")
    if source not in ("azure-cli", "sre-native-cli", "synthetic-fixture", "managed-identity-arm"):
        raise ValueError("Unsupported collection source")
    identity: Record = {
        "checkpointVersion": "1.0.0", "runId": run_id, "subscriptionId": subscription,
        "source": source, "pageSize": page_size, "capabilityVersion": VERSION,
        "catalogSha256": digest(configuration),
    }
    if include_dns_planning:
        identity["dnsHostingSubscriptionIds"] = dns_subscriptions
    progress = {} if progress is None else progress
    if not progress:
        progress.update({**identity, "collections": [], "current": None})
    if set(progress) != {*identity, "collections", "current"} or any(
        progress[key] != value for key, value in identity.items()
    ):
        raise ValueError("Acquisition progress identity/catalog/version mismatch")
    operations = collection_plan(configuration, subscription, dns_subscriptions)
    collected = records(progress["collections"])
    if len(collected) > len(operations):
        raise ValueError("Acquisition progress exceeds the catalog")
    saved = [*collected]
    if progress["current"] is not None:
        current = obj(progress["current"])
        saved.append(obj(current["collection"]))
    for index, collection in enumerate(saved):
        if index >= len(operations):
            raise ValueError("Unexpected current acquisition operation")
        operation, requested = operations[index]
        if (
            collection["collectionId"] != collection_id(run_id, operation["operationId"], requested, subscription)
            or collection["operationId"] != operation["operationId"]
            or collection["operationVersion"] != operation["operationVersion"]
            or collection["requestedSubscriptionId"] != requested or collection["source"] != source
            or collection["querySha256"] != (
                hashlib.sha256(text(operation["query"]).encode()).hexdigest()
                if operation["kind"] != "account" else None
            )
        ):
            raise ValueError("Acquisition progress collection identity mismatch")
        cached_rows = records(collection["rows"])
        if collection["retainedRowCount"] != len(cached_rows) or len(
            {text(row["id"]).lower() for row in cached_rows}
        ) != len(cached_rows):
            raise ValueError("Duplicate resource in acquisition progress")
        if not set(array(collection["returnedSubscriptionIds"])) <= {requested}:
            raise ValueError("Acquisition progress returned scope differs")
        for row in cached_rows:
            if row_selector(row, operation, requested) != row:
                raise ValueError("Acquisition progress contains unselected evidence")
        if operation["kind"] in NSP_KINDS and collection.get("apiVersion") != operation["apiVersion"]:
            raise ValueError("NSP checkpoint API version differs from catalog")
        if operation["kind"] == SERVICE_ARM_KIND:
            parent_collection = next(c for c in saved if c["operationId"] == "private-link-services"
                                     and c["requestedSubscriptionId"] == requested)
            validate_service_arm_collection(collection, records(parent_collection["rows"]), cached_rows, operation,
                                            complete=index < len(collected))
    for operation, requested in operations[len(collected):]:
        op_id = text(operation["operationId"])
        starting = progress["current"] is None
        if starting:
            collection = {
                "collectionId": collection_id(run_id, op_id, requested, subscription),
                "operationId": op_id, "operationVersion": operation["operationVersion"],
                "source": source,
                "querySha256": hashlib.sha256(text(operation["query"]).encode()).hexdigest()
                if operation["kind"] != "account" else None,
                "requestedSubscriptionId": requested,
                "startedAt": clock(), "completedAt": clock(), "status": "succeeded",
                "pages": [], "returnedSubscriptionIds": [], "retainedRowCount": 0,
                "issues": [], "executionRefs": [], "rows": [],
                **({"apiVersion": operation["apiVersion"]} if operation["kind"] == SERVICE_ARM_KIND or operation["kind"] in NSP_KINDS else {}),
            }
            current = {
                "collection": collection, "nextPage": 0, "token": None, "seenTokens": [],
                "totalSeen": 0, "expectedTotal": None,
            }
        else:
            current = obj(progress["current"])
        collection = obj(current["collection"])
        rows = {text(row["id"]).lower(): row for row in records(collection["rows"])}
        pages = records(collection["pages"])
        issues = [text(value) for value in array(collection["issues"])]
        execution_refs = [text(value) for value in array(collection["executionRefs"])]
        returned_subscriptions = {text(value) for value in array(collection["returnedSubscriptionIds"])}
        seen_tokens = {text(value) for value in array(current["seenTokens"])}
        token = text(current["token"]) if current["token"] is not None else None
        total_seen = integer(current["totalSeen"])
        expected_total = integer(current["expectedTotal"]) if current["expectedTotal"] is not None else None
        next_page = integer(current["nextPage"])
        parents = (
            records(next(c for c in collected if c["operationId"] == "private-endpoints")["rows"])
            if operation["kind"] == "private-dns-groups" else []
        )
        if operation["kind"] in ARM_CHILD_KINDS:
            parent_collection = next(c for c in collected if c["operationId"] == operation["parentOperation"]
                                     and c["requestedSubscriptionId"] == requested)
            parents = records(parent_collection["rows"])
            if parent_collection["status"] != "succeeded":
                issues.append("NspParentDiscoveryIncomplete" if operation["kind"] in NSP_CHILD_KINDS else "DnsParentDiscoveryIncomplete")
                if not parents:
                    collection["status"] = "notAttempted"
        if operation["kind"] == SERVICE_ARM_KIND:
            parent_collection = next(c for c in collected if c["operationId"] == "private-link-services"
                                     and c["requestedSubscriptionId"] == requested)
            parents = sorted([row for row in records(parent_collection["rows"])
                              if row["type"] == operation["parentEntityType"]], key=lambda row: text(row["id"]).lower())
            if parent_collection["status"] != "succeeded":
                issues.append("ServiceParentDiscoveryIncomplete")
                if not parents:
                    collection["status"] = "notAttempted"
        if operation["kind"] == "private-dns-record-metadata":
            parents = repeated_zone_parents(collected, requested)
            if any(c["status"] != "succeeded" for c in collected if c["operationId"] == "private-dns-zones"):
                issues.append("RepeatedZoneDiscoveryIncomplete")
        if operation["kind"] == "private-dns-groups" and not parents:
            parent_collection = next(c for c in collected if c["operationId"] == "private-endpoints")
            if parent_collection["status"] != "succeeded":
                collection["status"] = "notAttempted"
                issues.append("PrivateEndpointParentEvidenceUnavailable")
        if (
            set(current) != {"collection", "nextPage", "token", "seenTokens", "totalSeen", "expectedTotal"}
            or next_page != len(pages) or not 0 <= next_page <= integer(configuration["maxPagesPerOperation"])
            or total_seen != sum(integer(page["itemCount"]) for page in pages)
            or any(page["pageIndex"] != index or integer(page["itemCount"]) < 0
                   for index, page in enumerate(pages))
            or total_seen < len(rows)
            or (next_page > 0 and (not token or token not in seen_tokens))
        ):
            raise ValueError("Invalid acquisition page progress")
        progress.update({"collections": collected, "current": current})
        if save_progress is not None and starting:
            save_progress(progress)
        for page_index in range(next_page, integer(configuration["maxPagesPerOperation"])):
            paged_arm = operation.get("armPagination") is True
            parent_index = read_arm_cursor(token)[0] if paged_arm else page_index
            if operation["kind"] in CHILD_KINDS and parent_index >= len(parents):
                break
            parent = parents[parent_index] if operation["kind"] in CHILD_KINDS else None
            read_status = "succeeded"
            read_error = None
            try:
                response = reader(command_for(operation, requested, page_size, token, parent))
            except ReadFailure as exc:
                if operation["kind"] != SERVICE_ARM_KIND:
                    collection["status"] = "partial" if rows else exc.status
                    issues.append(exc.code)
                    break
                read_status, read_error = exc.status, exc.code
                response = ReadResponse({"count": 0, "data": []})
            if response.execution_id:
                execution_refs.append(response.execution_id)
            payload = response.payload
            if operation["kind"] == "account":
                items = [payload]
                reported_total: int | None = 1
                new_token = None
                truncated: bool | None = False
                declared_count = 1
            else:
                try:
                    items = records(payload["data"])
                except (KeyError, ValueError):
                    if operation["kind"] == SERVICE_ARM_KIND:
                        read_status, read_error, items = "failed", "InvalidServiceArmResponse", []
                    else:
                        issues.append("InvalidObjectArrayResponse")
                        collection["status"] = "partial" if rows else "failed"
                        break
                reported_total_value = payload.get("total_records", payload.get("totalRecords"))
                reported_total = reported_total_value if type(reported_total_value) is int else None
                declared_count = payload.get("count")
                new_token_value = payload.get("skip_token", payload.get("$skipToken"))
                new_token = text(new_token_value) if new_token_value else None
                raw_truncated = payload.get("resultTruncated")
                truncated = raw_truncated in (True, "true", 1) if raw_truncated is not None else None
                if operation["kind"] in ("private-dns-groups", "private-dns-record-metadata") and payload.get("hasContinuation") is True:
                    issues.append("NativeChildContinuationNotCollected")
                if operation["kind"] == SERVICE_ARM_KIND:
                    if parent is None:
                        raise ValueError("Service ARM read lacks a parent")
                    if read_error is None:
                        try:
                            if len(items) != 1 or type(declared_count) is not int or declared_count != 1:
                                raise ValueError("Service ARM GET must return exactly one selected object")
                            item = items[0]
                            if text(item["id"]).lower() != text(parent["id"]).lower() or text(item["type"]).lower() != operation["parentEntityType"]:
                                raise ValueError("Service ARM response differs from its requested parent")
                            props = obj(item["properties"]).copy()
                            for field in ("ipRuleCount", "virtualNetworkRuleCount", "resourceAccessRuleCount"):
                                known = props.pop(field + "Known")
                                if type(known) is not bool:
                                    raise ValueError("Service ARM count availability is invalid")
                                count = props[field]
                                if known and (type(count) is not int or count < 0) or not known and (
                                    count is not None and (type(count) is not int or count != 0)
                                ):
                                    raise ValueError("Service ARM count differs from its availability metadata")
                                if not known:
                                    props[field] = None
                            items = [row_selector({
                                "id": text(parent["id"]) + "/observedArmServiceAccess/summary",
                                "name": "summary", "type": operation["entityType"], "subscriptionId": requested,
                                "resourceGroup": parent["resourceGroup"], "location": item.get("location"),
                                "parentId": parent["id"], "properties": props,
                            }, operation, requested)]
                        except (KeyError, ValueError, ValidationError):
                            read_status, read_error, items = "failed", "InvalidServiceArmResponse", []
                    if read_error is not None:
                        issues.append("ServiceArmRead:" + text(parent["id"]).lower() + ":" + read_error)
                    declared_count = len(items)
                    reported_total, truncated = None, False
                    new_token = str(page_index + 1) if page_index + 1 < len(parents) else None
                elif operation["kind"] in ARM_ROOT_KINDS or operation["kind"] in ARM_CHILD_KINDS:
                    list_prefix = "NspArm" if operation["kind"] in NSP_KINDS else "DnsArm"
                    if type(declared_count) is not int or declared_count < 0:
                        issues.append(list_prefix + "PageCountUnavailable")
                    if len(items) > integer(configuration["childExpansionLimit"]):
                        items = items[:integer(configuration["childExpansionLimit"])]
                        issues.append(list_prefix + "SelectionBudgetExceeded")
                    if not paged_arm and payload.get("hasContinuation") is not False:
                        issues.append(list_prefix + "ContinuationNotCollected")
                    scoped_items = []
                    for item in items:
                        if operation["operationId"] == "nsp-rules":
                            try:
                                props = obj(item["properties"]).copy()
                                for field in NSP_SELECTOR_FIELDS:
                                    known = props.pop(field + "Known")
                                    count = props[field]
                                    if type(known) is not bool or known and (type(count) is not int or count < 0) or not known and (
                                        count is not None and (type(count) is not int or count != 0)
                                    ):
                                        raise ValueError("Invalid NSP selector count availability")
                                    if not known:
                                        props[field] = None
                            except (KeyError, ValueError):
                                issues.append("NspSelectorMetadataRejected")
                                continue
                            item = {**item, "properties": props}
                        resource_id = text(item["id"])
                        group = GROUP_PATTERN.match(resource_id)
                        if parent is not None and not resource_id.lower().startswith(
                            text(parent["id"]).lower() + "/" + text(operation["childSegment"]).lower() + "/"
                        ):
                            raise ValueError("NSP child response differs from approved parent" if operation["kind"] in NSP_CHILD_KINDS
                                             else "DNS child response differs from approved parent")
                        scoped_items.append({**item, "subscriptionId": requested,
                                             "resourceGroup": group.group(2) if group else None,
                                             "parentId": parent["id"] if parent else ""})
                    items = scoped_items
                    reported_total = None
                    if paged_arm:
                        next_link = payload.get("nextLink")
                        if "nextLink" not in payload or next_link not in (None, "") and not isinstance(next_link, str):
                            issues.append(list_prefix + "ContinuationUnavailable")
                            next_link = None
                        if next_link:
                            try:
                                expected_path = urlsplit(command_for(operation, requested, page_size, None, parent)[5]).path
                                validated_arm_url(text(next_link), expected_path, text(operation.get("apiVersion", "2022-07-01")))
                                new_token = arm_cursor(parent_index, text(next_link))
                            except ValueError:
                                issues.append(list_prefix + "ContinuationRejected")
                                new_token = None
                        else:
                            new_token = arm_cursor(parent_index + 1, None) if parent and parent_index + 1 < len(parents) else None
                        truncated = declared_count != len(items)
                    else:
                        new_token = str(page_index + 1) if parent and page_index + 1 < len(parents) else None
                        truncated = payload.get("hasContinuation") is not False
                elif parent is not None and operation["kind"] == "private-dns-record-metadata":
                    try:
                        summary_row, metadata_issues = record_metadata_row(payload, parent, operation)
                    except (ValueError, KeyError):
                        issues.append("InvalidRecordMetadataResponse")
                        collection["status"] = "partial" if rows else "failed"
                        break
                    items = [summary_row]
                    issues.extend(metadata_issues)
                    declared_count = 1
                    reported_total = None
                    new_token = str(page_index + 1) if page_index + 1 < len(parents) else None
                    truncated = False
                elif parent is not None:
                    scoped_items = []
                    for item in items:
                        if not text(item["id"]).lower().startswith(text(parent["id"]).lower() + "/privatednszonegroups/"):
                            raise ValueError("DNS zone group response differs from the approved endpoint parent")
                        scoped_items.append({
                            **item, "type": operation["entityType"], "subscriptionId": subscription,
                            "resourceGroup": parent["resourceGroup"], "location": None, "parentId": parent["id"],
                        })
                    items = scoped_items
                    reported_total = None
                    new_token = str(page_index + 1) if page_index + 1 < len(parents) else None
                    truncated = False
            pages.append({
                "pageIndex": page_index, "itemCount": len(items),
                "totalRecords": reported_total, "hasContinuation": bool(new_token),
                "resultTruncated": truncated,
            })
            if parent is not None:
                pages[-1]["parentResourceId"] = parent["id"]
            if operation["kind"] == SERVICE_ARM_KIND:
                pages[-1].update({"readStatus": read_status, "readError": read_error, "completedAt": clock()})
            if paged_arm:
                pages[-1]["armHasContinuation"] = bool(payload.get("nextLink"))
            if declared_count != len(items):
                issues.append("PageCountMismatch")
            if reported_total is not None:
                if expected_total is not None and expected_total != reported_total:
                    issues.append("InventoryChangedDuringPaging")
                expected_total = reported_total
            elif operation["kind"] == "graph":
                issues.append("TotalRecordCountUnavailable")
            total_seen += len(items)
            for item in items:
                try:
                    selected = row_selector(item, operation, requested)
                except (ValueError, KeyError, ValidationError) as exc:
                    issues.append("RejectedRow:" + type(exc).__name__)
                    continue
                resource_id = text(selected["id"]).lower()
                returned_subscriptions.add(requested)
                if resource_id in rows:
                    previous = rows[resource_id]
                    if previous["properties"] != selected["properties"]:
                        issues.append("ConflictingRepeatedResource")
                    else:
                        issues.append("DuplicateResourceAcrossPages")
                    continue
                rows[resource_id] = selected
            if new_token:
                if new_token in seen_tokens or not items and parent is None and not paged_arm:
                    issues.append("RepeatedOrEmptyContinuation")
                    break
                seen_tokens.add(new_token)
                token = new_token
                collection.update({
                    "pages": pages, "rows": [rows[key] for key in sorted(rows)],
                    "issues": sorted(set(issues)), "executionRefs": sorted(set(execution_refs)),
                    "returnedSubscriptionIds": sorted(returned_subscriptions),
                    "retainedRowCount": len(rows),
                })
                current.update({
                    "nextPage": page_index + 1, "token": token, "seenTokens": sorted(seen_tokens),
                    "totalSeen": total_seen, "expectedTotal": expected_total,
                })
                if save_progress is not None:
                    save_progress(progress)
                continue
            if truncated or expected_total is not None and total_seen < expected_total:
                issues.append("TruncatedWithoutContinuation")
            break
        else:
            issues.append("PageBudgetExceeded")
        if expected_total is not None and len(rows) != expected_total:
            issues.append("RetainedCountMismatch")
        if operation["kind"] == SERVICE_ARM_KIND and pages and all(page["readStatus"] != "succeeded" for page in pages):
            statuses = {text(page["readStatus"]) for page in pages}
            collection["status"] = next(iter(statuses)) if len(statuses) == 1 else "failed"
        collection.update({
            "completedAt": clock(), "pages": pages,
            "returnedSubscriptionIds": sorted(returned_subscriptions),
            "retainedRowCount": len(rows), "issues": sorted(set(issues)),
            "executionRefs": sorted(set(execution_refs)),
            "rows": [rows[key] for key in sorted(rows)],
        })
        if issues and collection["status"] == "succeeded":
            collection["status"] = "partial"
        collected.append(collection)
        progress.update({"collections": collected, "current": None})
        if save_progress is not None:
            save_progress(progress)
    return {
        "inputVersion": "0.9.0" if include_nsp else "0.8.0" if include_service_arm else "0.7.0" if include_service_access else "0.6.0" if include_dns_paths else "0.4.0" if include_record_metadata else "0.3.0" if include_dns_planning else CONTRACT_VERSION if include_private else "0.1.0", "runId": run_id,
        "requestedSubscriptionId": subscription,
        "queryCatalogVersion": configuration["catalogVersion"],
        "collections": collected,
        **({"dnsHostingSubscriptionIds": dns_subscriptions} if include_dns_planning else {}),
    }


def normalize(envelope: Record) -> Record:
    nsp_mode = envelope.get("queryCatalogVersion") == "1.8.0"
    arm_mode = nsp_mode or envelope.get("queryCatalogVersion") == "1.7.0"
    access_mode = arm_mode or envelope.get("queryCatalogVersion") == "1.6.0"
    paginated = access_mode or envelope.get("queryCatalogVersion") == "1.5.0"
    paths_mode = paginated or envelope.get("queryCatalogVersion") == "1.4.0"
    metadata_mode = paths_mode or envelope.get("queryCatalogVersion") == "1.3.0"
    planning = metadata_mode or envelope.get("queryCatalogVersion") == "1.2.0"
    enriched = planning or envelope.get("queryCatalogVersion") == "1.1.0"
    if envelope.get("inputVersion") != ("0.9.0" if nsp_mode else "0.8.0" if arm_mode else "0.7.0" if access_mode else "0.6.0" if paginated else "0.5.0" if paths_mode else "0.4.0" if metadata_mode else "0.3.0" if planning else CONTRACT_VERSION if enriched else "0.1.0"):
        raise ValueError("Unsupported acquisition input version")
    run_id = canonical_uuid(text(envelope["runId"]))
    subscription = canonical_uuid(text(envelope["requestedSubscriptionId"]))
    dns_subscriptions = dns_scopes([text(value) for value in array(envelope["dnsHostingSubscriptionIds"])]) if planning and envelope.get("dnsHostingSubscriptionIds") is not None else None
    configuration = catalog("1.8.0" if nsp_mode else "1.7.0" if arm_mode else "1.6.0" if access_mode else "1.5.0" if paginated else "1.4.0" if paths_mode else "1.3.0" if metadata_mode else "1.2.0" if planning else "1.1.0" if enriched else "1.0.0")
    if envelope.get("queryCatalogVersion") != configuration["catalogVersion"]:
        raise ValueError("Unsupported acquisition query catalog")
    operations = {text(op["operationId"]): op for op in records(configuration["operations"])}
    inputs = records(envelope["collections"])
    expected_scopes = {(text(op["operationId"]), sub) for op, sub in collection_plan(configuration, subscription, dns_subscriptions)}
    if len(inputs) != len(expected_scopes) or {(text(c["operationId"]), c["requestedSubscriptionId"]) for c in inputs} != expected_scopes:
        raise ValueError("Every restricted operation must have an explicit collection outcome")
    entities: dict[str, Record] = {}
    evidence: list[Record] = []
    assertions: list[Record] = []
    relationships: list[Record] = []
    collections: list[Record] = []
    coverage_issues: list[str] = []

    def reference(resource_id: str, evidence_id: str, kind: str = "reference") -> str | None:
        match = RESOURCE_PATTERN.match(resource_id)
        if not match:
            coverage_issues.append("InvalidRelationshipTarget")
            return None
        key = resource_id.lower()
        group = GROUP_PATTERN.match(resource_id)
        if key not in entities:
            entities[key] = {
                "entityId": key, "resourceId": resource_id, "resourceType": kind,
                "name": resource_id.rsplit("/", 1)[-1],
                "subscriptionId": canonical_uuid(match.group(1)),
                "resourceGroup": group.group(2) if group else None,
                "location": None, "collectionState": "referenceOnly",
                "properties": {}, "evidenceRefs": [evidence_id],
            }
        return key

    def relationship(source_id: str, target_id: str | None, kind: str, evidence_id: str) -> None:
        relationships.append({
            "relationshipId": stable("relationship", source_id, target_id, kind),
            "sourceId": source_id, "targetId": target_id, "relationshipType": kind,
            "classification": "OBSERVED" if target_id else "UNKNOWN",
            "unknownReason": None if target_id else "TargetNotCollectedOrPropertyUnavailable",
            "evidenceRefs": [evidence_id],
        })

    for incoming in inputs:
        op_id = text(incoming["operationId"])
        requested = canonical_uuid(text(incoming["requestedSubscriptionId"]))
        if incoming["collectionId"] != collection_id(run_id, op_id, requested, subscription):
            raise ValueError("Collection identity differs from requested scope")
        collection = {k: v for k, v in incoming.items() if k != "rows"}
        operation = operations[op_id]
        expected_hash = hashlib.sha256(text(operation["query"]).encode()).hexdigest() if operation["kind"] != "account" else None
        if incoming["operationVersion"] != operation["operationVersion"] or incoming["querySha256"] != expected_hash:
            raise ValueError("Collection operation version or query hash differs from catalog")
        selected_rows = [select_row(row, operation, requested) for row in records(incoming["rows"])]
        if operation["kind"] == SERVICE_ARM_KIND:
            parent_collection = next(c for c in inputs if c["operationId"] == "private-link-services"
                                     and c["requestedSubscriptionId"] == requested)
            validate_service_arm_collection(incoming, records(parent_collection["rows"]), selected_rows, operation)
        elif operation["kind"] in NSP_KINDS:
            if incoming.get("apiVersion") != operation["apiVersion"]:
                raise ValueError("NSP collection API version differs from catalog")
        elif "apiVersion" in incoming:
            raise ValueError("API version metadata is unsupported for this operation")
        if not set(array(incoming["returnedSubscriptionIds"])) <= {requested}:
            raise ValueError("Collection returned scope exceeds requested subscription")
        if operation["kind"] in ARM_CHILD_KINDS:
            parent_collection = next(c for c in inputs if c["operationId"] == operation["parentOperation"]
                                     and c["requestedSubscriptionId"] == requested)
            parent_ids = {text(row["id"]).lower() for row in records(parent_collection["rows"])}
            if any(text(row["parentId"]).lower() not in parent_ids or not text(row["id"]).lower().startswith(
                text(row["parentId"]).lower() + "/" + text(operation["childSegment"]).lower() + "/"
            ) for row in selected_rows):
                raise ValueError("NSP child input exceeds its collected parent scope" if operation["kind"] in NSP_CHILD_KINDS
                                 else "DNS child input exceeds its collected parent scope")
        if op_id == "repeated-zone-record-metadata":
            permitted_parents = {text(row["id"]).lower() for row in repeated_zone_parents(inputs, requested)}
            page_parents = [text(page["parentResourceId"]).lower() for page in records(incoming["pages"])]
            if len(page_parents) != len(set(page_parents)) or not set(page_parents) <= permitted_parents or any(
                text(row["parentId"]).lower() not in page_parents for row in selected_rows
            ) or len(page_parents) != len(selected_rows) or any(page["itemCount"] != 1 for page in records(incoming["pages"])):
                raise ValueError("Record metadata exceeds collected repeated-zone parent scope")
            if incoming["status"] == "succeeded" and (
                set(page_parents) != permitted_parents or any(
                    obj(row["properties"])["reportedRecordSetCount"] != obj(row["properties"])["selectedRecordSetCount"]
                    or obj(row["properties"])["unknownTypeCount"] or obj(row["properties"])["unknownTtlCount"]
                    for row in selected_rows
                )
            ):
                raise ValueError("Successful record metadata must have complete parents and selected metadata")
        if len(selected_rows) != incoming["retainedRowCount"]:
            raise ValueError("Collection retained count does not match supplied rows")
        collections.append(collection)
        if incoming["status"] != "succeeded":
            coverage_issues.append(op_id + ("@" + requested if planning else "") + ":" + text(incoming["status"]))
        for row in selected_rows:
            key = text(row["id"]).lower()
            props = obj(row["properties"])
            ev_id = stable("evidence", incoming["collectionId"], key)
            excerpt = {
                "resourceId": row["id"], "resourceType": row["type"], "properties": props,
                "name": row["name"], "subscriptionId": row["subscriptionId"],
                "resourceGroup": row["resourceGroup"], "location": row["location"],
                "parentId": row["parentId"],
            }
            evidence.append({
                "evidenceId": ev_id, "collectionId": incoming["collectionId"],
                "subjectId": key, "source": incoming["source"],
                "collectedAt": evidence_time(incoming, row["parentId"]), "classification": "OBSERVED",
                "propertyPaths": sorted(props), "excerpt": excerpt, "sha256": digest(excerpt),
                "hashScope": "canonical-retained-excerpt-not-raw-response",
                "redactionState": "allowlisted-properties-only",
            })
            entities[key] = {
                "entityId": key, "resourceId": row["id"], "resourceType": row["type"],
                "name": row["name"], "subscriptionId": requested,
                "resourceGroup": row["resourceGroup"], "location": row["location"],
                "collectionState": "configurationObject" if operation["kind"] == SERVICE_ARM_KIND or op_id in ("repeated-zone-record-metadata", "vnet-dns-settings") else "collected",
                "properties": props, "evidenceRefs": [ev_id],
            }
            group = GROUP_PATTERN.match(text(row["id"]))
            if group:
                group_id = reference(group.group(1), ev_id, "microsoft.resources/resourcegroups")
                if group_id is None:
                    raise ValueError("Resource-group context identifier is invalid")
                if entities[group_id]["collectionState"] == "referenceOnly":
                    entities[group_id]["collectionState"] = "contextOnly"
                relationship(key, group_id, "inResourceGroup", ev_id)
            parent = row["parentId"]
            if parent:
                parent_id = reference(text(parent), ev_id)
                if parent_id:
                    relationship(parent_id, key, "contains", ev_id)
            for prop, value in props.items():
                known_flag = {
                    "networkSecurityGroupId": "networkSecurityGroupKnown",
                    "routeTableId": "routeTableKnown",
                    "dnsServers": "dnsServersKnown",
                    "targetDnsServerIPs": "targetDnsServersKnown",
                    "targetDnsServerPorts": "targetDnsServersKnown",
                }.get(prop)
                known = props.get(known_flag) is True if known_flag else value is not None
                if op_id == "dns-inbound-endpoints" and prop == "ipConfigurationCount":
                    known = isinstance(props.get("inboundIpAddresses"), list) and isinstance(props.get("inboundSubnetIds"), list)
                assertions.append({
                    "assertionId": stable("assertion", key, prop),
                    "entityId": key, "property": prop, "value": value,
                    "classification": "OBSERVED" if known else "UNKNOWN",
                    "unknownReason": None if known else "PropertyUnavailable",
                    "evidenceRefs": [ev_id],
                })
            for prop, kind in (
                ("remoteVNetId", "peeringTo"),
                ("networkSecurityGroupId", "associatedWithNSG"),
                ("routeTableId", "associatedWithRouteTable"),
                ("subnetId", "attachedToSubnet"), ("workloadId", "attachedToWorkload"),
                ("privateLinkServiceId", "targetsPrivateLinkResource"),
                ("virtualNetworkId", "dnsLinkedToVNet"),
                ("privateLinkResourceId", "associatesPerimeterResource"),
                ("profileId", "associatedWithPerimeterProfile"),
            ):
                if prop not in props:
                    continue
                value = props[prop]
                if op_id == "dns-resolvers" and prop == "virtualNetworkId":
                    kind = "resolverAttachedToVNet"
                flag = {"networkSecurityGroupId": "networkSecurityGroupKnown",
                        "routeTableId": "routeTableKnown"}.get(prop)
                if flag and props.get(flag) is not True:
                    relationship(key, None, kind, ev_id)
                elif value:
                    relationship(key, reference(text(value), ev_id), kind, ev_id)
            for prop, kind in (("outboundEndpointIds", "referencesResolverOutboundEndpoint"),
                               ("inboundSubnetIds", "inboundAttachedToSubnet")):
                if prop in props:
                    values = props[prop]
                    if isinstance(values, list):
                        for value in values:
                            relationship(key, reference(text(value), ev_id), kind, ev_id)
                    elif values is None:
                        relationship(key, None, kind, ev_id)
            if op_id == "private-dns-groups":
                zone_ids = props.get("privateDnsZoneIds")
                if isinstance(zone_ids, list):
                    for zone_id in zone_ids:
                        relationship(key, reference(text(zone_id), ev_id), "referencesPrivateDnsZone", ev_id)
                elif zone_ids is None:
                    relationship(key, None, "referencesPrivateDnsZone", ev_id)
            if op_id == "routes" and props.get("nextHopType"):
                next_hop_id = key + "#configured-next-hop"
                entities[next_hop_id] = {
                    **entities[key], "entityId": next_hop_id,
                    "resourceId": row["id"],
                    "resourceType": "configured-next-hop", "name": "configured-next-hop",
                    "collectionState": "configurationObject",
                    "properties": {p: props[p] for p in ("nextHopType", "nextHopIpAddress")},
                }
                relationship(key, next_hop_id, "hasConfiguredNextHop", ev_id)
            elif op_id == "routes":
                relationship(key, None, "hasConfiguredNextHop", ev_id)
            for count_field in ("subnetCount", "peeringCount", "routeCount", "ipConfigurationCount", "automaticConnectionCount", "manualConnectionCount", "virtualNetworkLinkCount"):
                count = props.get(count_field)
                if type(count) is int and count > integer(configuration["childExpansionLimit"]):
                    coverage_issues.append("ChildExpansionLimit:" + key + ":" + count_field)

    parent_expectations = [
        ("microsoft.network/virtualnetworks", "subnetCount", "microsoft.network/virtualnetworks/subnets"),
        ("microsoft.network/virtualnetworks", "peeringCount", "microsoft.network/virtualnetworks/virtualnetworkpeerings"),
        ("microsoft.network/routetables", "routeCount", "microsoft.network/routetables/routes"),
        ("microsoft.network/privatednszones", "virtualNetworkLinkCount", "microsoft.network/privatednszones/virtualnetworklinks"),
    ]
    for parent in list(entities.values()):
        for parent_type, count_field, child_type in parent_expectations:
            if parent["resourceType"] != parent_type:
                continue
            expected = obj(parent["properties"]).get(count_field)
            if type(expected) is not int:
                continue
            count = sum(
                1 for child in entities.values()
                if child["resourceType"] == child_type
                and text(child["entityId"]).rsplit("/", 2)[0] == parent["entityId"]
            )
            if count != expected:
                coverage_issues.append("ChildCountMismatch:" + text(parent["entityId"]) + ":" + count_field)
    for nsg in list(entities.values()):
        if nsg["resourceType"] != "microsoft.network/networksecuritygroups":
            continue
        props = obj(nsg["properties"])
        custom, default = props.get("customRuleCount"), props.get("defaultRuleCount")
        if type(custom) is int and type(default) is int:
            actual = sum(
                1 for e in entities.values()
                if e["resourceType"] == "microsoft.network/networksecuritygroups/securityrules"
                and text(e["entityId"]).rsplit("/", 2)[0] == nsg["entityId"]
            )
            if actual != custom + default:
                coverage_issues.append("ChildCountMismatch:" + text(nsg["entityId"]) + ":rules")
    for endpoint in list(entities.values()):
        if endpoint["resourceType"] != "microsoft.network/privateendpoints":
            continue
        counts = obj(endpoint["properties"])
        for kind, field in (("automatic", "automaticConnectionCount"), ("manual", "manualConnectionCount")):
            expected = counts.get(field)
            actual = sum(1 for entity in entities.values() if (
                entity["resourceType"] == "microsoft.network/privateendpoints/privatelinkserviceconnections"
                and obj(entity["properties"]).get("connectionKind") == kind
                and text(entity["entityId"]).rsplit("/", 2)[0] == endpoint["entityId"]
            ))
            if type(expected) is int and actual != expected:
                coverage_issues.append("ChildCountMismatch:" + text(endpoint["entityId"]) + ":" + field)
    model: Record = {
        "schemaVersion": "0.9.0" if nsp_mode else "0.8.0" if arm_mode else "0.7.0" if access_mode else "0.6.0" if paginated else "0.5.0" if paths_mode else "0.4.0" if metadata_mode else "0.3.0" if planning else CONTRACT_VERSION if enriched else "0.1.0",
        "run": {
            "runId": run_id, "capabilityVersion": VERSION,
            "queryCatalogVersion": envelope["queryCatalogVersion"],
            "startedAt": min(text(c["startedAt"]) for c in collections),
            "completedAt": max(text(c["completedAt"]) for c in collections),
        },
        "scope": {
            "requestedSubscriptionIds": [subscription],
            "returnedSubscriptionIds": sorted({text(s) for c in collections for s in array(c["returnedSubscriptionIds"])}),
            "resourceTypes": sorted({text(value) for op in operations.values()
                                     for value in array(op.get("entityTypes", [op["entityType"]]))}),
            "deferredEvidence": [*[value for value in DEFERRED if value != "Target service public-network access"],
                                 "Other service families' public-network access", "NSP/AMPLS enforcement",
                                 "Service data-plane authorization and reachability"] if access_mode else DEFERRED if enriched else LEGACY_DEFERRED,
            "expansionPolicy": "no-automatic-cross-subscription-expansion",
            **({"dnsHostingSubscriptionIds": dns_subscriptions} if planning else {}),
        },
        "dataHandling": DATA_HANDLING,
        "collections": sorted(collections, key=lambda c: text(c["operationId"])),
        "coverage": {
            "status": "partial" if coverage_issues else "accessible-pages-collected",
            "permissionCompleteness": "UNKNOWN", "accessibleResultsOnly": True,
            "indexFreshness": "not-independently-established",
            "issues": sorted(set(coverage_issues)),
        },
        "entities": [entities[key] for key in sorted(entities)],
        "evidence": sorted(evidence, key=lambda e: text(e["evidenceId"])),
        "assertions": sorted(assertions, key=lambda a: text(a["assertionId"])),
        "relationships": sorted(relationships, key=lambda r: text(r["relationshipId"])),
    }
    validate_document(model, HERE / "observed-network.schema.json")
    verify_observation(model)
    return model


def evidence_time(collection: Record, parent_id: object) -> str:
    if collection["operationId"] not in SERVICE_ARM_PROFILES:
        return text(collection["completedAt"])
    pages = [page for page in records(collection["pages"])
             if text(page["parentResourceId"]).lower() == text(parent_id).lower()]
    if len(pages) != 1:
        raise ValueError("Service ARM evidence lacks its unique parent read timestamp")
    return text(pages[0]["completedAt"])


def validate_service_arm_collection(collection: Record, parent_rows: list[Record],
                                    selected_rows: list[Record], operation: Record, *, complete: bool = True) -> None:
    parents = sorted(text(row["id"]).lower() for row in parent_rows if text(row["type"]).lower() == operation["parentEntityType"])
    pages = records(collection["pages"])
    page_parents = [text(page["parentResourceId"]).lower() for page in pages]
    if collection.get("apiVersion") != operation["apiVersion"] or page_parents != parents[:len(pages)]:
        raise ValueError("Service ARM collection exceeds its ordered approved parents/API")
    successful = {text(page["parentResourceId"]).lower() for page in pages if page["readStatus"] == "succeeded"}
    if len(page_parents) != len(set(page_parents)) or len(selected_rows) != len(successful) or (
        {text(row["parentId"]).lower() for row in selected_rows} != successful
    ):
        raise ValueError("Service ARM rows differ from successful parent reads")
    if complete and collection["status"] == "succeeded" and (page_parents != parents or len(successful) != len(parents)):
        raise ValueError("Successful service ARM collection lacks complete parent coverage")
    for index, page in enumerate(pages):
        succeeded = page["readStatus"] == "succeeded"
        if page["readStatus"] not in ("succeeded", "partial", "permissionDenied", "unavailable", "unsupported", "failed", "notAttempted"):
            raise ValueError("Unsupported service ARM read outcome")
        if page["pageIndex"] != index or type(page["itemCount"]) is not int or page["itemCount"] != int(succeeded) or (
            succeeded and page["readError"] is not None or not succeeded and not page["readError"]
        ):
            raise ValueError("Service ARM page read outcome is inconsistent")
        completed = datetime.fromisoformat(text(page["completedAt"]).replace("Z", "+00:00"))
        start = datetime.fromisoformat(text(collection["startedAt"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(text(collection["completedAt"]).replace("Z", "+00:00"))
        if completed < start or complete and completed > end:
            raise ValueError("Service ARM page completion is outside collection time")


def unique_index(items: list[Record], key: str) -> dict[str, Record]:
    result = {text(item[key]): item for item in items}
    if len(result) != len(items):
        raise ValueError("Duplicate identifier in artifact: " + key)
    return result


def verify_observation(model: Record) -> None:
    entities = unique_index(records(model["entities"]), "entityId")
    evidence = unique_index(records(model["evidence"]), "evidenceId")
    collections = unique_index(records(model["collections"]), "collectionId")
    scope = obj(model["scope"])
    workload = canonical_uuid(text(array(scope["requestedSubscriptionIds"])[0]))
    nsp_mode = obj(model["run"])["queryCatalogVersion"] == "1.8.0"
    arm_mode = nsp_mode or obj(model["run"])["queryCatalogVersion"] == "1.7.0"
    access_mode = arm_mode or obj(model["run"])["queryCatalogVersion"] == "1.6.0"
    paginated = access_mode or obj(model["run"])["queryCatalogVersion"] == "1.5.0"
    paths_mode = paginated or obj(model["run"])["queryCatalogVersion"] == "1.4.0"
    planning = paths_mode or obj(model["run"])["queryCatalogVersion"] in ("1.2.0", "1.3.0")
    hosts = dns_scopes([text(value) for value in array(scope["dnsHostingSubscriptionIds"])]) if planning and scope.get("dnsHostingSubscriptionIds") is not None else None
    if planning and ("dnsHostingSubscriptionIds" not in scope or model["schemaVersion"] != ("0.9.0" if nsp_mode else "0.8.0" if arm_mode else "0.7.0" if access_mode else "0.6.0" if paginated else "0.5.0" if paths_mode else "0.4.0" if obj(model["run"])["queryCatalogVersion"] == "1.3.0" else "0.3.0")):
        raise ValueError("DNS planning observation must preserve explicit/unknown DNS-hosting scope")
    if not planning and "dnsHostingSubscriptionIds" in scope:
        raise ValueError("Historical observation cannot contain DNS-hosting scope")
    plan = collection_plan(catalog(text(obj(model["run"])["queryCatalogVersion"])), workload, hosts)
    expected_scopes = {(op["operationId"], requested) for op, requested in plan}
    if len(collections) != len(plan) or {(c["operationId"], c["requestedSubscriptionId"]) for c in collections.values()} != expected_scopes:
        raise ValueError("Observation collection scope differs from approved workload/DNS-hosting plan")
    if not set(array(scope["returnedSubscriptionIds"])) <= {workload, *(hosts or [])}:
        raise ValueError("Observation returned scope exceeds approved subscriptions")
    for collection in collections.values():
        if not set(array(collection["returnedSubscriptionIds"])) <= {collection["requestedSubscriptionId"]}:
            raise ValueError("Collection returned scope differs from its requested subscription")
        if collection["operationId"] in SERVICE_ARM_PROFILES:
            operation = next(op for op, requested in plan if op["operationId"] == collection["operationId"]
                             and requested == collection["requestedSubscriptionId"])
            parent_collection = next(c for c in collections.values() if c["operationId"] == "private-link-services")
            parents = [obj(ev["excerpt"]) for ev in evidence.values() if ev["collectionId"] == parent_collection["collectionId"]]
            rows = [obj(ev["excerpt"]) for ev in evidence.values() if ev["collectionId"] == collection["collectionId"]]
            validate_service_arm_collection(collection,
                                           [{"id": row["resourceId"], "type": row["resourceType"]} for row in parents],
                                           rows, operation)
    unique_index(records(model["assertions"]), "assertionId")
    unique_index(records(model["relationships"]), "relationshipId")
    for item in [
        *entities.values(), *records(model["assertions"]), *records(model["relationships"]),
    ]:
        if not set(array(item["evidenceRefs"])) <= set(evidence):
            raise ValueError("Unresolved observation evidence reference")
    for item in evidence.values():
        if item["collectionId"] not in collections or item["subjectId"] not in entities:
            raise ValueError("Unresolved evidence subject or collection")
        requested = collections[text(item["collectionId"])]["requestedSubscriptionId"]
        excerpt = obj(item["excerpt"])
        match = RESOURCE_PATTERN.match(text(excerpt["resourceId"]))
        if not match or canonical_uuid(match.group(1)) != requested or excerpt["subscriptionId"] != requested:
            raise ValueError("Evidence scope differs from its collection subscription")
        if item["sha256"] != digest(item["excerpt"]):
            raise ValueError("Evidence integrity mismatch")
        if collections[text(item["collectionId"])]["operationId"] in SERVICE_ARM_PROFILES and (
            item["collectedAt"] != evidence_time(collections[text(item["collectionId"])], excerpt["parentId"])
        ):
            raise ValueError("Service ARM evidence time differs from its selected parent read")
        if sorted(array(item["propertyPaths"])) != sorted(obj(obj(item["excerpt"])["properties"])):
            raise ValueError("Evidence property-path mismatch")
    for assertion in records(model["assertions"]):
        if assertion["entityId"] not in entities:
            raise ValueError("Unresolved assertion subject")
        if assertion["classification"] not in ("OBSERVED", "UNKNOWN"):
            raise ValueError("Normalizer may not emit inferred or declared assertions")
        props = obj(entities[text(assertion["entityId"])]["properties"])
        if assertion["property"] not in props or props[text(assertion["property"])] != assertion["value"]:
            raise ValueError("Assertion differs from the retained configuration")
    for rel in records(model["relationships"]):
        if rel["sourceId"] not in entities or rel["targetId"] and rel["targetId"] not in entities:
            raise ValueError("Unresolved relationship endpoint")
        if rel["classification"] not in ("OBSERVED", "UNKNOWN"):
            raise ValueError("Normalizer may not infer relationships")


def private_dns_plan(model: Record) -> Record:
    mapping = load(HERE / "private-dns-services.json")
    entities = [entity for entity in records(model["entities"]) if entity["collectionState"] == "collected"]
    collections = records(model["collections"])
    dns_collections = [item for item in collections if item["operationId"] in ("private-dns-zones", "private-dns-links")]
    declared_hosts = obj(model["scope"]).get("dnsHostingSubscriptionIds")
    scope_status = "not-declared" if declared_hosts is None else (
        "declared-accessible-results" if all(item["status"] == "succeeded" for item in dns_collections)
        else "declared-partial"
    )
    zones = [entity for entity in entities if entity["resourceType"] == "microsoft.network/privatednszones"]
    connections = [entity for entity in entities if entity["resourceType"] == "microsoft.network/privateendpoints/privatelinkserviceconnections"]
    links = [entity for entity in entities if entity["resourceType"] == "microsoft.network/privatednszones/virtualnetworklinks"]
    groups = [entity for entity in entities if entity["resourceType"] == "microsoft.network/privateendpoints/privatednszonegroups"]
    metadata_mode = obj(model["run"])["queryCatalogVersion"] in ("1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0")
    metadata_summaries = {text(entity["entityId"]).rsplit("/", 2)[0]: entity
                          for entity in records(model["entities"]) if entity["resourceType"] == "private-dns-record-metadata-summary"}
    zone_rows = []
    repeated: dict[str, list[str]] = {}
    for zone in zones:
        zone_id = text(zone["entityId"])
        normalized_name = text(zone["name"]).lower().rstrip(".")
        repeated.setdefault(normalized_name, []).append(zone_id)
        zone_links = [link for link in links if text(link["entityId"]).rsplit("/", 2)[0] == zone_id]
        zone_groups = [group for group in groups if any(
            text(value).lower() == zone_id for value in array(obj(group["properties"]).get("privateDnsZoneIds") or [])
        )]
        zone_rows.append({
            "zoneId": zone_id, "name": normalized_name, "subscriptionId": zone["subscriptionId"],
            "linkIds": sorted(text(link["entityId"]) for link in zone_links),
            "zoneGroupIds": sorted(text(group["entityId"]) for group in zone_groups),
            "evidenceRefs": sorted({text(ref) for entity in [zone, *zone_links, *zone_groups] for ref in array(entity["evidenceRefs"])}),
        })
        if metadata_mode:
            summary = metadata_summaries.get(zone_id)
            source_collection = next((c for c in collections if c["operationId"] == "repeated-zone-record-metadata"
                                      and c["requestedSubscriptionId"] == zone["subscriptionId"]), None)
            zone_rows[-1]["recordMetadata"] = {
                "status": "not-collected" if summary is None else "selected-metadata-collected"
                if source_collection is not None and source_collection["status"] == "succeeded" else "partial",
                "summaryEntityId": summary["entityId"] if summary else None,
                "properties": summary["properties"] if summary else {},
                "collectionRefs": [source_collection["collectionId"]] if source_collection else [],
                "evidenceRefs": summary["evidenceRefs"] if summary else [],
            }
    service_rows = []
    for row in records(mapping["services"]):
        services = [entity for entity in entities if entity["resourceType"] == row["resourceType"]]
        service_ids = {text(entity["entityId"]) for entity in services}
        subresources = {text(value).lower() for value in array(row["subresources"])}
        observed_connections = [connection for connection in connections if (
            isinstance(obj(connection["properties"]).get("privateLinkServiceId"), str)
            and text(obj(connection["properties"])["privateLinkServiceId"]).lower() in service_ids
            and subresources.intersection(text(value).lower() for value in array(obj(connection["properties"]).get("groupIds") or []))
        )]
        targets = {text(obj(connection["properties"])["privateLinkServiceId"]).lower() for connection in observed_connections}
        matches = []
        selected_zones = []
        for value in array(row["zones"]):
            zone_value = text(value)
            template = "{" in zone_value
            pattern = re.escape(zone_value)
            pattern = re.sub(r"\\\{[^}]+\\\}", r"[^.]+", pattern)
            matching_zones = [zone for zone in zones if re.fullmatch(pattern, text(zone["name"]).lower().rstrip("."))]
            selected_zones.extend(matching_zones)
            matches.append({
                "zoneValue": zone_value, "zoneIds": sorted(text(zone["entityId"]) for zone in matching_zones),
                "status": "template-candidates-require-context" if template else (
                    "observed-name" if matching_zones else "not-observed-in-accessible-scopes"
                    if scope_status == "declared-accessible-results" else "unknown-coverage"
                ),
            })
        service_rows.append({
            "resourceType": row["resourceType"], "subresources": row["subresources"], "zoneValues": row["zones"],
            "serviceIds": sorted(service_ids), "connectionIds": sorted(text(item["entityId"]) for item in observed_connections),
            "serviceIdsWithoutObservedConnection": sorted(service_ids - targets),
            "zoneMatches": matches, "applicability": "planning-only-requires-service-feature-and-customer-intent",
            "note": row.get("note", "Service/SKU/subresource use and private-access intent require validation."),
            "evidenceRefs": sorted({text(ref) for entity in [*services, *observed_connections, *selected_zones] for ref in array(entity["evidenceRefs"])}),
        })
    return {
        "catalogVersion": mapping["catalogVersion"], "catalogSha256": digest(mapping),
        "source": mapping["source"], "sourceRevision": mapping["sourceRevision"], "cloud": mapping["cloud"],
        "dnsHostingScopeStatus": scope_status,
        "serviceInventoryStatus": next(item["status"] for item in collections if item["operationId"] == "private-link-services"),
        "connectionInventoryStatus": next(item["status"] for item in collections if item["operationId"] == "private-endpoint-connections"),
        "dnsSubscriptionIds": sorted({text(item["requestedSubscriptionId"]) for item in dns_collections}),
        "collectionRefs": sorted(text(item["collectionId"]) for item in collections if item["operationId"] in (
            "private-link-services", "private-endpoints", "private-endpoint-connections", "private-dns-zones", "private-dns-links", "private-dns-groups",
            "repeated-zone-record-metadata",
        )),
        "serviceRows": service_rows, "zones": zone_rows,
        "repeatedZoneNames": [{"name": name, "zoneIds": sorted(ids)} for name, ids in sorted(repeated.items()) if len(ids) > 1],
        "limitations": [
            "Commercial AzureCloud mapping only; documentation values are DECLARED guidance, not observed requirements.",
            "Service metadata does not establish SKU/API/subresource eligibility, actual use, customer intent or all zone requirements.",
            "No observed target/subresource connection means not observed in this workload scope; consumer endpoints may exist in other subscriptions.",
            "A zone name alone does not prove endpoint association, records, forwarding, client visibility, resolution or private-only access.",
            "Missing observed zones never explain why a service has no observed endpoint; custom/external DNS and undeclared hosts remain possible.",
            "Repeated names can intentionally isolate tenants/environments/regions or disconnected DNS views; no zone is certified unused or safe to delete.",
            "Permission-wide completeness and index freshness remain unknown even for successful queries.",
        ],
    }


def configured_dns_paths(model: Record) -> Record:
    resource_types = {op["entityType"] for op in records(catalog("1.4.0")["operations"]) if op["operationId"] in DNS_PATH_OPERATIONS}
    return {
        "collectionRefs": sorted(text(c["collectionId"]) for c in records(model["collections"]) if c["operationId"] in DNS_PATH_OPERATIONS),
        "rows": [{"entityId": entity["entityId"], "resourceType": entity["resourceType"],
                  "properties": entity["properties"], "evidenceRefs": entity["evidenceRefs"]}
                 for entity in records(model["entities"]) if entity["resourceType"] in resource_types
                 and entity["collectionState"] in ("collected", "configurationObject")],
        "limitations": [
            "VNet DNS settings are configured DHCP defaults, not demonstrated client/NIC/OS DNS-server selection.",
            "Empty known VNet DNS-server arrays mean Azure-provided DNS configuration; unavailable fields are UNKNOWN.",
            "Resolver, subnet, outbound endpoint and ruleset-link references are configuration, not observed DNS queries or traffic.",
            "No scoped resolver/ruleset rows does not prove there are no custom, on-premises or externally hosted DNS services.",
            "Forwarding rules retain suffixes and ordered target IP/port pairs, not demonstrated availability or rule selection.",
            ("ARM lists use scope-validated bounded pagination; invalid/repeated/missing continuation or page-budget failures remain partial."
             if obj(model["run"])["queryCatalogVersion"] in ("1.5.0", "1.6.0", "1.7.0", "1.8.0")
             else "ARM continuation pages beyond the first are explicitly partial, never complete/absence evidence."),
            "Only the approved workload subscription's resolver paths are collected; additional DNS hosts retain only approved zone/link/metadata scope.",
            "Customer-managed DNS settings, NIC/OS overrides, forwarding outside scope, resolver cache, logs, actual resolution and cleanup safety remain unverified.",
        ],
    }


def resolver_adoption(model: Record) -> Record:
    entities = [entity for entity in records(model["entities"]) if entity["collectionState"] in ("collected", "configurationObject")]
    vnets = [entity for entity in entities if entity["resourceType"] == "microsoft.network/virtualnetworks"]
    resolvers = [entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsresolvers"]
    rulesets = [entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsforwardingrulesets"]
    inbound = [entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsresolvers/inboundendpoints"]
    outbound = {text(entity["entityId"]): entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsresolvers/outboundendpoints"}
    links = [entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsforwardingrulesets/virtualnetworklinks"]
    rules = [entity for entity in entities if entity["resourceType"] == "microsoft.network/dnsforwardingrulesets/forwardingrules"]
    settings = {text(entity["entityId"]).rsplit("/", 2)[0]: entity for entity in entities if entity["resourceType"] == "vnet-dns-settings"}
    collections = {text(c["operationId"]): c for c in records(model["collections"]) if c["operationId"] in DNS_PATH_OPERATIONS}

    def parent_complete(operation: str, parent_id: str, children: list[Record]) -> bool:
        collection = collections[operation]
        pages = [page for page in records(collection["pages"]) if text(page.get("parentResourceId", "")).lower() == parent_id]
        return collection["status"] == "succeeded" and not array(collection["issues"]) and bool(pages) and (
            all(page["resultTruncated"] is False for page in pages)
            and pages[-1].get("armHasContinuation", False) is False
            and sum(integer(page["itemCount"]) for page in pages) == len(children)
        )

    def address(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    root_pages = records(collections["dns-rulesets"]["pages"])
    link_complete = collections["dns-rulesets"]["status"] == "succeeded" and not array(collections["dns-rulesets"]["issues"]) and (
        bool(root_pages) and all(page["resultTruncated"] is False for page in root_pages)
        and root_pages[-1]["hasContinuation"] is False
        and sum(integer(page["itemCount"]) for page in root_pages) == len(rulesets)
        and collections["dns-rulesets"]["retainedRowCount"] == len(rulesets)
    ) and (
        collections["dns-ruleset-links"]["status"] == "succeeded"
        and not array(collections["dns-ruleset-links"]["issues"])
        and all(isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                and RESOURCE_PATTERN.match(text(obj(link["properties"])["virtualNetworkId"])) for link in links)
        and all(parent_complete("dns-ruleset-links", text(ruleset["entityId"]),
                                [link for link in links if text(link["entityId"]).rsplit("/", 2)[0] == ruleset["entityId"]])
                for ruleset in rulesets)
    )
    consumer_rows: list[Record] = []
    for vnet in vnets:
        vnet_id = text(vnet["entityId"])
        setting = settings.get(vnet_id)
        props = obj(setting["properties"]) if setting else {}
        servers = props.get("dnsServers")
        known = props.get("dnsServersKnown") is True and isinstance(servers, list)
        server_values = array(servers) if known else []
        unknown_addresses = sum(address(value) is None for value in server_values)
        mode = "UNKNOWN" if not known or unknown_addresses else "custom-configured" if server_values else "azure-provided-configured"
        candidates = [endpoint for endpoint in inbound if any(
            address(value) is not None and address(value) in {address(ip) for ip in array(obj(endpoint["properties"]).get("inboundIpAddresses") or [])}
            for value in server_values
        )]
        vnet_links = [link for link in links if isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                      and text(obj(link["properties"])["virtualNetworkId"]).lower() == vnet_id]
        succeeded_links = [link for link in vnet_links if obj(link["properties"]).get("provisioningState") == "Succeeded"]
        supporting = [vnet, *([setting] if setting else []), *vnet_links, *candidates]
        consumer_rows.append({
            "vnetId": vnet_id, "dnsMode": mode, "unknownAddressCount": unknown_addresses,
            "inboundEndpointCandidates": sorted(text(endpoint["entityId"]) for endpoint in candidates),
            "observedRulesetLinkIds": sorted(text(link["entityId"]) for link in vnet_links),
            "rulesetsWithSucceededLinks": sorted({text(link["entityId"]).rsplit("/", 2)[0] for link in succeeded_links}),
            "linkCoverage": "accessible-parent-lists-collected" if link_complete else "UNKNOWN",
            "unreadyLinkIds": sorted(text(link["entityId"]) for link in vnet_links if obj(link["properties"]).get("provisioningState") != "Succeeded"),
            "evidenceRefs": sorted({text(ref) for entity in supporting for ref in array(entity["evidenceRefs"])}),
        })
    ruleset_rows: list[Record] = []
    for ruleset in rulesets:
        ruleset_id = text(ruleset["entityId"])
        selected_links = [link for link in links if text(link["entityId"]).rsplit("/", 2)[0] == ruleset_id]
        selected_rules = [rule for rule in rules if text(rule["entityId"]).rsplit("/", 2)[0] == ruleset_id]
        raw_outbound = obj(ruleset["properties"]).get("outboundEndpointIds")
        outbound_values = array(raw_outbound) if isinstance(raw_outbound, list) else []
        valid_outbound = [text(value).lower() for value in outbound_values if isinstance(value, str) and RESOURCE_PATTERN.match(value)]
        ruleset_rows.append({
            "rulesetId": ruleset_id,
            "observedLinkIds": sorted(text(link["entityId"]) for link in selected_links),
            "unknownLinkTargetIds": sorted(text(link["entityId"]) for link in selected_links
                                          if not isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                                          or not RESOURCE_PATTERN.match(text(obj(link["properties"])["virtualNetworkId"]))),
            "observedVnetIds": sorted({text(obj(link["properties"])["virtualNetworkId"]).lower() for link in selected_links
                                      if isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                                      and obj(link["properties"]).get("virtualNetworkId")}),
            "vnetIdsWithSucceededLinks": sorted({text(obj(link["properties"])["virtualNetworkId"]).lower() for link in selected_links
                                       if isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                                       and obj(link["properties"]).get("virtualNetworkId")
                                       and obj(link["properties"]).get("provisioningState") == "Succeeded"}),
            "linkCoverage": "accessible-parent-list-collected" if parent_complete("dns-ruleset-links", ruleset_id, selected_links) else "UNKNOWN",
            "ruleCoverage": "accessible-parent-list-collected" if parent_complete("dns-forwarding-rules", ruleset_id, selected_rules) else "UNKNOWN",
            "enabledRuleIds": sorted(text(rule["entityId"]) for rule in selected_rules if obj(rule["properties"]).get("forwardingRuleState") == "Enabled"),
            "disabledRuleIds": sorted(text(rule["entityId"]) for rule in selected_rules if obj(rule["properties"]).get("forwardingRuleState") == "Disabled"),
            "unknownRuleStateIds": sorted(text(rule["entityId"]) for rule in selected_rules if obj(rule["properties"]).get("forwardingRuleState") not in ("Enabled", "Disabled")),
            "outboundReferencesKnown": isinstance(raw_outbound, list) and len(valid_outbound) == len(outbound_values),
            "unknownOutboundReferenceCount": len(outbound_values) - len(valid_outbound),
            "outboundEndpointIds": sorted(set(valid_outbound)),
            "unverifiedOutboundEndpointIds": sorted({value for value in valid_outbound
                                                     if value not in outbound
                                                     or obj(outbound[value]["properties"]).get("provisioningState") != "Succeeded"}),
            "evidenceRefs": sorted({text(ref) for entity in [ruleset, *selected_links, *selected_rules,
                                    *[outbound[value] for value in valid_outbound if value in outbound]]
                                    for ref in array(entity["evidenceRefs"])}),
        })
    return {
        "resolverIds": sorted(text(entity["entityId"]) for entity in resolvers),
        "collectionRefs": sorted(text(c["collectionId"]) for c in collections.values()),
        "consumers": consumer_rows, "rulesets": ruleset_rows,
        "migrationIntent": "UNKNOWN", "actualClientUse": "UNKNOWN",
        "limitations": [
            "This is a scoped configuration review, not a percentage migrated, customer target architecture or proven client adoption.",
            "Not every VNet needs a ruleset link: inbound-only, custom/on-premises DNS and deliberately isolated designs can be valid.",
            "Configured DNS-IP matches are inbound-endpoint candidates, not demonstrated client use; duplicate addresses can be ambiguous.",
            "Unobserved links or rules remain scoped observations only when their parent lists are complete; unavailable evidence is UNKNOWN.",
            "Different link/default cohorts can reflect intentional isolation or staged migration, not verified inconsistency.",
            "External consumer references are retained without querying their subscriptions; missing workload/consumer scope is not absence.",
            "Enabled/disabled rule counts do not prove the rules match needed suffixes, are selected or successfully forward queries.",
            "Owners, migration cohorts/requirements, NIC/OS DNS overrides, custom forwarding, live resolution and safe cleanup remain unverified.",
        ],
    }


def validate_dns_intent(model: Record, intent: Record) -> None:
    validate_document(intent, HERE / "dns-intent.schema.json")
    if obj(model["run"])["queryCatalogVersion"] not in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
        raise ValueError("DNS intent requires DNS-path observation input")
    if canonical_uuid(text(intent["runId"])) != obj(model["run"])["runId"] or (
        canonical_uuid(text(intent["subscriptionId"])) != array(obj(model["scope"])["requestedSubscriptionIds"])[0]
    ):
        raise ValueError("DNS intent run/subscription differs from observation scope")
    source = obj(intent["source"])
    if any(not text(source[key]).strip() for key in ("documentId", "revision", "owner")):
        raise ValueError("DNS intent source identity/revision/owner cannot be blank")
    if datetime.fromisoformat(text(source["reviewedAt"]).replace("Z", "+00:00")) < datetime.fromisoformat(text(source["declaredAt"]).replace("Z", "+00:00")):
        raise ValueError("DNS intent review time precedes declaration")
    cohort_ids: set[str] = set()
    consumers: set[str] = set()
    for cohort in records(intent["cohorts"]):
        cohort_id = text(cohort["cohortId"])
        if cohort_id in cohort_ids:
            raise ValueError("Duplicate DNS intent cohort ID")
        cohort_ids.add(cohort_id)
        if cohort["stage"] == "excluded" and (
            cohort["dnsMode"] != "unspecified" or array(cohort["requiredRulesetIds"]) or array(cohort["requiredInboundEndpointIds"])
        ):
            raise ValueError("Excluded DNS intent cohorts cannot require configuration")
        if cohort["stage"] == "required-now" and cohort["dnsMode"] == "unspecified" and not (
            array(cohort["requiredRulesetIds"]) or array(cohort["requiredInboundEndpointIds"])
        ):
            raise ValueError("Required-now DNS intent must declare a configuration expectation")
        if cohort["dnsMode"] == "azure-provided-configured" and array(cohort["requiredInboundEndpointIds"]):
            raise ValueError("Azure-provided DNS intent cannot require direct inbound DNS-server assignment")
        for field, resource_type in (("vnetIds", "virtualnetworks"), ("requiredRulesetIds", "dnsforwardingrulesets"),
                                     ("requiredInboundEndpointIds", "dnsresolvers/[^/]+/inboundendpoints")):
            ids = [text(value).lower() for value in array(cohort[field])]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate case-insensitive DNS intent resource IDs")
            for resource_id in ids:
                if re.search(r"\s", resource_id) or any(part in (".", "..") for part in resource_id.split("/")) or not re.fullmatch(r"/subscriptions/[a-f0-9-]{36}/resourcegroups/[^/?#%\\]+/providers/microsoft.network/"
                                    + resource_type + r"/[^/?#%\\]+", resource_id):
                    raise ValueError("Unsupported DNS intent resource ID")
                canonical_uuid(resource_id.split("/")[2])
            if field == "vnetIds":
                if consumers.intersection(ids):
                    raise ValueError("DNS intent VNet belongs to conflicting cohorts")
                if any(resource_id.split("/")[2] != canonical_uuid(text(intent["subscriptionId"])) for resource_id in ids):
                    raise ValueError("DNS intent consumer exceeds workload subscription")
                consumers.update(ids)
                if len(consumers) > 500:
                    raise ValueError("DNS intent exceeds the 500-consumer comparison budget")


def compare_dns_intent(model: Record, intent: Record) -> Record:
    validate_dns_intent(model, intent)
    adoption = resolver_adoption(model)
    consumers = {text(row["vnetId"]): row for row in records(adoption["consumers"])}
    entities = {text(entity["entityId"]): entity for entity in records(model["entities"])}
    collected = {key: entity for key, entity in entities.items() if entity["collectionState"] == "collected"}
    rulesets = {text(row["rulesetId"]): row for row in records(adoption["rulesets"])}
    collection_map = {text(c["operationId"]): c for c in records(model["collections"]) if c["operationId"] in DNS_PATH_OPERATIONS}
    source = obj(intent["source"])
    newer = datetime.fromisoformat(text(source["declaredAt"]).replace("Z", "+00:00")) > datetime.fromisoformat(
        text(obj(model["run"])["completedAt"]).replace("Z", "+00:00")
    )
    rows: list[Record] = []
    for cohort in records(intent["cohorts"]):
        for vnet_id in sorted(text(value).lower() for value in array(cohort["vnetIds"])):
            consumer = consumers.get(vnet_id)
            unknown: list[str] = []
            differences: list[str] = []
            supporting_ids = {vnet_id} if vnet_id in entities else set()
            if consumer is None:
                unknown.append("Consumer VNet was not collected; scope/access/index evidence is insufficient.")
            elif cohort["stage"] != "excluded":
                if cohort["dnsMode"] != "unspecified":
                    if consumer["dnsMode"] == "UNKNOWN":
                        unknown.append("Configured VNet DNS defaults are unavailable or unsupported.")
                    elif cohort["dnsMode"] != consumer["dnsMode"]:
                        differences.append("Configured VNet DNS mode differs from declared mode.")
                for ruleset_id in sorted(text(value).lower() for value in array(cohort["requiredRulesetIds"])):
                    if ruleset_id in entities:
                        supporting_ids.add(ruleset_id)
                    ruleset = rulesets.get(ruleset_id)
                    if ruleset is None:
                        unknown.append("Declared ruleset is uncollected or outside resolver scope: " + ruleset_id)
                    elif obj(collected[ruleset_id]["properties"]).get("provisioningState") != "Succeeded" or collection_map["dns-rulesets"]["status"] != "succeeded" or (
                        consumer["linkCoverage"] == "UNKNOWN" or ruleset["linkCoverage"] == "UNKNOWN" or array(ruleset["unknownLinkTargetIds"])
                    ):
                        unknown.append("Declared ruleset/link collection is incomplete: " + ruleset_id)
                    elif ruleset_id not in array(consumer["rulesetsWithSucceededLinks"]):
                        differences.append("No succeeded link to the declared ruleset was observed in its accessible parent list: " + ruleset_id)
                for endpoint_id in sorted(text(value).lower() for value in array(cohort["requiredInboundEndpointIds"])):
                    endpoint = collected.get(endpoint_id)
                    if endpoint_id in entities:
                        supporting_ids.add(endpoint_id)
                    props = obj(endpoint["properties"]) if endpoint else {}
                    ips = props.get("inboundIpAddresses")
                    parent_id = endpoint_id.rsplit("/", 2)[0]
                    parent_pages = [page for page in records(collection_map["dns-inbound-endpoints"]["pages"])
                                    if text(page.get("parentResourceId", "")).lower() == parent_id]
                    parent_endpoint_count = sum(entity["resourceType"] == "microsoft.network/dnsresolvers/inboundendpoints"
                                                and key.rsplit("/", 2)[0] == parent_id for key, entity in collected.items())
                    complete_parent = bool(parent_pages) and all(page["resultTruncated"] is False for page in parent_pages) and (
                        parent_pages[-1].get("armHasContinuation", False) is False
                        and sum(integer(page["itemCount"]) for page in parent_pages) == parent_endpoint_count
                    )
                    usable_ips = isinstance(ips, list) and bool(ips)
                    for ip in ips if isinstance(ips, list) else []:
                        try:
                            ipaddress.ip_address(text(ip))
                        except ValueError:
                            usable_ips = False
                    if endpoint is None or collection_map["dns-inbound-endpoints"]["status"] != "succeeded" or (
                        not complete_parent or not usable_ips or props.get("ipConfigurationCount") != len(array(ips))
                        or props.get("provisioningState") != "Succeeded"
                    ):
                        unknown.append("Declared inbound endpoint/IP evidence is unavailable or incomplete: " + endpoint_id)
                    elif consumer["dnsMode"] == "UNKNOWN":
                        unknown.append("Configured DNS-server evidence is unavailable for inbound assignment.")
                    elif endpoint_id not in array(consumer["inboundEndpointCandidates"]):
                        differences.append("Configured VNet DNS servers do not match the declared inbound endpoint's selected IPs: " + endpoint_id)
            if newer and cohort["stage"] != "excluded":
                unknown.append("Intent was declared after the observation interval; collect evidence appropriate to this revision.")
            has_target = cohort["dnsMode"] != "unspecified" or bool(array(cohort["requiredRulesetIds"]) or array(cohort["requiredInboundEndpointIds"]))
            result = "excluded" if cohort["stage"] == "excluded" else "no-declared-target" if not has_target else "unknown-evidence" if unknown else (
                "configured-difference" if differences else "configured-match"
            )
            evidence_refs = {text(ref) for key in supporting_ids for ref in array(entities[key]["evidenceRefs"])}
            if consumer is not None:
                evidence_refs.update(text(ref) for ref in array(consumer["evidenceRefs"]))
            supporting_ids.update(key for key, entity in entities.items() if evidence_refs.intersection(
                text(ref) for ref in array(entity["evidenceRefs"])
            ))
            rows.append({
                "cohortId": cohort["cohortId"], "stage": cohort["stage"], "vnetId": vnet_id,
                "expectedDnsMode": cohort["dnsMode"],
                "requiredRulesetIds": sorted(text(value).lower() for value in array(cohort["requiredRulesetIds"])),
                "requiredInboundEndpointIds": sorted(text(value).lower() for value in array(cohort["requiredInboundEndpointIds"])),
                "observedDnsMode": consumer["dnsMode"] if consumer else "UNKNOWN",
                "result": result, "differences": differences, "evidenceGaps": unknown,
                "evidenceRefs": sorted(evidence_refs), "supportingEntityIds": sorted(supporting_ids),
            })
    return {
        "comparisonVersion": "1.0.0", "classification": "DECLARED",
        "intent": intent, "intentSha256": digest(intent), "hashScope": "canonical-supplied-intent-not-source-document",
        "provenanceVerification": "operator-supplied-not-independently-authenticated",
        "observationCompletedAt": obj(model["run"])["completedAt"],
        "timeAlignment": "intent-declared-after-observation" if newer else "intent-declared-no-later-than-observation",
        "actualClientUse": "UNKNOWN", "rows": rows,
        "limitations": [
            "Supplied customer intent is DECLARED, not observed fact or independently authenticated/current documentation.",
            "Only explicitly named consumers/targets are compared; undeclared VNets do not inherit requirements.",
            "Planned/in-progress differences can be intentional rollout stages; required-now differences need owner validation, not automatic remediation.",
            "Ruleset expectations mean configured succeeded links; inbound expectations mean configured DNS-IP matching only, not actual client use or endpoint health.",
            "Accessible configuration matches do not certify completeness, readiness, successful DNS resolution or migration completion.",
            "Out-of-scope/uncollected targets remain unknown and are never queried automatically. No deployable desired state is generated.",
        ],
    }


def provenance_time_review(model: Record, reference_at: str, dns_intent: Record | None = None) -> Record:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", reference_at):
        raise ValueError("Review reference time must be an explicit UTC timestamp")
    reference = datetime.fromisoformat(reference_at.replace("Z", "+00:00"))

    def timestamp(value: object) -> datetime:
        return datetime.fromisoformat(text(value).replace("Z", "+00:00"))

    def age(value: object) -> int | None:
        delta = reference - timestamp(value)
        microseconds = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        return microseconds if microseconds >= 0 else None

    collections = records(model["collections"])
    rows: list[Record] = []
    for collection in collections:
        start, end = collection["startedAt"], collection["completedAt"]
        issues: list[str] = []
        if timestamp(end) < timestamp(start):
            issues.append("Collection completion precedes its start.")
        if age(start) is None or age(end) is None:
            issues.append("Collection interval is after the supplied review time.")
        if collection["status"] != "succeeded":
            issues.append("Collection coverage is incomplete; reported time is not evidence of successful collection.")
        if not array(collection["pages"]):
            issues.append("No collection pages were retained; timestamps do not establish a performed read.")
        evidence_items = [item for item in records(model["evidence"]) if item["collectionId"] == collection["collectionId"]]
        mismatched = [text(item["evidenceId"]) for item in evidence_items if timestamp(item["collectedAt"]) !=
                      timestamp(evidence_time(collection, obj(item["excerpt"])["parentId"]))]
        if mismatched:
            issues.append("Evidence timestamps differ from their retained parent read completion." if
                          collection["operationId"] in SERVICE_ARM_PROFILES else
                          "Evidence timestamps differ from their collection completion.")
        rows.append({
            "collectionId": collection["collectionId"], "operationId": collection["operationId"],
            "subscriptionId": collection["requestedSubscriptionId"], "collectionStatus": collection["status"],
            "startedAt": start, "completedAt": end,
            "startAgeMicroseconds": age(start), "completionAgeMicroseconds": age(end),
            "ageInterpretation": "age-only-validity-unknown", "issues": issues,
            "evidenceRefs": sorted(text(item["evidenceId"]) for item in evidence_items),
        })
    run = obj(model["run"])
    run_issues: list[str] = []
    if timestamp(run["completedAt"]) < timestamp(run["startedAt"]):
        run_issues.append("Observation completion precedes its start.")
    if timestamp(run["startedAt"]) != min(timestamp(row["startedAt"]) for row in collections) or (
        timestamp(run["completedAt"]) != max(timestamp(row["completedAt"]) for row in collections)
    ):
        run_issues.append("Observation interval does not match the retained collection interval.")
    if age(run["startedAt"]) is None or age(run["completedAt"]) is None:
        run_issues.append("Observation interval is after the supplied review time.")
    intent_review = None
    if dns_intent is not None:
        validate_dns_intent(model, dns_intent)
        source = obj(dns_intent["source"])
        source_issues = ["Source identity/revision/owner/currentness are operator-supplied, not independently authenticated."]
        if age(source["declaredAt"]) is None or age(source["reviewedAt"]) is None:
            source_issues.append("Intent declaration or review timestamp is after the supplied review time.")
        if timestamp(source["declaredAt"]) > timestamp(run["completedAt"]):
            source_issues.append("Intent was declared after the observation interval; evidence may not address this revision.")
        intent_review = {
            "classification": "DECLARED", "intentSha256": digest(dns_intent), "source": source,
            "declarationAgeMicroseconds": age(source["declaredAt"]),
            "reviewAgeMicroseconds": age(source["reviewedAt"]), "validity": "UNKNOWN",
            "provenanceVerification": "operator-supplied-not-independently-authenticated",
            "issues": source_issues,
        }
    return {
        "reviewVersion": "1.0.0", "referenceAt": reference_at,
        "referenceSource": "operator-supplied-not-independently-authenticated",
        "policy": "age-and-provenance-only-no-expiry-thresholds", "validity": "UNKNOWN",
        "observationStartedAt": run["startedAt"], "observationCompletedAt": run["completedAt"],
        "observationStartAgeMicroseconds": age(run["startedAt"]),
        "observationCompletionAgeMicroseconds": age(run["completedAt"]),
        "observationIssues": run_issues, "collections": rows, "intent": intent_review,
        "limitations": [
            "Ages are measured relative to the explicit operator-supplied reference time, not the wall clock.",
            "No freshness threshold, stale/expired classification, intent-validity period or readiness policy was supplied or inferred.",
            "Collection times do not establish resource-change time, source clock accuracy, index freshness or continuing configuration validity.",
            "Intent declaration/review dates do not authenticate the document, owner, revision, approval or currentness.",
            "Future timestamps and inconsistent intervals are chronology gaps; negative ages are not silently clamped.",
            "Reopening an immutable report does not update ages, refresh evidence, authorize acquisition or overwrite artifacts.",
        ],
    }


def service_access_review(model: Record) -> Record:
    if obj(model["run"])["queryCatalogVersion"] not in ("1.6.0", "1.7.0", "1.8.0"):
        raise ValueError("Service access review requires the opt-in acquisition catalog")
    collections = records(model["collections"])
    inventory = next(c for c in collections if c["operationId"] == "private-link-services")
    connection_inventory = next(c for c in collections if c["operationId"] == "private-endpoint-connections")
    service_ids = {text(ev["subjectId"]) for ev in records(model["evidence"])
                   if ev["collectionId"] == inventory["collectionId"]}
    entities = unique_index(records(model["entities"]), "entityId")
    connections = [entity for entity in entities.values() if (
        entity["collectionState"] == "collected"
        and entity["resourceType"] == "microsoft.network/privateendpoints/privatelinkserviceconnections"
    )]
    rows: list[Record] = []
    for service_id in sorted(service_ids):
        service = entities[service_id]
        supported = service["resourceType"] in SERVICE_ACCESS_TYPES
        props = obj(service["properties"])
        pna = props.get("publicNetworkAccess")
        default = props.get("firewallDefaultAction")
        state = "unsupported-family"
        gaps: list[str] = []
        if supported:
            state = "unknown-setting"
            if isinstance(pna, str):
                if pna.casefold() == "disabled":
                    state = "disabled-configured"
                elif pna.casefold() == "enabled":
                    state = {"allow": "enabled-firewall-allow", "deny": "enabled-firewall-deny"}.get(
                        default.casefold() if isinstance(default, str) else "", "enabled-firewall-unknown")
                elif pna.casefold() == "securedbyperimeter" and service["resourceType"] != "microsoft.containerregistry/registries":
                    state = "perimeter-mode-unverified"
            if state == "unknown-setting":
                gaps.append("PublicNetworkAccessUnavailableOrUnrecognized")
            if state == "enabled-firewall-unknown":
                gaps.append("FirewallDefaultActionUnavailableOrUnrecognized")
            bypass = props.get("trustedServiceBypass")
            allowed_bypasses = {"none", "azureservices", "logging", "metrics"} if service["resourceType"] == "microsoft.storage/storageaccounts" else {"none", "azureservices"}
            bypass_values = {value.strip().casefold() for value in bypass.split(",")} if isinstance(bypass, str) else set()
            if not bypass_values or not bypass_values <= allowed_bypasses:
                gaps.append("TrustedServiceBypassUnavailableOrUnrecognized")
            if state.startswith("enabled-"):
                for field in ("ipRuleCount", "virtualNetworkRuleCount"):
                    if props.get(field) is None:
                        gaps.append(field + "Unavailable")
                if service["resourceType"] == "microsoft.storage/storageaccounts" and props.get("resourceAccessRuleCount") is None:
                    gaps.append("resourceAccessRuleCountUnavailable")
            if state == "perimeter-mode-unverified":
                gaps.append("PerimeterAssociationProfileRulesAndEnforcementNotCollected")
        else:
            gaps.append("ServiceFamilyNotAssessed")
        matching = [connection for connection in connections if
                    isinstance(obj(connection["properties"]).get("privateLinkServiceId"), str)
                    and text(obj(connection["properties"])["privateLinkServiceId"]).lower() == service_id]
        approved = [connection for connection in matching if
                    isinstance(obj(connection["properties"]).get("connectionStatus"), str)
                    and text(obj(connection["properties"])["connectionStatus"]).casefold() == "approved"]
        groups: set[str] = set()
        for connection in approved:
            group_ids = obj(connection["properties"]).get("groupIds")
            if not isinstance(group_ids, list) or not group_ids or any(
                not isinstance(value, str) or not value for value in group_ids
            ):
                gaps.append("ApprovedConnectionGroupIdsUnavailable")
            else:
                groups.update(text(value) for value in group_ids)
        if inventory["status"] != "succeeded":
            gaps.append("ServiceInventoryPartial")
        if connection_inventory["status"] != "succeeded":
            gaps.append("PrivateEndpointConnectionInventoryPartial")
        rows.append({
            "serviceId": service_id, "resourceType": service["resourceType"],
            "supported": supported, "configurationState": state,
            "properties": props, "connectionIds": sorted(text(c["entityId"]) for c in matching),
            "approvedConnectionIds": sorted(text(c["entityId"]) for c in approved),
            "approvedGroupIds": sorted(groups), "actualReachability": "UNKNOWN",
            "exceptionApproval": "not-assessed",
            "evidenceRefs": sorted({text(ref) for entity in [service, *matching]
                                    for ref in array(entity["evidenceRefs"])}),
            "evidenceGaps": sorted(set(gaps)),
        })
    return {
        "reviewVersion": "1.0.0", "supportedResourceTypes": list(SERVICE_ACCESS_TYPES),
        "serviceInventoryStatus": inventory["status"],
        "connectionInventoryStatus": connection_inventory["status"],
        "collectionRefs": sorted([text(inventory["collectionId"]), text(connection_inventory["collectionId"])]),
        "rows": rows,
        "limitations": [
            "Public network settings are observed configuration; the private-preferred baseline is DECLARED, not an approved customer policy or compliance certificate.",
            "Enabled with Allow requests owner review, not proof of anonymous access, exploitation or actual public reachability; data-plane authorization remains unassessed.",
            "Enabled with Deny retains a public endpoint with selected-network controls; rule counts omit rule values, identities, ranges and actual enforcement.",
            "Disabled is a configured setting, not certified private-only access: trusted-service bypass and service-specific exceptions can remain relevant, including Key Vault and ACR.",
            "SecuredByPerimeter is only a configured mode; association, profile, access rules, transition mode and actual enforcement were not collected or accepted as an exception.",
            "Approved PE group IDs are scoped configuration, not all required subresources, DNS resolution, client use, traffic or complete endpoint coverage.",
            "Missing fields never inherit documented defaults. No observed connection is not proof of no endpoint elsewhere or of a missing required endpoint.",
            "Only Storage Accounts, Key Vault vaults and Container Registries are assessed; Monitor, Log Analytics and other mapped families remain explicitly unassessed.",
            "Successful Resource Graph collection is accessible indexed evidence only; permission-wide completeness, freshness and continuing validity are UNKNOWN.",
        ],
    }


def service_control_reconciliation(model: Record) -> Record:
    if obj(model["run"])["queryCatalogVersion"] not in ("1.7.0", "1.8.0"):
        raise ValueError("Service source reconciliation requires direct ARM acquisition")
    access = service_access_review(model)
    collections = records(model["collections"])
    inventory = next(c for c in collections if c["operationId"] == "private-link-services")
    entities = unique_index(records(model["entities"]), "entityId")
    direct = {text(entity["entityId"]).rsplit("/observedarmserviceaccess/", 1)[0]: entity
              for entity in entities.values() if entity["resourceType"] == "service-arm-access-settings"
              and entity["collectionState"] == "configurationObject"}
    rows: list[Record] = []
    for service in records(access["rows"]):
        if not service["supported"]:
            continue
        service_id = text(service["serviceId"])
        entity = entities[service_id]
        direct_entity = direct.get(service_id)
        operation_id = next(key for key, profile in SERVICE_ARM_PROFILES.items() if profile[0] == service["resourceType"])
        collection = next(c for c in collections if c["operationId"] == operation_id)
        page = next((p for p in records(collection["pages"]) if text(p["parentResourceId"]).lower() == service_id), None)
        direct_props = obj(direct_entity["properties"]) if direct_entity is not None else {}
        fields: list[Record] = []
        gaps: list[str] = []
        for field in SERVICE_ACCESS_FIELDS:
            indexed_value, direct_value = obj(entity["properties"]).get(field), direct_props.get(field)
            if field == "resourceAccessRuleCount" and service["resourceType"] != SERVICE_ACCESS_TYPES[0]:
                result = "not-applicable"
            elif direct_entity is None:
                result = "direct-not-collected"
            elif indexed_value is None and direct_value is None:
                result = "both-unavailable"
            elif indexed_value is None:
                result = "indexed-unavailable"
            elif direct_value is None:
                result = "direct-unavailable"
            else:
                result = "observed-match" if indexed_value == direct_value else "different-observed-values"
            if result not in ("observed-match", "not-applicable"):
                gaps.append(field + ":" + result)
            fields.append({"field": field, "indexedValue": indexed_value, "directValue": direct_value, "result": result})
        if inventory["status"] != "succeeded":
            gaps.append("IndexedServiceInventoryIncomplete")
        if collection["status"] != "succeeded":
            gaps.append("DirectServiceCollectionIncomplete")
        rows.append({
            "serviceId": service_id, "resourceType": service["resourceType"],
            "indexedSource": {"collectionId": inventory["collectionId"],
                              "collectedAt": inventory["completedAt"], "evidenceRefs": entity["evidenceRefs"]},
            "directSource": {
                "collectionId": collection["collectionId"], "apiVersion": collection["apiVersion"],
                "readStatus": page["readStatus"] if page is not None else "notAttempted",
                "readError": page["readError"] if page is not None else "DirectParentReadNotAttempted",
                "collectedAt": page["completedAt"] if page is not None else None,
                "entityId": direct_entity["entityId"] if direct_entity is not None else None,
                "evidenceRefs": direct_entity["evidenceRefs"] if direct_entity is not None else [],
            },
            "fields": fields, "actualReachability": "UNKNOWN", "evidenceGaps": sorted(set(gaps)),
        })
    return {
        "reviewVersion": "1.0.0",
        "collectionRefs": sorted(text(c["collectionId"]) for c in collections
                                 if c["operationId"] == "private-link-services" or c["operationId"] in SERVICE_ARM_PROFILES),
        "unsupportedServiceIds": sorted(text(row["serviceId"]) for row in records(access["rows"]) if not row["supported"]),
        "rows": rows,
        "limitations": [
            "Indexed and direct management GET values remain separate source observations; neither source is desired state or an automatically preferred truth.",
            "Observed-match requires two non-null values. Unavailable fields, failed/not-attempted reads and non-applicable fields never become matching zeros or proof of absent controls.",
            "Different observed values can reflect collection times, index freshness, API shape or changed configuration; they are not automatically defects or remediation instructions.",
            "Direct GETs use explicit stable API versions and only inventoried same-workload parents; each family is bounded to 100 parent reads. No external references or extra DNS-host service scope is followed.",
            "Selected rule counts omit rule values and authorization/enforcement semantics. Legacy ACR fields unavailable in the chosen API remain unavailable, even if the index reports zero.",
            "The indexed-only service access review is retained without overwriting its baseline comparison; review this source reconciliation alongside it, especially before relying on an apparent difference.",
            "Source collection/read completion times are not resource-change times or continuing-validity certification. Permission-wide inventory completeness and client DNS/traffic/reachability remain UNKNOWN.",
            "NSP/AMPLS enforcement and approved public-access exceptions remain unassessed; resource configuration, source agreement and PE approval do not certify private-only access.",
        ],
    }


def nsp_configuration_review(model: Record) -> Record:
    if obj(model["run"])["queryCatalogVersion"] != "1.8.0":
        raise ValueError("NSP review requires explicitly selected NSP acquisition")
    collections = {text(c["operationId"]): c for c in records(model["collections"]) if c["operationId"] in NSP_FIELDS}
    entities = unique_index(records(model["entities"]), "entityId")
    types = {text(op["operationId"]): text(op["entityType"]) for op in nsp_operations()}
    collected = {key: [e for e in entities.values() if e["resourceType"] == resource_type
                      and e["collectionState"] == "collected"] for key, resource_type in types.items()}
    workload = text(array(obj(model["scope"])["requestedSubscriptionIds"])[0])
    rows: list[Record] = []
    for association in collected["nsp-associations"]:
        props = obj(association["properties"])
        parent_id = text(association["entityId"]).rsplit("/resourceassociations/", 1)[0]
        profile_id = props.get("profileId")
        target_id = props.get("privateLinkResourceId")
        profile = entities.get(profile_id.lower()) if isinstance(profile_id, str) else None
        valid_profile = (
            isinstance(profile_id, str) and profile_id.lower().startswith(parent_id + "/profiles/")
            and profile is not None and profile["resourceType"] == types["nsp-profiles"]
            and profile["collectionState"] == "collected"
        )
        rules = [e for e in collected["nsp-rules"] if valid_profile and
                 text(e["entityId"]).rsplit("/accessrules/", 1)[0] == text(profile["entityId"])]
        rule_pages = [page for page in records(collections["nsp-rules"]["pages"]) if
                      isinstance(profile_id, str) and text(page["parentResourceId"]).lower() == profile_id.lower()]
        rule_coverage = "selected-metadata-collected" if valid_profile and (
            collections["nsp-rules"]["status"] == "succeeded" and rule_pages
            and rule_pages[-1].get("armHasContinuation") is False
            and all(page["resultTruncated"] is False for page in rule_pages)
        ) else "unknown-or-partial"
        mode = props.get("accessMode")
        mode_key = mode.casefold() if isinstance(mode, str) else ""
        state = {
            "enforced": "enforced-configured-unverified",
            "learning": "transition-configured-unverified", "transition": "transition-configured-unverified",
            "audit": "audit-configured-unverified",
        }.get(mode_key, "unknown-configured-mode")
        gaps: list[str] = []
        if state == "unknown-configured-mode":
            gaps.append("AssociationAccessModeUnavailableOrUnrecognized")
        if props.get("provisioningState") != "Succeeded":
            gaps.append("AssociationProvisioningNotConfirmedSucceeded")
        issue_flag = props.get("hasProvisioningIssues")
        if issue_flag is True or isinstance(issue_flag, str) and issue_flag.casefold() in ("yes", "true"):
            gaps.append("AssociationReportsProvisioningIssues")
        elif issue_flag is not False and (not isinstance(issue_flag, str) or issue_flag.casefold() not in ("no", "false")):
            gaps.append("AssociationProvisioningIssueFlagUnavailableOrUnrecognized")
        if not isinstance(target_id, str) or not RESOURCE_PATTERN.match(target_id):
            gaps.append("AssociationTargetResourceIdUnavailableOrInvalid")
        if not valid_profile:
            gaps.append("AssociationProfileNotCollectedWithinItsPerimeter")
        elif obj(profile["properties"]).get("provisioningState") != "Succeeded":
            gaps.append("ProfileProvisioningNotConfirmedSucceeded")
        if rule_coverage != "selected-metadata-collected":
            gaps.append("ProfileRuleMetadataCoverageUnknownOrPartial")
        for rule in rules:
            rule_props = obj(rule["properties"])
            if rule_props.get("direction") not in ("Inbound", "Outbound"):
                gaps.append("RuleDirectionUnavailableOrUnrecognized")
            if rule_props.get("provisioningState") != "Succeeded":
                gaps.append("RuleProvisioningNotConfirmedSucceeded")
            if any(rule_props.get(field) is None for field in NSP_SELECTOR_FIELDS):
                gaps.append("RuleSelectorCountsUnavailable")
        if any(collections[key]["status"] != "succeeded" for key in ("nsp-perimeters", "nsp-profiles", "nsp-associations")):
            gaps.append("PerimeterDiscoveryOrAssociationCoveragePartial")
        supporting = [association, *([profile] if valid_profile else []), *rules]
        target = entities.get(target_id.lower()) if isinstance(target_id, str) else None
        rows.append({
            "associationId": association["entityId"], "perimeterId": parent_id,
            "targetResourceId": target_id, "profileId": profile_id,
            "targetScope": "same-workload-reference" if isinstance(target_id, str) and target_id.lower().startswith(
                "/subscriptions/" + workload + "/") else "external-or-unknown-reference",
            "targetCollectionState": target["collectionState"] if target else "not-collected",
            "configuredAccessMode": mode, "configurationState": state,
            "associationProperties": props, "ruleMetadataCoverage": rule_coverage,
            "ruleIds": sorted(text(rule["entityId"]) for rule in rules),
            "retainedInboundRuleCount": sum(obj(rule["properties"]).get("direction") == "Inbound" for rule in rules),
            "retainedOutboundRuleCount": sum(obj(rule["properties"]).get("direction") == "Outbound" for rule in rules),
            "effectiveEnforcement": "UNKNOWN", "exceptionApproval": "not-assessed",
            "evidenceGaps": sorted(set(gaps)),
            "evidenceRefs": sorted({text(ref) for entity in supporting for ref in array(entity["evidenceRefs"])}),
        })
    associated = {text(row["targetResourceId"]).lower() for row in rows if isinstance(row["targetResourceId"], str)}
    candidates: list[Record] = []
    source = service_control_reconciliation(model)
    for service in records(source["rows"]):
        field = next(field for field in records(service["fields"]) if field["field"] == "publicNetworkAccess")
        if any(isinstance(value, str) and value.casefold() == "securedbyperimeter"
               for value in (field["indexedValue"], field["directValue"])) and service["serviceId"] not in associated:
            candidates.append({"serviceId": service["serviceId"],
                               "status": "association-not-observed-in-collected-perimeter-scope",
                               "evidenceRefs": entities[text(service["serviceId"])]["evidenceRefs"]})
    return {
        "reviewVersion": "1.0.0", "apiVersion": "2024-07-01",
        "collectionRefs": sorted(text(c["collectionId"]) for c in collections.values()),
        "collectionStatuses": {key: collection["status"] for key, collection in sorted(collections.items())},
        "perimeters": [{"entityId": e["entityId"], "properties": e["properties"], "evidenceRefs": e["evidenceRefs"]}
                       for e in collected["nsp-perimeters"]],
        "profiles": [{"entityId": e["entityId"], "properties": e["properties"], "evidenceRefs": e["evidenceRefs"]}
                     for e in collected["nsp-profiles"]],
        "ruleMetadata": [{"entityId": e["entityId"], "properties": e["properties"], "evidenceRefs": e["evidenceRefs"]}
                         for e in collected["nsp-rules"]],
        "associationRows": rows, "perimeterModeWithoutObservedAssociation": candidates,
        "limitations": [
            "Enforced is configured access mode, not demonstrated effective enforcement, service configuration synchronization or a private-only certificate.",
            "Learning/Transition and Audit remain separate raw configured modes; no readiness score, automatic mode switch or accepted exception is inferred.",
            "Only selected workload perimeters and their collected children are listed. Cross-subscription/profile/target references are never followed; no scoped rows does not prove no perimeter elsewhere.",
            "Rule metadata retains direction, provisioning and selector counts only. CIDRs, FQDNs, subscriptions, tags, email/phone values and rule semantics are omitted; counts do not establish effective access or rule safety.",
            "Unknown, failed, truncated or budget-limited profile/rule/association coverage is not resource absence or a successful enforcement test.",
            "No access tests, diagnostics/log enablement, resource mutations or automatic public-access exception acceptance occur.",
            "AMPLS and service-side perimeter configuration synchronization, client DNS/traffic, permission-wide visibility and customer exception approval remain unassessed.",
            "Azure Monitor workspace is not Log Analytics workspace; an association/reference or a generic Monitor label does not establish supported integration or an accepted alternative control.",
        ],
    }


def prioritize_findings(findings: list[Record]) -> None:
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "INFO": 3}
    findings.sort(key=lambda item: (
        priority_order[text(obj(item["priority"])["band"])], text(item["checkId"]), text(item["findingId"]),
    ))
    for rank, item in enumerate(findings, 1):
        obj(item["priority"])["rank"] = rank


def assess(model: Record, dns_intent: Record | None = None, review_at: str | None = None) -> Record:
    from first_pass import BASELINE
    validate_document(model, HERE / "observed-network.schema.json")
    verify_observation(model)
    configuration = load(HERE / "checks.json")
    access_check = next(check for check in records(configuration["checks"]) if check["checkId"] == "NET-SERVICE-ACCESS-001")
    source_check = next(check for check in records(configuration["checks"]) if check["checkId"] == "NET-SERVICE-SOURCE-001")
    nsp_check = next(check for check in records(configuration["checks"]) if check["checkId"] == "NET-NSP-001")
    configuration = {**configuration, "checks": [
        check for check in records(configuration["checks"]) if check["checkId"] not in ("NET-SERVICE-ACCESS-001", "NET-SERVICE-SOURCE-001", "NET-NSP-001")
    ]}
    time_check = next(check for check in records(configuration["checks"]) if check["checkId"] == "NET-EVID-TIME-001")
    configuration = {**configuration, "catalogVersion": "1.8.0",
                     "checks": [check for check in records(configuration["checks"]) if check["checkId"] != "NET-EVID-TIME-001"]}
    if dns_intent is None:
        configuration = {**configuration, "catalogVersion": "1.7.0",
                         "checks": [check for check in records(configuration["checks"]) if check["checkId"] != "NET-DNS-INTENT-001"]}
    else:
        validate_dns_intent(model, dns_intent)
    nsp_mode = obj(model["run"])["queryCatalogVersion"] == "1.8.0"
    arm_mode = nsp_mode or obj(model["run"])["queryCatalogVersion"] == "1.7.0"
    access_mode = arm_mode or obj(model["run"])["queryCatalogVersion"] == "1.6.0"
    paths_mode = obj(model["run"])["queryCatalogVersion"] in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0")
    metadata_mode = paths_mode or obj(model["run"])["queryCatalogVersion"] == "1.3.0"
    planning = metadata_mode or obj(model["run"])["queryCatalogVersion"] == "1.2.0"
    enriched = planning or obj(model["run"])["queryCatalogVersion"] == "1.1.0"
    if not paths_mode:
        configuration = {**configuration, "catalogVersion": "1.5.0",
                         "checks": [check for check in records(configuration["checks"]) if check["checkId"] not in ("NET-DNS-PATH-001", "NET-DNS-ADOPT-001")]}
    if planning and not metadata_mode:
        configuration = {
            **configuration, "catalogVersion": "1.4.0",
            "checks": [check for check in records(configuration["checks"]) if check["checkId"] != "NET-DNS-META-001"],
        }
    elif not planning:
        configuration = {
            **configuration, "catalogVersion": "1.3.0" if enriched else "1.2.0",
            "checks": [check for check in records(configuration["checks"]) if check["checkId"] in LEGACY_CHECK_VERSIONS
                       or enriched and check["checkId"] in ("NET-PRIVATE-001", "NET-PRIVATE-DNS-001")],
        }
    if review_at is not None:
        configuration = {**configuration, "catalogVersion": "1.9.0", "checks": [*records(configuration["checks"]), time_check]}
    if access_mode:
        configuration = {**configuration, "catalogVersion": "1.10.0", "checks": [*records(configuration["checks"]), access_check]}
    if arm_mode:
        configuration = {**configuration, "catalogVersion": "1.11.0", "checks": [*records(configuration["checks"]), source_check]}
    if nsp_mode:
        configuration = {**configuration, "catalogVersion": "1.12.0", "checks": [*records(configuration["checks"]), nsp_check]}
    checks = {text(c["checkId"]): c for c in records(configuration["checks"])}
    entities = records(model["entities"])
    findings: list[Record] = []

    def finding(
        check_id: str, affected: list[Record], title: str, observed: str, reasoning: str,
        risk: str, recommendation: str, *,
        record_type: str = "architectureObservation", severity: str | None = None,
        band: str = "INFO", action: str = "contextValidation",
        confidence: str = "high", gaps: list[str] | None = None,
        collection_refs: list[str] | None = None, deep_dive: str | None = None,
        expected_state: str | None = None,
        supporting: list[Record] | None = None, priority_context: str | None = None,
    ) -> None:
        check = checks[check_id]
        affected_ids = sorted({text(e["entityId"]) for e in affected})
        next_action_reason = {
            "evidenceCollection": "Collect missing evidence before drawing conclusions or planning remediation.",
            "contextValidation": "Validate customer intent and affected scope before considering remediation.",
            "remediationPlanning": "Plan remediation only after verified evidence and dependency review.",
            "none": "Informational record; no action inferred.",
        }[action]
        findings.append({
            "findingId": stable("NET", check_id, affected_ids, title),
            "checkId": check_id, "checkVersion": check["checkVersion"],
            "title": title, "category": check["category"], "recordType": record_type,
            "interpretationClassification": "UNKNOWN" if record_type == "evidenceGap"
            else "INFERRED" if record_type in ("potentialRisk", "contextValidation", "positiveObservation") else "OBSERVED",
            "severity": severity,
            "priority": {
                "rank": 1, "band": band, "actionType": action,
                "reason": (
                    f"{priority_context + ' ' if priority_context else ''}{next_action_reason} Impact={severity or 'not established'}; "
                    f"affected resources={len(affected_ids)}; evidence confidence={confidence}; "
                    "urgency not established; customer context/access dependencies apply."
                ),
            },
            "affectedResources": affected_ids,
            "observedState": observed, "expectedState": expected_state, "reasoning": reasoning,
            "risk": risk, "recommendation": recommendation,
            "dependencies": ["Customer connectivity intent and authorized evidence access"],
            "confidence": confidence, "evidenceGaps": gaps or [],
            "recommendedDeepDive": {
                "domain": text(check["category"]), "question": deep_dive,
                "requiredEvidence": gaps or ["Relevant connectivity intent and effective behavior"],
                "execution": "recommendationOnly",
            } if deep_dive else None,
            "evidenceRefs": sorted({text(ref) for e in [*affected, *(supporting or [])] for ref in array(e["evidenceRefs"])}),
            "collectionRefs": collection_refs or [],
            "guidanceReferences": check["references"],
        })

    vnets = [e for e in entities if e["resourceType"] == "microsoft.network/virtualnetworks"]
    prefixes: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    for vnet in vnets:
        values = obj(vnet["properties"]).get("addressPrefixes")
        if not isinstance(values, list) or not values:
            finding("NET-ADDR-001", [vnet], "VNet address-space evidence unavailable",
                    "No usable address-prefix list was collected.", "Missing evidence is not an empty address space.",
                    "Overlap cannot be evaluated.", "Collect the missing address-space configuration.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low")
            continue
        try:
            prefixes[text(vnet["entityId"])] = [ipaddress.ip_network(text(v), strict=True) for v in values]
        except ValueError:
            finding("NET-ADDR-001", [vnet], "VNet prefix could not be evaluated",
                    "A collected prefix is unsupported or non-canonical.", "The original property is retained unchanged.",
                    "Overlap evaluation is incomplete.", "Verify the prefix against a direct Azure read.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low")
    vnet_ids = {text(vnet["entityId"]) for vnet in vnets}
    relationships = records(model["relationships"])
    peering_entities = {
        text(entity["entityId"]): entity for entity in entities
        if entity["resourceType"] == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
        and entity["collectionState"] == "collected"
    }
    peering_parents = {
        text(rel["targetId"]): text(rel["sourceId"]) for rel in relationships
        if rel["relationshipType"] == "contains" and rel["classification"] == "OBSERVED"
        and rel["sourceId"] in vnet_ids and rel["targetId"] in peering_entities
    }
    peering_pairs: dict[tuple[str, str], list[Record]] = {}
    for rel in relationships:
        if (
            rel["relationshipType"] == "peeringTo" and rel["classification"] == "OBSERVED"
            and rel["sourceId"] in peering_parents and rel["targetId"] in vnet_ids
        ):
            first_id, second_id = peering_parents[text(rel["sourceId"])], text(rel["targetId"])
            if first_id != second_id:
                pair = tuple(sorted((first_id, second_id)))
                peering_pairs.setdefault(pair, []).append(peering_entities[text(rel["sourceId"])])
    overlap_ids: set[str] = set()
    for index, first in enumerate(vnets):
        for second in vnets[index + 1:]:
            overlaps = sorted({
                str(a) + " overlaps " + str(b)
                for a in prefixes.get(text(first["entityId"]), [])
                for b in prefixes.get(text(second["entityId"]), [])
                if a.version == b.version and a.overlaps(b)
            })
            if overlaps:
                pair = tuple(sorted((text(first["entityId"]), text(second["entityId"]))))
                overlap_ids.update(pair)
                peerings = peering_pairs.get(pair, [])
                finding("NET-ADDR-001", [first, second], "Overlapping VNet address spaces",
                        "; ".join(overlaps) + (
                            f"; {len(peerings)} collected peering reference(s) link this pair." if peerings else ""
                        ),
                        "Overlap is verified in retained configuration; connectivity intent, peering mode and effective behavior are unknown.",
                        "Overlap can constrain future peering or hybrid routing, but disconnected networks may intentionally overlap.",
                        (
                            "Collect direct peering mode, selected-subnet/IPv6-only settings and reciprocal configuration; "
                            "confirm whether this link is required before proposing address changes."
                            if peerings else
                            "Validate whether these networks need direct or shared connectivity before considering address changes."
                        ),
                        record_type="potentialRisk", severity="medium", band="P1" if peerings else "P2",
                        action="evidenceCollection" if peerings else "contextValidation",
                        supporting=peerings,
                        priority_context=(
                            "Configured peering makes the overlap relevant to a retained link; prioritize applicability evidence, "
                            "not remediation or an outage claim." if peerings else None
                        ),
                        gaps=["Peering mode/subnet selection/IPv6-only settings", "Connectivity intent", "Reciprocal/effective behavior"] if peerings else [],
                        deep_dive="Do these overlapping networks require connectivity, and does the configured peering mode use the overlapping ranges?")
    vnet_collection = next(c for c in records(model["collections"]) if c["operationId"] == "vnets")
    disjoint = [vnet for vnet in vnets if text(vnet["entityId"]) not in overlap_ids]
    if len(vnets) >= 2 and len(prefixes) == len(vnets) and vnet_collection["status"] == "succeeded" and disjoint:
        finding(
            "NET-ADDR-001", disjoint, "Collected VNet address spaces have no detected overlap with other collected VNets",
            f"{len(disjoint)} of {len(vnets)} collected VNets have valid ranges disjoint from every other collected VNet.",
            "This is a deterministic comparison of retained configuration, not permission-wide visibility or connectivity/health proof.",
            "No overlap-based change is inferred for this collected subset; uncollected scope and future connectivity remain unverified.",
            "Preserve the scoped address-planning evidence and validate future additions against the authorized environment.",
            record_type="positiveObservation", band="INFO", action="none", supporting=vnets,
            collection_refs=[text(vnet_collection["collectionId"])],
            gaps=["Accessible indexed configuration only", "Permission-wide completeness", "Effective behavior/traffic"],
        )
    peering_collection = next(c for c in records(model["collections"]) if c["operationId"] == "peerings")
    peering_targets = {
        text(rel["sourceId"]): text(rel["targetId"]) for rel in relationships
        if rel["relationshipType"] == "peeringTo" and rel["classification"] == "OBSERVED"
        and rel["sourceId"] in peering_entities and rel["targetId"] is not None
    }
    peering_groups: dict[tuple[str, str], list[Record]] = {}
    for peering_id, entity in peering_entities.items():
        parent, target = peering_parents.get(peering_id), peering_targets.get(peering_id)
        pair = tuple(sorted((parent, target))) if (
            parent in vnet_ids and target in vnet_ids and parent != target
        ) else ("unresolved", peering_id)
        peering_groups.setdefault(pair, []).append(entity)
    for pair, group in sorted(peering_groups.items()):
        group = sorted(group, key=lambda entity: text(entity["entityId"]))
        observed = "; ".join(
            f"{entity['entityId']}: peeringState={obj(entity['properties']).get('peeringState')}; "
            f"provisioningState={obj(entity['properties']).get('provisioningState')}"
            for entity in group
        )
        states = [obj(entity["properties"]).get("peeringState") for entity in group]
        provisioning = [obj(entity["properties"]).get("provisioningState") for entity in group]
        refs = [text(peering_collection["collectionId"])]
        paired = len(group) == 2 and {peering_parents.get(text(entity["entityId"])) for entity in group} == set(pair)
        unknown = any(state not in ("Connected", "Initiated", "Disconnected", "Failed", "Updating") for state in states) or any(
            state not in ("Succeeded", "Failed", "Updating", "Creating", "Deleting") for state in provisioning
        )
        if "Disconnected" in states or "Failed" in states or "Failed" in provisioning:
            finding(
                "NET-PEER-001", group, "Peering reports failed or disconnected state", observed,
                "Retained directional configuration reports this state; intent, decommissioning and application impact are unverified.",
                "Required connectivity could be affected; no outage or traffic failure is demonstrated.",
                "Confirm whether the link is required, then validate both directions and peering mode through authorized direct evidence.",
                record_type="contextValidation", severity="medium", band="P2",
                collection_refs=refs, gaps=["Connectivity intent", "Peering mode/effective behavior"] + (
                    ["Some directional state evidence is unavailable or unsupported"] if unknown else []
                ), deep_dive="Is the link intended to be active, and what do both directions and the peering mode report?",
            )
        elif unknown:
            finding(
                "NET-PEER-001", group, "Peering state evidence is unavailable or unsupported", observed,
                "Null or future state values are not proof of a failed or connected peering.",
                "Directional state interpretation is incomplete.",
                "Collect current direct directional state and provider documentation before drawing a conclusion.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=refs, gaps=["Directional peering/provisioning states"],
            )
        elif "Initiated" in states or "Updating" in states or any(state != "Succeeded" for state in provisioning):
            finding(
                "NET-PEER-001", group, "Peering initiation or transition needs connectivity context", observed,
                "Initiated indicates the first directional configuration; transition states may be temporary or intentional.",
                "Required connectivity is not established by these configuration states; no persistent failure is demonstrated.",
                "Validate expected timing and both directions; collect later direct state only when authorized and needed.",
                record_type="contextValidation", band="P2", collection_refs=refs,
                gaps=["Expected timing/connectivity intent", "Reciprocal/effective behavior"],
                deep_dive="Is this a planned transition, and what does the reciprocal configuration report?",
            )
        elif paired and peering_collection["status"] == "succeeded":
            finding(
                "NET-PEER-001", group, "Reciprocal peering directions report Connected configuration", observed,
                "Two unique retained directions report Connected and provisioning Succeeded; this is configuration state only.",
                "No defect, reachable traffic path or overall-health conclusion follows from these states.",
                "Preserve directional evidence; use a scoped effective-route/traffic assessment only if operational validation is required.",
                record_type="architectureObservation", band="INFO", action="none", collection_refs=refs,
                gaps=["Access/NSG/route applicability", "Selective/IPv6 peering mode", "Effective traffic behavior"],
            )
        if pair[0] == "unresolved":
            title = "Reciprocal peering evidence is outside collected VNet context"
            reason = "The retained source/target is unknown, reference-only, self-referential or outside collected VNet scope."
        elif len(group) == 1:
            title = "Reciprocal peering was not observed in collected configuration"
            reason = "The accessible indexed result contains only one retained direction; this is not proof that the reverse is absent."
        elif not paired:
            title = "Reciprocal peering configuration is ambiguous"
            reason = "Retained directions do not form one unique pair; no arbitrary reciprocal is selected."
        elif peering_collection["status"] != "succeeded":
            title = "Reciprocal peering collection evidence is incomplete"
            reason = "Both directions are retained, but collection failures/conflicts/partiality prevent a complete reciprocity conclusion."
        else:
            continue
        finding(
            "NET-PEER-001", group, title, observed, reason,
            "Reciprocity and intended connectivity cannot be fully established from this collected evidence.",
            "Validate the required reciprocal direction with authorized direct evidence; do not expand scope or recreate peering automatically.",
            record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
            collection_refs=refs, supporting=list(peering_entities.values()) if pair[0] != "unresolved" else [],
            gaps=["Reciprocal configuration/authorized scope", "Connectivity intent", "Peering mode/effective behavior"],
            deep_dive="What reciprocal configuration is required, and can authorized evidence establish it?",
        )
    for entity in entities:
        props = obj(entity["properties"])
        resource_type = entity["resourceType"]
        if resource_type == "microsoft.network/virtualnetworks/subnets":
            if props.get("networkSecurityGroupKnown") is True and not props.get("networkSecurityGroupId"):
                finding("NET-NSG-001", [entity], "Subnet has no configured subnet NSG association",
                        "The collected association property explicitly has no target.",
                        "Subnet-level association absence does not establish absent NIC-level controls or public reachability.",
                        "Segmentation intent requires context; service-specific exceptions may be valid.",
                        "Validate subnet purpose and other controls before recommending changes.",
                        deep_dive="What controls are appropriate for this subnet's purpose?")
            if props.get("routeTableKnown") is True and props.get("routeTableId"):
                finding("NET-ROUTE-001", [entity], "Subnet has a configured route-table association",
                        "Configured route-table reference: " + text(props["routeTableId"]),
                        "Association is configuration, not an effective-route or traffic-path observation.",
                        "No defect or healthy egress conclusion follows from association alone.",
                        "Use a targeted effective-route assessment if the intended path needs validation.",
                        deep_dive="Does the configured route table produce the required effective route?")
        elif resource_type == "microsoft.network/routetables/routes":
            kind, address = props.get("nextHopType"), props.get("nextHopIpAddress")
            allowed = {"VirtualAppliance", "VirtualNetworkGateway", "VnetLocal", "Internet", "None"}
            if kind not in allowed:
                finding("NET-ROUTE-002", [entity], "Configured next-hop type needs validation",
                        f"Collected next-hop type: {kind}", "Unknown or future types are not automatically invalid.",
                        "This version cannot validate the next-hop configuration.",
                        "Check the value against direct Azure evidence and current provider documentation.",
                        record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low")
            elif kind == "VirtualAppliance" and address is None:
                finding("NET-ROUTE-002", [entity], "Virtual-appliance next-hop IP evidence unavailable",
                        "No next-hop IP value was collected.", "Missing evidence is not proof of missing configuration.",
                        "Next-hop consistency cannot be evaluated.",
                        "Collect the configured next-hop address through a direct read.",
                        record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low")
            elif kind == "VirtualAppliance":
                try:
                    ipaddress.ip_address(text(address))
                except ValueError:
                    finding("NET-ROUTE-002", [entity], "Virtual-appliance route lacks a usable configured next-hop IP",
                            "The collected next-hop address is missing or not an IP address.",
                            "A virtual-appliance route requires a next-hop IP; this check does not test reachability.",
                            "The intended route may not be usable; confirm configuration before remediation.",
                            "Verify the configured next-hop IP against a direct route-table read.",
                            record_type="potentialRisk", severity="medium", band="P2",
                            expected_state="VirtualAppliance requires a next-hop IP address (Azure provider constraint, not a customer architecture requirement).",
                            deep_dive="What next-hop IP is configured and is it intended?")
    if enriched:
        by_id = {text(entity["entityId"]): entity for entity in entities}
        children: dict[str, list[Record]] = {}
        for rel in relationships:
            if rel["relationshipType"] == "contains" and rel["classification"] == "OBSERVED" and rel["targetId"] in by_id:
                children.setdefault(text(rel["sourceId"]), []).append(by_id[text(rel["targetId"])])
        private_collections = {text(c["operationId"]): c for c in records(model["collections"]) if c["operationId"] in PRIVATE_OPERATIONS
                               and c["requestedSubscriptionId"] == array(obj(model["scope"])["requestedSubscriptionIds"])[0]}
        endpoint_entities = [entity for entity in entities if entity["resourceType"] == "microsoft.network/privateendpoints"]
        approved: list[Record] = []
        dns_configured: list[Record] = []
        dns_support: list[Record] = []
        connection_support: list[Record] = []
        group_parent_counts = {
            text(page["parentResourceId"]).lower(): integer(page["itemCount"])
            for page in records(private_collections["private-dns-groups"]["pages"]) if "parentResourceId" in page
        }
        for endpoint in endpoint_entities:
            endpoint_id = text(endpoint["entityId"])
            connections = [child for child in children.get(endpoint_id, []) if child["resourceType"] == "microsoft.network/privateendpoints/privatelinkserviceconnections"]
            counts = obj(endpoint["properties"])
            expected_counts = [counts.get("automaticConnectionCount"), counts.get("manualConnectionCount")]
            complete_connections = all(type(count) is int for count in expected_counts) and sum(integer(count) for count in expected_counts) == len(connections)
            states = [obj(connection["properties"]).get("connectionStatus") for connection in connections]
            connection_provisioning = [obj(connection["properties"]).get("provisioningState") for connection in connections]
            details_complete = all(
                isinstance(obj(connection["properties"]).get("privateLinkServiceId"), str)
                and bool(obj(connection["properties"]).get("privateLinkServiceId"))
                and isinstance(obj(connection["properties"]).get("groupIds"), list)
                and bool(obj(connection["properties"]).get("groupIds"))
                for connection in connections
            )
            if not connections or not complete_connections or not details_complete or any(state not in ("Approved", "Pending", "Rejected", "Disconnected") for state in states) or any(
                state not in ("Succeeded", "Failed", "Updating", "Creating", "Deleting") for state in connection_provisioning
            ):
                finding(
                    "NET-PRIVATE-001", [endpoint], "Private endpoint connection evidence is incomplete",
                    f"{len(connections)} selected connection(s); expected counts={expected_counts}; approval values={states}",
                    "Missing arrays/states or retained-count gaps do not prove no connection or approval exists.",
                    "Approval and intended private connectivity cannot be fully evaluated.",
                    "Collect authorized direct endpoint connection state and verify target/subresource intent.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                    supporting=connections, collection_refs=[text(private_collections["private-endpoint-connections"]["collectionId"])],
                )
            elif any(state != "Approved" for state in states) or counts.get("provisioningState") != "Succeeded" or any(
                state != "Succeeded" for state in connection_provisioning
            ):
                finding(
                    "NET-PRIVATE-001", [endpoint], "Private endpoint connection/provisioning state needs context",
                    f"approval values={states}; provisioningState={counts.get('provisioningState')}",
                    "Pending/rejected/disconnected or nonfinal configuration can be planned, denied or transitional; no outage is demonstrated.",
                    "Required private connectivity might not yet be configured as intended.",
                    "Confirm approval/lifecycle intent and direct target/subresource evidence before proposing changes.",
                    record_type="contextValidation", band="P2", supporting=connections,
                    collection_refs=[text(private_collections["private-endpoint-connections"]["collectionId"])],
                )
            else:
                approved.append(endpoint)
                connection_support.extend(connections)
            groups = [child for child in children.get(endpoint_id, []) if child["resourceType"] == "microsoft.network/privateendpoints/privatednszonegroups"]
            if endpoint_id not in group_parent_counts or group_parent_counts[endpoint_id] != len(groups) or (
                "PageCountMismatch" in array(private_collections["private-dns-groups"]["issues"])
            ):
                finding(
                    "NET-PRIVATE-DNS-001", [endpoint], "Private endpoint DNS zone-group evidence was not collected",
                    "No complete retained parent-scoped zone-group list page supports this endpoint.",
                    "Resource Graph does not prove zone-group absence; unavailable or unattempted parent reads remain UNKNOWN.",
                    "Configured DNS integration cannot be evaluated for this endpoint.",
                    "Resolve the recorded parent-list collection gap through authorized read-only evidence.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                    collection_refs=[text(private_collections["private-dns-groups"]["collectionId"])],
                )
                continue
            if not groups:
                finding(
                    "NET-PRIVATE-DNS-001", [endpoint], "Private endpoint has no collected zone-group association",
                    "A successful direct parent-scoped list returned no zone groups.",
                    "Zone-group absence is configuration, not proof DNS is broken; manual/custom/shared DNS may be intentional.",
                    "DNS management intent requires context before any change.",
                    "Confirm the intended DNS architecture and existing records/forwarding rather than creating a zone group automatically.",
                    record_type="contextValidation", band="P2",
                    collection_refs=[text(private_collections["private-dns-groups"]["collectionId"])],
                )
                continue
            zone_ids = {
                text(rel["targetId"]) for rel in relationships if rel["sourceId"] in {group["entityId"] for group in groups}
                and rel["relationshipType"] == "referencesPrivateDnsZone" and rel["targetId"] is not None
            }
            zones = [by_id[zone_id] for zone_id in zone_ids if zone_id in by_id and by_id[zone_id]["collectionState"] == "collected"
                     and by_id[zone_id]["resourceType"] == "microsoft.network/privatednszones"]
            links = [child for zone in zones for child in children.get(text(zone["entityId"]), []) if child["resourceType"] == "microsoft.network/privatednszones/virtualnetworklinks"]
            endpoint_subnets = {text(rel["targetId"]) for rel in relationships if rel["sourceId"] == endpoint_id
                                and rel["relationshipType"] == "attachedToSubnet" and rel["targetId"] is not None}
            endpoint_vnets = {text(rel["sourceId"]) for rel in relationships if rel["relationshipType"] == "contains"
                              and rel["targetId"] in endpoint_subnets and rel["sourceId"] in vnet_ids}
            linked_zones = {
                text(rel["sourceId"]) for rel in relationships if rel["relationshipType"] == "contains"
                and rel["targetId"] in {
                    link["entityId"] for link in links if isinstance(obj(link["properties"]).get("virtualNetworkId"), str)
                    and text(obj(link["properties"])["virtualNetworkId"]).lower() in endpoint_vnets
                    and obj(link["properties"]).get("provisioningState") == "Succeeded"
                    and obj(link["properties"]).get("virtualNetworkLinkState") == "Completed"
                }
            }
            supported = (
                bool(zone_ids) and len(zones) == len(zone_ids) and zone_ids <= linked_zones
                and all(c["status"] == "succeeded" for c in records(model["collections"])
                        if c["operationId"] in ("private-dns-zones", "private-dns-links"))
                and private_collections["private-dns-groups"]["status"] == "succeeded"
                and all(obj(group["properties"]).get("provisioningState") == "Succeeded" for group in groups)
            )
            if supported:
                dns_configured.append(endpoint)
                dns_support.extend([*groups, *zones, *links])
            else:
                finding(
                    "NET-PRIVATE-DNS-001", [endpoint], "Private DNS configuration linkage needs architecture evidence",
                    f"Retained zone groups={len(groups)}; zone references={len(zone_ids)}; collected zones={len(zones)}; selected links={len(links)}.",
                    "Uncollected zones/links or no retained direct endpoint-VNet link do not prove resolution failure; custom/shared DNS may be valid.",
                    "Client resolution architecture and record applicability remain unverified.",
                    "Confirm authorized zone/link evidence, DNS records and client/custom/shared forwarding intent through a scoped specialist review.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                    supporting=[*groups, *zones, *links],
                    collection_refs=[text(private_collections[key]["collectionId"]) for key in ("private-dns-groups", "private-dns-zones", "private-dns-links")],
                    deep_dive="What DNS path is intended for the actual clients, and does selected configuration support it?",
                )
        if approved:
            finding(
                "NET-PRIVATE-001", approved, "Collected private endpoint connections report Approved configuration",
                f"{len(approved)} collected endpoint(s) have complete selected Approved connections and endpoint provisioning Succeeded.",
                "Approval/provisioning is configuration state, not successful application connectivity or public-access disablement.",
                "No private-only, reachability or service-health conclusion follows.",
                "Preserve approval/target/subresource evidence; validate client behavior only when required and authorized.",
                band="INFO", action="none", supporting=connection_support,
                collection_refs=[text(private_collections["private-endpoint-connections"]["collectionId"])],
            )
        if dns_configured:
            finding(
                "NET-PRIVATE-DNS-001", dns_configured, "Selected private DNS zone-group and VNet-link configuration is present",
                f"{len(dns_configured)} endpoint(s) have retained successful zone-group/zone/completed direct endpoint-VNet-link references.",
                "This joins configuration references only; records, actual DNS resolution and client reachability were not collected.",
                "No DNS-health or traffic-flow conclusion follows from configured links.",
                "Preserve linkage evidence and validate the real client's DNS path when required.",
                band="INFO", action="none", supporting=dns_support,
                collection_refs=[text(private_collections[key]["collectionId"]) for key in ("private-dns-groups", "private-dns-zones", "private-dns-links")],
            )
        if endpoint_entities:
            finding(
                "NET-PRIVATE-DNS-001", endpoint_entities, "Private endpoint DNS resolution and public-access behavior remain unverified",
                "Selected approval/zone-group/link configuration was collected; A/AAAA records, client resolution, forwarding and service public access were not.",
                "Private Endpoint presence is not proof public access is disabled or clients use the private path.",
                "Private-only exposure and operational behavior cannot be certified.",
                "Choose a scoped authorized client/DNS/target-service deep dive if those requirements apply; do not enable telemetry or modify configuration.",
                record_type="evidenceGap", band="P3", action="evidenceCollection", confidence="low",
                gaps=["DNS records/client resolution/forwarding", "Target service public access", "Effective security/routes/traffic"],
            )
    dns_plan = private_dns_plan(model) if planning else None
    if dns_plan is not None:
        by_id = {text(entity["entityId"]): entity for entity in entities}
        for repeated in records(dns_plan["repeatedZoneNames"]):
            affected = [by_id[text(value)] for value in array(repeated["zoneIds"])]
            finding(
                "NET-DNS-REPEAT-001", affected, "Repeated Private DNS zone name requires ownership review: " + text(repeated["name"]),
                f"{len(affected)} distinct collected zone resource IDs share this normalized DNS name.",
                "Same-name zones can intentionally isolate environments or DNS views; duplication is not automatically a defect.",
                "Possible accidental divergence or redundant management requires architectural validation, not automatic deletion.",
                "Review each zone's owner, records, VNet links, zone-group references, forwarding and cross-subscription consumers before planning consolidation.",
                record_type="contextValidation", band="P2",
                gaps=["Record contents and owners", "External/cross-subscription consumers and forwarding", "Customer isolation intent"],
                collection_refs=[text(value) for value in array(dns_plan["collectionRefs"])],
            )
        services = [entity for entity in entities if entity["resourceType"] in {
            row["resourceType"] for row in records(dns_plan["serviceRows"])
        } and entity["collectionState"] == "collected"]
        finding(
            "NET-DNS-PLAN-001", services, "Service-to-Private-DNS planning comparison is available",
            f"Scoped service resources={len(services)}; collected DNS zones={len(array(dns_plan['zones']))}; DNS-hosting scope={dns_plan['dnsHostingScopeStatus']}.",
            "The versioned commercial mapping lists possible subresources/zones, not universal architecture requirements. Unobserved connections and zone names are separate facts.",
            "Service use, endpoint consumers and central/custom DNS must be confirmed before planning private-access expansion.",
            "Review the service planning matrix with customer owners; select required service features/subresources and explicit central-DNS/consumer scopes. Never infer missing endpoints because zones were not observed.",
            record_type="contextValidation", band="P3",
            collection_refs=[text(value) for value in array(dns_plan["collectionRefs"])],
            gaps=[text(value) for value in array(dns_plan["limitations"])],
        )
        if dns_plan["dnsHostingScopeStatus"] != "declared-accessible-results":
            finding(
                "NET-DNS-PLAN-001", [], "Central DNS hosting coverage remains unverified",
                "DNS hosting is undeclared or some explicitly scoped DNS collections are incomplete.",
                "Workload subscriptions often use zones in a separate central subscription; uncollected hosting scope is not absence.",
                "A missing-zone conclusion cannot be made.",
                "Provide approved DNS-hosting subscription IDs or resolve recorded permission/collection failures; do not automatically discover or expand scope.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=[text(value) for value in array(dns_plan["collectionRefs"])],
            )
        if metadata_mode:
            repeated_ids = {text(value) for group in records(dns_plan["repeatedZoneNames"]) for value in array(group["zoneIds"])}
            metadata_zones = [zone for zone in records(dns_plan["zones"]) if zone["zoneId"] in repeated_ids]
            incomplete = [zone for zone in metadata_zones if obj(zone["recordMetadata"])["status"] != "selected-metadata-collected"]
            source_collections = [c for c in records(model["collections"]) if c["operationId"] == "repeated-zone-record-metadata"]
            if incomplete or any(c["status"] != "succeeded" for c in source_collections):
                finding(
                    "NET-DNS-META-001", [by_id[text(zone["zoneId"])] for zone in incomplete],
                    "Repeated-zone record-set metadata coverage is incomplete",
                    "One or more approved repeated-zone reads failed, were truncated, contained unavailable metadata or were not attempted.",
                    "No summary is UNKNOWN, not an empty zone; retained counts are selected record sets, not values.",
                    "Record content, dependencies and consolidation safety cannot be determined.",
                    "Resolve the explicitly recorded metadata coverage gaps before comparing zone summaries; do not delete or merge zones.",
                    record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                    collection_refs=[text(c["collectionId"]) for c in source_collections],
                )
            summaries = [entity for entity in entities if entity["resourceType"] == "private-dns-record-metadata-summary"]
            if summaries:
                finding(
                    "NET-DNS-META-001", [by_id[text(zone["zoneId"])] for zone in metadata_zones
                                        if obj(zone["recordMetadata"])["summaryEntityId"] is not None],
                    "Privacy-minimized repeated-zone record-set metadata is available for review",
                    "Per-zone selected record-set type counts and TTL ranges are retained without record names, IDs or values.",
                    "Equal summaries do not prove equal records or shared clients; different counts/TTLs can be intentional. SOA-only summaries are not certified unused zones.",
                    "No dependency, resolution, record equivalence or safe-cleanup conclusion is supported.",
                    "Review summaries alongside owners, zone-group/VNet-link associations, forwarding and all consumers before any authorized consolidation planning.",
                    record_type="contextValidation", band="P2", supporting=summaries,
                    collection_refs=[text(c["collectionId"]) for c in source_collections],
                    gaps=["Record content intentionally omitted", "Owners, external consumers and forwarding", "Resolution and safe deletion"],
                )
    dns_paths = configured_dns_paths(model) if paths_mode else None
    if dns_paths is not None:
        path_entities = [entity for entity in entities if entity["entityId"] in {row["entityId"] for row in records(dns_paths["rows"])}]
        incomplete_paths: list[Record] = []
        for entity in path_entities:
            props = obj(entity["properties"])
            resource_type = text(entity["resourceType"])
            incomplete = False
            if resource_type == "vnet-dns-settings":
                incomplete = props.get("dnsServersKnown") is not True or not isinstance(props.get("dnsServers"), list)
                addresses = props.get("dnsServers") or []
            elif resource_type.endswith("/forwardingrules"):
                ips, ports = props.get("targetDnsServerIPs"), props.get("targetDnsServerPorts")
                incomplete = props.get("targetDnsServersKnown") is not True or not isinstance(ips, list) or not ips or (
                    not isinstance(ports, list) or len(ips) != len(ports) or any(port is None for port in ports)
                ) or not props.get("domainName") or props.get("forwardingRuleState") not in ("Enabled", "Disabled")
                addresses = ips if isinstance(ips, list) else []
            elif resource_type.endswith("/inboundendpoints"):
                addresses = props.get("inboundIpAddresses") or []
                incomplete = not addresses or props.get("ipConfigurationCount") != len(addresses) or (
                    not isinstance(props.get("inboundSubnetIds"), list)
                    or len(array(props["inboundSubnetIds"])) != len(addresses)
                )
            else:
                addresses = []
                field = {"microsoft.network/dnsresolvers": "virtualNetworkId",
                         "microsoft.network/dnsforwardingrulesets": "outboundEndpointIds",
                         "microsoft.network/dnsresolvers/outboundendpoints": "subnetId",
                         "microsoft.network/dnsforwardingrulesets/virtualnetworklinks": "virtualNetworkId"}.get(resource_type)
                incomplete = field is not None and not props.get(field)
            for address in addresses:
                try:
                    ipaddress.ip_address(text(address))
                except ValueError:
                    incomplete = True
            if resource_type != "vnet-dns-settings" and props.get("provisioningState") not in ("Succeeded", "Failed", "Updating", "Creating", "Deleting"):
                incomplete = True
            if incomplete:
                incomplete_paths.append(entity)
        if incomplete_paths:
            finding(
                "NET-DNS-PATH-001", incomplete_paths, "Selected DNS path configuration fields need authoritative context",
                "Some configured addresses, target ports, references or recognized state fields are unavailable or unsupported.",
                "Missing/defaulted array entries and future states are UNKNOWN, not empty configuration or verified failure.",
                "A configured path cannot be fully described from these selected fields.",
                "Confirm the missing fields through scoped authoritative reads and customer DNS intent; do not silently default ports, assume client use or alter resources.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=[text(value) for value in array(dns_paths["collectionRefs"])],
            )
        if path_entities:
            finding(
                "NET-DNS-PATH-001", path_entities, "Selected DNS resolver and forwarding configuration is available",
                f"{len(path_entities)} selected VNet DNS/resolver/endpoint/ruleset/rule/link configuration objects were retained.",
                "Configured settings/references do not establish client use, selected forwarding rules or successful resolution.",
                "DNS dependency and consolidation safety remain unverified.",
                "Review VNet DNS defaults, endpoint/subnet references, ruleset links and enabled rules with customer DNS owners; do not infer actual traffic or delete zones.",
                record_type="contextValidation", band="P2",
                collection_refs=[text(value) for value in array(dns_paths["collectionRefs"])],
            )
        finding(
            "NET-DNS-PATH-001", path_entities, "Actual DNS client and forwarding behavior remain unverified",
            "Only approved VNet and Azure DNS Private Resolver configuration was selected; custom/on-premises DNS internals, client overrides and live lookups were not collected.",
            "No scoped Azure resolver/ruleset rows is not evidence of no DNS service or broken DNS.",
            "Client visibility, forwarding effectiveness, resolution and safe cleanup cannot be certified.",
            "Confirm customer DNS architecture and external dependencies, then choose explicitly authorized evidence; do not enable diagnostics or run active lookups.",
            record_type="evidenceGap", band="P3", action="evidenceCollection", confidence="low",
            collection_refs=[text(value) for value in array(dns_paths["collectionRefs"])],
            gaps=[text(value) for value in array(dns_paths["limitations"])],
        )
    adoption = resolver_adoption(model) if paths_mode else None
    if adoption is not None and (array(adoption["resolverIds"]) or array(adoption["rulesets"])):
        by_id = {text(entity["entityId"]): entity for entity in entities}
        adoption_support = [by_id[text(row["entityId"])] for row in records(obj(dns_paths)["rows"])]
        consumers = records(adoption["consumers"])
        modes = {row["dnsMode"] for row in consumers if row["dnsMode"] != "UNKNOWN"}
        linked = [row for row in consumers if array(row["rulesetsWithSucceededLinks"])]
        unlinked = [row for row in consumers if not array(row["observedRulesetLinkIds"])
                    and row["linkCoverage"] == "accessible-parent-lists-collected"]
        if len(modes) > 1 or linked and unlinked:
            finding(
                "NET-DNS-ADOPT-001", [by_id[text(row["vnetId"])] for row in consumers],
                "Resolver deployment has mixed configured consumer cohorts",
                f"Known DNS modes={sorted(modes)}; succeeded ruleset-associated VNets={len(linked)}; VNets with no observed ruleset link in accessible parent lists={len(unlinked)}.",
                "This can be staged migration, intentional isolation or different DNS architectures; there is no customer migration target or proof of client adoption.",
                "Potentially incomplete transition needs ownership/intent validation before concluding any consumer is misconfigured.",
                "Confirm intended consumer cohorts and DNS paths, including custom/inbound-only designs; review the adoption matrix without requiring every VNet to use or link a ruleset.",
                record_type="contextValidation", band="P2",
                supporting=adoption_support,
                collection_refs=[text(value) for value in array(adoption["collectionRefs"])],
                gaps=["Customer migration target/cohorts", "Actual client DNS use and custom forwarding", "Consumer scope and isolation intent"],
            )
        for row in records(adoption["rulesets"]):
            review_reasons = []
            if row["linkCoverage"] == "accessible-parent-list-collected" and not array(row["observedLinkIds"]):
                review_reasons.append("No VNet link was observed in a complete accessible parent list.")
            if row["ruleCoverage"] == "accessible-parent-list-collected" and not array(row["enabledRuleIds"]) and not array(row["unknownRuleStateIds"]):
                review_reasons.append("No enabled forwarding rule was observed in a complete accessible parent list.")
            if review_reasons:
                finding(
                    "NET-DNS-ADOPT-001", [by_id[text(row["rulesetId"])]],
                    "Ruleset association or enabled-rule configuration needs migration context",
                    " ".join(review_reasons),
                    "A ruleset can be staged, intentionally unused or awaiting an authorized migration; these observations do not establish broken DNS.",
                    "Planned resolver rollout and consumer coverage cannot be inferred from resource deployment alone.",
                    "Validate the ruleset's owner, intended consumers, required suffixes and rollout stage; do not automatically link VNets, enable rules or delete resources.",
                    record_type="contextValidation", band="P2",
                    supporting=adoption_support,
                    collection_refs=[text(value) for value in array(adoption["collectionRefs"])],
                )
        uncertain = [row for row in consumers if row["dnsMode"] == "UNKNOWN" or row["linkCoverage"] == "UNKNOWN" or array(row["unreadyLinkIds"])]
        uncertain_rulesets = [row for row in records(adoption["rulesets"]) if row["linkCoverage"] == "UNKNOWN"
                             or row["ruleCoverage"] == "UNKNOWN" or array(row["unknownRuleStateIds"]) or array(row["unknownLinkTargetIds"])
                             or array(row["unverifiedOutboundEndpointIds"]) or row["outboundReferencesKnown"] is not True]
        if uncertain or uncertain_rulesets:
            finding(
                "NET-DNS-ADOPT-001",
                [by_id[text(row["vnetId"])] for row in uncertain] + [by_id[text(row["rulesetId"])] for row in uncertain_rulesets],
                "Resolver consumer adoption coverage needs additional evidence",
                "Some DNS-default, link-state, parent-list, rule-state or outbound-reference evidence is unavailable, incomplete or not final.",
                "Uncollected or unready associations cannot establish a completed transition or missing required links.",
                "Configured adoption patterns are incomplete; client use and migration intent remain UNKNOWN.",
                "Resolve the recorded configuration/permission/continuation gaps and confirm intended migration cohorts before planning changes.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                supporting=adoption_support,
                collection_refs=[text(value) for value in array(adoption["collectionRefs"])],
            )
    intent_comparison = compare_dns_intent(model, dns_intent) if dns_intent is not None else None
    if intent_comparison is not None:
        by_id = {text(entity["entityId"]): entity for entity in entities}
        for row in records(intent_comparison["rows"]):
            if row["stage"] == "excluded":
                continue
            gap = row["result"] == "unknown-evidence"
            required_difference = row["stage"] == "required-now" and row["result"] == "configured-difference"
            finding(
                "NET-DNS-INTENT-001", [by_id[text(row["vnetId"])]] if row["vnetId"] in by_id else [],
                "Declared DNS cohort comparison: " + text(row["cohortId"]) + " / " + text(row["vnetId"]),
                f"Configured DNS mode={row['observedDnsMode']}; comparison={row['result']}; declared stage={row['stage']}.",
                "Customer intent is separately DECLARED with revision/owner/time provenance; observations are not desired state. "
                + ("No automatic rollout requirement applies to planned/in-progress stages." if row["stage"] != "required-now"
                   else "The supplied required-now target is not automatically authoritative/current; validate ownership and evidence."),
                "Missing evidence prevents comparison." if gap else "A declared configuration difference requires owner review." if required_difference
                else "Configuration comparison does not establish client use, readiness or DNS behavior.",
                "Collect the recorded missing evidence and confirm source revision/observation time." if gap
                else "Validate the declared required-now difference with the source owner before any separately authorized change." if required_difference
                else "Confirm the customer rollout stage and source revision; no completion or remediation is inferred.",
                record_type="evidenceGap" if gap else "contextValidation", band="P2" if gap or required_difference else "P3",
                action="evidenceCollection" if gap else "contextValidation", confidence="low" if gap else "high",
                expected_state="DECLARED DNS mode=" + text(row["expectedDnsMode"]) + "; rulesets=" +
                ", ".join(text(value) for value in array(row["requiredRulesetIds"])) + "; inbound endpoints=" +
                ", ".join(text(value) for value in array(row["requiredInboundEndpointIds"])),
                supporting=[by_id[text(value)] for value in array(row["supportingEntityIds"])],
                collection_refs=[text(value) for value in array(obj(adoption)["collectionRefs"])],
                gaps=[text(value) for value in array(row["evidenceGaps"])],
            )
    time_review = provenance_time_review(model, review_at, dns_intent) if review_at is not None else None
    if time_review is not None:
        chronology_gaps = [text(value) for value in array(time_review["observationIssues"])]
        chronology_gaps.extend(text(issue) for row in records(time_review["collections"]) for issue in array(row["issues"]))
        if time_review["intent"] is not None:
            chronology_gaps.extend(text(value) for value in array(obj(time_review["intent"])["issues"]))
        if chronology_gaps:
            finding(
                "NET-EVID-TIME-001", [], "Evidence chronology or supplied intent provenance needs review",
                "; ".join(sorted(set(chronology_gaps))),
                "Age alone does not determine validity or expiry. Missing reads, future timestamps and unauthenticated source claims remain explicit gaps.",
                "Temporal alignment/source currentness cannot be certified.",
                "Confirm collection/source clocks, the explicit review time and customer document owner/revision; choose fresh evidence only with separate authorization.",
                record_type="evidenceGap", band="P3", action="evidenceCollection", confidence="low",
                collection_refs=[text(row["collectionId"]) for row in records(time_review["collections"])],
                gaps=sorted(set(chronology_gaps)),
            )
        finding(
            "NET-EVID-TIME-001", [], "Evidence time review uses an explicit reference without an expiry policy",
            "The supplied UTC review time is recorded; ages are calculated only for timestamps no later than that reference, otherwise UNKNOWN.",
            "No customer expiry threshold or currentness requirement was assumed; ages are not fresh/stale/expired labels.",
            "Age reporting does not establish continuing configuration validity, intent authenticity or actual client behavior.",
            "Review recorded ages and provenance with customer owners; do not infer expiry or automatically recollect/change resources.",
            record_type="contextValidation", band="P3",
            collection_refs=[text(row["collectionId"]) for row in records(time_review["collections"])],
        )
    access_review = service_access_review(model) if access_mode else None
    if access_review is not None:
        access_rows = records(access_review["rows"])
        access_entities = unique_index(entities, "entityId")
        for state in sorted({text(row["configurationState"]) for row in access_rows}):
            selected = [row for row in access_rows if row["configurationState"] == state]
            affected = [access_entities[text(row["serviceId"])] for row in selected]
            supporting_ids = {text(ref) for row in selected for ref in array(row["connectionIds"])}
            gap = state in ("unknown-setting", "unsupported-family", "perimeter-mode-unverified")
            disabled = state == "disabled-configured"
            finding(
                "NET-SERVICE-ACCESS-001", affected, "Service access configuration: " + state,
                f"{len(selected)} inventoried service(s): {state}; actual reachability UNKNOWN.",
                "The observed settings are compared with a DECLARED private preference. Private Endpoint approval does not disable public access; service defaults are not substituted for missing fields.",
                "Public access/alternative-control evidence or owner-approved exceptions remain unresolved; no exposure or compliance result is established.",
                "Collect the missing service-specific settings or perimeter enforcement evidence; obtain owner context without changing resources." if gap
                else "Review documented service exceptions, selected-network rules and trusted-service bypass with owners before any separately authorized changes." if not disabled
                else "Confirm trusted-service bypass, required subresources and client/DNS paths; this configured setting does not certify private-only access.",
                record_type="evidenceGap" if gap else "architectureObservation" if disabled else "contextValidation",
                band="P3" if state == "unsupported-family" else "INFO" if disabled else "P2",
                action="evidenceCollection" if gap else "none" if disabled else "contextValidation",
                confidence="low" if gap else "high",
                expected_state="DECLARED private-preferred; public only by documented service-specific exception; no accepted exceptions.",
                supporting=[access_entities[key] for key in sorted(supporting_ids)],
                collection_refs=[text(ref) for ref in array(access_review["collectionRefs"])],
                gaps=sorted({text(value) for row in selected for value in array(row["evidenceGaps"])}),
            )
        selected_gaps = [row for row in access_rows if row["supported"] and row["evidenceGaps"]
                         and row["configurationState"] not in ("unknown-setting", "perimeter-mode-unverified")]
        if selected_gaps:
            finding(
                "NET-SERVICE-ACCESS-001", [access_entities[text(row["serviceId"])] for row in selected_gaps],
                "Selected service access-control evidence is incomplete",
                f"{len(selected_gaps)} supported service(s) retain unavailable fields or partial connection/inventory coverage.",
                "A known public-access setting does not fill missing firewall, bypass or connection evidence.",
                "A complete service-control or private-path assessment cannot be established.",
                "Collect only the recorded missing configuration and validate it independently; do not infer defaults.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=[text(ref) for ref in array(access_review["collectionRefs"])],
                gaps=sorted({text(value) for row in selected_gaps for value in array(row["evidenceGaps"])}),
            )
    source_review = service_control_reconciliation(model) if arm_mode else None
    if source_review is not None:
        source_rows = records(source_review["rows"])
        by_id = unique_index(entities, "entityId")
        for category in ("different-observed-values", "unavailable-evidence", "observed-match"):
            selected = [
                row for row in source_rows if
                (any(field["result"] == "different-observed-values" for field in records(row["fields"])) if category == "different-observed-values"
                 else bool([gap for gap in array(row["evidenceGaps"]) if not text(gap).endswith(":different-observed-values")]) if category == "unavailable-evidence"
                 else any(field["result"] == "observed-match" for field in records(row["fields"])))
            ]
            if not selected:
                continue
            matching = category == "observed-match"
            unavailable = category == "unavailable-evidence"
            supporting = [by_id[text(obj(row["directSource"])["entityId"])] for row in selected
                          if obj(row["directSource"])["entityId"] is not None]
            finding(
                "NET-SERVICE-SOURCE-001", [by_id[text(row["serviceId"])] for row in selected],
                "Indexed/direct service controls: " + category,
                f"{len(selected)} supported service(s) have at least one non-null matching selected field; unresolved fields remain explicit."
                if matching else f"{len(selected)} supported service(s) have {category}; the matrix retains individual values, API versions and source/read times.",
                "Only two non-null equal values constitute an observed match. Missing fields or read failures are not zero/absence; source differences are not automatically defects.",
                "Agreement is not enforcement, reachability, currentness or private-only certification; differing/unavailable evidence needs bounded validation.",
                "Collect the recorded unavailable source fields/reads without assuming defaults." if unavailable
                else "Validate source/API/collection-time differences and customer context before considering separately authorized changes." if not matching
                else "Retain the matching configuration evidence alongside explicit unresolved fields and actual-behaviour limitations.",
                record_type="evidenceGap" if unavailable else "architectureObservation" if matching else "contextValidation",
                band="INFO" if matching else "P2",
                action="none" if matching else "evidenceCollection" if unavailable else "contextValidation",
                confidence="low" if unavailable else "high", supporting=supporting,
                collection_refs=[text(value) for value in array(source_review["collectionRefs"])],
                gaps=sorted({text(value) for row in selected for value in array(row["evidenceGaps"])}),
            )
    nsp_review = nsp_configuration_review(model) if nsp_mode else None
    if nsp_review is not None:
        by_id = unique_index(entities, "entityId")
        association_rows = records(nsp_review["associationRows"])
        for state in sorted({text(row["configurationState"]) for row in association_rows}):
            selected = [row for row in association_rows if row["configurationState"] == state]
            supporting_ids = {text(value) for row in selected for value in array(row["ruleIds"])}
            supporting_ids.update(text(row["profileId"]).lower() for row in selected
                                  if isinstance(row["profileId"], str) and text(row["profileId"]).lower() in by_id)
            gap = state == "unknown-configured-mode" or any(row["evidenceGaps"] for row in selected)
            finding(
                "NET-NSP-001", [by_id[text(row["associationId"])] for row in selected],
                "NSP association configuration: " + state,
                f"{len(selected)} scoped association(s) have raw configured mode/state {state}; actual enforcement UNKNOWN.",
                "Association/profile references and access-rule metadata are configuration only. Provisioning and coverage gaps remain explicit; Enforced is not an operational test.",
                "A public-access exception, effective rule behaviour and service integration/synchronization cannot be certified.",
                "Resolve recorded configuration/evidence gaps and obtain service-specific owner context before any separately authorized action.",
                record_type="evidenceGap" if gap else "architectureObservation" if state.startswith("enforced-") else "contextValidation",
                band="P2" if gap else "INFO" if state.startswith("enforced-") else "P3",
                action="evidenceCollection" if gap else "none" if state.startswith("enforced-") else "contextValidation",
                confidence="low" if gap else "high",
                supporting=[by_id[key] for key in sorted(supporting_ids)],
                collection_refs=[text(value) for value in array(nsp_review["collectionRefs"])],
                gaps=sorted({text(value) for row in selected for value in array(row["evidenceGaps"])}),
            )
        missing_associations = records(nsp_review["perimeterModeWithoutObservedAssociation"])
        if missing_associations:
            finding(
                "NET-NSP-001", [by_id[text(row["serviceId"])] for row in missing_associations],
                "Perimeter-mode service lacks association evidence in collected perimeter scope",
                f"{len(missing_associations)} service(s) report SecuredByPerimeter but have no matching collected association.",
                "Perimeter hosting/access may be outside scope; unobserved associations are not proof of absence or misconfiguration.",
                "The alternative control and owner-approved exception cannot be verified.",
                "Obtain the actual hosting-perimeter/association/service synchronization evidence within separately authorized scope.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=[text(value) for value in array(nsp_review["collectionRefs"])],
            )
        if not association_rows or any(value != "succeeded" for value in obj(nsp_review["collectionStatuses"]).values()):
            finding(
                "NET-NSP-001", [], "NSP scope or association coverage does not establish effective controls",
                f"Collected perimeters={len(array(nsp_review['perimeters']))}; associations={len(association_rows)}; outcomes are recorded.",
                "Zero accessible rows or partial lists do not establish no perimeter outside scope, no protected service or healthy enforcement.",
                "Alternative-control coverage remains UNKNOWN.",
                "Review recorded scope/permission/API/parent coverage before drawing service-specific conclusions.",
                record_type="evidenceGap", band="P3", action="evidenceCollection", confidence="low",
                collection_refs=[text(value) for value in array(nsp_review["collectionRefs"])],
            )
    unknown_subnets = [
        e for e in entities
        if e["resourceType"] == "microsoft.network/virtualnetworks/subnets"
        and (obj(e["properties"]).get("networkSecurityGroupKnown") is not True
             or obj(e["properties"]).get("routeTableKnown") is not True)
    ]
    if unknown_subnets:
        finding("NET-COVERAGE-001", unknown_subnets, "Subnet association fields are not fully available",
                f"{len(unknown_subnets)} subnet(s) have unavailable association-field evidence.",
                "Missing fields are UNKNOWN, not proof of missing NSGs or route tables.",
                "Association checks cannot establish complete control coverage.",
                "Use direct configuration reads for the relevant subnets.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low")
    partial = [c for c in records(model["collections"]) if c["status"] != "succeeded"]
    if partial or obj(model["coverage"])["issues"]:
        finding("NET-COVERAGE-001", [], "Collection or normalization coverage is partial",
                "; ".join(text(i) for i in array(obj(model["coverage"])["issues"])),
                "Failed, truncated or inconsistent collections do not demonstrate resource absence.",
                "Important configuration may not have been assessed.",
                "Resolve the recorded access/collection gaps before relying on completeness.",
                record_type="evidenceGap", band="P2", action="evidenceCollection", confidence="low",
                collection_refs=[text(c["collectionId"]) for c in partial],
                gaps=["See collection outcomes and child-count/coverage issues"])
    finding("NET-COVERAGE-001", [], "Permission-wide completeness and operational health remain unverified",
            "Resource Graph returns accessible indexed configuration; effective behavior and telemetry are deferred.",
            "A successful query can omit inaccessible resources without a permission error.",
            "Zero detected problems cannot certify network health or complete subscription visibility.",
            "Confirm authorized scope and choose targeted operational deep dives where needed.",
            record_type="evidenceGap", band="P3", action="evidenceCollection", confidence="low",
            collection_refs=[text(c["collectionId"]) for c in records(model["collections"])],
            gaps=["Permission-wide completeness", "Effective routes/security", "Telemetry and packet behavior"])
    prioritize_findings(findings)
    result: Record = {
        "accessPreference": BASELINE,
        "schemaVersion": model["schemaVersion"], "runId": obj(model["run"])["runId"],
        "capabilityVersion": VERSION, "checkCatalogVersion": configuration["catalogVersion"],
        "priorityPolicyVersion": configuration["priorityPolicyVersion"],
        "observationArtifact": {"filename": "observed-network.json", "sha256": hashlib.sha256(encoded(model)).hexdigest()},
        "checksExecuted": [{"checkId": c["checkId"], "checkVersion": c["checkVersion"]}
                           for c in checks.values()],
        "status": "incomplete-configuration-triage" if obj(model["coverage"])["status"] == "partial"
        else "limited-configuration-triage",
        "scope": model["scope"], "coverage": model["coverage"],
        "dataHandling": model["dataHandling"], "findings": findings,
        "evidenceCatalog": model["evidence"], "collectionCatalog": model["collections"],
        **({"dnsPlanning": dns_plan} if dns_plan is not None else {}),
        **({"dnsPaths": dns_paths} if dns_paths is not None else {}),
        **({"dnsResolverAdoption": adoption} if adoption is not None else {}),
        **({"dnsIntentComparison": intent_comparison} if intent_comparison is not None else {}),
        **({"provenanceTimeReview": time_review} if time_review is not None else {}),
        **({"serviceAccessReview": access_review} if access_review is not None else {}),
        **({"serviceControlReconciliation": source_review} if source_review is not None else {}),
        **({"nspConfigurationReview": nsp_review} if nsp_review is not None else {}),
    }
    validate_document(result, HERE / "assessment.schema.json")
    verify_assessment(model, result)
    return result


def verify_assessment(model: Record, assessment: Record) -> None:
    if "accessPreference" in assessment:
        from first_pass import BASELINE
        if assessment["accessPreference"] != BASELINE:
            raise ValueError("Declared access preference differs from the versioned baseline")
    elif assessment["capabilityVersion"] == VERSION:
        raise ValueError("Current assessment must preserve the declared private-preferred baseline")
    if assessment["runId"] != obj(model["run"])["runId"]:
        raise ValueError("Bundle run IDs differ")
    if obj(assessment["observationArtifact"])["sha256"] != hashlib.sha256(encoded(model)).hexdigest():
        raise ValueError("Observation artifact hash mismatch")
    if assessment["scope"] != model["scope"] or assessment["coverage"] != model["coverage"]:
        raise ValueError("Assessment changed observation scope or coverage")
    if assessment["evidenceCatalog"] != model["evidence"] or assessment["collectionCatalog"] != model["collections"]:
        raise ValueError("Assessment evidence catalogs differ from observation")
    entities = unique_index(records(model["entities"]), "entityId")
    evidence = unique_index(records(model["evidence"]), "evidenceId")
    collections = unique_index(records(model["collections"]), "collectionId")
    catalog_config = load(HERE / "checks.json")
    if assessment["checkCatalogVersion"] in ("1.9.0", "1.10.0", "1.11.0", "1.12.0"):
        expected = {text(c["checkId"]): c["checkVersion"] for c in records(catalog_config["checks"])}
        version = obj(model["run"])["queryCatalogVersion"]
        allowed = set(LEGACY_CHECK_VERSIONS)
        if assessment["checkCatalogVersion"] == "1.9.0" or "provenanceTimeReview" in assessment:
            allowed.add("NET-EVID-TIME-001")
        if assessment["checkCatalogVersion"] in ("1.10.0", "1.11.0", "1.12.0"):
            if version != {"1.10.0": "1.6.0", "1.11.0": "1.7.0", "1.12.0": "1.8.0"}[text(assessment["checkCatalogVersion"])]:
                raise ValueError("Service check catalog differs from the versioned acquisition")
            allowed.add("NET-SERVICE-ACCESS-001")
            if assessment["checkCatalogVersion"] in ("1.11.0", "1.12.0"):
                allowed.add("NET-SERVICE-SOURCE-001")
            if assessment["checkCatalogVersion"] == "1.12.0":
                allowed.add("NET-NSP-001")
        if version != "1.0.0":
            allowed.update(("NET-PRIVATE-001", "NET-PRIVATE-DNS-001"))
        if version in ("1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            allowed.update(("NET-DNS-PLAN-001", "NET-DNS-REPEAT-001"))
        if version in ("1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            allowed.add("NET-DNS-META-001")
        if version in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            allowed.update(("NET-DNS-PATH-001", "NET-DNS-ADOPT-001"))
        if "dnsIntentComparison" in assessment:
            allowed.add("NET-DNS-INTENT-001")
        expected = {key: value for key, value in expected.items() if key in allowed}
        policy_version = catalog_config["priorityPolicyVersion"]
    elif assessment["checkCatalogVersion"] == "1.0.0":
        expected = LEGACY_CHECK_VERSIONS
        policy_version = "1.0.0"
    elif assessment["checkCatalogVersion"] == "1.1.0":
        expected = {**LEGACY_CHECK_VERSIONS, "NET-ADDR-001": "1.1.0"}
        policy_version = "1.1.0"
    elif assessment["checkCatalogVersion"] in ("1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
        expected = (
            {text(check["checkId"]): check["checkVersion"] for check in records(catalog_config["checks"])
             if check["checkId"] in LEGACY_CHECK_VERSIONS}
            if assessment["capabilityVersion"] == VERSION else
            {**LEGACY_CHECK_VERSIONS, "NET-ADDR-001": "1.1.0", "NET-PEER-001": "1.1.0"}
        )
        if assessment["checkCatalogVersion"] in ("1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            expected = {**expected, "NET-PRIVATE-001": "1.0.0", "NET-PRIVATE-DNS-001": "1.0.0"}
        if assessment["checkCatalogVersion"] in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            expected = {**expected, "NET-DNS-PLAN-001": "1.0.0", "NET-DNS-REPEAT-001": "1.0.0"}
        if assessment["checkCatalogVersion"] in ("1.5.0", "1.6.0", "1.7.0", "1.8.0"):
            expected = {**expected, "NET-DNS-META-001": "1.0.0"}
        if assessment["checkCatalogVersion"] in ("1.6.0", "1.7.0", "1.8.0"):
            expected = {**expected, "NET-DNS-PATH-001": "1.0.0"}
        if assessment["checkCatalogVersion"] in ("1.7.0", "1.8.0"):
            expected = {**expected, "NET-DNS-ADOPT-001": "1.0.0"}
        if assessment["checkCatalogVersion"] == "1.8.0":
            expected = {**expected, "NET-DNS-INTENT-001": "1.0.0"}
        policy_version = "1.1.0"
    else:
        raise ValueError("Unsupported historical check catalog")
    if assessment["priorityPolicyVersion"] != policy_version:
        raise ValueError("Priority policy differs from the versioned check catalog")
    executed = {text(c["checkId"]): c["checkVersion"] for c in records(assessment["checksExecuted"])}
    if expected != executed:
        raise ValueError("Check catalog differs from executed check versions")
    nsp_mode = obj(model["run"])["queryCatalogVersion"] == "1.8.0"
    arm_mode = nsp_mode or obj(model["run"])["queryCatalogVersion"] == "1.7.0"
    access_mode = arm_mode or obj(model["run"])["queryCatalogVersion"] == "1.6.0"
    if access_mode:
        if assessment["checkCatalogVersion"] != ("1.12.0" if nsp_mode else "1.11.0" if arm_mode else "1.10.0") or assessment.get("serviceAccessReview") != service_access_review(model):
            raise ValueError("Service access review differs from selected observation evidence")
    elif "serviceAccessReview" in assessment:
        raise ValueError("Service access review is unsupported for this acquisition catalog")
    if arm_mode:
        if assessment.get("serviceControlReconciliation") != service_control_reconciliation(model):
            raise ValueError("Service control reconciliation differs from selected source evidence")
    elif "serviceControlReconciliation" in assessment:
        raise ValueError("Service source reconciliation requires direct ARM acquisition")
    if nsp_mode:
        if assessment.get("nspConfigurationReview") != nsp_configuration_review(model):
            raise ValueError("NSP review differs from selected configuration evidence")
    elif "nspConfigurationReview" in assessment:
        raise ValueError("NSP review requires explicitly selected acquisition")
    versioned_paths = obj(model["run"])["queryCatalogVersion"] in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0")
    temporal = assessment["checkCatalogVersion"] == "1.9.0" or "provenanceTimeReview" in assessment
    if assessment["checkCatalogVersion"] in ("1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0") or (
        temporal and obj(model["run"])["queryCatalogVersion"] in ("1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0")
    ) or access_mode:
        if assessment.get("dnsPlanning") != private_dns_plan(model):
            raise ValueError("DNS planning comparison differs from selected evidence/catalog")
    elif "dnsPlanning" in assessment:
        raise ValueError("DNS planning is unsupported for this historical check catalog")
    if assessment["checkCatalogVersion"] in ("1.6.0", "1.7.0", "1.8.0") or temporal and versioned_paths or access_mode:
        if assessment.get("dnsPaths") != configured_dns_paths(model):
            raise ValueError("DNS path view differs from selected observation evidence")
    elif "dnsPaths" in assessment:
        raise ValueError("DNS paths are unsupported for this historical check catalog")
    if assessment["checkCatalogVersion"] in ("1.7.0", "1.8.0") or temporal and versioned_paths or access_mode:
        if assessment.get("dnsResolverAdoption") != resolver_adoption(model):
            raise ValueError("Resolver adoption view differs from selected observation evidence")
    elif "dnsResolverAdoption" in assessment:
        raise ValueError("Resolver adoption is unsupported for this historical check catalog")
    if assessment["checkCatalogVersion"] == "1.8.0" or (temporal or access_mode) and "dnsIntentComparison" in assessment:
        comparison = obj(assessment.get("dnsIntentComparison"))
        if comparison != compare_dns_intent(model, obj(comparison["intent"])):
            raise ValueError("DNS intent comparison differs from supplied intent/observations")
    elif "dnsIntentComparison" in assessment:
        raise ValueError("DNS intent is unsupported for this check catalog")
    if temporal:
        time_view = obj(assessment.get("provenanceTimeReview"))
        intent = obj(obj(assessment["dnsIntentComparison"])["intent"]) if "dnsIntentComparison" in assessment else None
        if time_view != provenance_time_review(model, text(time_view["referenceAt"]), intent):
            raise ValueError("Temporal review differs from source timestamps/reference time")
    elif "provenanceTimeReview" in assessment:
        raise ValueError("Temporal review is unsupported for this check catalog")
    unique_index(records(assessment["findings"]), "findingId")
    for item in records(assessment["findings"]):
        if expected.get(text(item["checkId"])) != item["checkVersion"]:
            raise ValueError("Finding check/version mismatch")
        if not set(array(item["affectedResources"])) <= set(entities):
            raise ValueError("Unresolved finding resource")
        if not set(array(item["evidenceRefs"])) <= set(evidence):
            raise ValueError("Unresolved finding evidence")
        if not set(array(item["collectionRefs"])) <= set(collections):
            raise ValueError("Unresolved finding collection")


def markdown(value: object) -> str:
    escaped = html.escape(str(value)).replace("\\", "\\\\")
    return re.sub(r"([`*_{}\[\]()|])", r"\\\1", escaped).replace("\n", " ").replace("\r", " ")


def report_provenance(assessment: Record) -> list[str]:
    return [
        f"**{label}:** {assessment[key]}" for label, key in (
            ("Capability", "capabilityVersion"), ("Schema", "schemaVersion"),
            ("Check catalog", "checkCatalogVersion"), ("Priority policy", "priorityPolicyVersion"),
        )
    ]


def report_prose(document: str) -> str:
    return re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*(?:\n|$)", "", document)


def dns_paths_report(view: Record) -> str:
    lines = ["## Configured DNS resolver and forwarding context", "",
             "These are selected configuration objects, not demonstrated client/forwarding paths.",
             "Domain suffixes and target IP/port values belong only in access-controlled engineering evidence.", "",
             "| Resource / configuration object | Type | Selected configuration |", "|---|---|---|"]
    for row in records(view["rows"]):
        lines.append(f"| {markdown(row['entityId'])} | {markdown(row['resourceType'])} | "
                     + markdown(json.dumps(row["properties"], sort_keys=True)) + " |")
    lines.extend(["", *["- " + markdown(value) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def provenance_time_report(view: Record) -> str:
    def seconds(value: object) -> str:
        if value is None:
            return "UNKNOWN (after reference time)"
        microseconds = integer(value)
        return f"{microseconds // 1000000}.{microseconds % 1000000:06d}"
    lines = ["## Evidence age and provenance chronology review", "",
             f"**Reference time:** {markdown(view['referenceAt'])} (operator-supplied, not independently authenticated)",
             "**Policy:** age/provenance only; no expiry thresholds. **Validity:** UNKNOWN.",
             f"**Observation interval:** {markdown(view['observationStartedAt'])} - {markdown(view['observationCompletedAt'])}",
             f"**Observation start / completion age (seconds):** {seconds(view['observationStartAgeMicroseconds'])} / {seconds(view['observationCompletionAgeMicroseconds'])}",
             "**Observation chronology issues:** " + markdown("; ".join(text(value) for value in array(view["observationIssues"])) or "None detected; not a validity certificate."),
             "", "| Operation / subscription | Outcome | Started / completed UTC | Start / completion age (seconds) | Provenance/chronology gaps |",
             "|---|---|---|---|---|"]
    for row in records(view["collections"]):
        lines.append(f"| {markdown(row['operationId'])} / {markdown(row['subscriptionId'])} | {markdown(row['collectionStatus'])} | "
                     f"{markdown(row['startedAt'])} / {markdown(row['completedAt'])} | "
                     f"{seconds(row['startAgeMicroseconds'])} / {seconds(row['completionAgeMicroseconds'])} | "
                     f"{markdown('; '.join(text(value) for value in array(row['issues'])))} |")
    if view["intent"] is not None:
        intent = obj(view["intent"])
        source = obj(intent["source"])
        lines.extend(["", "### Declared intent age and provenance", "",
                      f"**Source:** {markdown(source['documentId'])}; revision={markdown(source['revision'])}; owner={markdown(source['owner'])}",
                      f"**Declared / reviewed:** {markdown(source['declaredAt'])} / {markdown(source['reviewedAt'])}",
                      f"**Declaration / review age (seconds):** {seconds(intent['declarationAgeMicroseconds'])} / {seconds(intent['reviewAgeMicroseconds'])}",
                      "**Classification:** DECLARED; **document validity:** UNKNOWN; source not independently authenticated.",
                      *["- " + markdown(value) for value in array(intent["issues"])]])
    else:
        lines.extend(["", "No customer intent was supplied; no source dates or validity were invented."])
    lines.extend(["", *["- " + markdown(value) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def dns_intent_report(comparison: Record) -> str:
    source = obj(obj(comparison["intent"])["source"])
    lines = ["## Declared customer DNS intent comparison", "",
             "**Classification:** DECLARED; provenance is operator-supplied, not independently authenticated.",
             f"**Source:** {markdown(source['documentId'])}; revision={markdown(source['revision'])}; owner={markdown(source['owner'])}",
             f"**Declared / reviewed:** {markdown(source['declaredAt'])} / {markdown(source['reviewedAt'])}",
             f"**Intent hash:** {comparison['intentSha256']} (canonical supplied JSON, not source-document bytes)",
             f"**Observation completed:** {comparison['observationCompletedAt']}; alignment={comparison['timeAlignment']}",
             "**Actual client use:** UNKNOWN. Required-now targets are owner-supplied requirements; planned/in-progress targets are rollout context.", "",
             "| Cohort / stage | VNet | Declared mode | Configured mode | Result | Declared rulesets / inbound targets | Differences / evidence gaps |",
             "|---|---|---|---|---|---|---|"]
    for row in records(comparison["rows"]):
        lines.append(
            f"| {markdown(row['cohortId'])} / {markdown(row['stage'])} | {markdown(row['vnetId'])} | "
            f"{markdown(row['expectedDnsMode'])} | {markdown(row['observedDnsMode'])} | {markdown(row['result'])} | "
            + markdown("; ".join(text(value) for value in [*array(row["requiredRulesetIds"]), *array(row["requiredInboundEndpointIds"])]))
            + " | " + markdown("; ".join(text(value) for value in [*array(row["differences"]), *array(row["evidenceGaps"])])) + " |"
        )
    lines.extend(["", *["- " + markdown(value) for value in array(comparison["limitations"])], ""])
    return "\n".join(lines)


def resolver_adoption_report(view: Record) -> str:
    lines = [
        "## Resolver adoption and partial-transition review", "",
        "**Migration intent:** UNKNOWN; **actual client use:** UNKNOWN.",
        "This matrix describes scoped configuration cohorts, not a percentage migrated or missing required links. "
        "Inbound-IP matches are candidates only; ruleset linking is not a universal requirement.", "",
        "| VNet | Configured DNS mode | Inbound endpoint candidates | Observed ruleset links | Rulesets with succeeded links | Link coverage | Unready links |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in records(view["consumers"]):
        lines.append(
            f"| {markdown(row['vnetId'])} | {markdown(row['dnsMode'])} | "
            + " | ".join(markdown("; ".join(text(value) for value in array(row[key]))) for key in (
                "inboundEndpointCandidates", "observedRulesetLinkIds", "rulesetsWithSucceededLinks",
            ))
            + f" | {markdown(row['linkCoverage'])} | {markdown('; '.join(text(value) for value in array(row['unreadyLinkIds'])))} |"
        )
    lines.extend([
        "", "| Ruleset | Observed consumers / consumers with succeeded links | Link / rule coverage | Enabled / disabled / unknown-state rule counts | Outbound references |",
        "|---|---|---|---|---|",
    ])
    for row in records(view["rulesets"]):
        lines.append(
            f"| {markdown(row['rulesetId'])} | {len(array(row['observedVnetIds']))} / {len(array(row['vnetIdsWithSucceededLinks']))} | "
            f"{markdown(row['linkCoverage'])} / {markdown(row['ruleCoverage'])} | "
            f"{len(array(row['enabledRuleIds']))} / {len(array(row['disabledRuleIds']))} / {len(array(row['unknownRuleStateIds']))} | "
            f"{markdown('; '.join(text(value) for value in array(row['outboundEndpointIds'])))}; "
            f"unverified: {markdown('; '.join(text(value) for value in array(row['unverifiedOutboundEndpointIds'])))}; "
            f"known={row['outboundReferencesKnown']}; unknown references={row['unknownOutboundReferenceCount']} |"
        )
    lines.extend(["", *["- " + markdown(value) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def dns_planning_report(plan: Record) -> str:
    lines = [
        "## Private DNS service planning", "",
        f"**Mapping:** {markdown(plan['catalogVersion'])} / {markdown(plan['catalogSha256'])}; "
        f"cloud={markdown(plan['cloud'])}; source revision={markdown(plan['sourceRevision'])}",
        f"**DNS hosting scope:** {markdown(plan['dnsHostingScopeStatus'])}; "
        + ", ".join(markdown(value) for value in array(plan["dnsSubscriptionIds"])), "",
        f"**Selected service inventory:** {markdown(plan['serviceInventoryStatus'])}; "
        f"**Workload connection inventory:** {markdown(plan['connectionInventoryStatus'])}. "
        "Counts are observations within collection coverage, not certified absence.", "",
        "Microsoft Learn mapping values are DECLARED planning guidance. Resource/connection/zone rows are "
        "selected observations, not mandatory zones or proven service use. Zero observed connections is "
        "workload-scope-only; it is not explained by absent zone names. Templates require configuration context.", "",
        "| Service resource type | Possible subresources | Observed resources | Observed connections | Resources without observed matching connection | Zone comparison | Applicability |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for row in records(plan["serviceRows"]):
        zone_summary = "; ".join(
            text(match["zoneValue"]) + ": " + text(match["status"]) + " (" + str(len(array(match["zoneIds"]))) + ")"
            for match in records(row["zoneMatches"])
        )
        lines.append(
            f"| {markdown(row['resourceType'])} | {markdown(', '.join(text(v) for v in array(row['subresources'])))} | "
            f"{len(array(row['serviceIds']))} | {len(array(row['connectionIds']))} | "
            f"{len(array(row['serviceIdsWithoutObservedConnection']))} | {markdown(zone_summary)} | {markdown(row['note'])} |"
        )
    lines.extend([
        "", "### Collected zones and cleanup-review context", "",
        "Empty association lists mean no association retained in these scopes, not unused or safe to delete. "
        "Review records, owners, client/forwarding paths and all consumers before any consolidation.", "",
        "| Zone name | Resource ID / hosting subscription | Retained VNet-link IDs | Retained endpoint-zone-group IDs |",
        "|---|---|---|---|",
    ])
    for zone in records(plan["zones"]):
        lines.append(
            f"| {markdown(zone['name'])} | {markdown(zone['zoneId'])} / {markdown(zone['subscriptionId'])} | "
            f"{markdown('; '.join(text(v) for v in array(zone['linkIds'])))} | "
            f"{markdown('; '.join(text(v) for v in array(zone['zoneGroupIds'])))} |"
        )
    lines.extend(["", "### Repeated zone names", ""])
    for repeated in records(plan["repeatedZoneNames"]):
        lines.append("- " + markdown(repeated["name"]) + ": " + markdown("; ".join(text(v) for v in array(repeated["zoneIds"]))))
    if not array(plan["repeatedZoneNames"]):
        lines.append("No repeated names were observed in collected zones; this is not tenant-wide completeness.")
    if any("recordMetadata" in zone for zone in records(plan["zones"])):
        repeated_ids = {text(value) for row in records(plan["repeatedZoneNames"]) for value in array(row["zoneIds"])}
        lines.extend([
            "", "### Privacy-minimized repeated-zone record-set metadata", "",
            "Counts refer to selected record sets, not individual records. Names, IDs and values are omitted. "
            "Equal summaries do not establish equal content; SOA-only or zero selected sets do not establish "
            "an unused zone. No summary means uncollected, not empty. TTL differences require context.", "",
            "| Zone ID | Outcome | Reported / selected sets | A / AAAA / CNAME / MX / PTR / SOA / SRV / TXT | Unknown type / TTL | TTL range (seconds) |",
            "|---|---|---|---|---|---|",
        ])
        for zone in records(plan["zones"]):
            if zone["zoneId"] not in repeated_ids:
                continue
            metadata = obj(zone["recordMetadata"])
            props = obj(metadata["properties"])
            value = lambda key: str(props[key]) if props.get(key) is not None else "UNKNOWN"
            lines.append(
                f"| {markdown(zone['zoneId'])} | {markdown(metadata['status'])} | "
                f"{value('reportedRecordSetCount')} / {value('selectedRecordSetCount')} | "
                + " / ".join(value(kind + "RecordSetCount") for kind in ("a", "aaaa", "cname", "mx", "ptr", "soa", "srv", "txt"))
                + f" | {value('unknownTypeCount')} / {value('unknownTtlCount')} | {value('minTtl')} - {value('maxTtl')} |"
            )
    lines.extend(["", "### Planning limitations", "", *["- " + markdown(value) for value in array(plan["limitations"])], ""])
    return "\n".join(lines)


def access_preference_report(preference: Record) -> str:
    return "\n".join([
        "## Declared access preference", "",
        "Private preferred; public access by documented exception. This is a declared assessment baseline, "
        "not verified exposure, accepted customer policy or permission to change resources. "
        "Service-specific alternative controls require evidence; Azure Monitor workspace is not "
        "automatically exempted by the Log Analytics NSP integration.",
        "Baseline source: " + markdown(preference["source"]) + ". No exceptions automatically accepted.",
        *["- " + text(value) for value in array(preference["references"])], "",
    ])


def service_access_report(view: Record, executive: bool = False) -> str:
    rows = records(view["rows"])
    lines = [
        "## Service access-control configuration review", "",
        "**Review:** " + text(view["reviewVersion"]) + "; **Service inventory:** " +
        text(view["serviceInventoryStatus"]) + "; **PE connections:** " + text(view["connectionInventoryStatus"]),
        "",
    ]
    if executive:
        counts = Counter(text(row["configurationState"]) for row in rows)
        lines.extend(["| Configuration state | Services |", "|---|---:|",
                      *[f"| {markdown(state)} | {count} |" for state, count in sorted(counts.items())]])
    else:
        lines.extend([
            "| Service | Type | State | Public access | Firewall action | Trusted bypass | IP / VNet / resource rule counts | Approved groups | Evidence gaps |",
            "|---|---|---|---|---|---|---|---|---|",
        ])
        for row in rows:
            props = obj(row["properties"])
            values = [row["serviceId"], row["resourceType"], row["configurationState"],
                      *[props.get(key) if props.get(key) is not None else "UNKNOWN"
                        for key in ("publicNetworkAccess", "firewallDefaultAction", "trustedServiceBypass")],
                      " / ".join(str(props.get(key)) if props.get(key) is not None else "UNKNOWN/not applicable"
                                 for key in ("ipRuleCount", "virtualNetworkRuleCount", "resourceAccessRuleCount")),
                      ", ".join(text(value) for value in array(row["approvedGroupIds"])) or "none observed in scope",
                      "; ".join(text(value) for value in array(row["evidenceGaps"])) or "none recorded for selected fields"]
            lines.append("| " + " | ".join(markdown(str(value)) for value in values) + " |")
    lines.extend(["", *["- " + markdown(text(value)) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def service_source_report(view: Record, executive: bool = False) -> str:
    rows = records(view["rows"])
    lines = ["## Indexed and direct ARM service-control reconciliation", "",
             "**Review:** " + text(view["reviewVersion"]) + "; supported service rows=" + str(len(rows))
             + "; unsupported service resources=" + str(len(array(view["unsupportedServiceIds"]))), ""]
    if executive:
        counts = Counter(text(field["result"]) for row in rows for field in records(row["fields"]))
        lines.extend(["| Per-field comparison (not a health score) | Fields |", "|---|---:|",
                      *[f"| {markdown(result)} | {count} |" for result, count in sorted(counts.items())]])
    else:
        for row in rows:
            index, direct = obj(row["indexedSource"]), obj(row["directSource"])
            lines.extend([
                "**Service:** " + markdown(row["serviceId"]) + "; **Type:** " + markdown(row["resourceType"]),
                "**Indexed source:** " + markdown(index["collectionId"]) + "; **Collected:** " + markdown(index["collectedAt"]),
                "**Direct source:** " + markdown(direct["collectionId"]) + "; **API:** " + markdown(direct["apiVersion"]) +
                "; **Read outcome:** " + markdown(direct["readStatus"]) + "; **Read completion:** " +
                markdown(direct["collectedAt"] or "not collected") + "; **Read error:** " + markdown(direct["readError"] or "none"),
                "", "| Selected property | Indexed value | Direct value | Comparison |", "|---|---|---|---|",
            ])
            for field in records(row["fields"]):
                lines.append("| " + " | ".join(markdown(str(value)) for value in (
                    field["field"], field["indexedValue"] if field["indexedValue"] is not None else "UNKNOWN/not applicable",
                    field["directValue"] if field["directValue"] is not None else "UNKNOWN/not applicable", field["result"],
                )) + " |")
            lines.extend(["", "**Evidence gaps:** " + markdown("; ".join(text(value) for value in array(row["evidenceGaps"])) or "none for selected fields"), ""])
    lines.extend(["", *["- " + markdown(text(value)) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def nsp_report(view: Record, executive: bool = False) -> str:
    rows = records(view["associationRows"])
    lines = ["## Network security perimeter configuration review", "",
             "**API:** " + text(view["apiVersion"]) + "; **Perimeters:** " + str(len(array(view["perimeters"]))) +
             "; **Profiles:** " + str(len(array(view["profiles"]))) + "; **Associations:** " + str(len(rows)), "",
             "| Collection | Outcome |", "|---|---|",
             *[f"| {markdown(key)} | {markdown(value)} |" for key, value in obj(view["collectionStatuses"]).items()], ""]
    if executive:
        counts = Counter(text(row["configurationState"]) for row in rows)
        lines.extend(["| Configured association state (not effective enforcement) | Count |", "|---|---:|",
                      *[f"| {markdown(state)} | {count} |" for state, count in sorted(counts.items())]])
    else:
        lines.extend([
            "| Association | Target reference / scope | Profile | Raw mode / state | Rule metadata coverage | Retained inbound / outbound rules | Gaps |",
            "|---|---|---|---|---|---|---|",
        ])
        for row in rows:
            values = [
                row["associationId"], str(row["targetResourceId"] or "UNKNOWN") + " / " + text(row["targetScope"]),
                row["profileId"] or "UNKNOWN", str(row["configuredAccessMode"] or "UNKNOWN") + " / " + text(row["configurationState"]),
                row["ruleMetadataCoverage"], str(row["retainedInboundRuleCount"]) + " / " + str(row["retainedOutboundRuleCount"]),
                "; ".join(text(value) for value in array(row["evidenceGaps"])) or "none recorded for selected metadata",
            ]
            lines.append("| " + " | ".join(markdown(str(value)) for value in values) + " |")
        lines.extend(["", "| Rule metadata identifier | Selected configuration |", "|---|---|"])
        for row in records(view["ruleMetadata"]):
            lines.append("| " + markdown(row["entityId"]) + " | " + markdown(json.dumps(row["properties"], sort_keys=True)) + " |")
    candidates = records(view["perimeterModeWithoutObservedAssociation"])
    lines.extend(["", "**Perimeter-mode services without observed scoped association:** " + str(len(candidates)),
                  *["- " + markdown(row["serviceId"]) + ": " + markdown(row["status"]) for row in candidates], "",
                  *["- " + markdown(text(value)) for value in array(view["limitations"])], ""])
    return "\n".join(lines)


def render(assessment: Record) -> tuple[str, str]:
    validate_document(assessment, HERE / "assessment.schema.json")
    findings = records(assessment["findings"])
    types = Counter(text(f["recordType"]) for f in findings)
    severities = Counter(text(f["severity"]) for f in findings if f["severity"] is not None)
    scope = obj(assessment["scope"])
    summary = [
        "# Azure Network Configuration Triage", "",
        f"**Run ID:** {assessment['runId']}",
        f"**Status:** {assessment['status']}",
        *report_provenance(assessment),
        "**Scope:** " + ", ".join(markdown(s) for s in array(scope["requestedSubscriptionIds"])), "",
        "## Executive summary", "",
        "This is a restricted configuration triage, not a connectivity or operational-health certification. "
        "No IaC or customer architecture requirements were assumed. Successful collection covers accessible "
        "indexed data only; permission-wide completeness and effective behavior remain unverified.", "",
        "## Assessment overview", "", "| Record type | Count |", "|---|---:|",
        *[f"| {kind} | {types[kind]} |" for kind in (
            "verifiedProblem", "potentialRisk", "architectureObservation",
            "contextValidation", "evidenceGap", "positiveObservation",
        )],
        "", "| Severity (impact, not action ordering) | Count |", "|---|---:|",
        *[f"| {severity} | {severities[severity]} |" for severity in ("critical", "high", "medium", "low")],
        "", "## Prioritized next actions", "",
        "| Order | Priority | Type | Severity | Finding | Next action |",
        "|---:|---|---|---|---|---|",
    ]
    if "accessPreference" in assessment:
        summary[summary.index("## Assessment overview"):summary.index("## Assessment overview")] = [
            access_preference_report(obj(assessment["accessPreference"])), ""
        ]
    if "serviceAccessReview" in assessment:
        summary[summary.index("## Assessment overview"):summary.index("## Assessment overview")] = [
            service_access_report(obj(assessment["serviceAccessReview"]), executive=True), ""
        ]
    if "serviceControlReconciliation" in assessment:
        summary[summary.index("## Assessment overview"):summary.index("## Assessment overview")] = [
            service_source_report(obj(assessment["serviceControlReconciliation"]), executive=True), ""
        ]
    if "nspConfigurationReview" in assessment:
        summary[summary.index("## Assessment overview"):summary.index("## Assessment overview")] = [
            nsp_report(obj(assessment["nspConfigurationReview"]), executive=True), ""
        ]
    engineering = [
        "# Azure Network Engineering Evidence", "",
        f"**Run ID:** {assessment['runId']}",
        f"**Status:** {assessment['status']}",
        *report_provenance(assessment), "",
        "## Executed checks", "", "| Check | Version |", "|---|---|",
        *[f"| {markdown(check['checkId'])} | {markdown(check['checkVersion'])} |"
          for check in records(assessment["checksExecuted"])], "",
        "## Collection coverage", "",
        "Requested scope is separate from returned scope. Missing or inaccessible evidence is not absence. "
        "Configured routes are not demonstrated packet flow.", "",
        "| Operation | Outcome | Pages | Retained rows | Issues |", "|---|---|---:|---:|---|",
    ]
    for collection in records(assessment["collectionCatalog"]):
        engineering.extend([
            f"| {markdown(str(collection['operationId']) + (' @ ' + str(collection['requestedSubscriptionId']) if 'dnsPlanning' in assessment else ''))} | {collection['status']} | "
            f"{len(array(collection['pages']))} | {collection['retainedRowCount']} | "
            f"{markdown('; '.join(text(i) for i in array(collection['issues'])))} |",
        ])
    engineering.append("")
    if "accessPreference" in assessment:
        engineering.extend([access_preference_report(obj(assessment["accessPreference"])), ""])
    engineering.extend(f"<a id=\"{c['collectionId']}\"></a>" for c in records(assessment["collectionCatalog"]))
    if "dnsPlanning" in assessment:
        engineering.extend(["", dns_planning_report(obj(assessment["dnsPlanning"]))])
    if "dnsPaths" in assessment:
        engineering.extend(["", dns_paths_report(obj(assessment["dnsPaths"]))])
    if "dnsResolverAdoption" in assessment:
        engineering.extend(["", resolver_adoption_report(obj(assessment["dnsResolverAdoption"]))])
    if "dnsIntentComparison" in assessment:
        engineering.extend(["", dns_intent_report(obj(assessment["dnsIntentComparison"]))])
    if "provenanceTimeReview" in assessment:
        engineering.extend(["", provenance_time_report(obj(assessment["provenanceTimeReview"]))])
    if "serviceAccessReview" in assessment:
        engineering.extend(["", service_access_report(obj(assessment["serviceAccessReview"]))])
    if "serviceControlReconciliation" in assessment:
        engineering.extend(["", service_source_report(obj(assessment["serviceControlReconciliation"]))])
    if "nspConfigurationReview" in assessment:
        engineering.extend(["", nsp_report(obj(assessment["nspConfigurationReview"]))])
    engineering.extend(["", "## Findings", ""])
    for item in findings:
        priority = obj(item["priority"])
        summary.append(
            f"| {priority['rank']} | {priority['band']} / {priority['actionType']} | "
            f"{item['recordType']} | {item['severity'] or 'Not applicable'} | "
            f"[{markdown(item['title'])}](network-evidence.md#{item['findingId'].lower()}) | "
            f"{markdown(item['recommendation'])} |"
        )
        engineering.extend([
            f"<a id=\"{item['findingId'].lower()}\"></a>",
            f"### {markdown(item['findingId'])} - {markdown(item['title'])}", "",
            f"**Check:** {markdown(item['checkId'])} / {markdown(item['checkVersion'])}",
            f"**Type:** {item['recordType']}; **Severity:** {item['severity'] or 'Not applicable'}",
            f"**Interpretation classification:** {item['interpretationClassification']}",
            f"**Priority:** {priority['rank']} / {priority['band']} / {priority['actionType']}",
            f"**Priority rationale:** {markdown(priority['reason'])}",
            f"**Confidence:** {item['confidence']}", "",
        ])
        for field in ("observedState", "expectedState", "reasoning", "risk", "recommendation"):
            value = item[field]
            engineering.append(f"**{field}:** {markdown(value) if value is not None else 'No customer requirement supplied.'}")
        engineering.extend([
            "", "**Affected resources:** " + markdown(", ".join(text(v) for v in array(item["affectedResources"]))),
            "**Dependencies:** " + markdown("; ".join(text(v) for v in array(item["dependencies"]))),
            "**Evidence gaps:** " + markdown("; ".join(text(v) for v in array(item["evidenceGaps"]))),
            "**Evidence:** " + ", ".join(f"[{markdown(ref)}](#{ref})" for ref in array(item["evidenceRefs"])),
            "**Collections:** " + ", ".join(f"[{markdown(ref)}](#{ref})" for ref in array(item["collectionRefs"])),
        ])
        if item["recommendedDeepDive"]:
            deep = obj(item["recommendedDeepDive"])
            engineering.append("**Recommended deep dive (not executed):** " + markdown(deep["question"]))
        engineering.extend(["**Guidance:** " + ", ".join(text(v) for v in array(item["guidanceReferences"])), ""])
    engineering.extend(["## Selected evidence", ""])
    for ev in records(assessment["evidenceCatalog"]):
        engineering.extend([
            f"<a id=\"{ev['evidenceId']}\"></a>", f"### {markdown(ev['evidenceId'])}", "",
            f"**Source:** {markdown(ev['source'])}; **Collected:** {ev['collectedAt']}",
            f"**Classification:** {ev['classification']}; **SHA-256:** `{ev['sha256']}`",
            f"**Hash scope:** {markdown(ev['hashScope'])}", "",
            "```json", json.dumps(ev["excerpt"], sort_keys=True, indent=2), "```", "",
        ])
    summary.extend([
        "", "## Boundaries", "",
        "Deferred: " + ", ".join(markdown(v) for v in array(scope["deferredEvidence"])), "",
        "No Azure resource changes, remediation, diagnostics enablement or IaC generation were performed by this pipeline.",
        "Reports are generated views of assessment.json; external publication is separate.", "",
    ])
    engineering.extend([
        "## Data handling", "", "```json",
        json.dumps(assessment["dataHandling"], sort_keys=True, indent=2), "```", "",
        "Source lineage: Usman Mahmood's assessment discipline and Daniel Mauser's Network Desk foundations; "
        "see the plugin notices and project source map.", "",
    ])
    summary_text, engineering_text = "\n".join(summary), "\n".join(engineering)
    verify_reports(assessment, summary_text, engineering_text)
    return summary_text, engineering_text


def verify_reports(assessment: Record, summary: str, engineering: str) -> None:
    summary, engineering = report_prose(summary), report_prose(engineering)
    if "accessPreference" in assessment:
        baseline_text = access_preference_report(obj(assessment["accessPreference"]))
        if summary.count(baseline_text) != 1 or engineering.count(baseline_text) != 1:
            raise ValueError("Markdown declared access baseline differs from assessment")
    if "serviceAccessReview" in assessment:
        access_view = obj(assessment["serviceAccessReview"])
        if summary.count(service_access_report(access_view, executive=True)) != 1 or engineering.count(service_access_report(access_view)) != 1:
            raise ValueError("Markdown service access review differs from assessment")
    if "serviceControlReconciliation" in assessment:
        source_view = obj(assessment["serviceControlReconciliation"])
        if summary.count(service_source_report(source_view, executive=True)) != 1 or engineering.count(service_source_report(source_view)) != 1:
            raise ValueError("Markdown service source reconciliation differs from assessment")
    if "nspConfigurationReview" in assessment:
        nsp_view = obj(assessment["nspConfigurationReview"])
        if summary.count(nsp_report(nsp_view, executive=True)) != 1 or engineering.count(nsp_report(nsp_view)) != 1:
            raise ValueError("Markdown NSP configuration review differs from assessment")
    run_marker = "**Run ID:** " + text(assessment["runId"])
    if summary.splitlines().count(run_marker) != 1 or engineering.splitlines().count(run_marker) != 1:
        raise ValueError("Markdown report run IDs differ from assessment")
    anchors = re.findall(r'<a id="([^"]+)"></a>', engineering)
    if len(anchors) != len(set(anchors)):
        raise ValueError("Duplicate Markdown evidence anchor")
    expected = {
        *[text(f["findingId"]).lower() for f in records(assessment["findings"])],
        *[text(e["evidenceId"]) for e in records(assessment["evidenceCatalog"])],
        *[text(c["collectionId"]) for c in records(assessment["collectionCatalog"])],
    }
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", identifier) for identifier in expected):
        raise ValueError("Unsafe Markdown evidence/finding identifier")
    if set(anchors) != expected:
        raise ValueError("Markdown evidence/finding anchors are incomplete")
    link_pattern = r"(?<!\\)\]\((network-evidence\.md)?#([A-Za-z0-9_.:-]+)\)"
    summary_links = re.findall(link_pattern, summary)
    engineering_links = re.findall(link_pattern, engineering)
    if not {target for _, target in summary_links + engineering_links} <= expected:
        raise ValueError("Unresolved Markdown evidence link")
    expected_summary = Counter(("network-evidence.md", text(finding["findingId"]).lower())
                               for finding in records(assessment["findings"]))
    expected_engineering = Counter(
        ("", text(ref)) for finding in records(assessment["findings"])
        for key in ("evidenceRefs", "collectionRefs") for ref in array(finding[key])
    )
    if Counter(summary_links) != expected_summary or Counter(engineering_links) != expected_engineering:
        raise ValueError("Markdown generated links are missing, duplicated or changed")
    modern = assessment["capabilityVersion"] not in ("0.1.0", "0.1.1", "0.1.2") or any(
        line.startswith("**Schema:** ") for line in engineering.splitlines()
    )
    if modern:
        for marker in report_provenance(assessment):
            if summary.splitlines().count(marker) != 1 or engineering.splitlines().count(marker) != 1:
                raise ValueError("Markdown version provenance differs from assessment")
        for check in records(assessment["checksExecuted"]):
            marker = f"| {markdown(check['checkId'])} | {markdown(check['checkVersion'])} |"
            if engineering.splitlines().count(marker) != 1:
                raise ValueError("Markdown executed check versions are incomplete")
    if "dnsPlanning" in assessment and engineering.count(dns_planning_report(obj(assessment["dnsPlanning"]))) != 1:
        raise ValueError("Markdown DNS planning matrix differs from assessment")
    if "dnsPaths" in assessment and engineering.count(dns_paths_report(obj(assessment["dnsPaths"]))) != 1:
        raise ValueError("Markdown DNS path configuration differs from assessment")
    if "dnsResolverAdoption" in assessment and engineering.count(resolver_adoption_report(obj(assessment["dnsResolverAdoption"]))) != 1:
        raise ValueError("Markdown resolver adoption matrix differs from assessment")
    if "dnsIntentComparison" in assessment and engineering.count(dns_intent_report(obj(assessment["dnsIntentComparison"]))) != 1:
        raise ValueError("Markdown DNS intent comparison differs from assessment")
    if "provenanceTimeReview" in assessment and engineering.count(provenance_time_report(obj(assessment["provenanceTimeReview"]))) != 1:
        raise ValueError("Markdown temporal review differs from assessment")


def bundle(model: Record, assessment: Record, output_root: Path) -> Record:
    validate_document(model, HERE / "observed-network.schema.json")
    validate_document(assessment, HERE / "assessment.schema.json")
    verify_observation(model)
    verify_assessment(model, assessment)
    summary, engineering = render(assessment)
    run_id = canonical_uuid(text(assessment["runId"]))
    directory = output_root.resolve() / "runs" / run_id
    payloads = {
        "observed-network.json": encoded(model), "assessment.json": encoded(assessment),
        "network-assessment.md": summary.encode("utf-8"), "network-evidence.md": engineering.encode("utf-8"),
    }
    directory.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(directory):
        raise FileExistsError("Run bundle already exists: " + str(directory))
    staging = directory.with_name("." + run_id + ".pending")
    staging.mkdir(exist_ok=False)
    paths: Record = {}
    published = False
    try:
        for name, content in payloads.items():
            path = staging / name
            with path.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            expected_hash = hashlib.sha256(content).hexdigest()
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                raise OSError("Staged artifact integrity mismatch: " + name)
            paths[name] = {"path": str(directory / name), "sha256": expected_hash}
        if os.path.lexists(directory):
            raise FileExistsError("Run bundle already exists: " + str(directory))
        staging.rename(directory)
        published = True
    finally:
        if not published and staging.exists():
            for name in payloads:
                (staging / name).unlink(missing_ok=True)
            staging.rmdir()
    return {"runId": run_id, "status": assessment["status"], "artifacts": paths}


def atomic_json(path: Path, document: Record) -> None:
    temporary = path.parent / ("." + uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded(document))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def immutable_file(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or path.read_bytes() != content:
            raise ValueError("Immutable report publication copy differs from original")
        return
    stream = path.open("xb")
    verified = False
    try:
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != content:
            raise OSError("Immutable report publication copy verification failed")
        verified = True
    finally:
        if not verified:
            path.unlink(missing_ok=True)


def report_blob_key(value: str, thread_id: str, publication_name: str) -> str:
    if (
        not value.startswith("tmp/ThreadFiles/" + canonical_uuid(thread_id) + "/")
        or "\\" in value or any(character in value for character in ("%", "?", "#", "\r", "\n"))
        or any(part in ("", ".", "..") for part in value.split("/"))
        or value.rsplit("/", 1)[-1] != publication_name
    ):
        raise ValueError("Saved report key differs from the bound thread/immutable filename")
    return value


def publication_files(state: Record, run_id: str, thread_id: str) -> dict[str, Record]:
    if set(state) != {"publicationVersion", "runId", "threadId", "subscriptionId", "bundle", "files"} or state["publicationVersion"] != "1.0.0":
        raise ValueError("Unsupported report publication ledger")
    if state["runId"] != canonical_uuid(run_id) or state["threadId"] != canonical_uuid(thread_id):
        raise ValueError("Report publication run/thread mismatch")
    if state["subscriptionId"] != canonical_uuid(text(state["subscriptionId"])):
        raise ValueError("Report publication subscription identity is invalid")
    result = obj(state["bundle"])
    if set(result) != {"runId", "status", "artifacts"} or result["runId"] != run_id or set(obj(result["artifacts"])) != set(REPORT_FILES):
        raise ValueError("Report publication original bundle identity is invalid")
    files = obj(state["files"])
    if set(files) != set(REPORT_FILES):
        raise ValueError("Report publication requires exactly four originals")
    selected = {}
    for name in REPORT_FILES:
        item = obj(files[name])
        description = obj(obj(result["artifacts"])[name])
        if set(item) != {"sha256", "size", "publicationName", "phase", "key"}:
            raise ValueError("Invalid report publication artifact metadata")
        sha256 = text(item["sha256"])
        expected_name = Path(name).stem + "-" + run_id + "-" + sha256 + Path(name).suffix
        if (
            not re.fullmatch(r"[a-f0-9]{64}", sha256) or description["sha256"] != sha256
            or item["publicationName"] != expected_name or integer(item["size"]) < 1
            or item["phase"] not in ("pending", "saveStarted", "savedUnverified")
            or (item["key"] is not None) != (item["phase"] == "savedUnverified")
        ):
            raise ValueError("Report publication artifact identity/phase is invalid")
        if item["key"] is not None:
            report_blob_key(text(item["key"]), thread_id, expected_name)
        selected[name] = item
    return selected


def verify_original_reports(result: Record, output_root: Path, run_id: str) -> dict[str, bytes]:
    run_id = canonical_uuid(run_id)
    directory = output_root.resolve() / "runs" / run_id
    if directory.is_symlink() or result["runId"] != run_id:
        raise ValueError("Original report bundle identity/path mismatch")
    artifacts = obj(result["artifacts"])
    if set(result) != {"runId", "status", "artifacts"} or set(artifacts) != set(REPORT_FILES) or set(path.name for path in directory.iterdir()) != set(REPORT_FILES):
        raise ValueError("Report recovery requires all four original canonical files")
    contents = {}
    for name in REPORT_FILES:
        path = directory / name
        description = obj(artifacts[name])
        if set(description) != {"path", "sha256"} or path.is_symlink() or Path(text(description["path"])) != path:
            raise ValueError("Original report path differs from expected bundle")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != description["sha256"]:
            raise ValueError("Original report hash mismatch: " + name)
        contents[name] = content
    model = obj(json.loads(contents["observed-network.json"]))
    assessment = obj(json.loads(contents["assessment.json"]))
    validate_document(model, HERE / "observed-network.schema.json")
    validate_document(assessment, HERE / "assessment.schema.json")
    verify_observation(model)
    verify_assessment(model, assessment)
    if assessment["runId"] != run_id or result["status"] != assessment["status"]:
        raise ValueError("Original report run/status mismatch")
    verify_reports(
        assessment, contents["network-assessment.md"].decode("utf-8"),
        contents["network-evidence.md"].decode("utf-8"),
    )
    return contents


def report_save(
    output_root: Path, run_id: str, thread_id: str, action: str,
    manifest: Path | None = None, artifact: str | None = None, blob_key: str | None = None,
) -> Record:
    run_id, thread_id = canonical_uuid(run_id), canonical_uuid(thread_id)
    directory = output_root.resolve() / "report-publication" / run_id
    if action not in ("plan", "begin", "record"):
        raise ValueError("Unsupported report save action")
    if not directory.exists():
        if action != "plan" or manifest is None:
            raise ValueError("Initial report save plan requires the original helper-result manifest")
        result = load(manifest)
        contents = verify_original_reports(result, output_root, run_id)
        state: Record = {
            "publicationVersion": "1.0.0", "runId": run_id, "threadId": thread_id,
            "subscriptionId": obj(obj(json.loads(contents["observed-network.json"]))["scope"])["requestedSubscriptionIds"][0],
            "bundle": result,
            "files": {
                name: {
                    "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
                    "publicationName": Path(name).stem + "-" + run_id + "-" + hashlib.sha256(content).hexdigest() + Path(name).suffix,
                    "phase": "pending", "key": None,
                } for name, content in contents.items()
            },
        }
        directory.mkdir(parents=True, exist_ok=False)
        atomic_json(directory / "state.json", state)
    if directory.is_symlink():
        raise ValueError("Report publication directory is a symlink")
    lock = directory / ".publication.lock"
    lock.mkdir(exist_ok=False)
    try:
        state = load(directory / "state.json")
        files = publication_files(state, run_id, thread_id)
        if manifest is not None and load(manifest) != state["bundle"]:
            raise ValueError("Supplied report manifest differs from the durable original")
        contents = verify_original_reports(obj(state["bundle"]), output_root, run_id)
        if obj(obj(json.loads(contents["observed-network.json"]))["scope"])["requestedSubscriptionIds"] != [state["subscriptionId"]]:
            raise ValueError("Original report scope differs from publication ledger")
        for name, item in files.items():
            if len(contents[name]) != item["size"]:
                raise ValueError("Original report size differs from publication ledger")
            path = directory / text(item["publicationName"])
            immutable_file(path, contents[name])
        if action != "plan":
            if artifact not in files:
                raise ValueError("Report save action requires a canonical artifact name")
            item = files[artifact]
            if action == "begin":
                if item["phase"] == "savedUnverified":
                    raise ValueError("Report already has a receipt; verify it before requesting another save")
                item["phase"] = "saveStarted"
            else:
                if blob_key is None:
                    raise ValueError("Record requires a begun save and its actual returned key")
                key = report_blob_key(blob_key, thread_id, text(item["publicationName"]))
                if item["phase"] == "savedUnverified" and item["key"] != key:
                    raise ValueError("Report receipt differs from the durable saved key")
                if item["phase"] not in ("saveStarted", "savedUnverified"):
                    raise ValueError("Record requires a begun save and its actual returned key")
                item.update({"key": key, "phase": "savedUnverified"})
            atomic_json(directory / "state.json", state)
        ledger_export = directory / ("report-save-state-" + run_id + "-" + digest(state) + ".json")
        immutable_file(ledger_export, encoded(state))
        return {
            **state, "statePath": str(directory / "state.json"),
            "ledgerExportPath": str(ledger_export),
            "status": "saved-not-download-verified" if all(item["key"] is not None for item in files.values()) else "partial-report-save",
            "remaining": [name for name, item in files.items() if item["key"] is None],
            "publicationPaths": {name: str(directory / text(item["publicationName"])) for name, item in files.items()},
        }
    finally:
        lock.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--subscription-id")
    parser.add_argument("--run-id")
    parser.add_argument("--page-size", type=int, default=None)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--report-save-action", choices=("plan", "begin", "record"))
    parser.add_argument("--report-thread-id")
    parser.add_argument("--bundle-manifest", type=Path)
    parser.add_argument("--artifact", choices=REPORT_FILES)
    parser.add_argument("--blob-key")
    parser.add_argument("--bundle-result", type=Path)
    parser.add_argument("--include-private-connectivity", action="store_true")
    parser.add_argument("--include-dns-planning", action="store_true")
    parser.add_argument("--dns-hosting-subscription-id", action="append")
    parser.add_argument("--include-repeated-zone-metadata", action="store_true")
    parser.add_argument("--include-dns-paths", action="store_true")
    parser.add_argument("--include-service-access", action="store_true")
    parser.add_argument("--include-service-arm", action="store_true")
    parser.add_argument("--include-nsp", action="store_true")
    parser.add_argument("--dns-intent", type=Path)
    parser.add_argument("--review-at")
    args = parser.parse_args()
    if args.report_save_action:
        if args.input or args.subscription_id or args.page_size is not None or args.bundle_result or args.include_private_connectivity or args.include_dns_planning or args.dns_hosting_subscription_id or args.include_repeated_zone_metadata or args.include_dns_paths or args.include_service_access or args.include_service_arm or args.include_nsp or args.dns_intent or args.review_at is not None or not args.run_id or not args.report_thread_id:
            parser.error("Report save requires --run-id/--report-thread-id and no acquisition/input options")
        if (args.report_save_action == "plan" and (args.artifact or args.blob_key)) or (
            args.report_save_action != "plan" and not args.artifact
        ) or (args.report_save_action != "record" and args.blob_key):
            parser.error("Invalid artifact/key options for report save action")
        print(json.dumps(report_save(
            args.output_root, args.run_id, args.report_thread_id, args.report_save_action,
            args.bundle_manifest, args.artifact, args.blob_key,
        ), sort_keys=True))
        return 0
    if args.report_thread_id or args.bundle_manifest or args.artifact or args.blob_key:
        parser.error("Publication options require --report-save-action")
    if args.dns_intent and not args.input:
        parser.error("--dns-intent requires existing --input; it never authorizes acquisition")
    if args.review_at is not None and not args.input:
        parser.error("--review-at requires existing --input; it never authorizes acquisition")
    if args.bundle_result and os.path.lexists(args.bundle_result):
        raise FileExistsError("Original helper-result manifest already exists")
    if args.input:
        if args.subscription_id or args.run_id or args.page_size is not None or args.include_private_connectivity or args.include_dns_planning or args.dns_hosting_subscription_id or args.include_repeated_zone_metadata or args.include_dns_paths or args.include_service_access or args.include_service_arm or args.include_nsp:
            parser.error("--input cannot be combined with acquisition options")
        envelope = load(args.input)
    else:
        if not args.subscription_id or not args.run_id:
            parser.error("--subscription-id and --run-id are required for collection")
        envelope = collect(args.subscription_id, args.run_id, page_size=args.page_size, include_private=args.include_private_connectivity,
                           include_dns_planning=args.include_dns_planning, dns_subscriptions=args.dns_hosting_subscription_id,
                           include_record_metadata=args.include_repeated_zone_metadata, include_dns_paths=args.include_dns_paths,
                           include_service_access=args.include_service_access, include_service_arm=args.include_service_arm,
                           include_nsp=args.include_nsp)
    model = normalize(envelope)
    dns_intent = None
    if args.dns_intent:
        if args.dns_intent.stat().st_size > 262144:
            raise ValueError("DNS intent exceeds its 256 KiB processing budget")
        dns_intent = load(args.dns_intent)
    assessment = assess(model, dns_intent, args.review_at)
    result = bundle(model, assessment, args.output_root)
    if args.bundle_result:
        with args.bundle_result.open("xb") as stream:
            stream.write(encoded(result))
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
