"""Translate approved legacy read commands to the existing scoped managed-identity ARM bridge."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import evidence_files as ef
import network_capture
import reference_capture
import reference_profile as profile


PRIVATE_DEPENDENCIES = Path.home() / ".cache" / "azure-network-health" / "python" / "jmespath-1.1.0"
if PRIVATE_DEPENDENCIES.is_dir():
    sys.path.insert(0, str(PRIVATE_DEPENDENCIES))


class ReferenceArmReader(network_capture.ArmBridge):
    def bootstrap_arguments(self) -> list[str]:
        return ["-ReferenceProfile"]

    def __call__(self, command: list[str]) -> profile.nh.ReadResponse:
        subscription = ef.text(self.approved["subscriptionId"])
        operation = reference_capture.operation_for(command, subscription)
        context = self.context()
        kind = operation["kind"]
        if kind == "account":
            return profile.nh.ReadResponse({"subscriptionId": context["subscriptionId"]})
        if kind == "graph":
            reply = self.exchange({
                "query": operation["query"], "first": int(command[command.index("--first") + 1]),
                "skipToken": profile.nh.request_token(command),
            })
        elif command[1] == "rest":
            reply = self.get(command[command.index("--url") + 1])
        else:
            target = profile.nh.command_target(command, subscription)
            if target is None:
                raise ValueError("Reference child request lacks an approved parent")
            if kind == "private-dns-groups":
                identifier = ("/subscriptions/" + subscription + "/resourceGroups/" + ef.text(target["resourceGroup"])
                              + "/providers/Microsoft.Network/privateEndpoints/" + ef.text(target["name"]))
                url = "https://management.azure.com" + identifier + "/privateDnsZoneGroups?api-version=2026-01-01"
            elif kind == "private-dns-record-metadata":
                identifier = ("/subscriptions/" + subscription + "/resourceGroups/" + ef.text(target["resourceGroup"])
                              + "/providers/Microsoft.Network/privateDnsZones/" + ef.text(target["name"]))
                url = "https://management.azure.com" + identifier + "/ALL?api-version=2018-09-01"
            else:
                raise ValueError("Unsupported reference command kind")
            reply = self.get(url)
        status = ef.integer(reply["statusCode"])
        if status != 200 or reply.get("body") is None:
            failure = "permissionDenied" if status in (401, 403) else "unavailable" if status in (0, 404, 429) or status >= 500 else "failed"
            code = ef.text(reply["errorCode"]) if isinstance(reply.get("errorCode"), str) else "ArmHttp" + str(status)
            raise profile.nh.ReadFailure(code, failure)
        body = ef.obj(reply["body"])
        if kind == "graph":
            payload = body
        elif kind == "private-dns-groups":
            rows = []
            for row in ef.records(body["value"]):
                properties = ef.obj(row.get("properties"))
                configs = properties.get("privateDnsZoneConfigs")
                zones = [ef.obj(value.get("properties"))["privateDnsZoneId"] for value in ef.records(configs)] if isinstance(configs, list) else None
                rows.append({
                    "id": row["id"], "name": row["name"],
                    "properties": {"privateDnsZoneIds": zones, "provisioningState": properties.get("provisioningState")},
                })
            payload = {"count": len(rows), "data": rows, "hasContinuation": bool(body.get("nextLink"))}
        elif kind == "private-dns-record-metadata":
            rows = [{"type": row.get("type"), "ttl": ef.obj(row.get("properties")).get("ttl")} for row in ef.records(body["value"])]
            payload = {"count": len(rows), "data": rows[:2000], "hasContinuation": bool(body.get("nextLink"))}
        else:
            try:
                jmespath = importlib.import_module("jmespath")
            except ModuleNotFoundError as error:
                if error.name != "jmespath":
                    raise
                raise RuntimeError("JMESPath 1.1.0 is required in the approved private runtime dependency directory") from None
            payload = ef.obj(jmespath.search(ef.text(operation["query"]), body))
        execution = reply.get("requestId")
        return profile.nh.ReadResponse(payload, ef.text(execution) if isinstance(execution, str) else None)
