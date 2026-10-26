from __future__ import annotations

import json
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jmespath
import test_sre_transport as native


sys.path.insert(0, str(native.ROOT / "tools"))
import network_health_capsule as capsule
import network_health_snapshot as snapshot


SUB, RUN, TIME = native.SUB, native.RUN, native.TIME
TENANT = "00000000-0000-4000-8000-000000000055"
OTHER = "00000000-0000-4000-8000-000000000099"


class SnapshotReader:
    def __init__(self, resources=None):
        self.resources = resources or {}
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command[:3] == ["az", "account", "show"]:
            payload = {"id": SUB, "tenantId": TENANT}
        else:
            url = command[command.index("--url") + 1]
            payload = self.resources.get(url, {"value": []})
        query = command[command.index("--query") + 1]
        return native.nh.ReadResponse(jmespath.search(query, payload))


class SnapshotTests(unittest.TestCase):
    def test_native_source_cannot_claim_completion_without_a_required_resource_get(self):
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/storage"
        value = {"id": identifier, "type": "Microsoft.Storage/storageAccounts", "properties": {"minimumTlsVersion": "TLS1_2"}}
        get_url = "https://management.azure.com" + identifier + "?api-version=2023-05-01"
        service = native.NativeService(reader=SnapshotReader({
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01": {"value": [value]},
            get_url: value,
        }))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                source = snapshot.acquire(transport, TENANT, SUB, RUN, output)
            page = next(source.glob("storage-get-*.json"))
            record = json.loads(page.read_bytes())
            page.unlink()
            audit_path = source / snapshot.AUDIT
            audit = json.loads(audit_path.read_bytes())
            audit["nativeExecutionIds"].remove(record["nativeExecutionId"])
            commands = {tuple(command) for command in service.posts if "--url" not in command or command[command.index("--url") + 1] != get_url}
            audit["commandPolicySha256"] = native.nh.digest([list(command) for command in sorted(commands)])
            audit_path.write_bytes(native.nh.encoded(audit))
            index_path = source / snapshot.INDEX
            index = json.loads(index_path.read_bytes())
            index["artifacts"] = [capsule.descriptor(path.name, path.read_bytes()) for path in sorted(source.iterdir())
                                  if path.name != snapshot.INDEX]
            index_path.write_bytes(native.nh.encoded(index))
            with self.assertRaisesRegex(ValueError, "required"):
                capsule.seal(source, output, RUN)

    def test_native_continuation_resume_is_parent_bound_and_never_reposts(self):
        root_url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        continuation = root_url + "&%24skiptoken=fixture"
        service = native.NativeService(lose_after=4, reader=SnapshotReader({
            root_url: {"value": [], "nextLink": continuation}, continuation: {"value": []},
        }))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    snapshot.acquire(transport, TENANT, SUB, RUN, output)
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request", side_effect=service.request):
                source = snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True)
            self.assertEqual(len(service.posts), 8)
            self.assertEqual(len({tuple(command) for command in service.posts}), 8)
            replay = capsule.replay(capsule.seal(source, output, RUN))
            pages = [row for row in replay["coverage"]["collections"] if row["operationId"] == "keyvault-list"]
            self.assertEqual([row["page"] for row in pages], [1, 2])
            self.assertEqual(pages[0]["nextLink"], continuation)
            self.assertIsNone(pages[1]["nextLink"])

    def test_unknown_native_acceptance_and_foreign_continuation_block_new_reads(self):
        service = native.NativeService(lose_after=1, reader=SnapshotReader())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    snapshot.acquire(transport, TENANT, SUB, RUN, output)
            service.messages = []
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True)
            self.assertEqual(len(service.posts), 1)
        root_url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        foreign = root_url.replace(SUB, OTHER) + "&%24skiptoken=fixture"
        service = native.NativeService(reader=SnapshotReader({root_url: {"value": [], "nextLink": foreign}}))
        with tempfile.TemporaryDirectory() as temporary:
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaisesRegex(ValueError, "continuation exceeds"):
                    snapshot.acquire(transport, TENANT, SUB, RUN, Path(temporary))
            self.assertEqual(len(service.posts), 3)

    def test_rebound_native_bytes_cannot_change_a_get_target_identity(self):
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/storage"
        value = {"id": identifier, "type": "Microsoft.Storage/storageAccounts", "properties": {"minimumTlsVersion": "TLS1_2"}}
        reader = SnapshotReader({
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01": {"value": [value]},
            "https://management.azure.com" + identifier + "?api-version=2023-05-01": value,
        })
        service = native.NativeService(reader=reader)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                source = snapshot.acquire(transport, TENANT, SUB, RUN, output)
            path = next(source.glob("storage-get-*.json"))
            record = json.loads(path.read_bytes())
            record["rows"][0]["configuration"]["id"] += "-other"
            path.write_bytes(capsule.nh.encoded(record))
            index_path = source / snapshot.INDEX
            index = json.loads(index_path.read_bytes())
            for entry in index["artifacts"]:
                if entry["name"] == path.name:
                    entry.update(capsule.descriptor(path.name, path.read_bytes()))
            index_path.write_bytes(capsule.nh.encoded(index))
            with self.assertRaisesRegex(ValueError, "target"):
                capsule.seal(source, output, RUN)

    def test_control_children_follow_only_discovered_parents_and_preserve_exact_rules(self):
        base = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/"
        perimeter = base + "Microsoft.Network/networkSecurityPerimeters/perimeter"
        profile = perimeter + "/profiles/profile"
        association = perimeter + "/resourceAssociations/service"
        rule = profile + "/accessRules/rule"
        scope = base + "Microsoft.Insights/privateLinkScopes/scope"
        linked = scope + "/scopedResources/workspace"
        foreign = f"/subscriptions/{OTHER}/resourceGroups/foreign/providers/Microsoft.OperationalInsights/workspaces/workspace"

        def resource(identifier, resource_type, properties):
            return {"id": identifier, "type": resource_type, "name": identifier.rsplit("/", 1)[1],
                    "location": "eastus", "properties": properties}

        rows = {
            perimeter: resource(perimeter, "Microsoft.Network/networkSecurityPerimeters", {"provisioningState": "Succeeded"}),
            profile: resource(profile, "Microsoft.Network/networkSecurityPerimeters/profiles", {"provisioningState": "Succeeded"}),
            association: resource(association, "Microsoft.Network/networkSecurityPerimeters/resourceAssociations",
                                  {"accessMode": "Enforced", "profile": {"id": profile}, "privateLinkResource": {"id": foreign}}),
            rule: resource(rule, "Microsoft.Network/networkSecurityPerimeters/profiles/accessRules",
                           {"direction": "Inbound", "addressPrefixes": ["0.0.0.0/0", "::/0"],
                            "emailAddresses": ["synthetic-contact-do-not-retain"]}),
            scope: resource(scope, "Microsoft.Insights/privateLinkScopes",
                            {"accessModeSettings": {"ingestionAccessMode": "PrivateOnly", "queryAccessMode": "Open"}}),
            linked: resource(linked, "Microsoft.Insights/privateLinkScopes/scopedResources", {"linkedResourceId": foreign}),
        }
        responses = {}
        for identifier, value in rows.items():
            version = "2024-07-01" if "/Microsoft.Network/" in identifier else "2021-07-01-preview"
            responses["https://management.azure.com" + identifier + "?api-version=" + version] = value
        responses.update({
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityPerimeters?api-version=2024-07-01": {"value": [rows[perimeter]]},
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Insights/privateLinkScopes?api-version=2021-07-01-preview": {"value": [rows[scope]]},
            "https://management.azure.com" + perimeter + "/profiles?api-version=2024-07-01": {"value": [rows[profile]]},
            "https://management.azure.com" + perimeter + "/resourceAssociations?api-version=2024-07-01": {"value": [rows[association]]},
            "https://management.azure.com" + profile + "/accessRules?api-version=2024-07-01": {"value": [rows[rule]]},
            "https://management.azure.com" + scope + "/scopedResources?api-version=2021-07-01-preview": {"value": [rows[linked]]},
        })
        reader = SnapshotReader(responses)
        service = native.NativeService(reader=reader)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                source = snapshot.acquire(transport, TENANT, SUB, RUN, output)
            self.assertEqual(len(service.posts), 17)
            self.assertFalse(any(OTHER in command[command.index("--url") + 1] for command in service.posts if "--url" in command))
            replay = capsule.replay(capsule.seal(source, output, RUN))
            self.assertEqual(len(replay["resources"]), 6)
            observed_rule = next(row for row in replay["resources"] if row["id"] == rule.lower())
            self.assertEqual(observed_rule["observations"][0]["configuration"]["properties"]["addressPrefixes"], ["0.0.0.0/0", "::/0"])
            self.assertNotIn("synthetic-contact-do-not-retain", json.dumps(service.messages))
            self.assertFalse(replay["assessmentPerformed"])

    def test_accepted_native_read_resume_never_reposts(self):
        service = native.NativeService(lose_after=3, reader=SnapshotReader())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            first = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    snapshot.acquire(first, TENANT, SUB, RUN, output)
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request", side_effect=service.request):
                source = snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True)
            self.assertEqual(len(service.posts), 7)
            self.assertEqual(len({tuple(command) for command in service.posts}), 7)
            snapshot.source_members(source)

    def test_completed_source_finalization_recovers_offline_after_checkpoint_failure(self):
        service = native.NativeService(reader=SnapshotReader())
        original_replace = Path.replace
        interrupted = False

        def fail_complete(path, target):
            nonlocal interrupted
            if Path(target).name == "state.json" and not interrupted:
                state = json.loads(path.read_bytes())
                if state["progress"]["complete"]:
                    interrupted = True
                    raise OSError("Synthetic final checkpoint failure")
            return original_replace(path, target)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            first = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(first, "request", side_effect=service.request):
                with patch.object(Path, "replace", autospec=True, side_effect=fail_complete):
                    with self.assertRaisesRegex(OSError, "final checkpoint"):
                        snapshot.acquire(first, TENANT, SUB, RUN, output)
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request") as request:
                source = snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True)
                request.assert_not_called()
            self.assertEqual(len(service.posts), 7)
            snapshot.source_members(source)

    def test_failed_native_context_cannot_resume_into_resource_reads(self):
        def denied(command):
            raise native.nh.ReadFailure("AuthorizationFailed", "permissionDenied")

        service = native.NativeService(reader=denied)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaisesRegex(ValueError, "context is unavailable"):
                    snapshot.acquire(transport, TENANT, SUB, RUN, output)
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request") as request:
                with self.assertRaisesRegex(ValueError, "context"):
                    snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True)
                request.assert_not_called()
            self.assertEqual(len(service.posts), 1)

    def test_reviewed_get_preserves_missing_null_rules_and_filters_before_native_output(self):
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/storage"
        resource = {
            "id": identifier, "type": "Microsoft.Storage/storageAccounts", "name": "storage", "location": "eastus",
            "tags": {"credential": "synthetic-do-not-retain"},
            "properties": {
                "publicNetworkAccess": "Disabled", "minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": True,
                "allowBlobPublicAccess": None, "accessToken": "synthetic-do-not-retain",
                "networkAcls": {"bypass": "None", "defaultAction": "Deny",
                                "ipRules": [{"value": "198.51.100.0/24", "action": "Allow"}],
                                "ipv6Rules": [{"value": "2001:db8::/32", "action": "Allow"}]},
            },
        }
        resources = {
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01": {"value": [resource]},
            "https://management.azure.com" + identifier + "?api-version=2023-05-01": resource,
        }
        reader = SnapshotReader(resources)
        service = native.NativeService(reader=reader)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                source = snapshot.acquire(transport, TENANT, SUB, RUN, output)
            self.assertEqual(len(service.posts), 8)
            directory = capsule.seal(source, output, RUN)
            replay = capsule.replay(directory)
            self.assertEqual(len(replay["resources"]), 1)
            observations = replay["resources"][0]["observations"]
            full = next(row for row in observations if "storage-get" in row["member"])
            properties = full["configuration"]["properties"]
            self.assertEqual(properties["minimumTlsVersion"], "TLS1_2")
            self.assertIsNone(properties["allowBlobPublicAccess"])
            self.assertNotIn("allowSharedKeyAccess", properties)
            self.assertEqual(properties["networkAcls"]["ipRules"][0]["value"], "198.51.100.0/24")
            self.assertEqual(properties["networkAcls"]["ipv6Rules"][0]["value"], "2001:db8::/32")
            self.assertIn("/properties/accessToken", full["omittedPaths"])
            self.assertNotIn("synthetic-do-not-retain", json.dumps(service.messages))
            self.assertNotIn("synthetic-do-not-retain", "".join(path.read_text() for path in source.iterdir()))

    def test_all_catalogued_projections_compile_in_the_native_query_language(self):
        for op in ("context", *snapshot.OPS):
            with self.subTest(operation=op):
                jmespath.compile(snapshot.query(op))

    def test_native_empty_roots_are_captured_audited_sealed_and_replayed(self):
        reader = SnapshotReader()
        service = native.NativeService(reader=reader)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            transport = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                source = snapshot.acquire(transport, TENANT, SUB, RUN, output)
            self.assertEqual(len(service.posts), 7)
            self.assertTrue(all(command[:3] == ["az", "account", "show"] or command[:4] == ["az", "rest", "--method", "get"]
                                for command in service.posts))
            directory = capsule.seal(source, output, RUN)
            manifest = capsule.verify(directory)
            replay = capsule.replay(directory)
            self.assertEqual(manifest["capsuleVersion"], "0.2.0")
            self.assertEqual(replay["profileId"], "native-configuration-snapshot")
            self.assertEqual(replay["resources"], [])
            self.assertTrue(all(row["status"] == "notCollected" for row in replay["eventSources"]))
            self.assertEqual(replay, capsule.replay(directory))
            audit = json.loads((source / "native-audit.json").read_bytes())
            self.assertEqual(len(audit["nativeExecutionIds"]), 7)
            before = len(service.posts)
            resumed = native.bridge.SRETransport(native.ENDPOINT, native.THREAD, "synthetic-token")
            with patch.object(resumed, "request") as request:
                self.assertEqual(snapshot.acquire(resumed, TENANT, SUB, RUN, output, resume=True), source)
                request.assert_not_called()
            self.assertEqual(len(service.posts), before)


if __name__ == "__main__":
    unittest.main()
