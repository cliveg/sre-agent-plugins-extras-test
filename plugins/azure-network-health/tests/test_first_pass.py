from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_sre_transport as transport_tests
import first_pass as fp


nh = fp.nh
SUB, RUN, TIME = transport_tests.SUB, transport_tests.RUN, transport_tests.TIME
TENANT = "00000000-0000-4000-8000-000000000055"
OTHER = "00000000-0000-4000-8000-000000000099"
spec = importlib.util.spec_from_file_location("first_pass_bridge", transport_tests.ROOT / "tools" / "network_health_first_pass.py")
sys.path.insert(0, str(transport_tests.ROOT / "tools"))
if spec is None or spec.loader is None:
    raise RuntimeError("Cannot load first-pass bridge")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class FirstPassReader:
    def __init__(self):
        self.calls = []
        self.denied = False
        self.limit = False

    def __call__(self, command):
        self.calls.append(command)
        if command == fp.subscription_command(TENANT):
            return nh.ReadResponse({"count": 101 if self.limit else 2, "data": [
                {"subscriptionId": SUB, "displayName": "prod-spoke", "state": "Enabled", "tenantId": TENANT},
                {"subscriptionId": OTHER, "displayName": "shared-network-hub", "state": "Enabled", "tenantId": TENANT},
            ]})
        subscription = command[command.index("--subscriptions") + 1]
        if self.denied and subscription == OTHER:
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        token = nh.request_token(command)
        root = f"/subscriptions/{subscription}/resourceGroups/network/providers/Microsoft.Network"
        if token:
            rows = [{"id": root + "/virtualHubs/hub", "type": "Microsoft.Network/virtualHubs",
                     "name": "hub", "virtualWanId": root + "/virtualWans/wan"}]
        else:
            rows = [{"id": root + "/virtualNetworks/spoke", "type": "Microsoft.Network/virtualNetworks",
                     "name": "spoke", "remoteVNetIds": [f"/subscriptions/{OTHER}/resourceGroups/network/providers/Microsoft.Network/virtualNetworks/hub"],
                     "tags": {"secret": "omit"}, "properties": {"credentials": "omit"}}]
        for row in rows:
            row.update({"subscriptionId": subscription, "resourceGroup": "network", "location": "eastus"})
        return nh.ReadResponse({"count": len(rows), "total_records": 2, "data": rows,
                                "skip_token": "page-two" if token is None else None})


class FirstPassTests(unittest.TestCase):
    def make(self, reader=None):
        reader = reader or FirstPassReader()
        envelope = fp.collect(TENANT, RUN, reader, clock=lambda: TIME)
        return envelope, fp.summarize(envelope), reader

    def test_discovery_reads_visible_scopes_without_extra_approvals_and_stops_at_summary(self):
        envelope, summary, reader = self.make()
        self.assertEqual(len(reader.calls), 5)
        self.assertEqual(len(envelope["subscriptions"]), 2)
        self.assertEqual(summary["phase"], "initial-scope-and-components-not-full-assessment")
        self.assertTrue(all(fp.matches_command(command, TENANT, [SUB, OTHER]) for command in reader.calls))
        self.assertFalse(any("nsg-rules" in command for command in reader.calls))
        self.assertTrue(all(row["roleHints"]["classification"] == "INFERRED" for row in summary["subscriptions"]))

    def test_hub_spoke_and_vwan_signs_never_claim_complete_topology_or_traffic(self):
        _, summary, _ = self.make()
        sub = next(sub for sub in summary["subscriptions"] if sub["subscriptionId"] == SUB)
        self.assertEqual(len(sub["architectureSigns"]), 2)
        self.assertTrue(all(sign["classification"] == "INFERRED" for sign in sub["architectureSigns"]))
        self.assertEqual(len(sub["externalReferences"]), 1)
        self.assertNotIn("credentials", json.dumps(summary))
        self.assertNotIn('"tags"', json.dumps(summary))

    def test_denied_scope_is_reported_and_supplement_preserves_original_attempt(self):
        reader = FirstPassReader()
        reader.denied = True
        envelope, summary, _ = self.make(reader)
        denied = next(sub for sub in summary["subscriptions"] if sub["subscriptionId"] == OTHER)
        self.assertEqual(denied["collection"]["status"], "permissionDenied")
        self.assertEqual(denied["componentCounts"], {})
        supplemental = {"subscriptionId": OTHER, "querySha256": nh.digest(fp.QUERY), "identityDescription": "operator-Entra-context",
                        "collectedAt": TIME, "payload": {"data": [], "count": 0, "total_records": 0, "skip_token": None}}
        updated = fp.apply_supplement(envelope, supplemental)
        sub = next(sub for sub in fp.summarize(updated)["subscriptions"] if sub["subscriptionId"] == OTHER)
        self.assertEqual(sub["collection"]["status"], "succeeded")
        self.assertEqual(sub["collection"]["originalAttempt"]["status"], "permissionDenied")
        self.assertIn("operator-supplied", fp.render(fp.summarize(updated)).lower())
        supplemental["subscriptionId"] = TENANT
        with self.assertRaisesRegex(ValueError, "not discovered"):
            fp.apply_supplement(envelope, supplemental)

    def test_bad_or_partial_supplement_never_bypasses_query_scope_or_coverage(self):
        envelope, _, _ = self.make()
        supplemental = {"subscriptionId": SUB, "querySha256": nh.digest(fp.QUERY), "identityDescription": "operator",
                        "collectedAt": TIME, "payload": {"data": [], "count": 0, "total_records": 2, "skip_token": "next"}}
        with self.assertRaisesRegex(ValueError, "complete selected response"):
            fp.apply_supplement(envelope, supplemental)
        supplemental["querySha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "query/identity"):
            fp.apply_supplement(envelope, supplemental)

    def test_read_policy_rejects_unlisted_subscriptions_mutations_and_broad_queries(self):
        command = fp.component_command(SUB)
        self.assertTrue(fp.matches_command(command, TENANT, [SUB]))
        self.assertFalse(fp.matches_command(command, TENANT, [OTHER]))
        self.assertFalse(fp.matches_command([v.replace(fp.QUERY, "Resources") for v in command], TENANT, [SUB]))
        self.assertFalse(fp.matches_command(["az", "account", "set", "--subscription", SUB], TENANT, [SUB]))

    def test_first_pass_resume_retrieves_accepted_page_without_reposting(self):
        reader = FirstPassReader()
        service = transport_tests.NativeService(lose_after=3, reader=reader)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            t = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(t, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    host.acquire(t, TENANT, RUN, root)
            t2 = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(t2, "request", side_effect=service.request):
                envelope = host.acquire(t2, TENANT, RUN, root, True)
            self.assertEqual(len(service.posts), 5)
            self.assertEqual(len({tuple(command) for command in service.posts}), 5)
            t3 = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(t3, "request", side_effect=service.request):
                self.assertEqual(host.acquire(t3, TENANT, RUN, root, True), envelope)
            self.assertEqual(len(service.posts), 5)

    def test_first_pass_selected_checkpoint_failure_recovers_without_reposting(self):
        service = transport_tests.NativeService(reader=FirstPassReader())
        real_save = host.bridge.save_document
        interrupted = False

        def failed(path, state):
            nonlocal interrupted
            if path.name == "state.json" and state["progress"].get("subscriptionDiscovery") is not None and not interrupted:
                interrupted = True
                raise OSError("First-pass selected checkpoint write failed")
            real_save(path, state)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with patch.object(host.bridge, "save_document", side_effect=failed):
                    with self.assertRaisesRegex(OSError, "selected checkpoint write failed"):
                        host.acquire(transport, TENANT, RUN, root)
            checkpoint = root / "first-pass-acquisition" / RUN
            state = nh.load(checkpoint / "state.json")
            self.assertIsNotNone(state["pendingRead"])
            self.assertIsNone(transport.save_pending)
            self.assertFalse(transport.collection_only)
            self.assertFalse((checkpoint / ".acquisition.lock").exists())
            resumed = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = host.acquire(resumed, TENANT, RUN, root, True)
            self.assertEqual(len(envelope["subscriptions"]), 2)
            self.assertEqual(len(service.posts), 5)
            self.assertEqual(len({tuple(command) for command in service.posts}), 5)
            self.assertIsNone(nh.load(checkpoint / "state.json")["pendingRead"])

    def test_first_pass_invalid_checkpoint_is_preserved_before_requests(self):
        for field, value in (
            ("stateVersion", "99.0.0"), ("endpoint", "https://other.azuresre.ai"),
            ("threadId", OTHER), ("tenantId", OTHER), ("runId", OTHER),
            ("policySha256", "0" * 64), ("progressSha256", "0" * 64),
            ("unexpectedField", True),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                service = transport_tests.NativeService(lose_after=1, reader=FirstPassReader())
                transport = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
                with patch.object(transport, "request", side_effect=service.request):
                    with self.assertRaisesRegex(RuntimeError, "response loss"):
                        host.acquire(transport, TENANT, RUN, root)
                checkpoint = root / "first-pass-acquisition" / RUN
                path = checkpoint / "state.json"
                state = nh.load(path)
                state[field] = value
                host.bridge.save_document(path, state)
                before = path.read_bytes()
                resumed = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
                with patch.object(resumed, "request") as request:
                    with self.assertRaisesRegex(ValueError, "identity/policy/hash mismatch"):
                        host.acquire(resumed, TENANT, RUN, root, True)
                    request.assert_not_called()
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse((checkpoint / ".acquisition.lock").exists())
                self.assertFalse(resumed.collection_only)
                self.assertIsNone(resumed.save_pending)

    def test_first_pass_existing_lock_is_preserved_before_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = root / "first-pass-acquisition" / RUN
            checkpoint.mkdir(parents=True)
            lock = checkpoint / ".acquisition.lock"
            lock.mkdir()
            transport = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(transport, "request") as request:
                with self.assertRaises(FileExistsError):
                    host.acquire(transport, TENANT, RUN, root, True)
                request.assert_not_called()
            self.assertTrue(lock.exists())
            self.assertFalse(transport.collection_only)

    def test_first_pass_unknown_acceptance_never_reposts(self):
        service = transport_tests.NativeService(lose_after=1, reader=FirstPassReader())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    host.acquire(transport, TENANT, RUN, root)
            service.messages = []
            resumed = transport_tests.bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-token")
            with patch.object(resumed, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    host.acquire(resumed, TENANT, RUN, root, True)
            self.assertEqual(len(service.posts), 1)
            checkpoint = root / "first-pass-acquisition" / RUN
            self.assertIsNotNone(nh.load(checkpoint / "state.json")["pendingRead"])
            self.assertFalse((checkpoint / ".acquisition.lock").exists())

    def test_empty_subscription_list_and_selection_limit_are_not_complete_tenant_claims(self):
        reader = FirstPassReader()
        reader.limit = True
        envelope, _, _ = self.make(reader)
        self.assertEqual(envelope["subscriptionDiscovery"]["status"], "partial")
        self.assertIn("SubscriptionSelectionBudgetExceeded", envelope["subscriptionDiscovery"]["issues"])
        empty = fp.collect(TENANT, RUN, lambda command: nh.ReadResponse({"count": 0, "data": []}), clock=lambda: TIME)
        self.assertEqual(fp.summarize(empty)["subscriptions"], [])
        self.assertIn("complete tenant inventory", fp.summarize(empty)["limitations"][0])

    def test_public_preference_is_declared_and_monitor_types_are_not_conflated(self):
        _, summary, _ = self.make()
        self.assertEqual(summary["privateAccessBaseline"]["classification"], "DECLARED")
        self.assertEqual(summary["privateAccessBaseline"]["exceptions"], [])
        self.assertIn("microsoft.monitor/accounts", fp.COMPONENT_TYPES)
        self.assertIn("microsoft.operationalinsights/workspaces", fp.COMPONENT_TYPES)
        self.assertIn("not supported", " ".join(fp.BASELINE["limitations"]))
        model = transport_tests.fixture_tests.NetworkHealthTests().make()[1]
        a = nh.assess(model)
        self.assertEqual(a["accessPreference"], fp.BASELINE)
        altered = copy.deepcopy(a)
        altered["accessPreference"]["preference"] = "public-default"
        with self.assertRaisesRegex(ValueError, "access preference"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("Declared access preference", summary)
        self.assertIn("Declared access preference", engineering)
        with self.assertRaisesRegex(ValueError, "access baseline"):
            nh.verify_reports(a, summary.replace("Private preferred", "Public preferred"), engineering)

    def test_reports_are_persistent_and_refuse_overwrite(self):
        envelope, summary, _ = self.make()
        with tempfile.TemporaryDirectory() as directory:
            result = fp.write_summary(envelope, Path(directory))
            folder = Path(result["directory"])
            self.assertEqual({p.name for p in folder.iterdir()}, {"selected-input.json", "scope-summary.json", "scope-summary.md"})
            self.assertEqual(nh.load(folder / "scope-summary.json"), summary)
            with self.assertRaises(FileExistsError):
                fp.write_summary(envelope, Path(directory))

    def test_subscription_scope_duplicates_and_wrong_tenant_fail_explicitly(self):
        def duplicates(command):
            response = FirstPassReader()(command)
            if command == fp.subscription_command(TENANT):
                response.payload["data"][1]["subscriptionId"] = SUB
            return response
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            fp.collect(TENANT, RUN, duplicates, clock=lambda: TIME)
        envelope, _, _ = self.make()
        envelope["subscriptions"][0]["tenantId"] = OTHER
        with self.assertRaisesRegex(ValueError, "tenant mismatch"):
            fp.summarize(envelope)

    def test_unexpected_selected_values_and_cross_scope_rows_are_not_retained(self):
        envelope, _, _ = self.make()
        collection = envelope["collections"][0]
        collection["rows"][0]["subscriptionId"] = OTHER
        with self.assertRaisesRegex(ValueError, "scope/type"):
            fp.summarize(envelope)
        envelope, _, _ = self.make()
        envelope["unexpected"] = "secret"
        with self.assertRaisesRegex(ValueError, "envelope fields"):
            fp.summarize(envelope)
