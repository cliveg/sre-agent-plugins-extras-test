from __future__ import annotations

import importlib.util
import copy
import hashlib
import io
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_network_health as fixture_tests
from test_network_health import FixtureReader, PrivateFixtureReader, RUN, TIME


ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "plugins" / "azure-network-health" / "skills" / "azure-network-health-assessment"
sys.path.insert(0, str(SKILL))
import network_health as nh

SPEC = importlib.util.spec_from_file_location("network_health_transport", ROOT / "tools" / "network_health_sre.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load development transport")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

SUB = "00000000-0000-4000-8000-000000000002"
THREAD = "00000000-0000-4000-8000-000000000001"
ENDPOINT = "https://fixture.eastus2.azuresre.ai"


def audit_message(**fields):
    return {**{key: None for key in bridge.AUDIT_SURFACES}, **fields}


class NativeService:
    def __init__(self, lose_after=None, reader=None):
        self.reader = reader or FixtureReader(1)
        self.lose_after = lose_after
        self.posts = []
        self.messages = []

    def request(self, path, data=None, content_type="application/json"):
        if data is not None:
            prompt = json.loads(data)["text"]
            command = shlex.split(prompt.rsplit("\n", 1)[1])
            self.posts.append(command)
            try:
                response = self.reader(command)
                status, output, error = "Completed", json.dumps(response.payload), None
            except nh.ReadFailure as failure:
                status, output, error = "Failed", None, failure.code
            execution = {
                "id": "native-" + str(len(self.posts)), "command": shlex.join(command),
                "status": status, "output": output, "error": error,
            }
            self.messages.extend([
                audit_message(text=prompt, author={"role": "User"}),
                audit_message(azCliExecution=execution, author={"role": "SREAgent"}),
            ])
            if len(self.posts) == self.lose_after:
                raise RuntimeError("Injected response loss")
            return {}
        query = bridge.urllib.parse.parse_qs(bridge.urllib.parse.urlsplit(path).query)
        skip, top = int(query["skip"][0]), int(query["top"][0])
        messages = list(reversed(self.messages)) if query["orderby"][0].endswith("desc") else self.messages
        return {"state": "Idle", "value": messages[skip:skip + top]}


class TransportTests(unittest.TestCase):
    def test_arm_continuation_accepted_read_resume_never_reposts(self):
        import test_arm_pagination as pagination
        reader = pagination.PagedDNSReader()
        nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True)
        loss = next(i + 1 for i, command in enumerate(reader.calls)
                    if nh.child_kind(command) == "dns-inbound-endpoints" and nh.request_token(command))
        service = NativeService(lose_after=loss, reader=pagination.PagedDNSReader())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, include_dns_paths=True)
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.6.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            final = self.make()
            before = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(len(service.posts), before)

    def test_dns_paths_rest_accepted_read_resumes_and_mode_is_bound(self):
        import test_dns_paths as paths
        reader = paths.DNSPathFixtureReader(1)
        nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, include_dns_paths=True)
        loss = next(i + 1 for i, command in enumerate(reader.calls) if nh.child_kind(command) == "dns-forwarding-rules")
        service = NativeService(lose_after=loss, reader=paths.DNSPathFixtureReader(1))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_dns_paths=True)
            rejected = self.make()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "DNS path acquisition differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_dns_paths=False)
                request.assert_not_called()
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.6.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(c) for c in service.posts}))

    def test_metadata_accepted_parent_read_resumes_without_reposting_and_mode_is_bound(self):
        import test_dns_record_metadata as metadata
        reader = metadata.MetadataFixtureReader(1)
        nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, include_record_metadata=True)
        service = NativeService(lose_after=len(reader.calls) - 1, reader=metadata.MetadataFixtureReader(1))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_record_metadata=True)
            rejected = self.make()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "metadata acquisition differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_record_metadata=False)
                request.assert_not_called()
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.4.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(c) for c in service.posts}))
            self.assertNotIn("secret-name", (bridge.acquisition_directory(root, RUN) / "state.json").read_text())

    def test_dns_planning_central_accepted_read_resumes_and_scope_is_bound(self):
        import test_dns_planning as planning
        reader = planning.PlanningFixtureReader(1)
        nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME,
                   include_dns_planning=True, dns_subscriptions=[planning.HOST])
        service = NativeService(lose_after=len(reader.calls) - 1, reader=planning.PlanningFixtureReader(1))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_dns_planning=True, dns_subscriptions=[planning.HOST])
            rejected = self.make()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "DNS-hosting subscription scope"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, dns_subscriptions=[SUB])
                request.assert_not_called()
                with self.assertRaisesRegex(ValueError, "DNS planning acquisition scope"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_dns_planning=False)
                request.assert_not_called()
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["dnsHostingSubscriptionIds"], [planning.HOST])
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            self.assertEqual(len(envelope["collections"]), 17)
            final = self.make()
            before = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(before, len(service.posts))

    def test_dns_host_read_scope_rejects_service_inventory_and_new_hosts_before_dispatch(self):
        import test_dns_planning as planning
        transport = self.make()
        operations = nh.records(nh.catalog("1.2.0")["operations"])
        transport.approved_operations = {planning.HOST: [op for op in operations if op["operationId"] in ("private-dns-zones", "private-dns-links")]}
        service_op = next(op for op in operations if op["operationId"] == "private-link-services")
        zone_op = next(op for op in operations if op["operationId"] == "private-dns-zones")
        with patch.object(transport, "request") as request:
            for command in (nh.command_for(service_op, planning.HOST, 1, None), nh.command_for(zone_op, SUB, 1, None)):
                with self.assertRaisesRegex(ValueError, "exceeds approved"):
                    transport.read(command)
            request.assert_not_called()

    def make(self):
        return bridge.SRETransport(ENDPOINT, THREAD, "synthetic-not-a-secret")

    def checkpoint(self, root: Path, transport=None):
        transport = transport or self.make()
        envelope = nh.collect(SUB, RUN, FixtureReader(), "synthetic-fixture", clock=lambda: TIME)
        model = nh.normalize(envelope)
        result = nh.bundle(model, nh.assess(model), root)
        bridge.prepare_upload(transport, SUB, RUN, root, envelope, result)
        directory = bridge.state_directory(root, RUN)
        content = (directory / "selected-input.json").read_bytes()
        receipt = {
            "fileId": "fixture-file", "fileName": "collection-input-" + RUN + ".json",
            "fileSize": len(content), "contentType": "application/json",
            "downloadUrl": f"/api/files/{THREAD}/fixture-file_collection-input-{RUN}.json",
        }
        return transport, directory, content, receipt

    def uploaded(self, receipt):
        def upload(name, content, before_send):
            before_send()
            return [receipt]
        return upload

    def test_acquisition_resumes_accepted_page_without_reposting(self) -> None:
        service = NativeService(lose_after=3)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1)
            checkpoint = bridge.acquisition_directory(root, RUN)
            state = nh.load(checkpoint / "state.json")
            self.assertIsNotNone(state["pendingRead"])
            self.assertEqual(state["progress"]["current"]["nextPage"], 1)
            self.assertNotIn(first.token, (checkpoint / "state.json").read_text())
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            self.assertEqual(len(envelope["collections"]), 9)
            self.assertIsNone(nh.load(checkpoint / "state.json")["pendingRead"])
            last = self.make()
            before = len(service.posts)
            with patch.object(last, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(last, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(len(service.posts), before)

    def test_private_acquisition_mode_and_child_read_resume_are_bound(self) -> None:
        reader = PrivateFixtureReader(1)
        service = NativeService(lose_after=19, reader=reader)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_private=True)
            state = nh.load(bridge.acquisition_directory(root, RUN) / "state.json")
            self.assertTrue(state["includePrivateConnectivity"])
            self.assertIsNotNone(state["pendingRead"])
            self.assertEqual(state["progress"]["current"]["collection"]["operationId"], "private-dns-groups")
            rejected = self.make()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "scope differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_private=False)
                request.assert_not_called()
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["queryCatalogVersion"], "1.1.0")
            self.assertEqual(len(service.posts), 19)
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))

    def test_only_exact_parent_scoped_dns_group_read_is_permitted(self) -> None:
        transport = self.make()
        op = next(op for op in nh.catalog("1.1.0")["operations"] if op["operationId"] == "private-dns-groups")
        target = {"name": "storage", "resourceGroup": "fixture", "subscriptionId": SUB}
        command = nh.command_for(op, SUB, 1, None, target)
        self.assertTrue(nh.matches_command(command, SUB, 1000))
        for changed in (
            [value.replace("list", "delete") for value in command],
            command + ["--include-secret"],
            command[:-2],
        ):
            with self.subTest(changed=changed), patch.object(transport, "request") as request:
                with self.assertRaises(ValueError):
                    transport.read(changed)
                request.assert_not_called()

    def test_unknown_native_acceptance_blocks_repost(self) -> None:
        service = NativeService(lose_after=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    bridge.acquire(transport, SUB, RUN, root, 1)
            service.messages = []
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(len(service.posts), 1)

    def test_readiness_interruption_is_resumable_not_a_terminal_collection_failure(self) -> None:
        service = NativeService()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with patch.object(first, "wait_for_idle", side_effect=nh.ReadFailure("ThreadDidNotBecomeIdle")):
                    with self.assertRaisesRegex(RuntimeError, "readiness interrupted"):
                        bridge.acquire(first, SUB, RUN, root, 1)
            self.assertEqual(len(service.posts), 0)
            state = nh.load(bridge.acquisition_directory(root, RUN) / "state.json")
            self.assertIsNone(state["pendingRead"])
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertTrue(all(c["status"] == "succeeded" for c in envelope["collections"]))

    def test_page_checkpoint_failure_recovers_completed_execution_without_new_post(self) -> None:
        service = NativeService()
        real_save = bridge.save_state
        interrupted = False

        def failed(directory, state):
            nonlocal interrupted
            current = state["progress"].get("current")
            if current and current["collection"]["operationId"] == "vnets" and current["nextPage"] == 1 and not interrupted:
                interrupted = True
                raise OSError("Selected-page checkpoint write failed")
            real_save(directory, state)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with patch.object(bridge, "save_state", side_effect=failed):
                    with self.assertRaisesRegex(OSError, "checkpoint write failed"):
                        bridge.acquire(transport, SUB, RUN, root, 1)
            state = nh.load(bridge.acquisition_directory(root, RUN) / "state.json")
            self.assertIsNotNone(state["pendingRead"])
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))

    def test_terminal_permission_failure_is_retained_not_retried(self) -> None:
        reader = FixtureReader(1)
        reader.fail = "nsgs"
        service = NativeService(lose_after=11, reader=reader)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    bridge.acquire(transport, SUB, RUN, root, 1)
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            nsgs = next(c for c in envelope["collections"] if c["operationId"] == "nsgs")
            self.assertEqual(nsgs["status"], "permissionDenied")
            self.assertIn("PermissionDenied", nsgs["issues"])
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            self.assertEqual(nh.assess(nh.normalize(envelope))["status"], "incomplete-configuration-triage")

    def test_pending_read_reconciliation_pages_complete_history(self) -> None:
        service = NativeService(lose_after=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    bridge.acquire(transport, SUB, RUN, root, 1)
            service.messages.extend([audit_message(author={"role": "SREAgent"}, text="wait") for _ in range(120)])
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request) as request:
                bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertTrue(any("skip=100" in call.args[0] for call in request.call_args_list))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))

    def test_duplicate_pending_native_executions_stop_recovery(self) -> None:
        service = NativeService(lose_after=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    bridge.acquire(transport, SUB, RUN, root, 1)
            duplicate = copy.deepcopy(service.messages[-1])
            duplicate["azCliExecution"]["id"] = "unexpected-duplicate"
            service.messages.append(duplicate)
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "Duplicate outstanding"):
                    bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(len(service.posts), 1)

    def test_acquisition_scope_page_size_catalog_and_integrity_are_bound(self) -> None:
        for field, value in (
            ("endpoint", "https://other.azuresre.ai"), ("threadId", "00000000-0000-4000-8000-000000000004"),
            ("subscriptionId", "00000000-0000-4000-8000-000000000004"),
            ("runId", "00000000-0000-4000-8000-000000000004"),
            ("catalogSha256", "0" * 64), ("progressSha256", "0" * 64), ("capabilityVersion", "99.0.0"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                service = NativeService(lose_after=1)
                transport = self.make()
                with patch.object(transport, "request", side_effect=service.request):
                    with self.assertRaises(RuntimeError):
                        bridge.acquire(transport, SUB, RUN, root, 1)
                checkpoint = bridge.acquisition_directory(root, RUN)
                state = nh.load(checkpoint / "state.json")
                state[field] = value
                bridge.save_state(checkpoint, state)
                resumed = self.make()
                with patch.object(resumed, "request") as request:
                    with self.assertRaises(ValueError):
                        bridge.acquire(resumed, SUB, RUN, root, resume=True)
                    request.assert_not_called()
                self.assertFalse((checkpoint / ".acquisition.lock").exists())

    def test_acquisition_lock_blocks_before_loading_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = bridge.acquisition_directory(root, RUN)
            checkpoint.mkdir(parents=True)
            lock = checkpoint / ".acquisition.lock"
            lock.mkdir()
            with patch.object(bridge.nh, "load") as load:
                with self.assertRaises(FileExistsError):
                    bridge.acquire(self.make(), SUB, RUN, root, resume=True)
                load.assert_not_called()
            self.assertTrue(lock.exists())

    def test_existing_completed_bundle_is_verified_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, _, _ = self.checkpoint(root)
            model = nh.load(root / "runs" / RUN / "observed-network.json")
            assessment = nh.load(root / "runs" / RUN / "assessment.json")
            before = {path.name: path.read_bytes() for path in (root / "runs" / RUN).iterdir()}
            with patch.object(nh, "bundle") as bundle:
                result = bridge.existing_bundle(model, assessment, root)
                bundle.assert_not_called()
            self.assertEqual(set(result["artifacts"]), bridge.ARTIFACT_NAMES)
            self.assertEqual(before, {path.name: path.read_bytes() for path in (root / "runs" / RUN).iterdir()})
            (root / "runs" / RUN / "assessment.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "differs from checkpoint"):
                bridge.existing_bundle(model, assessment, root)

    def test_checkpoint_preserves_selected_bytes_and_excludes_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport, checkpoint, content, _ = self.checkpoint(Path(directory))
            state, validated = bridge.validate_upload(transport, SUB, RUN, Path(directory))
            self.assertEqual(content, validated)
            self.assertEqual(state["phase"], "prepared")
            self.assertEqual(nh.obj(state["result"])["inputSha256"], hashlib.sha256(content).hexdigest())
            self.assertNotIn(transport.token, (checkpoint / "state.json").read_text())
            self.assertEqual(len(list((Path(directory) / "runs" / RUN).iterdir())), 4)

    def test_pre_dispatch_failure_remains_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, content, receipt = self.checkpoint(root)
            with patch.object(transport, "wait_for_idle", side_effect=RuntimeError("Preflight failure")):
                with patch.object(transport, "request") as request:
                    with self.assertRaisesRegex(RuntimeError, "Preflight failure"):
                        bridge.resume_upload(transport, SUB, RUN, root)
                    request.assert_not_called()
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "prepared")
            with patch.object(transport, "upload", side_effect=self.uploaded(receipt)):
                with patch.object(transport, "download", return_value=content):
                    result = bridge.resume_upload(transport, SUB, RUN, root)
            self.assertTrue(result["uploadVerified"])
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "verified")

    def test_accepted_upload_error_requires_actual_receipt_without_reposting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, content, receipt = self.checkpoint(root)

            def accepted(name, content, before_send):
                before_send()
                raise bridge.SREHttpError(503)

            with patch.object(transport, "upload", side_effect=accepted):
                with self.assertRaises(bridge.SREHttpError):
                    bridge.resume_upload(transport, SUB, RUN, root)
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "uploadStarted")
            with patch.object(transport, "upload") as upload, patch.object(transport, "download") as download:
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    bridge.resume_upload(transport, SUB, RUN, root)
                upload.assert_not_called()
                download.assert_not_called()
                receipt_file = root / "actual-receipt.json"
                receipt_file.write_text(json.dumps([receipt]))
                download.return_value = content
                result = bridge.resume_upload(transport, SUB, RUN, root, receipt_file)
                self.assertTrue(result["uploadVerified"])
                upload.assert_not_called()

    def test_saved_receipt_survives_retrieval_failure_and_skips_repeat_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, content, receipt = self.checkpoint(root)
            with patch.object(transport, "upload", side_effect=self.uploaded(receipt)) as upload:
                with patch.object(transport, "download", side_effect=bridge.SREHttpError(404)):
                    with self.assertRaises(bridge.SREHttpError):
                        bridge.resume_upload(transport, SUB, RUN, root)
                self.assertEqual(upload.call_count, 1)
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "receiptStored")
            with patch.object(transport, "upload") as upload, patch.object(transport, "download", return_value=content):
                bridge.resume_upload(transport, SUB, RUN, root)
                bridge.resume_upload(transport, SUB, RUN, root)
                upload.assert_not_called()

    def test_corrupt_download_is_not_success_and_recovery_keeps_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, content, receipt = self.checkpoint(root)
            with patch.object(transport, "upload", side_effect=self.uploaded(receipt)):
                with patch.object(transport, "download", return_value=b"corrupt"):
                    with self.assertRaisesRegex(ValueError, "differs from checkpoint"):
                        bridge.resume_upload(transport, SUB, RUN, root)
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "receiptStored")
            with patch.object(transport, "upload") as upload, patch.object(transport, "download", return_value=content):
                self.assertTrue(bridge.resume_upload(transport, SUB, RUN, root)["uploadVerified"])
                upload.assert_not_called()

    def test_checkpoint_identity_and_local_corruption_stop_before_network(self) -> None:
        for kind in ("endpoint", "thread", "scope", "run", "input", "artifact"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                transport, checkpoint, _, _ = self.checkpoint(root)
                scope = SUB
                if kind == "endpoint":
                    transport.endpoint = "https://other.eastus2.azuresre.ai"
                elif kind == "thread":
                    transport.thread_id = "00000000-0000-4000-8000-000000000004"
                elif kind == "scope":
                    scope = "00000000-0000-4000-8000-000000000004"
                elif kind == "run":
                    state = nh.load(checkpoint / "state.json")
                    state["runId"] = "00000000-0000-4000-8000-000000000004"
                    bridge.save_state(checkpoint, state)
                elif kind == "input":
                    (checkpoint / "selected-input.json").write_bytes(b"corrupt")
                else:
                    (root / "runs" / RUN / "network-assessment.md").write_bytes(b"corrupt")
                with patch.object(transport, "upload") as upload, patch.object(transport, "download") as download:
                    with self.assertRaises(ValueError):
                        bridge.resume_upload(transport, scope, RUN, root)
                    upload.assert_not_called()
                    download.assert_not_called()

    def test_receipt_mismatch_or_untrusted_url_is_rejected_without_network(self) -> None:
        for key, value in (
            ("fileName", "different.json"), ("fileSize", 0),
            ("contentType", "text/plain"), ("downloadUrl", "https://evil.example/file"),
            ("downloadUrl", f"/api/files/00000000-0000-4000-8000-000000000004/file"),
            ("downloadUrl", f"/api/files/{THREAD}/file?token=private"),
        ):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                transport, _, _, receipt = self.checkpoint(root)
                receipt[key] = value
                receipt_file = root / "actual-receipt.json"
                receipt_file.write_text(json.dumps(receipt))
                with patch.object(transport, "upload") as upload, patch.object(transport, "download") as download:
                    with self.assertRaises(ValueError):
                        bridge.resume_upload(transport, SUB, RUN, root, receipt_file)
                    upload.assert_not_called()
                    download.assert_not_called()

    def test_upload_checkpoint_write_failure_prevents_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, _, _ = self.checkpoint(root)
            with patch.object(transport, "wait_for_idle"), patch.object(transport, "request") as request:
                with patch.object(bridge, "save_state", side_effect=OSError("Checkpoint write failed")):
                    with self.assertRaisesRegex(OSError, "Checkpoint write failed"):
                        bridge.resume_upload(transport, SUB, RUN, root)
                request.assert_not_called()
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "prepared")
            self.assertFalse((checkpoint / ".upload.lock").exists())

    def test_receipt_checkpoint_failure_leaves_ambiguous_upload_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, _, receipt = self.checkpoint(root)
            real_save = bridge.save_state

            def failed(directory, state):
                if state["phase"] == "receiptStored":
                    raise OSError("Receipt write failed")
                real_save(directory, state)

            with patch.object(transport, "upload", side_effect=self.uploaded(receipt)):
                with patch.object(bridge, "save_state", side_effect=failed):
                    with self.assertRaisesRegex(OSError, "Receipt write failed"):
                        bridge.resume_upload(transport, SUB, RUN, root)
            self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "uploadStarted")
            with patch.object(transport, "upload") as upload:
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    bridge.resume_upload(transport, SUB, RUN, root)
                upload.assert_not_called()

    def test_existing_upload_lock_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, _, _ = self.checkpoint(root)
            lock = checkpoint / ".upload.lock"
            lock.mkdir()
            with patch.object(transport, "upload") as upload:
                with self.assertRaises(FileExistsError):
                    bridge.resume_upload(transport, SUB, RUN, root)
                upload.assert_not_called()
            self.assertTrue(lock.exists())

    def test_upload_receipt_persists_only_needed_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, content, receipt = self.checkpoint(root)
            receipt["unneededProperty"] = "private-extra"
            with patch.object(transport, "upload", side_effect=self.uploaded(receipt)):
                with patch.object(transport, "download", return_value=content):
                    result = bridge.resume_upload(transport, SUB, RUN, root)
            self.assertNotIn("private-extra", (checkpoint / "state.json").read_text())
            self.assertNotIn("unneededProperty", nh.records(result["attachment"])[0])

    def test_previous_capability_upload_checkpoint_still_validates_without_relabeling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, checkpoint, _, _ = self.checkpoint(root)
            bundle_dir = root / "runs" / RUN
            model, assessment = nh.load(bundle_dir / "observed-network.json"), nh.load(bundle_dir / "assessment.json")
            model["run"]["capabilityVersion"] = "0.1.1"
            assessment["capabilityVersion"] = "0.1.1"
            assessment["observationArtifact"]["sha256"] = hashlib.sha256(nh.encoded(model)).hexdigest()
            summary, engineering = nh.render(assessment)
            historical = {
                "observed-network.json": nh.encoded(model), "assessment.json": nh.encoded(assessment),
                "network-assessment.md": summary.encode(), "network-evidence.md": engineering.encode(),
            }
            state = nh.load(checkpoint / "state.json")
            for name, content in historical.items():
                (bundle_dir / name).write_bytes(content)
                state["result"]["artifacts"][name]["sha256"] = hashlib.sha256(content).hexdigest()
            bridge.save_state(checkpoint, state)
            bridge.validate_upload(transport, SUB, RUN, root)
            self.assertEqual(nh.load(bundle_dir / "observed-network.json")["run"]["capabilityVersion"], "0.1.1")

    def test_resume_cli_never_collects_or_rebuilds_existing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, _, content, receipt = self.checkpoint(root)
            before = {p.name: p.read_bytes() for p in (root / "runs" / RUN).iterdir()}
            args = [
                "bridge", "--endpoint", ENDPOINT, "--thread-id", THREAD, "--subscription-id", SUB,
                "--run-id", RUN, "--output-root", str(root), "--resume-upload",
            ]
            with patch.object(sys, "argv", args), patch.object(bridge, "access_token", return_value="fixture"):
                with patch.object(bridge, "SRETransport", return_value=transport):
                    with patch.object(transport, "upload", side_effect=self.uploaded(receipt)):
                        with patch.object(transport, "download", return_value=content):
                            with patch.object(nh, "collect") as collect, patch.object(nh, "bundle") as bundle:
                                with patch.object(nh, "assess") as assess, patch("sys.stdout", new_callable=io.StringIO):
                                    self.assertEqual(bridge.main(), 0)
                                collect.assert_not_called()
                                bundle.assert_not_called()
                                assess.assert_not_called()
            self.assertEqual(before, {p.name: p.read_bytes() for p in (root / "runs" / RUN).iterdir()})

    def test_fresh_cli_refuses_existing_run_before_any_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.checkpoint(root)
            args = [
                "bridge", "--endpoint", ENDPOINT, "--thread-id", THREAD, "--subscription-id", SUB,
                "--run-id", RUN, "--output-root", str(root),
            ]
            with patch.object(sys, "argv", args), patch.object(bridge, "access_token", return_value="fixture"):
                with patch.object(nh, "collect") as collect:
                    with self.assertRaises(FileExistsError):
                        bridge.main()
                    collect.assert_not_called()

    def test_fresh_cli_checkpoints_before_upload_and_returns_verified_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            envelope = nh.collect(SUB, RUN, FixtureReader(), "sre-native-cli", clock=lambda: TIME)
            real_collect = nh.collect
            content = nh.encoded(envelope)
            receipt = {
                "fileId": "fixture-file", "fileName": "collection-input-" + RUN + ".json",
                "fileSize": len(content), "contentType": "application/json",
                "downloadUrl": f"/api/files/{THREAD}/fixture-file.json",
            }

            def upload(name, uploaded, before_send):
                checkpoint = bridge.state_directory(root, RUN)
                self.assertEqual((checkpoint / "selected-input.json").read_bytes(), content)
                self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "prepared")
                self.assertEqual(uploaded, content)
                before_send()
                self.assertEqual(nh.load(checkpoint / "state.json")["phase"], "uploadStarted")
                return [receipt]

            args = [
                "bridge", "--endpoint", ENDPOINT, "--thread-id", THREAD, "--subscription-id", SUB,
                "--run-id", RUN, "--output-root", str(root),
            ]

            def collect_fixture(subscription, run_id, reader, **kwargs):
                return real_collect(subscription, run_id, FixtureReader(), clock=lambda: TIME, **kwargs)

            with patch.object(sys, "argv", args), patch.object(bridge, "access_token", return_value="fixture"):
                with patch.object(bridge, "SRETransport", return_value=transport):
                    with patch.object(nh, "collect", side_effect=collect_fixture) as collect:
                        with patch.object(transport, "audit", return_value={}), patch.object(transport, "wait_for_idle"):
                            with patch.object(transport, "upload", side_effect=upload):
                                with patch.object(transport, "download", return_value=content):
                                    with patch("sys.stdout", new_callable=io.StringIO) as output:
                                        self.assertEqual(bridge.main(), 0)
                                result = json.loads(output.getvalue())
                    collect.assert_called_once()
            self.assertTrue(result["uploadVerified"])
            self.assertEqual(result["attachment"], [receipt])
            self.assertEqual(result["inputSha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(set(result["artifacts"]), bridge.ARTIFACT_NAMES)

    def test_download_guard_rejects_redirects_and_cross_thread_paths(self) -> None:
        transport = self.make()
        for url in (
            f"/api/files/{THREAD}/../other", f"/api/files/{THREAD}/%252e%252e/other",
            f"/api/files/{THREAD}/file?token=private", ENDPOINT + f":444/api/files/{THREAD}/file",
            "https://evil.example/file", f"/api/files/{THREAD}/folder\\file",
        ):
            with self.subTest(url=url), patch.object(bridge.urllib.request, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    transport.download(url)
                opener.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "redirects"):
            bridge.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example")

    def test_download_budget_is_bounded(self) -> None:
        transport = self.make()
        with patch.object(bridge.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(b"x" * (bridge.INPUT_BUDGET + 1))
            with self.assertRaisesRegex(ValueError, "download exceeds"):
                transport.download(f"/api/files/{THREAD}/file")

    def test_endpoint_rejects_external_or_untrusted_origins(self) -> None:
        for value in (
            "http://fixture.azuresre.ai", "https://azuresre.ai.evil.example",
            "https://user:pass@fixture.azuresre.ai", ENDPOINT + "/path",
            ENDPOINT + "?query=x", ENDPOINT + ":444",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    bridge.valid_endpoint(value)

    def test_only_exact_catalog_reads_can_be_sent(self) -> None:
        transport = self.make()
        with patch.object(transport, "request") as request:
            for command in (
                ["az", "network", "vnet", "delete"],
                ["az", "graph", "query", "-q", "Resources"],
                ["az", "account", "list"],
            ):
                with self.subTest(command=command):
                    with self.assertRaises(ValueError):
                        transport.read(command)
            request.assert_not_called()

    def test_native_output_is_decoded_without_rewriting(self) -> None:
        transport = self.make()
        op = nh.records(nh.catalog()["operations"])[0]
        command = nh.command_for(op, SUB, 1000, None)
        execution = {
            "id": "read-fixture", "command": shlex.join(command),
            "status": "Completed", "error": None,
            "output": json.dumps({"subscriptionId": SUB}),
        }
        with patch.object(transport, "executions", side_effect=[[], [execution]]):
            with patch.object(transport, "request", return_value={"state": "Idle"}):
                response = transport.read(command)
        self.assertEqual(response.payload, {"subscriptionId": SUB})
        self.assertEqual(response.execution_id, "read-fixture")

    def test_unrelated_thread_or_unexpected_read_is_rejected(self) -> None:
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        with patch.object(transport, "executions", return_value=[{"id": "existing"}]):
            with self.assertRaisesRegex(ValueError, "fresh controlled thread"):
                transport.read(command)
        execution = {"id": "bad", "command": "az account list", "status": "Completed"}
        with patch.object(transport, "executions", side_effect=[[], [execution]]):
            with patch.object(transport, "request", return_value={"state": "Idle"}):
                with self.assertRaisesRegex(RuntimeError, "Unexpected Azure operation"):
                    transport.read(command)

    def test_attachment_is_exact_bytes_and_scoped_to_thread(self) -> None:
        transport = self.make()
        content = b'{"selected":"evidence"}\n'
        with patch.object(transport, "wait_for_idle"):
            with patch.object(transport, "request", return_value=[]) as request:
                transport.upload("input.json", content)
        args = request.call_args.args
        self.assertEqual(args[0], f"/api/v1/threads/{THREAD}/attachments")
        self.assertIn(content, args[1])
        self.assertIn('name="files"; filename="input.json"', args[1].decode())

    def test_attachment_budget_and_path_validation(self) -> None:
        transport = self.make()
        with patch.object(transport, "request") as request:
            with self.assertRaises(ValueError):
                transport.upload("../input.json", b"{}")
            with self.assertRaises(ValueError):
                transport.upload("input.json", b"x" * (5 * 1024 * 1024 + 1))
            request.assert_not_called()

    def test_audit_detects_duplicate_native_execution(self) -> None:
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        transport.allowed_commands.add(tuple(command))
        transport.seen_executions.add("read-one")
        messages = [
            audit_message(azCliExecution={"id": name, "command": shlex.join(command), "status": "Completed"})
            for name in ("read-one", "read-two")
        ]
        with patch.object(transport, "request", return_value={"value": messages}):
            with self.assertRaisesRegex(RuntimeError, "duplicate"):
                transport.audit()

    def test_audit_pages_execution_history(self) -> None:
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        transport.allowed_commands.add(tuple(command))
        transport.seen_executions.add("read-one")
        first = [audit_message()] * 99 + [audit_message(
            azCliExecution={"id": "read-one", "command": shlex.join(command), "status": "Completed"},
        )]
        with patch.object(transport, "request", side_effect=[{"value": first}, {"value": []}]) as request:
            transport.audit()
        self.assertIn("skip=100", request.call_args.args[0])

    def test_collection_audit_requires_every_known_surface_field(self) -> None:
        for field in bridge.AUDIT_SURFACES:
            with self.subTest(field=field):
                message = audit_message()
                del message[field]
                with patch.object(self.make(), "request") as unused:
                    with self.assertRaisesRegex(RuntimeError, "visibility is incomplete"):
                        bridge.verify_collection_message(message)
                    unused.assert_not_called()

    def test_non_azure_surfaces_and_empty_nonnull_values_are_not_silently_ignored(self) -> None:
        for field in bridge.AUDIT_SURFACES:
            if field == "azCliExecution":
                continue
            for value in ({}, [], False, {"output": "must-not-be-in-audit-errors"}):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(RuntimeError, "Noncatalogued") as error:
                        bridge.verify_collection_message(audit_message(**{field: value}))
                    self.assertNotIn("must-not-be-in-audit-errors", str(error.exception))

    def test_unknown_execution_result_query_activity_fails_closed(self) -> None:
        for field in ("futureExecution", "futureResult", "futureQuery"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, "Noncatalogued"):
                    bridge.verify_collection_message(audit_message(**{field: {}}))

    def test_unclassified_null_fields_are_recorded_without_universal_enforcement_claim(self) -> None:
        transport = self.make()
        with patch.object(transport, "request", return_value={"value": [audit_message(futureExecution=None)]}):
            report = transport.audit()
        self.assertEqual(report["unclassifiedNullSurfaceFields"], ["futureExecution"])
        self.assertFalse(report["universalToolEnforcement"])
        self.assertEqual(report["visibilityBoundary"], "structured-thread-fields-within-message-budget")
        for coverage in report["surfaceCoverage"].values():
            self.assertEqual(coverage, {"messagesExposingField": 1, "nonNullOccurrences": 0})

    def test_empty_audit_history_and_malformed_native_surfaces_are_explicit_failures(self) -> None:
        transport = self.make()
        with patch.object(transport, "request", return_value={"value": []}):
            with self.assertRaisesRegex(RuntimeError, "history is empty"):
                transport.audit()
        for execution in ({}, False, [], {"id": "read", "command": "az account show"}):
            with self.subTest(execution=execution):
                with self.assertRaises((RuntimeError, ValueError)):
                    bridge.verify_collection_message(audit_message(azCliExecution=execution))

    def test_nonterminal_and_duplicated_native_records_fail_audit(self) -> None:
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        for status, duplicated in (("Running", False), ("Completed", True)):
            with self.subTest(status=status, duplicated=duplicated):
                transport = self.make()
                transport.allowed_commands.add(tuple(command))
                transport.seen_executions.add("read-one")
                message = audit_message(azCliExecution={
                    "id": "read-one", "command": shlex.join(command), "status": status,
                })
                messages = [message, copy.deepcopy(message)] if duplicated else [message]
                with patch.object(transport, "request", return_value={"value": messages}):
                    with self.assertRaises(RuntimeError):
                        transport.audit()

    def test_collection_surface_gate_stops_before_native_submission(self) -> None:
        service = NativeService()
        service.messages.append(audit_message(terminalResult={"command": "unapproved", "output": "private"}))
        with tempfile.TemporaryDirectory() as directory:
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "Noncatalogued"):
                    bridge.acquire(transport, SUB, RUN, Path(directory), 1)
            self.assertEqual(service.posts, [])
            self.assertFalse(transport.collection_only)

    def test_standalone_native_read_also_enforces_collection_surface_policy(self) -> None:
        service = NativeService()
        service.messages.append(audit_message(readFileResult={"content": "private"}))
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        with patch.object(transport, "request", side_effect=service.request):
            with self.assertRaisesRegex(RuntimeError, "Noncatalogued"):
                transport.read(command)
        self.assertEqual(service.posts, [])
        self.assertFalse(transport.collection_only)

    def test_resuming_after_non_azure_activity_is_a_protocol_violation(self) -> None:
        service = NativeService(lose_after=3)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1)
            service.messages.append(audit_message(mcpToolExecution={"output": "private"}))
            resumed = self.make()
            with patch.object(resumed, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "Noncatalogued"):
                    bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(len(service.posts), 3)

    def test_metadata_only_audit_is_persisted_beside_acquisition_checkpoint(self) -> None:
        service = NativeService()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = self.make()
            with patch.object(transport, "request", side_effect=service.request):
                bridge.acquire(transport, SUB, RUN, root, 1)
            path = bridge.acquisition_directory(root, RUN) / "audit.json"
            report = nh.load(path)
            self.assertEqual(report["status"], "verified-collection-only")
            self.assertEqual(report["runId"], RUN)
            self.assertEqual(report["subscriptionId"], SUB)
            self.assertEqual(report["auditPolicyVersion"], bridge.AUDIT_POLICY_VERSION)
            self.assertEqual(len(report["nativeExecutionIds"]), len(service.posts))
            self.assertNotIn(transport.token, path.read_text())
            self.assertNotIn(nh.catalog()["operations"][1]["query"], path.read_text())
            self.assertNotIn("output", path.read_text())

    def saved_publication(self, root: Path, count=4):
        _, model, assessment, _ = fixture_tests.NetworkHealthTests().make()
        result = nh.bundle(model, assessment, root)
        manifest = root / "helper-result.json"
        manifest.write_bytes(nh.encoded(result))
        nh.report_save(root, RUN, THREAD, "plan", manifest)
        for name in nh.REPORT_FILES[:count]:
            plan = nh.report_save(root, RUN, THREAD, "begin", artifact=name)
            key = f"tmp/ThreadFiles/{THREAD}/" + plan["files"][name]["publicationName"]
            nh.report_save(root, RUN, THREAD, "record", artifact=name, blob_key=key)
        state = nh.load(root / "report-publication" / RUN / "state.json")
        contents = {state["files"][name]["key"]: Path(result["artifacts"][name]["path"]).read_bytes()
                    for name in nh.REPORT_FILES[:count]}
        return state, contents

    def test_saved_report_downloads_are_verified_not_inferred_from_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, contents = self.saved_publication(Path(directory))
            transport = self.make()
            with patch.object(transport, "download", side_effect=lambda url, budget: contents[url.split(f"/api/files/{THREAD}/", 1)[1]]):
                proof = bridge.verify_report_saves(transport, state, SUB, RUN)
            self.assertEqual(proof["status"], "download-verified")
            self.assertEqual(set(proof["artifacts"]), set(nh.REPORT_FILES))
            self.assertEqual(proof["remaining"], [])
            self.assertEqual(proof["publicationSha256"], nh.digest(state))

    def test_partial_saved_reports_never_claim_full_download_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, contents = self.saved_publication(Path(directory), 2)
            transport = self.make()
            with patch.object(transport, "download", side_effect=lambda url, budget: contents[url.split(f"/api/files/{THREAD}/", 1)[1]]):
                proof = bridge.verify_report_saves(transport, state, SUB, RUN)
            self.assertEqual(proof["status"], "partially-download-verified")
            self.assertEqual(len(proof["artifacts"]), 2)
            self.assertEqual(set(proof["remaining"]), set(nh.REPORT_FILES[2:]))

    def test_report_verification_corruption_and_identity_stop_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, _ = self.saved_publication(Path(directory))
            transport = self.make()
            with patch.object(transport, "download", return_value=b"corrupt"):
                with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
                    bridge.verify_report_saves(transport, state, SUB, RUN)
            state["threadId"] = "00000000-0000-4000-8000-000000000004"
            with patch.object(transport, "download") as download:
                with self.assertRaisesRegex(ValueError, "run/thread mismatch"):
                    bridge.verify_report_saves(transport, state, SUB, RUN)
                download.assert_not_called()

    def test_thread_readiness_is_required_and_polled(self) -> None:
        transport = self.make()
        with patch.object(transport, "request", side_effect=[{"state": "Running"}, {"state": "Idle"}]):
            with patch.object(bridge.time, "sleep"):
                transport.wait_for_idle()

    def test_error_after_accepted_submission_never_reposts_command(self) -> None:
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)
        submitted: list[str] = []

        def request(path, data=None, content_type="application/json"):
            if data is not None:
                submitted.append(json.loads(data)["text"])
                raise bridge.SREHttpError(422)
            if "top=20" in path:
                return {"value": [{"text": submitted[0], "author": {"role": "User"}}]}
            return {"state": "Idle"}

        execution = {
            "id": "accepted-read", "command": shlex.join(command), "status": "Completed",
            "error": None, "output": json.dumps({"subscriptionId": SUB}),
        }
        with patch.object(transport, "request", side_effect=request):
            with patch.object(transport, "executions", side_effect=[[], [execution]]):
                response = transport.read(command)
        self.assertEqual(len(submitted), 1)
        self.assertEqual(response.execution_id, "accepted-read")
        self.assertEqual(transport.submission_warnings[0]["httpStatus"], 422)

    def test_unaccepted_submission_error_is_not_success_shaped(self) -> None:
        transport = self.make()
        command = nh.command_for(nh.records(nh.catalog()["operations"])[0], SUB, 1000, None)

        def request(path, data=None, content_type="application/json"):
            if data is not None:
                raise bridge.SREHttpError(422)
            return {"state": "Idle", "value": []}

        with patch.object(transport, "request", side_effect=request):
            with patch.object(transport, "executions", return_value=[]):
                with self.assertRaises(bridge.SREHttpError):
                    transport.read(command)
        self.assertFalse(transport.submission_warnings)
        with patch.object(transport, "request", return_value={}):
            with self.assertRaisesRegex(RuntimeError, "readiness state"):
                transport.wait_for_idle()


if __name__ == "__main__":
    unittest.main()
