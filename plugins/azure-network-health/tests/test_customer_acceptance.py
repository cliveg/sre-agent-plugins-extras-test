from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_arm_pagination as pagination
import test_dns_intent as intent_tests
import test_sre_transport as transport_tests


nh = pagination.nh
bridge = transport_tests.bridge
SUB, RUN, TIME = pagination.SUB, pagination.RUN, pagination.TIME
HOST = pagination.paths.HOST
COLLECTION_THREAD = "00000000-0000-4000-8000-000000000011"
PROCESSING_THREAD = "00000000-0000-4000-8000-000000000012"
REVIEW = "2026-10-11T12:00:00.123456Z"


class AcceptanceReader(pagination.PagedDNSReader):
    def __init__(self, partial_host=False):
        super().__init__()
        self.partial_host = partial_host

    def __call__(self, command):
        if "--subscriptions" in command and command[command.index("--subscriptions") + 1] == HOST:
            self.calls.append(command)
            if not self.partial_host:
                raise AssertionError("Unexpected additional subscription")
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        return super().__call__(command)


class CustomerAcceptanceTests(unittest.TestCase):
    def transport(self, thread):
        return bridge.SRETransport(transport_tests.ENDPOINT, thread, "synthetic-not-a-secret")

    def exercise(self, partial_host):
        reader = AcceptanceReader(partial_host)
        discovery = AcceptanceReader(partial_host)
        hosts = [HOST] if partial_host else [SUB]
        nh.collect(SUB, RUN, discovery, "synthetic-fixture", clock=lambda: TIME,
                   include_dns_paths=True, dns_subscriptions=hosts)
        loss = next(i + 1 for i, command in enumerate(discovery.calls)
                    if nh.child_kind(command) == "dns-inbound-endpoints" and nh.request_token(command))
        service = transport_tests.NativeService(lose_after=loss, reader=reader)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            acquisition_root = root / "acquisition"
            collection = self.transport(COLLECTION_THREAD)
            with patch.object(collection, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(collection, SUB, RUN, acquisition_root,
                                   include_dns_paths=True, dns_subscriptions=hosts)
            rejected = self.transport(COLLECTION_THREAD)
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "DNS-hosting subscription scope"):
                    bridge.acquire(rejected, SUB, RUN, acquisition_root, resume=True,
                                   dns_subscriptions=[SUB] if partial_host else [HOST])
                request.assert_not_called()
            resumed = self.transport(COLLECTION_THREAD)
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, acquisition_root, resume=True)
            self.assertEqual(len(service.posts), len(discovery.calls))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            checkpoint = nh.load(bridge.acquisition_directory(acquisition_root, RUN) / "state.json")
            self.assertIsNone(checkpoint["pendingRead"])
            audit = nh.load(bridge.acquisition_directory(acquisition_root, RUN) / "audit.json")
            self.assertEqual(audit["status"], "verified-collection-only")
            self.assertEqual(len(audit["nativeExecutionIds"]), len(service.posts))
            model = nh.normalize(envelope)
            intent = intent_tests.DNSIntentTests().intent(reader, "in-progress")
            intent["cohorts"][0]["dnsMode"] = "custom-configured"
            assessment = nh.assess(model, intent, REVIEW)
            if partial_host:
                self.assertEqual(assessment["status"], "incomplete-configuration-triage")
                self.assertEqual(assessment["dnsPlanning"]["dnsHostingScopeStatus"], "declared-partial")
                self.assertTrue(any(c["requestedSubscriptionId"] == HOST and c["status"] == "permissionDenied"
                                    for c in model["collections"]))
                self.assertTrue(any(f["recordType"] == "evidenceGap" for f in assessment["findings"]))
            else:
                self.assertEqual(assessment["status"], "limited-configuration-triage")
                self.assertTrue(all(c["status"] == "succeeded" for c in model["collections"]))
            self.assertEqual(assessment["provenanceTimeReview"]["referenceAt"], REVIEW)
            self.assertEqual(assessment["dnsIntentComparison"]["classification"], "DECLARED")
            self.assertNotIn("dnsIntentComparison", model)
            initial_result = nh.bundle(model, assessment, acquisition_root)
            before = {name: Path(initial_result["artifacts"][name]["path"]).read_bytes() for name in nh.REPORT_FILES}
            bridge.prepare_upload(resumed, SUB, RUN, acquisition_root, envelope, initial_result)
            name = "collection-input-" + RUN + ".json"
            selected_bytes = nh.encoded(envelope)
            receipt = {"fileId": "accepted-upload", "fileName": name, "contentType": "application/json",
                       "fileSize": len(selected_bytes),
                       "downloadUrl": f"/api/files/{COLLECTION_THREAD}/accepted-upload_{name}"}
            upload_posts = []
            def accepted_upload(name, content, before_send):
                before_send()
                upload_posts.append((name, content))
                raise RuntimeError("Injected accepted upload response loss")
            with patch.object(resumed, "upload", side_effect=accepted_upload):
                with self.assertRaisesRegex(RuntimeError, "upload response loss"):
                    bridge.resume_upload(resumed, SUB, RUN, acquisition_root)
            with patch.object(resumed, "upload") as upload, patch.object(resumed, "download") as download:
                with self.assertRaisesRegex(RuntimeError, "acceptance is unknown"):
                    bridge.resume_upload(resumed, SUB, RUN, acquisition_root)
                upload.assert_not_called()
                download.assert_not_called()
            receipt_path = root / "actual-receipt.json"
            receipt_path.write_bytes(nh.encoded(receipt))
            with patch.object(resumed, "upload") as upload, patch.object(resumed, "download", return_value=selected_bytes):
                result = bridge.resume_upload(resumed, SUB, RUN, acquisition_root, receipt_path)
                upload.assert_not_called()
            self.assertTrue(result["uploadVerified"])
            self.assertEqual(len(upload_posts), 1)
            processing_root = root / "processing"
            input_path, intent_path, manifest = root / "uploaded-input.json", root / "intent.json", root / "actual-helper-result.json"
            input_path.write_bytes(selected_bytes)
            intent_path.write_bytes(nh.encoded(intent))
            command = [sys.executable, str(nh.HERE / "network_health.py"), "--input", str(input_path),
                       "--dns-intent", str(intent_path), "--review-at", REVIEW, "--output-root", str(processing_root),
                       "--bundle-result", str(manifest)]
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
            helper_result = json.loads(completed.stdout)
            self.assertEqual(nh.load(manifest), helper_result)
            self.assertEqual(set(helper_result["artifacts"]), set(nh.REPORT_FILES))
            for name, content in before.items():
                self.assertEqual(Path(helper_result["artifacts"][name]["path"]).read_bytes(), content)
            processing = self.transport(PROCESSING_THREAD)
            plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "plan", manifest)
            storage = {}
            save_calls = []
            def save_blob(name, plan):
                content = Path(plan["publicationPaths"][name]).read_bytes()
                key = f"tmp/ThreadFiles/{PROCESSING_THREAD}/" + plan["files"][name]["publicationName"]
                if key in storage:
                    self.assertEqual(storage[key], content)
                storage[key] = content
                save_calls.append(key)
                return key
            first = nh.REPORT_FILES[0]
            plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "begin", artifact=first)
            first_key = save_blob(first, plan)
            plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "record", artifact=first, blob_key=first_key)
            with patch.object(processing, "download", side_effect=lambda url, max_bytes: storage[url.split(f"/api/files/{PROCESSING_THREAD}/", 1)[1]]):
                partial_proof = bridge.verify_report_saves(processing, nh.load(Path(plan["ledgerExportPath"])), SUB, RUN)
            self.assertEqual(partial_proof["status"], "partially-download-verified")
            second = nh.REPORT_FILES[1]
            plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "begin", artifact=second)
            ambiguous_key = save_blob(second, plan)
            resumed_plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "plan")
            self.assertNotIn(first, resumed_plan["remaining"])
            self.assertIn(second, resumed_plan["remaining"])
            for name in resumed_plan["remaining"]:
                plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "begin", artifact=name)
                key = save_blob(name, plan)
                if name == second:
                    self.assertEqual(key, ambiguous_key)
                plan = nh.report_save(processing_root, RUN, PROCESSING_THREAD, "record", artifact=name, blob_key=key)
            final_ledger = nh.load(Path(plan["ledgerExportPath"]))
            self.assertEqual(plan["status"], "saved-not-download-verified")
            self.assertTrue(all(item["phase"] == "savedUnverified" for item in final_ledger["files"].values()))
            with patch.object(processing, "download", side_effect=lambda url, max_bytes: storage[url.split(f"/api/files/{PROCESSING_THREAD}/", 1)[1]]):
                proof = bridge.verify_report_saves(processing, final_ledger, SUB, RUN)
            self.assertEqual(proof["status"], "download-verified")
            self.assertEqual(proof["remaining"], [])
            self.assertEqual(len(proof["artifacts"]), 4)
            self.assertEqual(proof["publicationSha256"], nh.digest(final_ledger))
            self.assertEqual(save_calls.count(first_key), 1)
            self.assertEqual(save_calls.count(ambiguous_key), 2)
            self.assertEqual(len(save_calls), 5)
            with patch.object(processing, "download", return_value=b"corrupted"):
                with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
                    bridge.verify_report_saves(processing, final_ledger, SUB, RUN)
            with patch.object(processing, "download") as download:
                with self.assertRaisesRegex(ValueError, "subscription differs"):
                    bridge.verify_report_saves(processing, final_ledger, HOST, RUN)
                download.assert_not_called()
            self.assertNotEqual(subprocess.run(command, capture_output=True, text=True, check=False).returncode, 0)
            for name, content in before.items():
                self.assertEqual(Path(helper_result["artifacts"][name]["path"]).read_bytes(), content)
                self.assertEqual(Path(initial_result["artifacts"][name]["path"]).read_bytes(), content)
                self.assertEqual(proof["artifacts"][name]["sha256"], hashlib.sha256(content).hexdigest())
            final = self.transport(COLLECTION_THREAD)
            before_posts = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, acquisition_root, resume=True), envelope)
            self.assertEqual(len(service.posts), before_posts)
            self.assertEqual(nh.load(Path(plan["ledgerExportPath"])), final_ledger)

    def test_complete_customer_path_preserves_scope_intent_review_and_recovers_delivery(self):
        self.exercise(False)

    def test_partial_permission_path_still_delivers_honest_evidence_gaps(self):
        self.exercise(True)

    def test_collection_thread_rejects_processing_activity_before_any_resource_read(self):
        service = transport_tests.NativeService(reader=AcceptanceReader())
        service.messages.append(transport_tests.audit_message(terminalResult={}))
        with tempfile.TemporaryDirectory() as directory:
            transport = self.transport(COLLECTION_THREAD)
            with patch.object(transport, "request", side_effect=service.request):
                with self.assertRaises(RuntimeError):
                    bridge.acquire(transport, SUB, RUN, Path(directory), include_dns_paths=True)
            self.assertEqual(service.posts, [])
