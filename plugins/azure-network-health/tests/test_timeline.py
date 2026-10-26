from __future__ import annotations

import json
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import test_history as fixture
import test_workspace_activity as workspace_fixture


sys.path.insert(0, str(fixture.configuration.SCRIPTS))
import network_timeline as timeline


TIMELINE = "00000000-0000-4000-8000-000000000070"


class TimelineTests(unittest.TestCase):
    def test_compact_pages_split_by_real_byte_size_below_the_row_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = []
            for number in range(320):
                value = fixture.activity(f"opaque-{number:04}-" + "x" * 17000)
                del value["id"]
                values.append(value)
            link = (
                f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.Insights/eventtypes/management/values"
                "?api-version=2015-04-01&$skiptoken=page-two"
            )
            source = fixture.history.capture(
                fixture.HistoryService("activity-log", [
                    {"statusCode": 200, "requestId": None, "body": {"value": values[:160], "nextLink": link}},
                    {"statusCode": 200, "requestId": None, "body": {"value": values[160:], "nextLink": None}},
                ]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            directory = timeline.build([source], TIMELINE, root, compact=True)
            header = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual([page["count"] for page in header["sections"]["events"]], [160, 160])
            files = [path for path in directory.rglob("*") if path.is_file()]
            self.assertLessEqual(max(path.stat().st_size for path in files), 5 * 1024 * 1024)
            self.assertLessEqual(sum(path.stat().st_size for path in files), 20 * 1024 * 1024)
            self.assertEqual(len(timeline.read(directory)["events"]), 320)

    def test_rehashed_compact_witness_or_missing_page_cannot_change_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture.history.capture(
                fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            original = timeline.build([source], TIMELINE, root, compact=True)
            for mode in ("wrong-witness", "missing-page", "wrong-version"):
                with self.subTest(mode=mode):
                    directory = root / mode
                    shutil.copytree(original, directory)
                    manifest = json.loads((directory / "manifest.json").read_bytes())
                    header = json.loads((directory / "timeline.json").read_bytes())
                    page_name = header["sections"]["events"][0]["json"]
                    if mode == "wrong-witness":
                        page = json.loads((directory / page_name).read_bytes())
                        page["items"][0]["witnesses"][0]["memberIndex"] = 9999
                        content = fixture.capture.ef.encoded(page)
                        (directory / page_name).write_bytes(content)
                        header["sections"]["events"][0]["sha256"] = fixture.capture.ef.descriptor(page_name, content)["sha256"]
                    elif mode == "missing-page":
                        (directory / page_name).unlink()
                        header["sections"]["events"] = []
                    else:
                        manifest["bundleVersion"] = manifest["processorVersion"] = "1.9.0"
                    (directory / "timeline.json").write_bytes(fixture.capture.ef.encoded(header))
                    manifest["members"] = [
                        fixture.capture.ef.descriptor(entry["name"], (directory / entry["name"]).read_bytes())
                        for entry in manifest["members"] if (directory / entry["name"]).exists()
                    ]
                    (directory / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
                    with self.assertRaises(ValueError):
                        timeline.read(directory)

    def test_compact_empty_denied_and_unknown_times_keep_their_original_meanings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            denied = fixture.history.capture(
                fixture.HistoryService("resource-changes", [{
                    "statusCode": 403, "requestId": None, "body": None, "errorCode": "AuthorizationFailed",
                }]), "resource-changes", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            health = fixture.history.capture(
                fixture.HistoryService("service-health", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [{
                        "id": f"/subscriptions/{fixture.SUB}/providers/Microsoft.ResourceHealth/events/untimed",
                        "properties": {"eventSource": "ServiceHealth"},
                    }]},
                }]), "service-health", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                "00000000-0000-4000-8000-000000000071", root,
                fixture.START, fixture.END, planning_time=fixture.END,
            )
            directory = timeline.build([denied, health], TIMELINE, root, compact=True)
            header = json.loads((directory / "timeline.json").read_bytes())
            logical = timeline.read(directory)
            self.assertEqual(header["sections"]["configurationObservations"], [])
            self.assertEqual(logical["events"][0]["times"], {
                "eventTime": None, "sourceUpdatedTime": None, "submissionTime": None, "ingestionTime": None,
            })
            self.assertIn("permissionDenied", (directory / "timeline.md").read_text(encoding="utf-8"))
            page = header["sections"]["events"][0]["markdown"]
            self.assertIn("UNKNOWN", (directory / page).read_text(encoding="utf-8"))
            self.assertEqual(len(logical["unboundEventRevisions"]), 1)

    def test_compact_cli_is_offline_and_input_order_does_not_change_any_view(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = [fixture.history.capture(
                fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                f"00000000-0000-4000-8000-{number:012}", root,
                fixture.START, fixture.END, planning_time=fixture.END,
            ) for number in (71, 72)]
            first_root, second_root = root / "one", root / "two"
            first_root.mkdir()
            second_root.mkdir()
            args = ["timeline", "build", "--compact", "--timeline-id", TIMELINE, "--output-root", str(first_root)]
            for source in sources:
                args.extend(("--capsule", str(source)))
            output = io.StringIO()
            with patch.object(sys, "argv", args), redirect_stdout(output), \
                    patch("socket.socket", side_effect=AssertionError("Network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process access")):
                self.assertEqual(timeline.main(), 0)
            first = Path(json.loads(output.getvalue())["timeline"])
            second = timeline.build(list(reversed(sources)), TIMELINE, second_root, compact=True)
            first_views = {path.name: path.read_bytes() for path in first.iterdir() if path.is_file() and path.name != "manifest.json"}
            second_views = {path.name: path.read_bytes() for path in second.iterdir() if path.is_file() and path.name != "manifest.json"}
            self.assertEqual(first_views, second_views)
            self.assertLess(len(output.getvalue().encode()), 4000)
            with patch("socket.socket", side_effect=AssertionError("Network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process access")):
                self.assertEqual(timeline.verify(first)["bundleVersion"], "1.1.0")
                self.assertEqual(len(timeline.read(first)["events"]), 1)

    def test_compact_pages_preserve_complete_normalized_events_and_original_witnesses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = [fixture.activity(f"event-{number:04}") for number in range(1001)]
            link = (
                f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.Insights/eventtypes/management/values"
                "?api-version=2015-04-01&$skiptoken=page-two"
            )
            source = fixture.history.capture(
                fixture.HistoryService("activity-log", [
                    {"statusCode": 200, "requestId": None, "body": {"value": values[:1000], "nextLink": link}},
                    {"statusCode": 200, "requestId": None, "body": {"value": values[1000:], "nextLink": None}},
                ]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            one, two = root / "legacy", root / "compact"
            one.mkdir()
            two.mkdir()
            legacy = timeline.build([source], TIMELINE, one)
            directory = timeline.build([source], TIMELINE, two, compact=True)
            manifest = timeline.verify(directory)
            self.assertEqual(manifest["bundleVersion"], "1.1.0")
            header = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual(header["storage"]["mode"], "compact-paged")
            self.assertNotIn("events", header)
            self.assertEqual([page["count"] for page in header["sections"]["events"]], [500, 500, 1])
            self.assertEqual(fixture.capture.ef.encoded(timeline.read(directory)), (legacy / "timeline.json").read_bytes())
            pages = [json.loads((directory / page["json"]).read_bytes()) for page in header["sections"]["events"]]
            self.assertEqual(sum(len(page["items"]) for page in pages), 1001)
            member_documents = {}
            for event in pages[0]["items"]:
                self.assertNotIn("record", event)
                self.assertNotIn("evidence", event)
                witness = event["witnesses"][0]
                member = header["evidenceMembers"][witness["memberIndex"]]
                if member["member"] not in member_documents:
                    member_documents[member["member"]] = json.loads((directory / member["member"]).read_bytes())
                value = member_documents[member["member"]]
                for token in witness["pointer"].split("/")[1:]:
                    value = value[int(token)] if isinstance(value, list) else value[token]
                self.assertEqual(fixture.capture.ef.digest(value), event["revisionId"])

    def test_markdown_preserves_unknown_workspace_readiness_despite_successful_http(self):
        class EmptyCollection(workspace_fixture.WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "page":
                    return {"statusCode": 200, "requestId": None, "body": workspace_fixture.table(
                        [], workspace_fixture.workspace.EVENT_COLUMNS,
                    )}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = workspace_fixture.workspace.capture(
                EmptyCollection(), fixture.TENANT, fixture.SUB, fixture.CLIENT, fixture.RUN,
                root, workspace_fixture.RESOURCE, workspace_fixture.START, workspace_fixture.END,
                planning_time=workspace_fixture.END,
            )
            readiness = fixture.capture.verify(source)["coverage"]["readiness"]
            self.assertEqual(readiness["status"], "UNKNOWN")
            directory = timeline.build([source], TIMELINE, root)
            markdown = (directory / "timeline.md").read_text(encoding="utf-8")
            self.assertIn("UNKNOWN / " + readiness["reason"], markdown)

    def test_mixed_subscription_evidence_is_rejected_without_a_completed_bundle(self):
        other_subscription = "00000000-0000-4000-8000-000000000099"

        class OtherSubscription(fixture.HistoryService):
            def context(self):
                value = super().context()
                value["subscriptionId"] = other_subscription
                return value

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = fixture.activity()
            changed = {**original, "subscriptionId": other_subscription,
                       "id": original["id"].replace(fixture.SUB, other_subscription),
                       "resourceId": original["resourceId"].replace(fixture.SUB, other_subscription)}
            sources = []
            for number, subscription, reader in (
                (71, fixture.SUB, fixture.HistoryService),
                (72, other_subscription, OtherSubscription),
            ):
                values = [original] if subscription == fixture.SUB else [changed]
                sources.append(fixture.history.capture(
                    reader("activity-log", [{"statusCode": 200, "requestId": None, "body": {"value": values}}]),
                    "activity-log", fixture.TENANT, subscription, fixture.CLIENT,
                    f"00000000-0000-4000-8000-{number:012}", root,
                    fixture.START, fixture.END, planning_time=fixture.END,
                ))
            with self.assertRaisesRegex(ValueError, "scope"):
                timeline.build(sources, TIMELINE, root)
            self.assertFalse((root / "timelines" / TIMELINE).exists())

    def test_twenty_capsules_are_supported_and_twenty_one_are_explicitly_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for number in range(100, 120):
                sources.append(fixture.history.capture(
                    fixture.HistoryService("service-health", [{
                        "statusCode": 200, "requestId": None, "body": {"value": []},
                    }]), "service-health", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                    f"00000000-0000-4000-8000-{number:012}", root,
                    fixture.START, fixture.END, planning_time=fixture.END,
                ))
            directory = timeline.build(sources, TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual(document["statistics"]["inputCapsules"], 20)
            self.assertEqual(document["statistics"]["eventRevisions"], 0)
            with self.assertRaisesRegex(ValueError, "20"):
                timeline.build(sources + [sources[0]], "00000000-0000-4000-8000-000000000080", root)

    def test_record_budget_counts_retained_occurrences_not_only_deduplicated_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {
                "id": f"/subscriptions/{fixture.SUB}/providers/Microsoft.ResourceHealth/events/repeated",
                "properties": {"lastUpdateTime": fixture.EVENT_TIME, "eventSource": "ServiceHealth"},
            }
            sources = []
            for number, count in ((71, 10000), (72, 10001)):
                pages = []
                for offset in range(0, count, 1000):
                    remaining = min(1000, count - offset)
                    next_link = (
                        f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.ResourceHealth/events"
                        f"?api-version=2025-05-01&$skiptoken=page-{offset + remaining}"
                    ) if offset + remaining < count else None
                    pages.append({"statusCode": 200, "requestId": None,
                                  "body": {"value": [value] * remaining, "nextLink": next_link}})
                sources.append(fixture.history.capture(
                    fixture.HistoryService("service-health", pages), "service-health",
                    fixture.TENANT, fixture.SUB, fixture.CLIENT, f"00000000-0000-4000-8000-{number:012}",
                    root, fixture.START, fixture.END, planning_time=fixture.END,
                ))
            with self.assertRaisesRegex(ValueError, "record budget"):
                timeline.build(sources, TIMELINE, root)
            self.assertFalse((root / "timelines" / TIMELINE).exists())

    def test_output_inside_a_source_is_refused_without_mutating_the_capsule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture.history.capture(
                fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            original = {path.name: path.read_bytes() for path in source.iterdir()}
            with self.assertRaises(ValueError):
                timeline.build([source], TIMELINE, source)
            self.assertEqual(set(path.name for path in source.iterdir()), set(original))
            self.assertEqual(fixture.capture.verify(source)["capsuleId"], fixture.RUN)

    def test_workspace_and_native_event_identities_do_not_collapse_across_sources(self):
        class Rows(workspace_fixture.WorkspaceService):
            def __init__(self, workspace_id):
                super().__init__()
                self.workspace_id = workspace_id

            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "page":
                    row = workspace_fixture.activity_row("2026-10-13T18:00:00.0000001Z")
                    row["SubmittedTime"] = "2026-10-13T18:00:01.0000002Z"
                    row["IngestedTime"] = "2026-10-13T19:01:00.0000007Z"
                    return {"statusCode": 200, "requestId": None, "body": workspace_fixture.table(
                        [[row[name] for name in workspace_fixture.workspace.EVENT_COLUMNS]],
                        workspace_fixture.workspace.EVENT_COLUMNS,
                    )}
                response = super().workspace(operation, resource_id, workspace_id, window, cursor)
                if operation == "describe":
                    response["body"]["properties"]["customerId"] = self.workspace_id
                return response

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for number in (71, 72):
                sources.append(workspace_fixture.workspace.capture(
                    Rows(f"00000000-0000-4000-8000-{number + 20:012}"),
                    fixture.TENANT, fixture.SUB, fixture.CLIENT, f"00000000-0000-4000-8000-{number:012}",
                    root, workspace_fixture.RESOURCE + str(number), workspace_fixture.START, workspace_fixture.END,
                    planning_time=workspace_fixture.END,
                ))
            sources.append(fixture.history.capture(
                fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            ))
            directory = timeline.build(sources, TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual(document["statistics"]["eventIdentities"], 3)
            self.assertEqual(len({event["sourceKey"] for event in document["events"]}), 3)
            for event in document["events"]:
                if event["sourceId"] == "workspace-activity":
                    self.assertEqual(event["times"], {
                        "eventTime": "2026-10-13T18:00:00.0000001Z", "sourceUpdatedTime": None,
                        "submissionTime": "2026-10-13T18:00:01.0000002Z", "ingestionTime": "2026-10-13T19:01:00.0000007Z",
                    })

    def test_commands_are_offline_and_views_are_deterministic_under_input_reordering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for number in (71, 72):
                sources.append(fixture.history.capture(
                    fixture.HistoryService("activity-log", [{
                        "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                    }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                    f"00000000-0000-4000-8000-{number:012}", root,
                    fixture.START, fixture.END, planning_time=fixture.END,
                ))
            first_root, second_root = root / "first", root / "second"
            first_root.mkdir()
            second_root.mkdir()
            arguments = ["timeline", "build", "--timeline-id", TIMELINE, "--output-root", str(first_root)]
            for source in sources:
                arguments.extend(("--capsule", str(source)))
            stdout = io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(stdout), \
                    patch("socket.socket", side_effect=AssertionError("Unexpected network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Unexpected host-tool invocation")):
                self.assertEqual(timeline.main(), 0)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["azureReads"], 0)
            self.assertLess(len(stdout.getvalue().encode()), 4000)
            first = Path(receipt["timeline"])
            second = timeline.build(list(reversed(sources)), TIMELINE, second_root)
            self.assertEqual((first / "timeline.json").read_bytes(), (second / "timeline.json").read_bytes())
            self.assertEqual((first / "timeline.md").read_bytes(), (second / "timeline.md").read_bytes())
            with self.assertRaises(FileExistsError):
                timeline.build(sources, TIMELINE, first_root)
            with patch.object(sys, "argv", ["timeline", "verify", "--timeline", str(first)]), \
                    redirect_stdout(io.StringIO()), \
                    patch("socket.socket", side_effect=AssertionError("Unexpected network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Unexpected host-tool invocation")):
                self.assertEqual(timeline.main(), 0)

    def test_rehashed_derived_view_cannot_fabricate_retained_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture.history.capture(
                fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }]), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            directory = timeline.build([source], TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            document["events"][0]["record"]["caller"] = "forged@example.invalid"
            content = fixture.capture.ef.encoded(document)
            (directory / "timeline.json").write_bytes(content)
            manifest = json.loads((directory / "manifest.json").read_bytes())
            manifest["members"] = [
                fixture.capture.ef.descriptor("timeline.json", content) if entry["name"] == "timeline.json" else entry
                for entry in manifest["members"]
            ]
            (directory / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
            with self.assertRaisesRegex(ValueError, "views"):
                timeline.verify(directory)

    def test_parent_evidence_is_an_explicit_gap_or_an_exact_verified_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def reader():
                return fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": [fixture.activity()]},
                }])

            parent = fixture.history.capture(
                reader(), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT, fixture.RUN,
                root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            child = fixture.history.capture(
                reader(), "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                "00000000-0000-4000-8000-000000000071", root, fixture.START,
                "2026-10-14T04:00:00Z", planning_time="2026-10-14T04:00:00Z", previous_capsule=parent,
            )
            alone = timeline.build([child], TIMELINE, root)
            gap = json.loads((alone / "timeline.json").read_bytes())["coverage"]["parentReferences"][0]
            self.assertEqual(gap["state"], "notProvided")
            self.assertEqual(gap["parentCapsuleId"], fixture.RUN)
            combined = timeline.build([child, parent], "00000000-0000-4000-8000-000000000080", root)
            binding = json.loads((combined / "timeline.json").read_bytes())["coverage"]["parentReferences"][0]
            self.assertEqual(binding["state"], "verified")
            self.assertEqual(binding["expectedManifestSha256"], fixture.capture.ef.descriptor(
                "manifest.json", (parent / "manifest.json").read_bytes(),
            )["sha256"])
            forged = json.loads((child / "manifest.json").read_bytes())
            forged["parentCapsule"]["manifestSha256"] = "0" * 64
            (child / "manifest.json").write_bytes(fixture.capture.ef.encoded(forged))
            with self.assertRaisesRegex(ValueError, "parent"):
                timeline.build([parent, child], "00000000-0000-4000-8000-000000000081", root)

    def test_denied_empty_and_unknown_time_evidence_remain_visible_gaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = fixture.history.capture(
                fixture.HistoryService("service-health", [{
                    "statusCode": 200, "requestId": None,
                    "body": {"value": [{
                        "id": f"/subscriptions/{fixture.SUB}/providers/Microsoft.ResourceHealth/events/untimed",
                        "properties": {"eventSource": "ServiceHealth", "eventType": "HealthAdvisory"},
                    }]},
                }]), "service-health", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                "00000000-0000-4000-8000-000000000071", root,
                fixture.START, fixture.END, planning_time=fixture.END,
            )
            denied = fixture.history.capture(
                fixture.HistoryService("resource-changes", [{
                    "statusCode": 403, "requestId": None, "body": None, "errorCode": "AuthorizationFailed",
                }]), "resource-changes", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                "00000000-0000-4000-8000-000000000072", root,
                fixture.START, fixture.END, planning_time=fixture.END,
            )
            directory = timeline.build([service, denied], TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            event = document["events"][0]
            self.assertEqual(event["times"], {
                "eventTime": None, "sourceUpdatedTime": None, "submissionTime": None, "ingestionTime": None,
            })
            self.assertIn("configuration", document["coverage"]["notProvidedSources"])
            coverage = {entry["sourceId"]: entry for entry in document["coverage"]["sourceOutcomes"]}
            self.assertEqual(coverage["resource-changes"]["outcomes"], {"permissionDenied": 1})
            self.assertEqual(coverage["resource-changes"]["retainedRecords"], 0)
            self.assertIsNotNone(coverage["resource-changes"]["queryWindow"]["retentionGap"])
            markdown = (directory / "timeline.md").read_text(encoding="utf-8")
            self.assertIn("permissionDenied", markdown)
            self.assertIn("Retention gap", markdown)
            self.assertIn("UNKNOWN", markdown)
            self.assertEqual(timeline.verify(directory)["timelineId"], TIMELINE)

    def test_resource_and_correlation_context_keeps_historical_and_unbound_health_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_id = f"/subscriptions/{fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/app"
            resource = {"id": resource_id, "name": "app", "type": "Microsoft.Storage/storageAccounts",
                        "location": "westus2", "properties": {"publicNetworkAccess": "Enabled"}}
            base = f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.Storage/storageAccounts"
            configuration = fixture.configuration.ArmService({
                base + "?api-version=2023-05-01": {"statusCode": 200, "requestId": None, "body": {"value": [resource]}},
                "https://management.azure.com" + resource_id + "?api-version=2023-05-01": {
                    "statusCode": 200, "requestId": None, "body": resource,
                },
            })
            sources = [fixture.capture.capture(
                configuration, fixture.TENANT, fixture.SUB, fixture.CLIENT, fixture.RUN, root,
            )]
            change = {
                "id": "change-one", "subscriptionId": fixture.SUB, "targetResourceId": resource_id.upper(),
                "targetResourceType": "Microsoft.Storage/storageAccounts", "changeType": "Update",
                "changeAttributes": {"timestamp": fixture.EVENT_TIME, "correlationId": "correlation-1"}, "changes": {},
            }
            health = {
                "id": f"/subscriptions/{fixture.SUB}/providers/Microsoft.ResourceHealth/events/health-one",
                "properties": {"lastUpdateTime": fixture.EVENT_TIME, "impactStartTime": fixture.EVENT_TIME,
                               "eventSource": "ServiceHealth", "eventType": "HealthAdvisory", "status": "Active"},
            }
            replies = [
                ("activity-log", {"value": [fixture.activity(resourceId=resource_id.upper()), fixture.activity("historical")]}),
                ("resource-changes", {"data": [change], "count": 1, "totalRecords": 1, "resultTruncated": False}),
                ("service-health", {"value": [health]}),
            ]
            for number, (source_id, body) in enumerate(replies, 71):
                sources.append(fixture.history.capture(
                    fixture.HistoryService(source_id, [{"statusCode": 200, "requestId": None, "body": body}]),
                    source_id, fixture.TENANT, fixture.SUB, fixture.CLIENT,
                    f"00000000-0000-4000-8000-{number:012}", root,
                    fixture.START, fixture.END, planning_time=fixture.END,
                ))
            directory = timeline.build(sources, TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual(document["statistics"]["eventRevisions"], 4)
            self.assertEqual(document["statistics"]["configurationObservations"], 2)
            resources = {entry["id"]: entry for entry in document["resources"]}
            self.assertEqual(len(resources), 2)
            self.assertEqual(len(resources[resource_id.lower()]["configurationObservations"]), 2)
            self.assertEqual(len(resources[resource_id.lower()]["eventRevisions"]), 2)
            historical = next(entry for key, entry in resources.items() if key != resource_id.lower())
            self.assertEqual(historical["configurationEvidence"], "notObservedInProvidedSnapshots")
            self.assertEqual(historical["configurationObservations"], [])
            self.assertEqual(len(historical["eventRevisions"]), 1)
            self.assertEqual(len(document["unboundEventRevisions"]), 1)
            self.assertEqual(len(document["correlationGroups"]), 1)
            self.assertEqual(len(document["correlationGroups"][0]["eventRevisions"]), 3)
            self.assertEqual(document["correlationGroups"][0]["meaning"], "shared-recorded-id-not-causation")
            self.assertEqual(document["configurationComparison"], "notPerformed")
            self.assertEqual(timeline.verify(directory)["timelineId"], TIMELINE)

    def test_overlap_keeps_all_revisions_and_evidence_with_exact_event_time_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = fixture.activity(eventTimestamp="2026-10-13T18:00:00.0000002Z")
            earlier = fixture.activity("event-2", eventTimestamp="2026-10-13T18:00:00.0000001Z")
            revision = fixture.activity(
                eventTimestamp="2026-10-13T18:00:00.0000002Z", status={"value": "Failed"},
            )
            sources = []
            for number, values in enumerate(([first], [first, earlier], [revision]), 71):
                reader = fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "requestId": None, "body": {"value": values, "nextLink": None},
                }])
                sources.append(fixture.history.capture(
                    reader, "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                    f"00000000-0000-4000-8000-{number:012}", root,
                    fixture.START, fixture.END, planning_time=fixture.END,
                ))
            directory = timeline.build(sources, TIMELINE, root)
            document = json.loads((directory / "timeline.json").read_bytes())
            self.assertEqual(document["statistics"]["inputEventRows"], 4)
            self.assertEqual(document["statistics"]["eventRevisions"], 3)
            self.assertEqual(document["statistics"]["eventIdentities"], 2)
            self.assertEqual(document["events"][0]["sourceEventId"], "event-2")
            originals = [event for event in document["events"] if event["record"]["status"]["value"] == "Succeeded"]
            original = next(event for event in originals if event["sourceEventId"] == "event-1")
            self.assertEqual(len(original["evidence"]), 2)
            self.assertEqual(len({reference["capsuleId"] for reference in original["evidence"]}), 2)
            self.assertEqual(len({event["revisionId"] for event in document["events"] if event["sourceEventId"] == "event-1"}), 2)
            self.assertEqual(timeline.verify(directory)["timelineId"], TIMELINE)

    def test_timeline_is_a_self_contained_verified_view_of_unchanged_source_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = fixture.HistoryService("activity-log", [{
                "statusCode": 200, "requestId": None,
                "body": {"value": [fixture.activity()], "nextLink": None},
            }])
            source = fixture.history.capture(
                reader, "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT,
                fixture.RUN, root, fixture.START, fixture.END, planning_time=fixture.END,
            )
            original = {path.name: path.read_bytes() for path in source.iterdir()}

            directory = timeline.build([source], TIMELINE, root)
            manifest = timeline.verify(directory)
            document = json.loads((directory / "timeline.json").read_bytes())
            markdown = (directory / "timeline.md").read_text(encoding="utf-8")

            self.assertEqual(manifest["timelineId"], TIMELINE)
            self.assertEqual(document["statistics"]["inputCapsules"], 1)
            self.assertEqual(document["statistics"]["eventRevisions"], 1)
            event = document["events"][0]
            self.assertEqual(event["times"]["eventTime"], "2026-10-13T18:00:00Z")
            self.assertEqual(event["times"]["submissionTime"], "2026-10-13T18:05:00Z")
            self.assertEqual(event["record"]["caller"], "fixture-actor@example.invalid")
            self.assertEqual(event["evidence"][0]["pointer"], "/events/0/record")
            self.assertEqual(event["evidence"][0]["member"], f"sources/{fixture.RUN}/events-p0001.json")
            self.assertIn(event["evidence"][0]["member"], markdown)
            self.assertNotIn("fixture-actor@example.invalid", markdown)
            self.assertFalse(document["assessmentPerformed"])
            self.assertEqual(document["causalConclusions"], "notGenerated")
            for name, content in original.items():
                self.assertEqual((source / name).read_bytes(), content)
                self.assertEqual((directory / "sources" / fixture.RUN / name).read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
