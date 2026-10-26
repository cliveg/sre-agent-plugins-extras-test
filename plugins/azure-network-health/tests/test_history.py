from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_hostless_capture as configuration


sys.path.insert(0, str(configuration.SCRIPTS))
import network_history as history
import network_capture as capture


SUB, TENANT, CLIENT, RUN = configuration.SUB, configuration.TENANT, configuration.CLIENT, configuration.RUN
END = "2026-10-14T03:00:00Z"
START = "2025-10-14T03:00:00Z"
EVENT_TIME = "2026-10-13T18:00:00Z"


class HistoryService(configuration.ArmService):
    def __init__(self, source, pages):
        super().__init__()
        self.source = source
        self.pages = list(pages)
        self.event_calls = []

    def events(self, source, window, cursor):
        self.event_calls.append({"source": source, "window": window, "cursor": cursor})
        if source != self.source:
            raise AssertionError("Unplanned source")
        return self.pages.pop(0)


def activity(event_id="event-1", **changes):
    value = {
        "eventDataId": event_id, "id": f"/subscriptions/{SUB}/providers/Microsoft.Insights/events/{event_id}",
        "subscriptionId": SUB, "resourceId": f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Compute/virtualMachines/deleted",
        "category": {"value": "Administrative", "localizedValue": "Administrative"},
        "eventTimestamp": EVENT_TIME, "submissionTimestamp": "2026-10-13T18:05:00Z",
        "caller": "fixture-actor@example.invalid", "correlationId": "correlation-1",
        "operationName": {"value": "Microsoft.Compute/virtualMachines/write"},
        "status": {"value": "Succeeded"},
        "claims": {"appid": CLIENT, "http://schemas.microsoft.com/identity/claims/objectidentifier": RUN,
                   "access_token": "synthetic-do-not-retain"},
        "httpRequest": {"clientIpAddress": "198.51.100.1"},
        "properties": {"requestBody": {"password": "synthetic-do-not-retain"}},
    }
    value.update(changes)
    return value


class HistoryTests(unittest.TestCase):
    def test_rehashed_checkpoint_cannot_skip_missing_history_pages_before_authentication(self):
        class Interrupted(HistoryService):
            def events(self, source, window, cursor):
                raise capture.UnconfirmedRead("Synthetic interruption")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(capture.UnconfirmedRead):
                history.capture(Interrupted("activity-log", []), "activity-log", TENANT, SUB, CLIENT, RUN,
                                root, START, END, planning_time=END)
            path = root / "history-acquisition" / RUN / "state.json"
            state = json.loads(path.read_bytes())
            state["progress"]["page"] = 50
            state["progressSha256"] = capture.ef.digest(state["progress"])
            path.write_bytes(capture.ef.encoded(state))
            reader = HistoryService("activity-log", [{"statusCode": 200, "body": {"value": [], "nextLink": None}, "requestId": None}])
            with self.assertRaisesRegex(ValueError, "checkpoint"):
                history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, resume=True,
                                retry_unconfirmed=True)
            self.assertEqual(reader.context_calls, 0)
            self.assertEqual(reader.event_calls, [])

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell unavailable; actual history bridge not exercised")
    def test_actual_history_protocol_allows_only_fixed_gets_and_resource_graph_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "modules" / "Az.Accounts" / "3.0.4"
            module.mkdir(parents=True)
            (module / "Az.Accounts.psd1").write_text(
                "@{RootModule='Az.Accounts.psm1';ModuleVersion='3.0.4';GUID='00000000-0000-4000-8000-000000000010';"
                "FunctionsToExport=@('Disable-AzContextAutosave','Connect-AzAccount','Get-AzContext','Invoke-AzRestMethod')}",
                encoding="utf-8",
            )
            (module / "Az.Accounts.psm1").write_text(
                """function Disable-AzContextAutosave { param($Scope) if($Scope -ne 'Process'){throw 'Unscoped auth'} }
function Connect-AzAccount { param([switch]$Identity,$AccountId,$Tenant,$Subscription,$Scope,$WarningAction)
 if(-not $Identity -or $Scope -ne 'Process'){throw 'Wrong auth'}
 $script:ctx=[pscustomobject]@{Tenant=[pscustomobject]@{Id=$Tenant};Subscription=[pscustomobject]@{Id=$Subscription}}
}
function Get-AzContext { return $script:ctx }
function Invoke-AzRestMethod { param($Method,$Path,$Payload,$DefaultProfile,$ErrorAction)
 if(-not $DefaultProfile){throw 'Missing scope'}
 if($Method -eq 'POST'){
  if($Path -cne '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'){throw 'Unexpected POST'}
  $body=$Payload|ConvertFrom-Json -AsHashtable
  if($body.subscriptions.Count -ne 1 -or $body.subscriptions[0] -ne $script:ctx.Subscription.Id -or
     -not $body.query.StartsWith('resourcechanges') -or $body.options['$top'] -ne 500){throw 'Unexpected query'}
  return [pscustomobject]@{StatusCode=200;Content='{"data":[],"count":0,"totalRecords":0,"resultTruncated":"false"}';Headers=@{}}
 }
 if($Method -ne 'GET'){throw 'Resource mutation'}
 return [pscustomobject]@{StatusCode=200;Content='{"value":[]}';Headers=@{}}
}
""", encoding="utf-8",
            )
            frames = [
                {"source": "activity-log", "start": "2026-10-01T00:00:00Z", "end": END, "cursor": None},
                {"source": "resource-changes", "start": "2026-10-01T00:00:00Z", "end": END, "cursor": None},
                {"source": "resource-changes", "start": "2026-10-01T00:00:00Z", "end": END, "cursor": None,
                 "query": "Resources | take 1000"},
            ]
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(configuration.SCRIPTS / "history_reader.ps1"),
                 "-TenantId", TENANT, "-SubscriptionId", SUB, "-ManagedIdentityClientId", CLIENT],
                input="\n".join(json.dumps(value) for value in frames) + "\n", capture_output=True, text=True,
                timeout=60, check=False, env={**os.environ, "WARA_CACHE": str(root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(replies), 4)
            self.assertEqual(replies[0]["status"], "ready")
            self.assertEqual(replies[1]["body"], {"value": []})
            self.assertEqual(replies[2]["body"]["totalRecords"], 0)
            self.assertEqual(replies[3]["errorCode"], "HistoryReadPolicyRejected")

    def test_missing_event_time_and_identity_remain_unknown_without_collection_time_substitution(self):
        value = activity()
        for key in ("id", "eventDataId", "eventTimestamp", "submissionTimestamp", "caller"):
            value.pop(key)
        reader = HistoryService("activity-log", [{"statusCode": 200, "body": {"value": [value, value], "nextLink": None}, "requestId": None}])
        with tempfile.TemporaryDirectory() as temporary:
            result = capture.replay(history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, Path(temporary), START, END,
                                                     planning_time=END))
            self.assertEqual(len(result["events"]), 2)
            self.assertNotEqual(result["events"][0]["id"], result["events"][1]["id"])
            self.assertTrue(all(event["eventTime"] is None and event["sourceEventId"] is None for event in result["events"]))
            self.assertTrue(all(event["timeAvailability"]["eventTime"] == "UNKNOWN" for event in result["events"]))

    def test_repeated_continuation_is_rejected_before_another_request_or_watermark(self):
        root_url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$skiptoken=repeat"
        reader = HistoryService("activity-log", [
            {"statusCode": 200, "body": {"value": [], "nextLink": root_url}, "requestId": None},
            {"statusCode": 200, "body": {"value": [], "nextLink": root_url}, "requestId": None},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "repeated"):
                history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, planning_time=END)
            self.assertEqual(len(reader.event_calls), 2)
            self.assertFalse((root / "capsules" / RUN).exists())

    def test_rebound_unknown_history_member_is_rejected_instead_of_published(self):
        reader = HistoryService("activity-log", [{"statusCode": 200, "body": {"value": [], "nextLink": None}, "requestId": None}])
        with tempfile.TemporaryDirectory() as temporary:
            directory = history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, Path(temporary), START, END,
                                        planning_time=END)
            unexpected = directory / "unreviewed.json"
            unexpected.write_bytes(b'{"accessToken": "synthetic-do-not-retain"}\n')
            path = directory / "manifest.json"
            manifest = json.loads(path.read_bytes())
            manifest["members"].append(capture.ef.descriptor(unexpected.name, unexpected.read_bytes()))
            path.write_bytes(capture.ef.encoded(manifest))
            with self.assertRaisesRegex(ValueError, "member"):
                capture.verify(directory)

    def test_incremental_overlap_uses_terminal_source_watermark_and_denial_cannot_advance_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = history.capture(HistoryService("activity-log", [{
                "statusCode": 200, "body": {"value": [activity()], "nextLink": None}, "requestId": None,
            }]), "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, planning_time=END)
            identifier = "00000000-0000-4000-8000-000000000058"
            later = "2026-10-14T04:00:00Z"
            reader = HistoryService("activity-log", [{"statusCode": 403, "body": None, "requestId": "denied"}])
            second = history.capture(reader, "activity-log", TENANT, SUB, CLIENT, identifier, root, START, later,
                                     planning_time=later, previous_capsule=first)
            manifest = capture.verify(second)
            self.assertEqual(reader.event_calls[0]["window"]["start"], "2026-10-13T03:00:00Z")
            self.assertIsNone(manifest["watermark"]["enumeratedThrough"])
            self.assertEqual(manifest["coverage"]["pages"][0]["status"], "permissionDenied")
            self.assertIsNone(manifest["coverage"]["pages"][0]["returnedRows"])
            blocked = HistoryService("activity-log", [])
            with self.assertRaisesRegex(ValueError, "incomplete"):
                history.capture(blocked, "activity-log", TENANT, SUB, CLIENT,
                                "00000000-0000-4000-8000-000000000059", root, START, later,
                                planning_time=later, previous_capsule=second)
            self.assertEqual(blocked.event_calls, [])

    def test_uncertain_history_page_requires_explicit_retry_and_completed_resume_is_offline(self):
        class Interrupted(HistoryService):
            def events(self, source, window, cursor):
                self.event_calls.append({"source": source, "window": window, "cursor": cursor})
                raise capture.UnconfirmedRead("Synthetic history interruption")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = Interrupted("activity-log", [])
            with self.assertRaises(capture.UnconfirmedRead):
                history.capture(first, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, planning_time=END)
            stopped = HistoryService("activity-log", [])
            with self.assertRaisesRegex(capture.UnconfirmedRead, "explicit"):
                history.capture(stopped, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, resume=True)
            self.assertEqual(stopped.context_calls, 0)
            self.assertEqual(stopped.event_calls, [])
            reader = HistoryService("activity-log", [{"statusCode": 200, "body": {"value": [], "nextLink": None}, "requestId": None}])
            directory = history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END,
                                        resume=True, retry_unconfirmed=True)
            self.assertEqual(len(capture.verify(directory)["coverage"]["unconfirmedAttempts"]), 1)
            final = HistoryService("activity-log", [])
            self.assertEqual(history.capture(final, "activity-log", TENANT, SUB, CLIENT, RUN, root, START, END, resume=True), directory)
            self.assertEqual(final.context_calls, 0)
            self.assertEqual(final.event_calls, [])

    def test_resource_changes_keep_reviewed_values_and_recorded_system_attribution_only(self):
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/storage"
        change = {
            "id": identifier + "/providers/Microsoft.Resources/changes/change-1",
            "subscriptionId": SUB, "targetResourceId": identifier, "targetResourceType": "microsoft.storage/storageaccounts",
            "changeType": "Update", "changeAttributes": {
                "timestamp": EVENT_TIME, "changedBy": "System", "changedByType": "System", "clientType": "Unspecified",
                "operation": "Microsoft.Storage/storageAccounts/write", "correlationId": "correlation-1", "changesCount": 3,
            },
            "changes": {
                "properties.publicNetworkAccess": {"previousValue": "Disabled", "newValue": "Enabled", "isTruncated": "false"},
                "properties.supportsHttpsTrafficOnly": {"previousValue": "true", "newValue": "false"},
                "tags.secret": {"previousValue": "synthetic-do-not-retain", "newValue": "synthetic-do-not-retain"},
            },
        }
        reader = HistoryService("resource-changes", [{"statusCode": 200, "body": {
            "data": [change], "count": 1, "totalRecords": 1, "resultTruncated": "false",
        }, "requestId": None}])
        with tempfile.TemporaryDirectory() as temporary:
            directory = history.capture(reader, "resource-changes", TENANT, SUB, CLIENT, RUN, Path(temporary), START, END,
                                        planning_time=END)
            result = capture.replay(directory)
            self.assertEqual(len(result["events"]), 1)
            record = result["events"][0]["record"]
            self.assertEqual(record["changeAttributes"]["changedByType"], "System")
            self.assertEqual(record["changeType"], "Update")
            public = next(row for row in record["changedProperties"] if row["path"] == "properties.publicNetworkAccess")
            self.assertEqual(public["previous"]["value"], "Disabled")
            self.assertEqual(public["new"]["value"], "Enabled")
            flag = next(row for row in record["changedProperties"] if row["path"] == "properties.supportsHttpsTrafficOnly")
            self.assertEqual(flag["new"]["value"], "false")
            self.assertEqual(flag["new"]["representation"], "source-string")
            private = next(row for row in record["changedProperties"] if row["path"] == "tags.secret")
            self.assertEqual(private["new"], {"status": "unreviewedPathOmitted"})
            self.assertNotIn("synthetic-do-not-retain", "".join(path.read_text() for path in directory.iterdir()))
            self.assertEqual(capture.verify(directory)["queryWindow"]["start"], "2026-09-30T03:00:00Z")

    def test_health_revisions_preserve_updates_and_omit_sensitive_messages_without_causal_claims(self):
        identifier = f"/subscriptions/{SUB}/providers/Microsoft.ResourceHealth/events/tracking-1"
        first = {"id": identifier, "name": "tracking-1", "properties": {
            "eventType": "ServiceIssue", "eventSource": "ServiceHealth", "status": "Active",
            "impactStartTime": "2026-10-12T18:00:00Z", "lastUpdateTime": EVENT_TIME, "platformInitiated": True,
            "isEventSensitive": True, "summary": "synthetic-do-not-retain",
            "description": "synthetic-do-not-retain",
            "impact": [{"impactedService": "Storage", "impactedRegions": [{"impactedRegion": "West US",
                "updates": [{"updateDateTime": EVENT_TIME, "summary": "synthetic-do-not-retain", "eventTags": ["Preliminary PIR"]}]}]}],
        }}
        second = json.loads(json.dumps(first))
        second["properties"].update({"status": "Resolved", "lastUpdateTime": "2026-10-13T20:00:00Z",
                                     "impactMitigationTime": "2026-10-13T19:00:00Z"})
        reader = HistoryService("service-health", [{"statusCode": 200, "body": {"value": [first, second], "nextLink": None}, "requestId": None}])
        with tempfile.TemporaryDirectory() as temporary:
            directory = history.capture(reader, "service-health", TENANT, SUB, CLIENT, RUN, Path(temporary), START, END,
                                        planning_time=END)
            result = capture.replay(directory)
            self.assertEqual(len(result["events"]), 2)
            self.assertEqual(result["events"][0]["id"], result["events"][1]["id"])
            self.assertNotEqual(result["events"][0]["revisionId"], result["events"][1]["revisionId"])
            self.assertEqual(result["events"][0]["record"]["properties"]["impact"][0]["impactedRegions"][0]["updates"][0]["updateDateTime"], EVENT_TIME)
            self.assertNotIn("synthetic-do-not-retain", "".join(path.read_text() for path in directory.iterdir()))
            self.assertEqual(result["causalConclusions"], "notGenerated")

    def test_subscription_activity_history_is_sealed_replayed_and_keeps_recorded_actor_without_secrets(self):
        reader = HistoryService("activity-log", [{"statusCode": 200, "body": {"value": [activity()], "nextLink": None}, "requestId": "request-1"}])
        with tempfile.TemporaryDirectory() as temporary:
            directory = history.capture(reader, "activity-log", TENANT, SUB, CLIENT, RUN, Path(temporary), START, END,
                                        planning_time=END)
            manifest = capture.verify(directory)
            self.assertEqual(manifest["capsuleVersion"], "0.4.0")
            with patch("subprocess.run", side_effect=AssertionError("Offline replay cannot spawn processes")):
                with patch("urllib.request.urlopen", side_effect=AssertionError("Offline replay cannot use network")):
                    replay = capture.replay(directory)
                    self.assertEqual(replay, capture.replay(directory))
            self.assertEqual(len(replay["events"]), 1)
            event = replay["events"][0]
            self.assertEqual(event["record"]["caller"], "fixture-actor@example.invalid")
            self.assertEqual(event["eventTime"], EVENT_TIME)
            self.assertEqual(event["submissionTime"], "2026-10-13T18:05:00Z")
            self.assertIn("deleted", event["record"]["resourceId"])
            self.assertEqual(event["record"]["actorClaims"]["appid"], CLIENT)
            self.assertNotIn("synthetic-do-not-retain", "".join(path.read_text() for path in directory.iterdir()))
            self.assertNotIn("clientIpAddress", event["record"])
            self.assertEqual(manifest["queryWindow"]["start"], "2026-07-16T03:00:00Z")
            self.assertEqual(manifest["watermark"]["enumeratedThrough"], END)
            self.assertFalse(replay["assessmentPerformed"])


if __name__ == "__main__":
    unittest.main()
