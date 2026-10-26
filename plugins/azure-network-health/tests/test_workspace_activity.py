from __future__ import annotations

import sys
import tempfile
import unittest
import json
import os
import shutil
import subprocess
import io
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path

import test_hostless_capture as configuration
import network_capture as capture
import network_history as history


sys.path.insert(0, str(configuration.SCRIPTS))
import workspace_activity as workspace


SUB, TENANT, CLIENT, RUN = configuration.SUB, configuration.TENANT, configuration.CLIENT, configuration.RUN
GUID = "00000000-0000-4000-8000-000000000060"
RESOURCE = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.OperationalInsights/workspaces/activity"
START = "2026-07-15T00:00:00Z"
END = "2026-10-14T00:00:00Z"


def table(rows, names):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": name, "type": "string"} for name in names], "rows": rows}]}


def activity_row(stamp="2026-10-13T18:00:00Z", key="1" * 64):
    value = {name: "" for name in workspace.EVENT_COLUMNS}
    value.update({"TimeGenerated": stamp, "EventId": "event-1", "SubmittedTime": stamp, "IngestedTime": stamp,
                  "AssessedSubscription": SUB, "Category": "Administrative", "Caller": "fixture-actor@example.invalid",
                  "Copies": 1, "RowKey": key})
    return value


class WorkspaceService(configuration.ArmService):
    def __init__(self, summaries=None, metadata_status=200):
        super().__init__()
        self.summaries = summaries
        self.metadata_status = metadata_status
        self.workspace_calls = []
        self.closed = False

    def close(self):
        self.closed = True

    def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
        self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
        if operation == "describe":
            return {"statusCode": self.metadata_status, "requestId": None, "body": {
                "id": resource_id, "properties": {"customerId": GUID, "retentionInDays": 30},
            } if self.metadata_status == 200 else None}
        if operation == "table":
            return {"statusCode": 200, "requestId": None, "body": {"name": "AzureActivity", "properties": {
                "plan": "Analytics", "retentionInDays": 90, "totalRetentionInDays": 365,
                "schema": {"columns": [{"name": name} for name in ("TimeGenerated", "SubscriptionId", "EventDataId", "CategoryValue", "Caller")]},
            }}}
        if operation == "summary":
            return {"statusCode": 200, "requestId": "query-1", "body": self.summaries or table(
                [["Administrative", 12, "2026-07-20T00:00:00Z", "2026-10-13T00:00:00Z", 12]],
                ["Category", "Records", "Earliest", "Latest", "WithCaller"],
            )}
        raise AssertionError("Unplanned workspace operation: " + operation)


class WorkspaceActivityTests(unittest.TestCase):
    def test_keyset_query_uses_kusto_string_comparison_and_preserves_exact_cursor_time(self):
        window = workspace.query_window(START, END, END)
        stamp = "2026-10-13T18:00:00.1234567Z"
        for key in ("0" * 64, "f" * 64, "09af" * 16):
            with self.subTest(key=key):
                query = workspace.kql("page", SUB, window, {"afterTime": stamp, "afterKey": key})
                self.assertIn(
                    f"TimeGenerated > datetime('{stamp}') or "
                    f"(TimeGenerated == datetime('{stamp}') and strcmp(RowKey, '{key}') > 0)",
                    query,
                )
                self.assertNotRegex(query, r"\bRowKey\s*>")
        self.assertIn("| where true", workspace.kql("page", SUB, window))

    def test_standard_schema_columns_are_combined_without_losing_inventory_provenance(self):
        class StandardColumns(WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                response = super().workspace(operation, resource_id, workspace_id, window, cursor)
                if operation == "table":
                    schema = response["body"]["properties"]["schema"]
                    schema["columns"] = [column for column in schema["columns"] if column["name"] != "TimeGenerated"]
                    schema["standardColumns"] = [{"name": "TimeGenerated"}]
                return response

        result = workspace.preflight(StandardColumns(), TENANT, SUB, CLIENT, RESOURCE, START, END)
        self.assertEqual(result["readiness"], "AVAILABLE")
        self.assertIn("TimeGenerated", result["tableMetadata"]["columns"])
        self.assertEqual(result["tableMetadata"]["schemaSources"]["standardColumns"], ["TimeGenerated"])
        self.assertNotIn("TimeGenerated", result["tableMetadata"]["schemaSources"]["columns"])

    def test_empty_first_page_after_positive_preflight_is_preserved_unknown_without_advancing_watermark(self):
        class EmptyCollection(WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "page":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    return {"statusCode": 200, "requestId": "empty-query",
                            "body": table([], workspace.EVENT_COLUMNS)}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        with tempfile.TemporaryDirectory() as temporary:
            directory = workspace.capture(EmptyCollection(), TENANT, SUB, CLIENT, RUN, Path(temporary),
                                          RESOURCE, START, END, planning_time=END)
            manifest = capture.verify(directory)
            self.assertIsNone(manifest["watermark"]["enumeratedThrough"])
            self.assertEqual(manifest["coverage"]["readiness"]["status"], "UNKNOWN")
            self.assertEqual(len(capture.replay(directory)["events"]), 0)
            self.assertEqual(manifest["coverage"]["pages"][0]["status"], "succeeded")
            self.assertEqual(manifest["workspace"]["readiness"], "AVAILABLE")

    def test_summary_and_page_queries_both_filter_approved_categories_at_the_shared_base(self):
        window = workspace.query_window(START, END, END)
        for operation in ("summary", "page"):
            with self.subTest(operation=operation):
                query = workspace.kql(operation, SUB, window)
                self.assertIn("CategoryValue in ('Administrative', 'ResourceHealth', 'ServiceHealth')", query)

    def test_partial_page_is_not_sealed_as_complete_workspace_history(self):
        class PartialPage(WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "page":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    return {"statusCode": 200, "requestId": "partial-query", "body": {
                        "tables": [], "error": {"code": "PartialError", "message": "synthetic-private-message"},
                    }}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        reader = PartialPage()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "partial/error"):
                workspace.capture(reader, TENANT, SUB, CLIENT, RUN, root, RESOURCE, START, END, planning_time=END)
            self.assertFalse((root / "capsules" / RUN).exists())
            state = json.loads((root / "history-acquisition" / RUN / "state.json").read_bytes())
            self.assertFalse(state["progress"]["complete"])
            self.assertFalse(state["progress"]["terminal"])
            self.assertEqual([value[0] for value in reader.workspace_calls], ["describe", "table", "summary", "page"])
            self.assertNotIn("synthetic-private-message", str(state))

    def test_capture_refuses_empty_workspace_without_a_success_capsule(self):
        reader = WorkspaceService(summaries=table([], workspace.SUMMARY_COLUMNS))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "UNKNOWN"):
                workspace.capture(reader, TENANT, SUB, CLIENT, RUN, root, RESOURCE, START, END, planning_time=END)
            self.assertEqual(list(root.iterdir()), [])

    def test_preflight_cli_persists_unknown_readiness_and_returns_nonzero_with_compact_output(self):
        reader = WorkspaceService(metadata_status=403)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "readiness.json"
            arguments = ["workspace", "preflight", "--tenant-id", TENANT, "--subscription-id", SUB,
                         "--managed-identity-client-id", CLIENT, "--workspace-resource-id", RESOURCE,
                         "--start-time", START, "--end-time", END, "--output", str(output)]
            stdout = io.StringIO()
            with patch.object(sys, "argv", arguments), patch.object(workspace, "WorkspaceBridge", return_value=reader):
                with redirect_stdout(stdout):
                    result = workspace.main()
            self.assertEqual(result, 2)
            self.assertEqual(json.loads(output.read_bytes())["readiness"], "UNKNOWN")
            self.assertEqual(json.loads(stdout.getvalue())["readiness"], "UNKNOWN")
            self.assertFalse(json.loads(stdout.getvalue())["directFallbackAttempted"])
            self.assertLess(len(stdout.getvalue().encode()), 2000)
            self.assertTrue(reader.closed)

    def test_incremental_resume_reuses_saved_workspace_window_without_repeating_preflight(self):
        class Incremental(WorkspaceService):
            def __init__(self, interrupt=False):
                super().__init__()
                self.interrupt = interrupt

            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "summary":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    return {"statusCode": 200, "requestId": None, "body": table(
                        [["Administrative", 1, window["start"], window["end"], 1]], workspace.SUMMARY_COLUMNS,
                    )}
                if operation == "page":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    if self.interrupt:
                        raise capture.UnconfirmedRead("Synthetic incomplete Logs query")
                    row = activity_row()
                    return {"statusCode": 200, "requestId": None,
                            "body": table([[row[name] for name in workspace.EVENT_COLUMNS]], workspace.EVENT_COLUMNS)}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = workspace.capture(Incremental(), TENANT, SUB, CLIENT, RUN, root, RESOURCE, START, END,
                                         planning_time=END)
            identifier = "00000000-0000-4000-8000-000000000061"
            later = "2026-10-14T01:00:00Z"
            with self.assertRaises(capture.UnconfirmedRead):
                workspace.capture(Incremental(True), TENANT, SUB, CLIENT, identifier, root, RESOURCE, START, later,
                                  planning_time=later, previous_capsule=previous)
            reader = Incremental()
            directory = workspace.capture(reader, TENANT, SUB, CLIENT, identifier, root, RESOURCE, START, later,
                                          previous_capsule=previous, resume=True, retry_unconfirmed=True)
            self.assertEqual(capture.verify(directory)["queryWindow"]["start"], "2026-10-13T00:00:00Z")
            self.assertEqual([value[0] for value in reader.workspace_calls], ["page"])
            self.assertEqual(len(capture.verify(directory)["coverage"]["unconfirmedAttempts"]), 1)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell unavailable; workspace protocol not exercised")
    def test_actual_workspace_protocol_binds_metadata_and_rejects_arbitrary_queries_and_unknown_workspaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "modules" / "Az.Accounts" / "3.0.4"
            module.mkdir(parents=True)
            (module / "Az.Accounts.psd1").write_text(
                "@{RootModule='Az.Accounts.psm1';ModuleVersion='3.0.4';GUID='00000000-0000-4000-8000-000000000010';"
                "FunctionsToExport=@('Disable-AzContextAutosave','Connect-AzAccount','Get-AzContext','Invoke-AzRestMethod','Get-AzAccessToken')}",
                encoding="utf-8",
            )
            code = """function Disable-AzContextAutosave { param($Scope) if($Scope -ne 'Process'){throw 'Unscoped auth'} }
function Connect-AzAccount { param([switch]$Identity,$AccountId,$Tenant,$Subscription,$Scope,$WarningAction)
 if(-not $Identity -or $Scope -ne 'Process'){throw 'Wrong auth'}
 $script:ctx=[pscustomobject]@{Tenant=[pscustomobject]@{Id=$Tenant};Subscription=[pscustomobject]@{Id=$Subscription}}
}
function Get-AzContext { return $script:ctx }
function Invoke-AzRestMethod { param($Method,$Path,$Payload,$DefaultProfile,$ErrorAction)
 if($Method -ne 'GET' -or -not $DefaultProfile){throw 'Unexpected query/mutation'}
 $resource='__RESOURCE__';$guid='__GUID__'
 return [pscustomobject]@{StatusCode=200;Content=(@{id=$resource;properties=@{customerId=$guid}}|ConvertTo-Json -Compress);Headers=@{}}
}
function Get-AzAccessToken { param($ResourceUrl,$DefaultProfile,$ErrorAction)
 if($ResourceUrl -ne 'https://api.loganalytics.io' -or -not $DefaultProfile){throw 'Wrong scope'}
 throw 'Synthetic credential unavailable; must not log raw errors'
}
""".replace("__RESOURCE__", RESOURCE).replace("__GUID__", GUID)
            (module / "Az.Accounts.psm1").write_text(code, encoding="utf-8")
            window = workspace.query_window(START, END, END)
            frames = [
                {"operation": "describe", "workspaceResourceId": RESOURCE, "workspaceId": None, "window": None, "cursor": None},
                {"operation": "summary", "workspaceResourceId": RESOURCE, "workspaceId": GUID, "window": window, "cursor": None},
                {"operation": "summary", "workspaceResourceId": RESOURCE, "workspaceId": GUID, "window": window,
                 "cursor": None, "query": "union *"},
                {"operation": "describe", "workspaceResourceId": RESOURCE.replace(SUB, RUN),
                 "workspaceId": None, "window": None, "cursor": None},
            ]
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(configuration.SCRIPTS / "workspace_reader.ps1"),
                 "-TenantId", TENANT, "-SubscriptionId", SUB, "-ManagedIdentityClientId", CLIENT],
                input="\n".join(json.dumps(frame) for frame in frames) + "\n", capture_output=True, text=True,
                timeout=60, check=False, env={**os.environ, "WARA_CACHE": str(root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(replies), 5)
            self.assertEqual(replies[0]["status"], "ready")
            self.assertEqual(replies[1]["body"]["properties"]["customerId"], GUID)
            self.assertEqual(replies[2]["errorCode"], "LogsCredentialUnavailable")
            self.assertEqual(replies[3]["errorCode"], "WorkspaceReadPolicyRejected")
            self.assertEqual(replies[4]["errorCode"], "WorkspaceReadPolicyRejected")
            self.assertNotIn("Synthetic credential", result.stdout + result.stderr)

    def test_discovery_does_not_follow_cross_subscription_export_without_explicit_approval(self):
        foreign = RESOURCE.replace(SUB, RUN)

        class Discovery(WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "destinations":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    return {"statusCode": 200, "requestId": "settings-1", "body": {"value": [{
                        "name": "central-export", "properties": {"workspaceId": foreign, "logs": [
                            {"category": "Administrative", "enabled": True},
                            {"category": "ResourceHealth", "enabled": False},
                        ]},
                    }], "nextLink": None}}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        reader = Discovery()
        result = workspace.discover(reader, TENANT, SUB, CLIENT, START, END)
        self.assertEqual(result["readiness"], "UNKNOWN")
        self.assertEqual(result["candidates"][0]["reason"], "WorkspaceReadScopeApprovalRequired")
        self.assertEqual([value[0] for value in reader.workspace_calls], ["destinations"])
        reader = Discovery()
        result = workspace.discover(reader, TENANT, SUB, CLIENT, START, END, approved_workspaces=[foreign])
        self.assertEqual(result["readiness"], "AVAILABLE")
        self.assertEqual(result["selectedWorkspaceResourceId"], foreign)
        self.assertEqual(result["candidates"][0]["configuredCategories"][0]["enabled"], True)
        self.assertFalse(result["candidates"][0]["exportSettingProvesIngestion"])

    def test_workspace_capture_replays_with_bound_preflight_and_preserves_old_history_contract(self):
        class Populated(WorkspaceService):
            def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                if operation == "page":
                    self.workspace_calls.append((operation, resource_id, workspace_id, window, cursor))
                    row = activity_row()
                    return {"statusCode": 200, "requestId": "logs-page-1",
                            "body": table([[row[name] for name in workspace.EVENT_COLUMNS]], workspace.EVENT_COLUMNS)}
                return super().workspace(operation, resource_id, workspace_id, window, cursor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = Populated()
            directory = workspace.capture(reader, TENANT, SUB, CLIENT, RUN, root, RESOURCE, START, END,
                                          planning_time=END)
            manifest = capture.verify(directory)
            self.assertEqual(manifest["capsuleVersion"], "0.5.0")
            self.assertEqual(manifest["profileId"], "hostless-workspace-activity")
            self.assertEqual(manifest["workspace"]["workspaceId"], GUID)
            self.assertEqual(manifest["queryWindow"]["start"], START)
            result = capture.replay(directory)
            self.assertEqual(len(result["events"]), 1)
            self.assertEqual(result["events"][0]["record"]["Caller"], "fixture-actor@example.invalid")
            self.assertEqual(result["events"][0]["eventTime"], "2026-10-13T18:00:00Z")
            self.assertEqual(result["watermark"]["enumeratedThrough"], END)
            self.assertEqual(result, capture.replay(directory))
            stopped = WorkspaceService(metadata_status=403)
            self.assertEqual(workspace.capture(stopped, TENANT, SUB, CLIENT, RUN, root, RESOURCE, START, END,
                                              resume=True), directory)
            self.assertEqual(stopped.workspace_calls, [])
            self.assertEqual(stopped.context_calls, 0)
            self.assertEqual(history.CAPSULE_VERSION, "0.4.0")

    def test_no_data_denial_and_http_200_partial_results_never_become_available(self):
        for case in ("empty", "denied", "partial"):
            with self.subTest(case=case):
                body = table([], workspace.SUMMARY_COLUMNS)
                if case == "partial":
                    body["error"] = {"code": "PartialError", "message": "synthetic-private-message"}
                reader = WorkspaceService(summaries=body, metadata_status=403 if case == "denied" else 200)
                result = workspace.preflight(reader, TENANT, SUB, CLIENT, RESOURCE, START, END)
                self.assertEqual(result["readiness"], "UNKNOWN")
                self.assertNotEqual(result["reason"], "RelevantAzureActivityRowsObserved")
                self.assertFalse(result["fullWindowCompletenessProven"])
                if case == "denied":
                    self.assertEqual([value[0] for value in reader.workspace_calls], ["describe"])
                self.assertNotIn("synthetic-private-message", str(result))

    def test_paged_projection_is_fixed_and_subscription_filtered_with_exact_lookahead(self):
        rows = [activity_row(key=hex(number)[2:].zfill(64)) for number in range(501)]
        window = workspace.query_window(START, END, END)
        body = table([[row[name] for name in workspace.EVENT_COLUMNS] for row in rows], workspace.EVENT_COLUMNS)
        selected, cursor, count, _ = workspace.select_page(body, SUB, window, None)
        self.assertEqual(count, 500)
        self.assertEqual(len(selected), 500)
        self.assertEqual(cursor["afterKey"], rows[499]["RowKey"])
        query = workspace.kql("page", SUB, window, cursor)
        self.assertIn("SubscriptionId =~ '" + SUB + "'", query)
        self.assertIn("take 501", query)
        self.assertIn(cursor["afterKey"], query)
        self.assertNotIn("pack_all", query)
        for forbidden in ("CallerIpAddress", "requestBody", "access_token"):
            self.assertNotIn(forbidden, query)

    def test_workspace_paging_preserves_seventh_fractional_digit(self):
        rows = [activity_row("2026-10-13T18:00:00.1234561Z", "f" * 64),
                activity_row("2026-10-13T18:00:00.1234562Z", "0" * 64)]
        body = table([[row[name] for name in workspace.EVENT_COLUMNS] for row in rows], workspace.EVENT_COLUMNS)
        window = workspace.query_window(START, END, END)
        selected, cursor, count, dropped = workspace.select_page(body, SUB, window, None)
        self.assertEqual(count, 2)
        self.assertIsNone(cursor)
        self.assertEqual(selected[0]["record"]["TimeGenerated"], "2026-10-13T18:00:00.1234561Z")

    def test_preflight_verifies_bound_workspace_rows_categories_and_retention_without_cross_scope_fallback(self):
        reader = WorkspaceService()
        result = workspace.preflight(reader, TENANT, SUB, CLIENT, RESOURCE, START, END)
        self.assertEqual(result["readiness"], "AVAILABLE")
        self.assertEqual(result["workspaceId"], GUID)
        self.assertEqual(result["workspaceResourceId"], RESOURCE)
        self.assertEqual(result["observedCoverage"]["relevantRecords"], 12)
        self.assertEqual(result["observedCoverage"]["missingCategories"], ["ResourceHealth", "ServiceHealth"])
        self.assertEqual(result["tableMetadata"]["retentionInDays"], 90)
        self.assertEqual(result["tableMetadata"]["totalRetentionInDays"], 365)
        self.assertEqual([operation[0] for operation in reader.workspace_calls], ["describe", "table", "summary"])
        self.assertTrue(all(operation[1] == RESOURCE for operation in reader.workspace_calls))
        self.assertFalse(result["fullWindowCompletenessProven"])


if __name__ == "__main__":
    unittest.main()
