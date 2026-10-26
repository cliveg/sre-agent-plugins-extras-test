from __future__ import annotations

import sys
import json
import copy
import shutil
import subprocess
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "azure-network-evidence-capture" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import network_capture as capture


SUB = "00000000-0000-4000-8000-000000000002"
TENANT = "00000000-0000-4000-8000-000000000055"
CLIENT = "00000000-0000-4000-8000-000000000056"
RUN = "00000000-0000-4000-8000-000000000057"
TIME = "2026-10-13T15:00:00Z"


class ArmService:
    def __init__(self, replies=None):
        self.replies = replies or {}
        self.calls = []
        self.context_calls = 0

    def context(self):
        self.context_calls += 1
        return {"subscriptionId": SUB, "tenantId": TENANT, "managedIdentityClientId": CLIENT,
                "authentication": "managedIdentity", "powershellVersion": "7.6.6", "azAccountsVersion": "3.0.4"}

    def get(self, url):
        self.calls.append(url)
        return self.replies.get(url, {"statusCode": 200, "body": {"value": []}, "requestId": None})


class HostlessCaptureTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is unavailable; packaged ARM adapter syntax/runtime not exercised")
    def test_packaged_powershell_bridge_filters_scope_and_returns_only_process_local_http_data(self):
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
                """function Disable-AzContextAutosave { param($Scope) if($Scope -ne 'Process'){throw 'Unscoped autosave'} }
function Connect-AzAccount { param([switch]$Identity,$AccountId,$Tenant,$Subscription,$Scope,$WarningAction)
 if(-not $Identity -or $Scope -ne 'Process'){throw 'Unexpected authentication'}
 $script:ctx=[pscustomobject]@{Tenant=[pscustomobject]@{Id=$Tenant};Subscription=[pscustomobject]@{Id=$Subscription}}
}
function Get-AzContext { return $script:ctx }
function Invoke-AzRestMethod { param($Method,$Path,$DefaultProfile,$ErrorAction)
 if($Method -ne 'GET' -or -not $DefaultProfile){throw 'Unexpected operation'}
 return [pscustomobject]@{StatusCode=200;Content='{"value":[]}';Headers=@{'x-ms-request-id'='fixture-request'}}
}
""",
                encoding="utf-8",
            )
            url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
            inputs = "\n".join(json.dumps({"url": value}) for value in (url, url.replace(SUB, RUN))) + "\n"
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(SCRIPTS / "arm_reader.ps1"),
                 "-TenantId", TENANT, "-SubscriptionId", SUB, "-ManagedIdentityClientId", CLIENT],
                input=inputs, capture_output=True, text=True, check=False, timeout=60,
                env={**os.environ, "WARA_CACHE": str(root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0]["status"], "ready")
            self.assertEqual(lines[0]["context"]["managedIdentityClientId"], CLIENT)
            self.assertEqual(lines[1]["body"], {"value": []})
            self.assertEqual(lines[1]["requestId"], "fixture-request")
            self.assertEqual(lines[2]["errorCode"], "ArmScopePolicyRejected")
            self.assertIsNone(lines[2]["body"])

    def test_paged_root_capture_resume_requires_explicit_retry_and_binds_the_continuation(self):
        root_url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        next_url = root_url + "&%24skiptoken=fixture"

        class InterruptedPage(ArmService):
            def get(self, url):
                if url == next_url:
                    self.calls.append(url)
                    raise capture.UnconfirmedRead("Synthetic continuation interruption")
                return super().get(url)

        first = InterruptedPage({root_url: {"statusCode": 200, "body": {"value": [], "nextLink": next_url}, "requestId": None}})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(capture.UnconfirmedRead):
                capture.capture(first, TENANT, SUB, CLIENT, RUN, root)
            resumed = ArmService()
            result = capture.replay(capture.capture(resumed, TENANT, SUB, CLIENT, RUN, root,
                                                    resume=True, retry_unconfirmed=True))
            self.assertNotIn(root_url, resumed.calls)
            self.assertEqual(resumed.calls[0], next_url)
            pages = [row for row in result["coverage"]["collections"] if row["operationId"] == "keyvault-list"]
            self.assertEqual([row["page"] for row in pages], [1, 2])
            self.assertEqual(len(result["coverage"]["unconfirmedAttempts"]), 1)

    def test_foreign_continuation_and_mismatched_identity_do_not_trigger_fallback_reads(self):
        root_url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
        foreign = root_url.replace(SUB, RUN) + "&%24skiptoken=fixture"
        reader = ArmService({root_url: {"statusCode": 200, "body": {"value": [], "nextLink": foreign}, "requestId": None}})
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "scope"):
                capture.capture(reader, TENANT, SUB, CLIENT, RUN, Path(temporary))
            self.assertEqual(reader.calls, [root_url])

        class WrongIdentity(ArmService):
            def context(self):
                return {**super().context(), "managedIdentityClientId": RUN}

        reader = WrongIdentity()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "scope"):
                capture.capture(reader, TENANT, SUB, CLIENT, RUN, Path(temporary))
            self.assertEqual(reader.calls, [])

    def test_copied_skill_scripts_verify_and_replay_with_isolated_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = capture.capture(ArmService(), TENANT, SUB, CLIENT, RUN, root)
            installed = root / "installed" / "scripts"
            shutil.copytree(SCRIPTS, installed, ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run([sys.executable, "-I", str(installed / "network_capture.py"), "verify",
                                     "--capsule", str(directory)], cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "verified-retained-bytes")
            output = root / "replay.json"
            result = subprocess.run([sys.executable, "-I", str(installed / "network_capture.py"), "replay",
                                     "--capsule", str(directory), "--output", str(output)], cwd=root,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), capture.replay(directory))

    def test_rehashed_checkpoint_cannot_queue_a_get_for_an_undiscovered_parent(self):
        class Interrupted(ArmService):
            def get(self, url):
                raise capture.UnconfirmedRead("Synthetic interruption")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(capture.UnconfirmedRead):
                capture.capture(Interrupted(), TENANT, SUB, CLIENT, RUN, root)
            state_path = root / "acquisition" / RUN / "state.json"
            state = json.loads(state_path.read_bytes())
            identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/undiscovered"
            state["progress"]["jobs"].append(capture.job("storage-get", SUB, identifier))
            state["progressSha256"] = capture.ef.digest(state["progress"])
            state_path.write_bytes(capture.ef.encoded(state))
            reader = ArmService()
            with self.assertRaisesRegex(ValueError, "discovered"):
                capture.capture(reader, TENANT, SUB, CLIENT, RUN, root, resume=True, retry_unconfirmed=True)
            self.assertEqual(reader.calls, [])

    def test_retained_page_recovery_never_recollects_after_checkpoint_failure(self):
        original = Path.replace
        interrupted = False

        def fail_after_page(path, target):
            nonlocal interrupted
            if Path(target).name == "state.json" and not interrupted:
                state = json.loads(path.read_bytes())
                if state["progress"]["current"] == 1:
                    interrupted = True
                    raise OSError("Synthetic retained-page checkpoint failure")
            return original(path, target)

        first = ArmService()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(Path, "replace", autospec=True, side_effect=fail_after_page):
                with self.assertRaisesRegex(OSError, "checkpoint failure"):
                    capture.capture(first, TENANT, SUB, CLIENT, RUN, root)
            resumed = ArmService()
            directory = capture.capture(resumed, TENANT, SUB, CLIENT, RUN, root, resume=True)
            self.assertEqual(len(first.calls), 1)
            self.assertEqual(len(resumed.calls), 5)
            self.assertNotIn(first.calls[0], resumed.calls)
            capture.verify(directory)

    def test_capsule_member_tampering_and_extra_fields_fail_before_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = capture.capture(ArmService(), TENANT, SUB, CLIENT, RUN, Path(temporary))
            path = next(directory.glob("storage-list-*.json"))
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "integrity"):
                capture.replay(directory)

    def test_uncertain_read_requires_explicit_retry_and_keeps_both_attempt_times(self):
        class Interrupted(ArmService):
            def get(self, url):
                self.calls.append(url)
                raise capture.UnconfirmedRead("Synthetic transport interruption")

        first = Interrupted()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(capture.UnconfirmedRead):
                capture.capture(first, TENANT, SUB, CLIENT, RUN, root)
            stopped = ArmService()
            with self.assertRaisesRegex(capture.UnconfirmedRead, "explicit"):
                capture.capture(stopped, TENANT, SUB, CLIENT, RUN, root, resume=True)
            self.assertEqual(stopped.calls, [])
            resumed = ArmService()
            directory = capture.capture(resumed, TENANT, SUB, CLIENT, RUN, root, resume=True, retry_unconfirmed=True)
            result = capture.replay(directory)
            self.assertEqual(len(first.calls), 1)
            self.assertEqual(len(resumed.calls), 6)
            attempts = result["coverage"]["unconfirmedAttempts"]
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["status"], "unconfirmed")
            first_page = next(row for row in result["coverage"]["collections"] if row["operationId"] == "storage-list")
            self.assertNotEqual(first_page["attemptId"], attempts[0]["attemptId"])
            self.assertGreaterEqual(first_page["startedAtUtc"], attempts[0]["startedAtUtc"])

    def test_denied_source_is_preserved_without_empty_success(self):
        url = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        service = ArmService({url: {"statusCode": 403, "body": None, "requestId": "request-denied"}})
        with tempfile.TemporaryDirectory() as temporary:
            result = capture.replay(capture.capture(service, TENANT, SUB, CLIENT, RUN, Path(temporary)))
            denied = next(row for row in result["coverage"]["collections"] if row["operationId"] == "keyvault-list")
            self.assertEqual(denied["status"], "permissionDenied")
            self.assertEqual(denied["httpStatus"], 403)
            self.assertIsNone(denied["returnedRows"])
            self.assertEqual(denied["errorCode"], "ArmAuthorizationDenied")

    def test_reviewed_values_missing_null_and_omissions_are_preserved_without_auth_repetition(self):
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/storage"
        resource = {"id": identifier, "type": "Microsoft.Storage/storageAccounts", "name": "storage",
                    "tags": {"secret": "synthetic-do-not-retain"},
                    "properties": {"publicNetworkAccess": "Disabled", "minimumTlsVersion": "TLS1_2",
                                   "allowBlobPublicAccess": None, "password": "synthetic-do-not-retain",
                                   "networkAcls": {"defaultAction": "Deny", "ipRules": [{"value": "198.51.100.0/24"}]}}}
        service = ArmService({
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01":
                {"statusCode": 200, "body": {"value": [resource]}, "requestId": "request-list"},
            "https://management.azure.com" + identifier + "?api-version=2023-05-01":
                {"statusCode": 200, "body": resource, "requestId": "request-get"},
        })
        with tempfile.TemporaryDirectory() as temporary:
            directory = capture.capture(service, TENANT, SUB, CLIENT, RUN, Path(temporary))
            self.assertEqual(service.context_calls, 1)
            result = capture.replay(directory)
            self.assertEqual(len(result["resources"]), 1)
            full = next(row for row in result["resources"][0]["observations"] if row["member"].startswith("storage-get-"))
            properties = full["configuration"]["properties"]
            self.assertIsNone(properties["allowBlobPublicAccess"])
            self.assertNotIn("allowSharedKeyAccess", properties)
            self.assertEqual(properties["networkAcls"]["ipRules"][0]["value"], "198.51.100.0/24")
            self.assertIn("/properties/password", full["omittedPaths"])
            self.assertNotIn("synthetic-do-not-retain", "".join(path.read_text() for path in directory.iterdir()))

    def test_packaged_capture_seals_and_replays_without_host_or_native_agent_dependencies(self):
        service = ArmService()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = capture.capture(service, TENANT, SUB, CLIENT, RUN, root)
            manifest = capture.verify(directory)
            self.assertEqual(manifest["capsuleVersion"], "0.3.0")
            self.assertEqual(manifest["profileId"], "hostless-configuration-snapshot")
            self.assertEqual(len(service.calls), 6)
            with patch("subprocess.run", side_effect=AssertionError("Offline replay cannot spawn processes")):
                with patch("urllib.request.urlopen", side_effect=AssertionError("Offline replay cannot use network")):
                    result = capture.replay(directory)
                    self.assertEqual(result, capture.replay(directory))
            self.assertEqual(result["resources"], [])
            self.assertTrue(all(source["status"] == "notCollected" for source in result["eventSources"]))
            resumed = ArmService()
            self.assertEqual(capture.capture(resumed, TENANT, SUB, CLIENT, RUN, root, resume=True), directory)
            self.assertEqual(resumed.context_calls, 0)
            self.assertEqual(resumed.calls, [])


if __name__ == "__main__":
    unittest.main()
