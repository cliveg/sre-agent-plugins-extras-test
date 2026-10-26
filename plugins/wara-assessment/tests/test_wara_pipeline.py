"""Contract tests for the wara-assessment derived layer (normalize_findings.py + prioritize.py).

Synthetic data only: no customer identifiers. Run with:
    python -m unittest discover -s plugins/wara-assessment/tests -v
Requires PyYAML (for the default prioritization.yaml).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, "..", "skills", "wara-assessment"))
SCRIPTS = os.path.join(SKILL, "scripts")
DEFAULT_CONFIG = os.path.join(SKILL, "config", "prioritization.yaml")

SUB = "00000000-0000-0000-0000-000000000001"
RG = "rg-test"


def rid(kind: str, name: str) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/{kind}/{name}"


DB = rid("Microsoft.DBforPostgreSQL/flexibleServers", "pg1")
PLAN = rid("Microsoft.Web/serverfarms", "plan1")
NSG = rid("Microsoft.Network/networkSecurityGroups", "nsg1")

CATALOG = [
    {"aprlGuid": "aaaaaaaa-0000-0000-0000-000000000001", "description": "Enable zone-redundant HA",
     "recommendationImpact": "High", "recommendationControl": "HighAvailability", "longDescription": "Long text",
     "potentialBenefits": "Survives zone loss", "pgVerified": True,
     "learnMoreLink": [{"name": "Docs", "url": "https://learn.microsoft.com/x"}]},
    {"aprlGuid": "aaaaaaaa-0000-0000-0000-000000000002", "description": "Configure diagnostic settings",
     "recommendationImpact": "Medium", "recommendationControl": "MonitoringAndAlerting", "learnMoreLink": []},
]


def row(action: str, rec: str, res_id: str, rtype: str, name: str, param1: str = "") -> dict:
    return {"validationAction": action, "recommendationId": rec, "name": name, "id": res_id, "type": rtype,
            "location": "westus2", "subscriptionId": SUB, "resourceGroup": RG, "param1": param1,
            "param2": "", "param3": "", "param4": "", "param5": "", "checkName": "", "selector": "APRL"}


def collector(include_plan: bool = True) -> dict:
    impacted = [
        row("APRL - Queries", CATALOG[0]["aprlGuid"], DB, "Microsoft.DBforPostgreSQL/flexibleServers", "pg1", "ha: Disabled"),
        # duplicate pair with a second parameter -> merged into one finding
        row("APRL - Queries", CATALOG[0]["aprlGuid"], DB, "Microsoft.DBforPostgreSQL/flexibleServers", "pg1", "zone: 1"),
        row("IMPORTANT - Recommendation cannot be validated with ARGs - Validate Resources manually",
            CATALOG[1]["aprlGuid"], NSG, "Microsoft.Network/networkSecurityGroups", "nsg1"),
        row("IMPORTANT - Resource Type is not available in either APRL or Advisor - Validate Resources manually if applicable, if not delete this line",
            "", rid("Microsoft.Maps/accounts", "maps1"), "microsoft.maps/accounts", "maps1"),
    ]
    advisory = []
    if include_plan:
        advisory.append({"recommendationId": "bbbbbbbb-0000-0000-0000-000000000001", "type": "microsoft.web/serverfarms",
                         "name": "plan1", "id": PLAN.lower(), "subscriptionId": SUB, "resourceGroup": RG,
                         "location": "westus2", "category": "HighAvailability", "impact": "High",
                         "description": "Use zone-supported App Service Plan"})
    inventory = [{"id": DB, "name": "pg1"}, {"id": NSG, "name": "nsg1"}]
    if include_plan:
        inventory.append({"id": PLAN, "name": "plan1"})
    return {
        "scriptDetails": {"Version": "1.0.6", "TenantId": SUB, "ResourceGroups": [f"/subscriptions/{SUB}/resourceGroups/{RG}"]},
        "impactedResources": impacted, "advisory": advisory, "resourceInventory": inventory,
        "resourceType": [{"Resource Type": "microsoft.maps/accounts", "Number Of Resources": 1, "Available in APRL/ADVISOR?": "No"}],
        "outages": {"name": "TRACK-1", "properties": {"title": "Synthetic outage"}},
        "retirements": None, "supportTickets": None, "serviceHealth": None,
    }


def run(script: str, *args: str) -> str:
    proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(f"{script} failed: {proc.stderr or proc.stdout}")
    return proc.stdout


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.catalog = self._write("recommendations.json", CATALOG)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, obj):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def test_marketplace_versions_match_plugin(self):
        plugin_dir = os.path.dirname(HERE)
        root = os.path.dirname(os.path.dirname(plugin_dir))
        with open(os.path.join(plugin_dir, "plugin.json"), encoding="utf-8") as fh:
            version = json.load(fh)["version"]
        for path in ("marketplace.json", os.path.join(".github", "plugin", "marketplace.json")):
            with open(os.path.join(root, path), encoding="utf-8") as fh:
                entry = next(p for p in json.load(fh)["plugins"] if p["name"] == "wara-assessment")
            self.assertEqual(entry["version"], version, path)

    def _normalize(self, coll, run_id, name, collection_status="Completed"):
        cpath = self._write(f"collector-{name}.json", coll)
        rpath = self._write(f"run-{name}.json", {
            "runId": run_id, "scope": {"type": "ResourceGroup", "resourceGroup": RG, "subscriptionId": SUB},
            "collector": {"status": collection_status, "errors": []},
        })
        out = os.path.join(self.dir, name, "findings.json")
        run("normalize_findings.py", "--collector-json", cpath, "--run-json", rpath, "--recommendations", self.catalog, "--out", out)
        with open(out, encoding="utf-8") as fh:
            return out, json.load(fh)

    def _prioritize(self, findings, out_dir, config=DEFAULT_CONFIG, previous=None, today="2026-10-09"):
        args = ["--findings", findings, "--config", config, "--out-dir", out_dir, "--today", today]
        if previous:
            args += ["--previous", previous]
        summary = json.loads(run("prioritize.py", *args).strip().splitlines()[-1])
        with open(os.path.join(out_dir, "prioritized-findings.json"), encoding="utf-8") as fh:
            return summary, json.load(fh)

    def test_normalize_classification_and_merge(self):
        _, doc = self._normalize(collector(), "2026-10-01T0600Z", "a")
        self.assertEqual(doc["schemaVersion"], "1.0")
        self.assertEqual(doc["counts"]["findings"], 4)
        by_name = {f["resource"]["name"]: f for f in doc["findings"]}
        db = by_name["pg1"]
        self.assertEqual(db["evidence"]["classification"], "OBSERVED")
        self.assertEqual(db["evidence"]["reason"], "aprl-query-match")
        self.assertEqual(sorted(db["evidence"]["details"]), ["ha: Disabled", "zone: 1"])
        self.assertEqual(db["impact"], "High")
        self.assertEqual(db["learnMore"][0]["url"], "https://learn.microsoft.com/x")
        self.assertEqual(by_name["nsg1"]["evidence"]["classification"], "UNKNOWN")
        self.assertEqual(by_name["nsg1"]["evidence"]["reason"], "not-queryable")
        self.assertEqual(by_name["maps1"]["evidence"]["reason"], "no-guidance-for-type")
        self.assertEqual(by_name["plan1"]["source"], "Advisor")
        self.assertEqual(by_name["plan1"]["evidence"]["classification"], "OBSERVED")
        self.assertEqual(doc["coverage"]["typesWithoutGuidance"], ["microsoft.maps/accounts"])
        self.assertEqual(len(doc["context"]["outages"]), 1)
        # keys are deterministic
        _, again = self._normalize(collector(), "2026-10-01T0600Z", "b")
        self.assertEqual({f["findingKey"] for f in doc["findings"]}, {f["findingKey"] for f in again["findings"]})

    def test_scoring_bands_and_actions(self):
        findings, _ = self._normalize(collector(), "2026-10-01T0600Z", "a")
        summary, pri = self._prioritize(findings, os.path.join(self.dir, "a"))
        by_name = {f["resource"]["name"]: f for f in pri["findings"]}
        self.assertEqual(by_name["pg1"]["priority"]["score"], 3.6)        # 3 x 1.0 x 1.2 x 1.0
        self.assertEqual(by_name["pg1"]["priority"]["band"], "P1")
        self.assertEqual(by_name["nsg1"]["priority"]["score"], 1.35)      # 2 x 0.75 x 0.9 x 1.0
        self.assertEqual(by_name["nsg1"]["priority"]["band"], "P4")       # below P3 min 1.4
        self.assertTrue(by_name["nsg1"]["priority"]["nextAction"].startswith("Validate"))
        self.assertEqual(by_name["plan1"]["priority"]["band"], "P1")      # Advisor High HA, OBSERVED
        self.assertEqual(summary["lifecycle"], {"BASELINE": 4})
        for name in ("prioritized-report.md", "prioritized-findings.csv", "delta.json"):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, "a", name)), name)

    def test_suppression_and_criticality(self):
        cfg = self._write("cfg.json", {
            "version": 1,
            "weights": {"impact": {"High": 3, "Medium": 2, "Low": 1}, "evidence": {"OBSERVED": 1.0, "UNKNOWN": 0.75},
                        "control": {"default": 1.0}},
            "criticality": {"default": "standard", "levels": {"standard": 1.0, "low": 0.5},
                            "rules": [{"field": "name", "match": "^plan", "level": "low"}]},
            "bands": [{"name": "P1", "min": 3}, {"name": "P2", "min": 2}, {"name": "P3", "min": 1}, {"name": "P4", "min": 0}],
            "suppressions": [
                {"recommendationId": CATALOG[0]["aprlGuid"], "reason": "accepted", "owner": "team", "expires": "2027-01-01"},
                {"resourceIdMatch": "nsg1", "reason": "expired", "expires": "2026-01-01"},
            ],
        })
        findings, _ = self._normalize(collector(), "2026-10-01T0600Z", "a")
        _, pri = self._prioritize(findings, os.path.join(self.dir, "a"), config=cfg)
        by_name = {f["resource"]["name"]: f for f in pri["findings"]}
        self.assertEqual(by_name["pg1"]["priority"]["band"], "Accepted")
        self.assertNotEqual(by_name["nsg1"]["priority"]["band"], "Accepted")   # expired suppression ignored
        self.assertEqual(by_name["plan1"]["priority"]["factors"]["criticalityLevel"], "low")
        self.assertEqual(by_name["plan1"]["priority"]["score"], 1.5)

    def test_lifecycle_delta(self):
        f1, _ = self._normalize(collector(include_plan=True), "2026-09-01T0600Z", "m1")
        self._prioritize(f1, os.path.join(self.dir, "m1"))
        prev = os.path.join(self.dir, "m1", "prioritized-findings.json")
        f2, _ = self._normalize(collector(include_plan=False), "2026-10-01T0600Z", "m2")
        summary, pri = self._prioritize(f2, os.path.join(self.dir, "m2"), previous=prev)
        self.assertEqual(summary["previousRunId"], "2026-09-01T0600Z")
        self.assertEqual(summary["lifecycle"], {"PERSISTING": 3})
        for f in pri["findings"]:
            self.assertEqual(f["lifecycle"]["firstSeenRunId"], "2026-09-01T0600Z")
        self.assertEqual([r["status"] for r in pri["resolved"]], ["RESOURCE_NOT_LISTED"])

    def test_incomplete_collection_preserves_missing_findings_across_runs(self):
        f1, _ = self._normalize(collector(), "first", "m1")
        self._prioritize(f1, os.path.join(self.dir, "m1"))
        prev = os.path.join(self.dir, "m1", "prioritized-findings.json")
        for name in ("m2", "m3"):
            f2, _ = self._normalize(collector(False), name, name, "CompletedWithErrors")
            summary, pri = self._prioritize(f2, os.path.join(self.dir, name), previous=prev)
            self.assertEqual(summary["resolved"], 0)
            self.assertEqual(summary["notReobserved"], 1)
            self.assertEqual(pri["resolved"][0]["status"], "NOT_REOBSERVED")
            prev = os.path.join(self.dir, name, "prioritized-findings.json")
        f4, _ = self._normalize(collector(), "last", "m4")
        _, pri = self._prioritize(f4, os.path.join(self.dir, "m4"), previous=prev)
        plan = next(f for f in pri["findings"] if f["resource"]["name"] == "plan1")
        self.assertEqual(plan["lifecycle"]["status"], "PERSISTING")
        self.assertEqual(plan["lifecycle"]["firstSeenRunId"], "first")

    def test_missing_previous_file_fails(self):
        findings, _ = self._normalize(collector(), "first", "m1")
        with self.assertRaisesRegex(AssertionError, "FileNotFoundError"):
            self._prioritize(findings, os.path.join(self.dir, "m1"), previous=os.path.join(self.dir, "missing.json"))

    def test_different_scope_previous_file_fails(self):
        findings, _ = self._normalize(collector(), "first", "m1")
        _, pri = self._prioritize(findings, os.path.join(self.dir, "m1"))
        pri["scope"]["resourceGroup"] = "rg-another"
        previous = self._write("other-scope.json", pri)
        with self.assertRaisesRegex(AssertionError, "scope does not match"):
            self._prioritize(findings, os.path.join(self.dir, "m2"), previous=previous)

    def test_collector_errors_block_disappearance_claims(self):
        findings, _ = self._normalize(collector(), "first", "m1")
        self._prioritize(findings, os.path.join(self.dir, "m1"))
        prev = os.path.join(self.dir, "m1", "prioritized-findings.json")
        findings, doc = self._normalize(collector(False), "second", "m2")
        doc["coverage"]["collectionErrors"] = ["403: inventory query denied"]
        with open(findings, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        _, pri = self._prioritize(findings, os.path.join(self.dir, "m2"), previous=prev)
        self.assertEqual(pri["resolved"][0]["status"], "NOT_REOBSERVED")


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required for offline runner tests")
class RunnerTest(unittest.TestCase):
    def test_isolated_run_folders_scope_parameters_and_failure_record(self):
        runner = os.path.join(SCRIPTS, "Invoke-WaraRun.ps1").replace("'", "''")
        with tempfile.TemporaryDirectory() as tmp:
            root = tmp.replace("'", "''")
            code = r"""
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('RUNNER', [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in 'Write-Step', 'Get-Sha256', 'ConvertTo-Label', 'Invoke-WaraScope') {
    $fn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Invoke-Expression $fn.Extent.Text
}
function Get-AzSubscription { [CmdletBinding()] param($SubscriptionId, $TenantId) [pscustomobject]@{Name='Test'} }
function Start-WARACollector {
    [CmdletBinding()] param($TenantID, $ResourceGroups, $SubscriptionIds)
    if ($script:fail) { throw 'synthetic collector failure' }
    '{}' | Set-Content 'WARA-File-test.json'
}
$OutputRoot = 'ROOT'
$script:TenantId = '00000000-0000-0000-0000-000000000001'
$RunnerVersion = 'test'
$SkipAnalyzer = $true; $SkipDerived = $true; $script:fail = $false
$ctx = [pscustomobject]@{Account=[pscustomobject]@{Id='test';Type='test'}}
$scope = @{SubscriptionId='00000000-0000-0000-0000-000000000001'; ScopeType='ResourceGroup'; ResourceGroupName='rg-test'; ScopeName=$null; SubscriptionLabel=$null}
$a = Invoke-WaraScope $scope @{} $ctx
$b = Invoke-WaraScope $scope @{} $ctx
if ($a.RunId -eq $b.RunId) { throw 'Run folders collided' }
foreach ($r in $a, $b) {
    $doc = Get-Content -Raw (Join-Path $r.RunPath 'run.json') | ConvertFrom-Json
    if ($doc.status -ne 'Succeeded') { throw 'Unexpected run status' }
    if ($doc.scope.waraParameters.PSObject.Properties.Name -contains 'SubscriptionIds') { throw 'RG run has subscription filter' }
    if (-not $doc.scope.waraParameters.ResourceGroups) { throw 'RG filter missing' }
}
$scope.ScopeType = 'Subscription'; $scope.ResourceGroupName = $null
$sub = Invoke-WaraScope $scope @{} $ctx
$doc = Get-Content -Raw (Join-Path $sub.RunPath 'run.json') | ConvertFrom-Json
if ($doc.scope.waraParameters.PSObject.Properties.Name -contains 'ResourceGroups') { throw 'Subscription run has RG filter' }
if (-not $doc.scope.waraParameters.SubscriptionIds) { throw 'Subscription filter missing' }
$script:fail = $true
try { Invoke-WaraScope $scope @{} $ctx; throw 'Collector failure was swallowed' }
catch { if ($_ -notmatch 'Start-WARACollector failed') { throw } }
$failed = @(Get-ChildItem $OutputRoot -Filter run.json -Recurse | ForEach-Object { Get-Content -Raw $_ | ConvertFrom-Json } | Where-Object status -eq 'Failed')
if ($failed.Count -ne 1 -or -not $failed[0].completedUtc) { throw 'Missing durable failure record' }
"""
            proc = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                                   code.replace("RUNNER", runner).replace("ROOT", root)],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
