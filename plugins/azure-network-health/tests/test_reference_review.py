from __future__ import annotations

import json
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

import test_hostless_capture as capture_fixture
import test_network_health as network_fixture
import test_comparison as snapshots
import test_history as history_fixture
import test_hostless_publish as publication_fixture


sys.path.insert(0, str(capture_fixture.SCRIPTS))
import reference_capture
import reference_profile
import network_reference
import network_restriction
import network_timeline
import publish_evidence


class EmptyReader:
    def __init__(self):
        self.calls = []

    def context(self):
        return capture_fixture.ArmService().context()

    def __call__(self, command):
        self.calls.append(command)
        if command[1:3] == ["account", "show"]:
            return network_fixture.nh.ReadResponse({"subscriptionId": capture_fixture.SUB})
        return network_fixture.nh.ReadResponse({
            "count": 0, "data": [], "total_records": 0, "resultTruncated": False, "nextLink": None,
        })


class NetworkReader(EmptyReader):
    def __init__(self):
        super().__init__()
        base = f"/subscriptions/{capture_fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Network"
        vnet, nsg, nic = base + "/virtualNetworks/app", base + "/networkSecurityGroups/app", base + "/networkInterfaces/app"
        subnet, ipconfig = vnet + "/subnets/app", nic + "/ipConfigurations/default"
        self.resources = {
            "vnets": [(vnet, "", {"addressPrefixes": ["10.0.0.0/16"], "subnetCount": 1, "peeringCount": 0})],
            "subnets": [(subnet, vnet, {
                "addressPrefix": "10.0.0.0/24", "addressPrefixes": [], "networkSecurityGroupId": nsg,
                "networkSecurityGroupKnown": True, "routeTableId": None, "routeTableKnown": True,
            })],
            "nsgs": [(nsg, "", {"customRuleCount": 1, "defaultRuleCount": 0})],
            "nsg-rules": [(nsg + "/securityRules/admin", nsg, {
                "isDefault": False, "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                "sourceAddressPrefix": "*", "sourceAddressPrefixes": [], "destinationAddressPrefix": "*",
                "destinationAddressPrefixes": [], "sourcePortRange": "*", "sourcePortRanges": [],
                "destinationPortRange": "22", "destinationPortRanges": [],
            })],
            "ip-attachments": [(ipconfig, nic, {
                "subnetId": subnet, "workloadId": nic, "privateIPAddress": "10.0.0.4", "ipConfigurationCount": 1,
            })],
            "reference-public-ips": [(base + "/publicIPAddresses/app", "", {
                "ipConfigurationId": ipconfig, "ipAddressKnown": True, "ipAddressPresent": True,
                "ipVersion": "IPv4", "allocationMethod": "Static", "provisioningState": "Succeeded",
            })],
        }

    def __call__(self, command):
        if "-q" not in command:
            return super().__call__(command)
        query = command[command.index("-q") + 1]
        operation = next(row for row in reference_profile.catalog()["operations"] if row.get("query") == query)
        self.calls.append(command)
        rows = []
        for entry in self.resources.get(operation["operationId"], []):
            identifier, parent, properties = entry[:3]
            rows.append({
                "id": identifier, "name": identifier.rsplit("/", 1)[-1],
                "type": entry[3] if len(entry) == 4 else operation["entityType"],
                "subscriptionId": capture_fixture.SUB, "resourceGroup": "fixture", "location": "eastus",
                "parentId": parent, "properties": properties,
            })
        return network_fixture.nh.ReadResponse({"count": len(rows), "data": rows, "total_records": len(rows), "resultTruncated": False})


class ReferenceReviewTests(unittest.TestCase):
    def test_published_v1_review_remains_verifiable_without_rewriting_its_original_statistics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Synthetic bundle generated through 0.21.1's public API at 6b6eb822.
            with zipfile.ZipFile(Path(__file__).with_name("reference-review-1.0.0.zip")) as archive:
                archive.extractall(root)
            originals = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
            with patch("socket.socket", side_effect=AssertionError("Unexpected network access")), \
                 patch("subprocess.Popen", side_effect=AssertionError("Unexpected process")), \
                 patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected URL access")):
                manifest = network_reference.verify(root)
            self.assertEqual(manifest["bundleVersion"], "1.0.0")
            assessment = json.loads((root / "assessment.json").read_bytes())
            self.assertEqual(assessment["statistics"]["collectedEntities"], 8)
            self.assertNotIn("normalizedEntities", assessment["statistics"])
            for name, content in originals.items():
                self.assertEqual((root / name).read_bytes(), content)

    def test_large_observations_preserve_all_facts_and_sources_within_existing_byte_budget(self):
        reader = NetworkReader()
        _, parent, properties = reader.resources["nsg-rules"][0]
        expected_priorities = {
            parent.lower() + "/securityrules/review-" + str(index): 100 + index for index in range(500)
        }
        reader.resources["nsg-rules"] = [
            (identifier, parent, {**properties, "direction": "Outbound", "priority": priority})
            for identifier, priority in expected_priorities.items()
        ]
        reader.resources["nsgs"][0][2]["customRuleCount"] = 500
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = reference_capture.capture(
                reader, capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            originals = {path.name: path.read_bytes() for path in source.iterdir()}
            result = network_reference.build(source, snapshots.RUN, root)
            self.assertEqual(network_reference.verify(result)["reviewId"], snapshots.RUN)
            content = (result / "observed-network.json").read_bytes()
            observed = json.loads(content)
            self.assertGreater(len(json.dumps(observed, sort_keys=True, indent=2).encode()) + 1, 5 * 1024 * 1024)
            self.assertLessEqual(len(content), 5 * 1024 * 1024)
            self.assertEqual(
                {row["entityId"]: row["value"] for row in observed["assertions"]
                 if row["property"] == "priority"},
                expected_priorities,
            )
            assessment = json.loads((result / "assessment.json").read_bytes())
            self.assertEqual(assessment["observationArtifact"]["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(
                network_reference.render(assessment),
                ((result / "network-assessment.md").read_bytes(), (result / "network-evidence.md").read_bytes()),
            )
            for name, value in originals.items():
                self.assertEqual((source / name).read_bytes(), value)
                self.assertEqual((result / "sources" / capture_fixture.RUN / name).read_bytes(), value)

    def test_invocation_budget_pauses_before_a_request_and_resumes_without_uncertain_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = EmptyReader()
            arguments = (capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT, capture_fixture.RUN, root)
            with self.assertRaises(reference_capture.CapturePaused):
                reference_capture.capture(first, *arguments, source="synthetic-fixture", read_budget=2)
            self.assertEqual(len(first.calls), 2)
            second = EmptyReader()
            result = reference_capture.capture(second, *arguments, source="synthetic-fixture", resume=True)
            self.assertFalse(any(command in first.calls for command in second.calls))
            self.assertEqual(reference_capture.verify(result)["sourceId"], capture_fixture.RUN)

    def test_diagram_contains_only_collected_configuration_relationships_not_packet_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = reference_capture.capture(
                NetworkReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            report = network_reference.build(source, snapshots.RUN, root)
            assessment = json.loads((report / "assessment.json").read_bytes())
            self.assertEqual(network_reference.verify(report)["bundleVersion"], "1.0.1")
            self.assertEqual(assessment["profileVersion"], "1.0.1")
            diagram = assessment["topologyDiagram"]
            self.assertEqual(diagram["relationshipMeaning"], "configured-associations-not-traffic")
            self.assertLessEqual(len(diagram["nodes"]), 80)
            self.assertLessEqual(len(diagram["edges"]), 120)
            self.assertIn("flowchart LR", diagram["mermaid"])
            self.assertTrue(diagram["edges"])
            observed = json.loads((report / "observed-network.json").read_bytes())
            self.assertEqual(assessment["statistics"]["collectedEntities"], 6)
            self.assertEqual(assessment["statistics"]["normalizedEntities"], 8)
            ids = {row["entityId"] for row in observed["entities"] if row["collectionState"] == "collected"}
            self.assertTrue(all(row["resourceId"] in ids for row in diagram["nodes"]))
            self.assertIn("## Configuration architecture",
                          (report / "network-assessment.md").read_text(encoding="utf-8"))

    def test_missing_nsg_rule_classification_fields_are_explicit_gaps_not_ignored_rules(self):
        for field, reason in (("direction", "DirectionUnavailable"), ("access", "AccessUnavailable"),
                              ("isDefault", "CustomRuleKindUnavailable")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                reader = NetworkReader()
                reader.resources["nsg-rules"][0][2][field] = None
                source = reference_capture.capture(
                    reader, capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                    capture_fixture.RUN, root, source="synthetic-fixture",
                )
                report = network_reference.build(source, snapshots.RUN, root)
                assessment = json.loads((report / "assessment.json").read_bytes())
                security = next(row for row in assessment["domainReviews"] if row["areaId"] == "network-security")
                self.assertTrue(any(row["reason"] == reason for row in security["details"]["ruleReviewGaps"]))
                self.assertEqual(security["details"]["broadSourceRuleCandidates"], 0)

    def test_assessment_commands_are_offline_and_both_reports_are_views_of_assessment_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = reference_capture.capture(
                NetworkReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            stdout = io.StringIO()
            with patch.object(sys, "argv", [
                "reference", "build", "--network-source", str(source), "--run-id", snapshots.RUN,
                "--output-root", str(root),
            ]), redirect_stdout(stdout), patch("socket.socket", side_effect=AssertionError("Network call")), \
                    patch("subprocess.Popen", side_effect=AssertionError("External process")):
                self.assertEqual(network_reference.main(), 0)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["azureReads"], 0)
            self.assertEqual(receipt["areas"], 6)
            self.assertLess(len(stdout.getvalue().encode()), 4000)
            directory = Path(receipt["review"])
            assessment = json.loads((directory / "assessment.json").read_bytes())
            self.assertEqual(network_reference.render(assessment), (
                (directory / "network-assessment.md").read_bytes(), (directory / "network-evidence.md").read_bytes(),
            ))
            with patch.object(sys, "argv", ["reference", "verify", "--review", str(directory)]), \
                    redirect_stdout(io.StringIO()), patch("socket.socket", side_effect=AssertionError("Network call")), \
                    patch("subprocess.Popen", side_effect=AssertionError("External process")):
                self.assertEqual(network_reference.main(), 0)

    def test_comprehensive_report_uses_the_existing_private_publisher_without_touching_wara_or_main(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, seed, clone = publication_fixture.connected_repository(root, "example/evidence-output")
            (clone / "unrelated.txt").write_text("preserve")
            before = publication_fixture.git(clone, "status", "--porcelain")
            source = reference_capture.capture(
                NetworkReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            report = network_reference.build(source, snapshots.RUN, root)
            receipt = publish_evidence.publish(
                report, clone, "example/evidence-output", private_destination_reviewed=True, artifact_kind="review",
            )
            self.assertEqual(receipt["reviewId"], snapshots.RUN)
            self.assertEqual(receipt["branch"], "network-review/" + snapshots.RUN)
            self.assertEqual(publication_fixture.git(clone, "status", "--porcelain"), before)
            self.assertEqual(publication_fixture.git(remote, "rev-parse", "refs/heads/main"),
                             publication_fixture.git(seed, "rev-parse", "HEAD"))
            for entry in receipt["artifacts"]:
                self.assertEqual(entry["path"], "network-health/runs/" + snapshots.RUN + "/" + entry["name"])
                self.assertEqual(publication_fixture.git(remote, "show", receipt["commit"] + ":" + entry["path"]),
                                 (report / entry["name"]).read_bytes())

    def test_hybrid_and_monitoring_configuration_do_not_become_outage_or_telemetry_health_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = NetworkReader()
            base = f"/subscriptions/{capture_fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Network"
            reader.resources["reference-hybrid"] = [(base + "/connections/vpn", "", {
                "provisioningState": "Succeeded", "connectionStatus": "NotConnected",
                "gateway1Id": base + "/virtualNetworkGateways/hub",
            }, "microsoft.network/connections")]
            reader.resources["reference-monitoring"] = [(base + "/networkWatchers/region/flowLogs/app", "", {
                "enabled": True, "retentionEnabled": True, "retentionDays": 30,
                "targetResourceId": reader.resources["vnets"][0][0],
            }, "microsoft.network/networkwatchers/flowlogs")]
            source = reference_capture.capture(
                reader, capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            result = network_reference.build(source, snapshots.RUN, root)
            assessment = json.loads((result / "assessment.json").read_bytes())
            hybrid = next(row for row in assessment["domainReviews"] if row["areaId"] == "firewall-hybrid")
            connection = hybrid["details"]["hybridResources"][0]
            self.assertEqual(connection["reportedConnectionStatus"], "NotConnected")
            self.assertEqual(connection["effectiveRouting"], "UNKNOWN")
            self.assertEqual(connection["statusInterpretation"], "coarse-indexed-state-not-traffic-or-outage-proof")
            monitoring = next(row for row in assessment["domainReviews"] if row["areaId"] == "telemetry-history")
            self.assertTrue(monitoring["details"]["existingMonitoring"][0]["configuredEnabled"])
            self.assertEqual(monitoring["details"]["existingMonitoring"][0]["dataCoverageVerified"], "UNKNOWN")
            self.assertFalse(any(row["recordType"] == "verifiedProblem" for row in assessment["findings"]))

    def test_recorded_context_is_self_contained_and_never_promoted_to_causation_or_current_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = NetworkReader()
            network = reference_capture.capture(
                reader, capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            target = reader.resources["vnets"][0][0]
            history = history_fixture.history.capture(
                history_fixture.HistoryService("activity-log", [{
                    "statusCode": 200, "body": {"value": [history_fixture.activity(resourceId=target)], "nextLink": None},
                    "requestId": "fixture-history",
                }]),
                "activity-log", capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                snapshots.BEFORE, root, "2026-10-13T00:00:00Z", history_fixture.END,
                planning_time=history_fixture.END,
            )
            timeline = network_timeline.build([history], snapshots.RUN, root, compact=True)
            originals = {path.relative_to(timeline).as_posix(): path.read_bytes()
                         for path in timeline.rglob("*") if path.is_file()}
            result = network_reference.build(
                network, "00000000-0000-4000-8000-000000000090", root, timeline=timeline,
            )
            assessment = json.loads((result / "assessment.json").read_bytes())
            context = assessment["recordedContext"]
            self.assertEqual(context["eventRevisions"], 1)
            self.assertEqual(context["matchedResourceCount"], 1)
            self.assertEqual(context["resources"][0]["resourceId"], target.lower())
            self.assertEqual(context["causalConclusions"], "notGenerated")
            self.assertIn("## Recorded change and health context",
                          (result / "network-assessment.md").read_text(encoding="utf-8"))
            for name, content in originals.items():
                self.assertEqual((result / "sources" / snapshots.RUN / name).read_bytes(), content)

    def test_public_source_review_is_composed_unchanged_with_its_own_time_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network = reference_capture.capture(
                EmptyReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            config = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER, {
                "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"},
            })
            restriction = network_restriction.build(config, snapshots.RUN, root)
            originals = {path.relative_to(restriction).as_posix(): path.read_bytes()
                         for path in restriction.rglob("*") if path.is_file()}
            result = network_reference.build(
                network, "00000000-0000-4000-8000-000000000090", root, restriction=restriction,
            )
            assessment = json.loads((result / "assessment.json").read_bytes())
            view = assessment["publicSourceReview"]
            self.assertEqual(view["sourceRunId"], snapshots.RUN)
            self.assertEqual(view["statistics"]["servicePaths"], 1)
            self.assertEqual(view["collectionWindow"]["startedAtUtc"], snapshots.EARLIER)
            self.assertEqual(view["results"][0]["criterionVerdict"], "UNKNOWN")
            self.assertEqual(view["relationship"], "separate-source-window-not-merged-current-state")
            self.assertIn("## Public-source restriction context",
                          (result / "network-assessment.md").read_text(encoding="utf-8"))
            for name, content in originals.items():
                self.assertEqual((result / "sources" / snapshots.RUN / name).read_bytes(), content)

    def test_native_child_continuation_is_partial_not_a_complete_dns_chain(self):
        class Continued(NetworkReader):
            def __init__(self):
                super().__init__()
                self.endpoint = f"/subscriptions/{capture_fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Network/privateEndpoints/app"
                self.resources["private-endpoints"] = [(self.endpoint, "", {
                    "subnetId": self.resources["subnets"][0][0], "provisioningState": "Succeeded",
                    "automaticConnectionCount": 0, "manualConnectionCount": 0,
                })]

            def __call__(self, command):
                if command[:5] == ["az", "network", "private-endpoint", "dns-zone-group", "list"]:
                    self.calls.append(command)
                    return network_fixture.nh.ReadResponse({
                        "count": 1, "data": [{
                            "id": self.endpoint + "/privateDnsZoneGroups/default", "name": "default",
                            "properties": {"privateDnsZoneIds": [], "provisioningState": "Succeeded"},
                        }], "hasContinuation": True,
                    })
                return super().__call__(command)

        with tempfile.TemporaryDirectory() as temporary:
            source = reference_capture.capture(
                Continued(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, Path(temporary), source="synthetic-fixture",
            )
            document = json.loads((source / "selected-input.json").read_bytes())
            collection = next(row for row in document["collections"] if row["operationId"] == "private-dns-groups")
            self.assertEqual(collection["status"], "partial")
            self.assertIn("NativeChildContinuationNotCollected", collection["issues"])

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell unavailable for the process transport test")
    def test_collector_command_uses_scoped_managed_identity_and_read_only_graph_without_cli_extensions(self):
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
                """function Disable-AzContextAutosave { param($Scope) if($Scope -ne 'Process'){throw 'Unscoped context'} }
function Connect-AzAccount { param([switch]$Identity,$AccountId,$Tenant,$Subscription,$Scope,$WarningAction)
 if(-not $Identity -or $Scope -ne 'Process'){throw 'Unexpected authentication'}
 $script:ctx=[pscustomobject]@{Tenant=[pscustomobject]@{Id=$Tenant};Subscription=[pscustomobject]@{Id=$Subscription}}
}
function Get-AzContext { return $script:ctx }
function Invoke-AzRestMethod { param($Method,$Path,$Payload,$DefaultProfile,$ErrorAction)
 if(-not $DefaultProfile -or $Method -notin @('GET','POST')){throw 'Unapproved operation'}
 if($Method -eq 'POST'){
  if($Path -cne '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'){throw 'Write endpoint'}
  $body=$Payload|ConvertFrom-Json
  if($body.subscriptions.Count -ne 1 -or $body.subscriptions[0] -ne $script:ctx.Subscription.Id){throw 'Expanded scope'}
  $content='{"count":0,"data":[],"totalRecords":0,"resultTruncated":false}'
 } else { $content='{"value":[]}' }
 return [pscustomobject]@{StatusCode=200;Content=$content;Headers=@{'x-ms-request-id'='fixture-request'}}
}
""", encoding="utf-8",
            )
            result = subprocess.run([
                sys.executable, "-B", str(capture_fixture.SCRIPTS / "reference_capture.py"), "capture",
                "--tenant-id", capture_fixture.TENANT, "--subscription-id", capture_fixture.SUB,
                "--managed-identity-client-id", capture_fixture.CLIENT, "--capture-id", capture_fixture.RUN,
                "--output-root", str(root),
            ], capture_output=True, text=True, check=False, timeout=90, env={**os.environ, "WARA_CACHE": str(root)})
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["collectionOutcomes"], 34)
            self.assertEqual(receipt["source"], "managed-identity-arm")
            self.assertTrue(receipt["selectedEvidenceVerified"])
            self.assertLess(len(result.stdout.encode()), 4000)

    def test_network_desk_rule_review_is_contextual_and_does_not_certify_public_reachability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = reference_capture.capture(
                NetworkReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            result = network_reference.build(source, "00000000-0000-4000-8000-000000000080", root)
            assessment = json.loads((result / "assessment.json").read_bytes())
            findings = [row for row in assessment["findings"] if row["checkId"] == "NET-NSG-002"]
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["checkVersion"], "1.0.0")
            self.assertEqual(finding["recordType"], "potentialRisk")
            self.assertIsNone(finding["severity"])
            self.assertEqual(finding["actualReachability"], "UNKNOWN")
            self.assertEqual(finding["ingressEvidence"], "configured-public-ip-nic-subnet-reference")
            self.assertEqual(finding["priority"]["actionType"], "evidenceCollection")
            self.assertTrue(finding["dependencies"])
            self.assertGreaterEqual(len(finding["evidenceRefs"]), 4)
            self.assertTrue(all(value in assessment["evidenceCatalog"] for value in finding["evidenceRefs"]))
            area = next(row for row in assessment["domainReviews"] if row["areaId"] == "network-security")
            self.assertEqual(area["details"]["broadSourceRuleCandidates"], 1)
            self.assertEqual(area["details"]["effectiveRuleEvaluation"], "not-collected")

    def test_report_composes_core_checks_and_upstream_framework_without_zero_finding_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = reference_capture.capture(
                EmptyReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, root, source="synthetic-fixture",
            )
            originals = {path.name: path.read_bytes() for path in source.iterdir()}
            result = network_reference.build(source, "00000000-0000-4000-8000-000000000080", root)
            self.assertEqual(network_reference.verify(result)["reviewId"], result.name)
            observed = json.loads((result / "observed-network.json").read_bytes())
            assessment = json.loads((result / "assessment.json").read_bytes())
            self.assertNotIn("findings", observed)
            self.assertEqual(assessment["profileId"], "reference-network-assessment")
            self.assertEqual(len(assessment["scorecard"]), 6)
            self.assertTrue(all(row["status"] != "Healthy" for row in assessment["scorecard"]))
            self.assertTrue({"NET-ADDR-001", "NET-PEER-001", "NET-PRIVATE-DNS-001"} <= {
                row["checkId"] for row in assessment["checksExecuted"]
            })
            self.assertEqual({row["author"] for row in assessment["framework"]["upstream"]},
                             {"Usman Mahmood", "Daniel Mauser"})
            markdown = (result / "network-assessment.md").read_text(encoding="utf-8")
            for heading in ("## Executive summary", "## Assessment scorecard", "## Positive observations",
                            "## Assumptions and validation required"):
                self.assertIn(heading, markdown)
            engineering = (result / "network-evidence.md").read_text(encoding="utf-8")
            self.assertIn("**Observed state:**", engineering)
            self.assertIn("**Expected state:**", engineering)
            self.assertIn("**Risk:**", engineering)
            self.assertIn("**Dependencies / considerations:**", engineering)
            for name, content in originals.items():
                self.assertEqual((source / name).read_bytes(), content)

    def test_interrupted_capture_requires_retry_approval_and_never_recollects_retained_reads(self):
        class Interrupted(EmptyReader):
            def __call__(self, command):
                if len(self.calls) == 2:
                    self.calls.append(command)
                    raise capture_fixture.capture.UnconfirmedRead("Synthetic response interruption")
                return super().__call__(command)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = Interrupted()
            arguments = (capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT, capture_fixture.RUN, root)
            with self.assertRaises(capture_fixture.capture.UnconfirmedRead):
                reference_capture.capture(first, *arguments, source="synthetic-fixture")
            resumed = EmptyReader()
            with self.assertRaises(capture_fixture.capture.UnconfirmedRead):
                reference_capture.capture(resumed, *arguments, source="synthetic-fixture", resume=True)
            self.assertEqual(resumed.calls, [])
            result = reference_capture.capture(
                resumed, *arguments, source="synthetic-fixture", resume=True, retry_unconfirmed=True,
            )
            self.assertFalse(any(command in first.calls[:2] for command in resumed.calls))
            self.assertEqual(resumed.calls.count(first.calls[2]), 1)
            self.assertEqual(reference_capture.verify(result)["sourceId"], capture_fixture.RUN)

    def test_managed_identity_source_is_explicit_not_native_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = reference_capture.capture(
                EmptyReader(), capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                capture_fixture.RUN, Path(temporary),
            )
            manifest = reference_capture.verify(result)
            self.assertEqual(manifest["source"], "managed-identity-arm")
            document = json.loads((result / "selected-input.json").read_bytes())
            self.assertTrue(all(row["source"] == "managed-identity-arm" for row in document["collections"]))
            self.assertFalse(manifest["assurance"]["rawResponsesPersisted"])

    def test_capture_preserves_scope_and_explicit_core_and_specialist_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = EmptyReader()
            with patch.object(reference_capture.ef, "utc_now", return_value=capture_fixture.TIME):
                result = reference_capture.capture(
                    reader, capture_fixture.TENANT, capture_fixture.SUB, capture_fixture.CLIENT,
                    capture_fixture.RUN, root, source="synthetic-fixture",
                )
            manifest = reference_capture.verify(result)
            self.assertEqual(manifest["profileId"], "reference-network-source")
            self.assertEqual(manifest["sourceId"], capture_fixture.RUN)
            self.assertEqual(manifest["scope"]["subscriptionId"], capture_fixture.SUB)
            document = json.loads((result / "selected-input.json").read_bytes())
            self.assertEqual(document["inputVersion"], "1.0.0")
            self.assertEqual(document["queryCatalogVersion"], "1.9.0")
            self.assertEqual(len(document["collections"]), 34)
            self.assertEqual(
                {entry["operationId"] for entry in document["collections"] if entry["operationId"] in (
                    "reference-firewalls", "reference-hybrid", "reference-monitoring", "reference-public-ips",
                )},
                {"reference-firewalls", "reference-hybrid", "reference-monitoring", "reference-public-ips"},
            )
            self.assertTrue(all(entry["requestedSubscriptionId"] == capture_fixture.SUB for entry in document["collections"]))
            self.assertTrue(all(entry["source"] == "synthetic-fixture" for entry in document["collections"]))
            self.assertTrue(reader.calls)
            self.assertNotIn("findings", document)


if __name__ == "__main__":
    unittest.main()
