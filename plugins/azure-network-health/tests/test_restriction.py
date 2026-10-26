from __future__ import annotations

import sys
import copy
import unittest

import io
import ipaddress
import json
import tempfile
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

import test_hostless_capture as fixture
import test_comparison as snapshots


sys.path.insert(0, str(fixture.SCRIPTS))
import network_restriction as restriction


def snapshot_resources(root, resources):
    replies = {}
    for family, resource in resources:
        identifier = resource["id"]
        operation = family + "-list"
        parent = identifier.rsplit("/", 2)[0] if restriction.profile.OPS[operation][2] is not None else None
        url = restriction.profile.initial_url(operation, fixture.SUB, parent)
        replies.setdefault(url, {"statusCode": 200, "requestId": None, "body": {"value": []}})["body"]["value"].append(resource)
        replies[restriction.profile.initial_url(family + "-get", fixture.SUB, identifier)] = {
            "statusCode": 200, "requestId": None, "body": resource,
        }
    with patch.object(fixture.capture.ef, "utc_now", return_value=fixture.TIME):
        return fixture.capture.capture(fixture.ArmService(replies), fixture.TENANT, fixture.SUB, fixture.CLIENT, snapshots.BEFORE, root)


class RestrictionTests(unittest.TestCase):
    def test_nonempty_perimeter_modes_and_ampls_private_only_are_never_bare_presence_passes(self):
        prefix = f"/subscriptions/{fixture.SUB}/resourceGroups/fixture/providers/"
        store = snapshots.RESOURCE
        registry = prefix + "Microsoft.ContainerRegistry/registries/app"
        workspace = prefix + "Microsoft.OperationalInsights/workspaces/app"
        perimeter = prefix + "Microsoft.Network/networkSecurityPerimeters/review"
        perimeter_profile = perimeter + "/profiles/policy"
        scope = prefix + "Microsoft.Insights/privateLinkScopes/review"

        def resource(family, identifier, properties):
            return family, {"id": identifier, "name": identifier.rsplit("/", 1)[-1],
                            "type": restriction.profile.TYPES[family][0], "properties": properties}

        for mode in ("Learning", "Transition", "Enforced", "FutureMode"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = snapshot_resources(root, [
                    resource("storage", store, {"publicNetworkAccess": "Disabled"}),
                    resource("acr", registry, {"publicNetworkAccess": "Disabled"}),
                    resource("loganalytics", workspace, {
                        "publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Enabled",
                        "privateLinkScopedResources": [{"resourceId": workspace, "scopeId": scope}],
                    }),
                    resource("nsp", perimeter, {"provisioningState": "Succeeded"}),
                    resource("nsp-profiles", perimeter_profile, {"provisioningState": "Succeeded"}),
                    resource("nsp-associations", perimeter + "/resourceAssociations/storage", {
                        "accessMode": mode, "privateLinkResource": {"id": store}, "profile": {"id": perimeter_profile},
                    }),
                    resource("nsp-associations", perimeter + "/resourceAssociations/acr", {
                        "accessMode": mode, "privateLinkResource": {"id": registry}, "profile": {"id": perimeter_profile},
                    }),
                    resource("nsp-rules", perimeter_profile + "/accessRules/ingress", {
                        "direction": "Inbound", "addressPrefixes": ["8.8.8.0/24"],
                    }),
                    resource("ampls", scope, {
                        "accessModeSettings": {"ingestionAccessMode": "PrivateOnly", "queryAccessMode": "PrivateOnly"},
                        "privateEndpointConnections": [{
                            "id": scope + "/privateEndpointConnections/a",
                            "properties": {"privateLinkServiceConnectionState": {"status": "Approved"}},
                        }],
                    }),
                    resource("ampls-scoped", scope + "/scopedResources/workspace", {"linkedResourceId": workspace}),
                ])
                directory = restriction.build(source, snapshots.RUN, root)
                document = json.loads((directory / "assessment.json").read_bytes())
                self.assertEqual(document["statistics"]["resources"], 3)
                self.assertEqual(document["statistics"]["servicePaths"], 4)
                self.assertTrue(all(row["criterionVerdict"] == "UNKNOWN" for row in document["results"]))
                self.assertTrue(all(row["alternativeControlEvidenceRefs"] for row in document["results"]))
                acr = next(row for row in document["results"] if row["family"] == "acr")
                self.assertEqual(acr["serviceConfiguration"], "PUBLIC_DISABLED")
                self.assertIn("UnsupportedAcrPerimeterAssociationObserved", acr["evidenceGaps"])
                observed = json.loads((directory / "observed-network.json").read_bytes())
                direct = [value for value in observed["alternativeControlObservations"]
                          if value["family"] == "nsp-associations" and value["direct"]]
                self.assertTrue(direct)
                self.assertEqual({value["configuration"]["properties"]["accessMode"] for value in direct}, {mode})

    def test_storage_and_key_vault_selectors_keep_service_specific_unknowns(self):
        for family in ("storage", "keyvault"):
            properties = {
                "publicNetworkAccess": "Enabled", "networkAcls": {
                    "defaultAction": "Deny", "bypass": "None", "ipRules": [{"value": "8.8.8.0/24"}],
                    "virtualNetworkRules": [], "resourceAccessRules": [],
                },
            }
            if family == "storage":
                properties["networkAcls"]["ipRules"][0]["action"] = "Allow"
            with self.subTest(family=family):
                row = restriction.evaluate_configuration(family, properties)[0]
                self.assertEqual(row["serviceConfiguration"], "SELECTED_NETWORKS")
                self.assertEqual(row["criterionVerdict"], "UNKNOWN")
                omitted = restriction.evaluate_configuration(
                    family, properties, omitted_paths=["/properties/networkAcls/ipRules/*/value"],
                )[0]
                self.assertEqual(omitted["serviceConfiguration"], "UNKNOWN")
                malformed = copy.deepcopy(properties)
                malformed["networkAcls"]["virtualNetworkRules"] = [{"id": "/subscriptions/not-a-subnet", "action": "Allow"}]
                self.assertEqual(restriction.evaluate_configuration(family, malformed)[0]["serviceConfiguration"], "UNKNOWN")
                subnet = f"/subscriptions/{fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Network/virtualNetworks/app/subnets/default"
                for entry in ({"id": subnet, "action": "FutureAction"}, {"id": subnet.replace("default", "*"), "action": "Allow"}):
                    malformed["networkAcls"]["virtualNetworkRules"] = [entry]
                    self.assertEqual(restriction.evaluate_configuration(family, malformed)[0]["serviceConfiguration"], "UNKNOWN")
                if family == "storage":
                    malformed["networkAcls"]["virtualNetworkRules"] = []
                    malformed["networkAcls"]["resourceAccessRules"] = [{"resourceId": snapshots.RESOURCE, "tenantId": "*"}]
                    self.assertEqual(restriction.evaluate_configuration(family, malformed)[0]["serviceConfiguration"], "UNKNOWN")

    def test_empty_visible_inventory_remains_an_unknown_scope_not_a_global_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER, present=False)
            directory = restriction.build(source, snapshots.RUN, root)
            document = json.loads((directory / "assessment.json").read_bytes())
            self.assertEqual(document["results"], [])
            self.assertEqual(document["assessmentState"], "UNKNOWN-no-service-paths-observed")
            self.assertEqual(document["scopeCoverageConclusion"], "UNKNOWN-not-global-completeness")

    def test_cli_is_offline_deterministic_private_and_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER, {
                "publicNetworkAccess": "Enabled", "networkAcls": {
                    "defaultAction": "Deny", "bypass": "None", "ipRules": [{"value": "8.8.8.0/24", "action": "Allow"}],
                    "virtualNetworkRules": [], "resourceAccessRules": [],
                },
            })
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            output = io.StringIO()
            with patch.object(sys, "argv", [
                "restriction", "build", "--capsule", str(source), "--run-id", snapshots.RUN, "--output-root", str(first),
            ]), redirect_stdout(output), patch("socket.socket", side_effect=AssertionError("Network call")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process invocation")):
                self.assertEqual(restriction.main(), 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["azureReads"], 0)
            self.assertEqual(receipt["memoryWrites"], 0)
            self.assertFalse(receipt["installedAcceptance"])
            self.assertLess(len(output.getvalue().encode()), 4000)
            directory = Path(receipt["restriction"])
            duplicate = restriction.build(source, snapshots.RUN, second)
            for path in directory.rglob("*"):
                if path.is_file() and path.relative_to(directory).as_posix() != "manifest.json":
                    self.assertEqual(path.read_bytes(), (duplicate / path.relative_to(directory)).read_bytes())
            for name in ("network-assessment.md", "network-evidence.md"):
                self.assertNotIn("8.8.8.0/24", (directory / name).read_text(encoding="utf-8"))
            with self.assertRaises(FileExistsError):
                restriction.build(source, snapshots.RUN, first)
            with self.assertRaisesRegex(ValueError, "outside"):
                restriction.build(source, snapshots.RUN, source)
            with patch.object(sys, "argv", ["restriction", "verify", "--run", str(directory)]), \
                    redirect_stdout(io.StringIO()), patch("socket.socket", side_effect=AssertionError("Network call")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process invocation")):
                self.assertEqual(restriction.main(), 0)

    def test_denied_get_does_not_turn_inventory_into_default_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER,
                                        {"publicNetworkAccess": "Disabled"}, status=403)
            directory = restriction.build(source, snapshots.RUN, root)
            document = json.loads((directory / "assessment.json").read_bytes())
            row = document["results"][0]
            self.assertEqual(row["serviceConfiguration"], "UNKNOWN")
            self.assertEqual(row["criterionVerdict"], "UNKNOWN")
            self.assertEqual(row["directGetOutcomes"][0]["httpStatus"], 403)
            self.assertTrue(any(value.startswith("DirectGetUnavailable:403:") for value in row["evidenceGaps"]))
            self.assertFalse(document["policy"]["defaultValuesAssumed"])
            for evidence_id in row["evidenceRefs"]:
                self.assertIn(evidence_id, document["evidenceCatalog"])
            self.assertFalse(any(value["direct"] for value in json.loads(
                (directory / "observed-network.json").read_bytes(),
            )["entities"][0]["observations"]))
        guarded = restriction.evaluate_configuration(
            "acr", {"publicNetworkAccess": "Disabled"}, source_eligible=False,
        )[0]
        self.assertEqual(guarded["criterionVerdict"], "UNKNOWN")

    def test_rehashed_assessment_or_report_cannot_forge_a_verdict(self):
        for member in ("assessment.json", "network-assessment.md", "observed-network.json"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER,
                                            {"publicNetworkAccess": "Disabled"})
                directory = restriction.build(source, snapshots.RUN, root)
                path = directory / member
                if member.endswith(".md"):
                    content = path.read_bytes().replace(b"UNKNOWN", b"RESTRICTED")
                else:
                    document = json.loads(path.read_bytes())
                    if member == "assessment.json":
                        document["results"][0]["criterionVerdict"] = "RESTRICTED"
                    else:
                        document["entities"][0]["observations"][0]["configuration"]["properties"] = {
                            "publicNetworkAccess": "Enabled",
                        }
                    content = fixture.capture.ef.encoded(document)
                path.write_bytes(content)
                manifest = json.loads((directory / "manifest.json").read_bytes())
                for entry in manifest["members"]:
                    if entry["name"] == member:
                        entry.update(fixture.capture.ef.descriptor(member, content))
                (directory / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
                with self.assertRaisesRegex(ValueError, "differ from verified"):
                    restriction.verify(directory)

    def test_global_exception_and_indeterminate_holes_use_versioned_registry_facts(self):
        def excluding(cidr):
            return [str(value) for value in ipaddress.IPv4Network("0.0.0.0/0").address_exclude(ipaddress.IPv4Network(cidr))]
        self.assertEqual(restriction.address_coverage(excluding("192.0.0.9/32"))["ipv4"]["internetCoverage"], "SUBSET")
        self.assertEqual(restriction.address_coverage(excluding("192.0.0.10/32"))["ipv4"]["internetCoverage"], "SUBSET")
        self.assertEqual(restriction.address_coverage(excluding("192.0.0.8/32"))["ipv4"]["internetCoverage"], "ALL")
        self.assertEqual(restriction.address_coverage(excluding("192.88.99.0/24"))["ipv4"]["internetCoverage"], "UNKNOWN")
        self.assertEqual(restriction.address_coverage(excluding("224.0.0.0/4"))["ipv4"]["internetCoverage"], "ALL")
        self.assertEqual(restriction.address_coverage(["8.8.8.8"] * 1000)["ipv4"]["internetCoverage"], "SUBSET")

    def test_missing_null_and_omitted_fields_preserve_distinct_evidence_gaps(self):
        for properties, expected in (
            ({}, "PublicNetworkAccessNotReturned"),
            ({"publicNetworkAccess": None}, "PublicNetworkAccessNull"),
            ({"publicNetworkAccess": True}, "PublicNetworkAccessUnexpectedType"),
            ({"publicNetworkAccess": "Enabled"}, "NetworkRulesNotReturned"),
            ({"publicNetworkAccess": "Enabled", "networkRuleSet": None}, "NetworkRulesNull"),
            ({"publicNetworkAccess": "Enabled", "networkRuleSet": {}}, "DefaultActionNotReturned"),
        ):
            with self.subTest(expected=expected):
                row = restriction.evaluate_configuration("acr", properties)[0]
                self.assertEqual(row["criterionVerdict"], "UNKNOWN")
                self.assertIn(expected, row["evidenceGaps"])
        with self.assertRaises(ValueError):
            restriction.evaluate_configuration("unsupported-service", {})
        with self.assertRaises(ValueError):
            restriction.evaluate_configuration("acr", {}, omitted_paths=["not-a-pointer"])

    def test_offline_run_keeps_observations_separate_and_renders_both_reports_from_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER, {
                "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"},
            })
            originals = {path.name: path.read_bytes() for path in source.iterdir()}
            result = restriction.build(source, snapshots.RUN, root)
            self.assertEqual(result, root / "runs" / snapshots.RUN)
            self.assertEqual(restriction.verify(result)["restrictionId"], snapshots.RUN)
            observed = json.loads((result / "observed-network.json").read_bytes())
            assessment = json.loads((result / "assessment.json").read_bytes())
            self.assertEqual(observed["profileId"], "retained-source-restriction-observations")
            self.assertNotIn("results", observed)
            self.assertEqual(assessment["profileId"], "retained-source-restriction-assessment")
            self.assertEqual(assessment["statistics"]["resources"], 1)
            self.assertEqual(assessment["statistics"]["servicePaths"], 1)
            self.assertEqual(assessment["results"][0]["serviceConfiguration"], "UNRESTRICTED")
            self.assertEqual(assessment["results"][0]["criterionVerdict"], "UNKNOWN")
            self.assertEqual(assessment["results"][0]["priority"]["actionType"], "evidenceCollection")
            self.assertEqual(assessment["causalConclusions"], "notGenerated")
            self.assertEqual(assessment["observationArtifact"]["filename"], "observed-network.json")
            direct = [value for value in observed["entities"][0]["observations"] if value["direct"]]
            self.assertEqual(assessment["results"][0]["evidenceRefs"], [direct[-1]["evidenceId"]])
            self.assertIn("UNKNOWN", (result / "network-assessment.md").read_text(encoding="utf-8"))
            self.assertIn("not anonymous access", (result / "network-evidence.md").read_text(encoding="utf-8"))
            self.assertEqual(restriction.render(assessment), (
                (result / "network-assessment.md").read_bytes(), (result / "network-evidence.md").read_bytes(),
            ))
            for name, content in originals.items():
                self.assertEqual((source / name).read_bytes(), content)
                self.assertEqual((result / "sources" / source.name / name).read_bytes(), content)

    def test_selected_networks_require_complete_valid_selectors_not_rule_counts(self):
        properties = {
            "publicNetworkAccess": "Enabled", "networkRuleBypassOptions": "None",
            "networkRuleSet": {"defaultAction": "Deny", "ipRules": [
                {"action": "Allow", "iPAddressOrRange": "8.8.8.0/24"},
            ], "virtualNetworkRules": []},
        }
        selected = restriction.evaluate_configuration("acr", properties)[0]
        self.assertEqual(selected["serviceConfiguration"], "SELECTED_NETWORKS")
        self.assertEqual(selected["criterionVerdict"], "RESTRICTED")
        self.assertEqual(selected["addressAnalysis"]["ipv4"]["internetCoverage"], "SUBSET")
        broad = copy.deepcopy(properties)
        broad["networkRuleSet"]["ipRules"] = [
            {"action": "Allow", "iPAddressOrRange": "0.0.0.0/1"},
            {"action": "Allow", "iPAddressOrRange": "128.0.0.0/1"},
        ]
        row = restriction.evaluate_configuration("acr", broad)[0]
        self.assertEqual(row["serviceConfiguration"], "UNRESTRICTED")
        self.assertEqual(row["criterionVerdict"], "NOT_RESTRICTED")
        for edit in ("missing-ips", "null-ips", "bad-action", "invalid-selector", "unknown-bypass", "unqualified-vnet"):
            with self.subTest(edit=edit):
                incomplete = copy.deepcopy(properties)
                if edit == "missing-ips":
                    del incomplete["networkRuleSet"]["ipRules"]
                elif edit == "null-ips":
                    incomplete["networkRuleSet"]["ipRules"] = None
                elif edit == "bad-action":
                    incomplete["networkRuleSet"]["ipRules"][0]["action"] = "FutureAction"
                elif edit == "invalid-selector":
                    incomplete["networkRuleSet"]["ipRules"][0]["iPAddressOrRange"] = "Internet"
                elif edit == "unknown-bypass":
                    incomplete["networkRuleBypassOptions"] = "FutureBypass"
                else:
                    incomplete["networkRuleSet"]["virtualNetworkRules"] = [{"id": "/unknown/vnet"}]
                row = restriction.evaluate_configuration("acr", incomplete)[0]
                self.assertEqual(row["serviceConfiguration"], "UNKNOWN")
                self.assertEqual(row["criterionVerdict"], "UNKNOWN")
                self.assertTrue(row["evidenceGaps"])

    def test_unsupported_ipv6_omitted_settings_and_unknown_modes_cannot_pass(self):
        base = {
            "publicNetworkAccess": "Enabled", "networkAcls": {
                "defaultAction": "Deny", "bypass": "None", "ipRules": [], "ipv6Rules": [{"value": "::/0", "action": "Allow"}],
                "virtualNetworkRules": [], "resourceAccessRules": [],
            },
        }
        row = restriction.evaluate_configuration("storage", base)[0]
        self.assertEqual(row["serviceConfiguration"], "UNKNOWN")
        self.assertIn("ServiceIPv6SelectorNotQualified", row["evidenceGaps"])
        for mode in (None, "", "FutureMode", "SecuredByPerimeter"):
            with self.subTest(mode=mode):
                row = restriction.evaluate_configuration("acr", {"publicNetworkAccess": mode})[0]
                self.assertEqual(row["criterionVerdict"], "UNKNOWN")
        row = restriction.evaluate_configuration(
            "acr", {"publicNetworkAccess": "Disabled"}, omitted_paths=["/properties/publicNetworkAccess"],
        )[0]
        self.assertEqual(row["criterionVerdict"], "UNKNOWN")

    def test_malformed_address_evidence_and_registry_uncertainty_stay_unknown(self):
        for values in (["0.0.0.0/0", "not-an-ip"], ["8.8.8.1/24"], ["::%eth0/0"], [False], [" 8.8.8.8"]):
            with self.subTest(values=values):
                row = restriction.address_coverage(values)
                self.assertEqual(row["status"], "UNKNOWN")
                self.assertTrue(row["errors"])
                self.assertEqual(row["ipv4"]["internetCoverage"], "UNKNOWN")
        with self.assertRaisesRegex(ValueError, "budget"):
            restriction.address_coverage(["8.8.8.8"] * 1001)
        self.assertEqual(restriction.address_coverage([])["ipv4"]["internetCoverage"], "SUBSET")

    def test_local_settings_and_overall_criterion_do_not_hide_unqualified_controls(self):
        disabled = restriction.evaluate_configuration("acr", {"publicNetworkAccess": "Disabled"})[0]
        self.assertEqual(disabled["serviceConfiguration"], "PUBLIC_DISABLED")
        self.assertEqual(disabled["criterionVerdict"], "RESTRICTED")
        self.assertFalse(disabled["privateConnectivityVerified"])
        self.assertEqual(disabled["actualReachability"], "UNKNOWN")
        allowed = restriction.evaluate_configuration("acr", {
            "publicNetworkAccess": "Enabled", "networkRuleSet": {"defaultAction": "Allow"},
        })[0]
        self.assertEqual(allowed["serviceConfiguration"], "UNRESTRICTED")
        self.assertEqual(allowed["criterionVerdict"], "NOT_RESTRICTED")
        for family in ("storage", "keyvault"):
            with self.subTest(family=family):
                row = restriction.evaluate_configuration(family, {
                    "publicNetworkAccess": "Disabled",
                    "privateEndpointConnections": [{"id": "present-but-not-proof"}],
                })[0]
                self.assertEqual(row["serviceConfiguration"], "PUBLIC_DISABLED")
                self.assertEqual(row["criterionVerdict"], "UNKNOWN")
                self.assertIn("PerimeterPrecedenceAndApplicabilityNotQualified", row["evidenceGaps"])
                self.assertEqual(row["checkId"], "NET-SOURCE-RESTRICTION-001")
                self.assertEqual(row["checkVersion"], "1.0.0")

    def test_log_analytics_ingestion_and_query_have_independent_local_results(self):
        rows = restriction.evaluate_configuration("loganalytics", {
            "publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Enabled",
            "privateLinkScopedResources": [{"resourceId": "a-reference-only", "scopeId": "not-enforcement"}],
        })
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(set(by_path), {"ingestion", "query"})
        self.assertEqual(by_path["ingestion"]["serviceConfiguration"], "PUBLIC_DISABLED")
        self.assertEqual(by_path["query"]["serviceConfiguration"], "UNRESTRICTED")
        self.assertTrue(all(row["criterionVerdict"] == "UNKNOWN" for row in rows))
        self.assertIn("AMPLSAssociationIsNotPathEnforcementProof", by_path["query"]["evidenceGaps"])

    def test_address_unions_detect_full_families_and_private_only_holes(self):
        full = restriction.address_coverage(["0.0.0.0/1", "128.0.0.0/1"])
        self.assertTrue(full["ipv4"]["coversEntireFamily"])
        self.assertEqual(full["ipv4"]["internetCoverage"], "ALL")
        without_private = restriction.address_coverage([
            "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6",
            "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
        ])
        self.assertFalse(without_private["ipv4"]["coversEntireFamily"])
        self.assertEqual(without_private["ipv4"]["internetCoverage"], "ALL")
        ipv6 = restriction.address_coverage(["::/1", "8000::/1"])
        self.assertTrue(ipv6["ipv6"]["coversEntireFamily"])
        self.assertEqual(ipv6["ipv6"]["internetCoverage"], "ALL")
        self.assertEqual(restriction.address_coverage(["8.8.8.0/24"])["ipv4"]["internetCoverage"], "SUBSET")


if __name__ == "__main__":
    unittest.main()
