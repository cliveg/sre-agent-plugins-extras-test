from __future__ import annotations

import copy
import json
import io
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

import test_hostless_capture as fixture


sys.path.insert(0, str(fixture.SCRIPTS))
import network_comparison as comparison


BEFORE = "00000000-0000-4000-8000-000000000071"
AFTER = "00000000-0000-4000-8000-000000000072"
RUN = "00000000-0000-4000-8000-000000000080"
EARLIER = "2026-10-13T15:00:00Z"
LATER = "2026-10-18T15:00:00Z"
RESOURCE = f"/subscriptions/{fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/app"


def snapshot(root, identifier, stamp, properties=None, status=200, present=True, tenant=fixture.TENANT):
    resource = {
        "id": RESOURCE, "name": "app", "type": "Microsoft.Storage/storageAccounts",
        "location": "westus2", "systemData": {"lastModifiedAt": stamp},
        "properties": properties if properties is not None else {"allowBlobPublicAccess": False},
    }
    class ScopedReader(fixture.ArmService):
        def context(self):
            value = super().context()
            value["tenantId"] = tenant
            return value

    reader = ScopedReader({
        f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01": {
            "statusCode": 200, "requestId": None, "body": {"value": [resource] if present else []},
        },
        "https://management.azure.com" + RESOURCE + "?api-version=2023-05-01": {
            "statusCode": status, "requestId": None, "body": resource if status == 200 else None,
        },
    })
    with patch.object(fixture.capture.ef, "utc_now", return_value=stamp):
        return fixture.capture.capture(reader, tenant, fixture.SUB, fixture.CLIENT, identifier, root)


class ComparisonTests(unittest.TestCase):
    def test_scope_and_exact_seven_digit_chronology_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER)
            other = snapshot(root, AFTER, LATER, tenant="00000000-0000-4000-8000-000000000099")
            with self.assertRaisesRegex(ValueError, "scope"):
                comparison.build(before, other, RUN, root)
            first = snapshot(root, "00000000-0000-4000-8000-000000000073", "2026-10-18T15:00:00.0000002Z")
            second = snapshot(root, "00000000-0000-4000-8000-000000000074", "2026-10-18T15:00:00.0000001Z")
            with self.assertRaisesRegex(ValueError, "chronological"):
                comparison.build(first, second, RUN, root)

    def test_arm_reference_casing_does_not_fabricate_settings_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER, {"networkAcls": {"resourceAccessRules": [
                {"resourceId": RESOURCE, "tenantId": fixture.TENANT},
            ]}})
            after = snapshot(root, AFTER, LATER, {"networkAcls": {"resourceAccessRules": [
                {"resourceId": RESOURCE.upper(), "tenantId": fixture.TENANT},
            ]}})
            result = comparison.build(before, after, RUN, root)
            self.assertEqual(json.loads((result / "comparison.json").read_bytes())["statistics"]["settingsDifferences"], 0)

    def test_explicit_omission_is_a_gap_even_when_a_retained_value_is_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER)
            after = snapshot(root, AFTER, LATER, {"allowBlobPublicAccess": True})
            manifest = json.loads((after / "manifest.json").read_bytes())
            for entry in manifest["members"]:
                path = after / entry["name"]
                page = json.loads(path.read_bytes())
                if page.get("operationId") != "storage-get":
                    continue
                page["rows"][0]["omittedPaths"].append("/properties/allowBlobPublicAccess")
                content = fixture.capture.ef.encoded(page)
                path.write_bytes(content)
                entry.update(fixture.capture.ef.descriptor(entry["name"], content))
            (after / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
            result = comparison.build(before, after, RUN, root)
            document = json.loads((result / "comparison.json").read_bytes())
            self.assertEqual(document["statistics"]["settingsDifferences"], 0)
            self.assertIn({"path": "/properties/allowBlobPublicAccess", "reason": "omittedInAfter"},
                          document["resources"][0]["evidenceGaps"])

    def test_public_commands_are_offline_deterministic_and_keep_private_values_out_of_markdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER, {"networkAcls": {"ipRules": [{"value": "192.0.2.0/24"}]}})
            after = snapshot(root, AFTER, LATER, {"networkAcls": {"ipRules": [{"value": "198.51.100.0/24"}]}})
            first, second = root / "one", root / "two"
            first.mkdir()
            second.mkdir()
            output = io.StringIO()
            args = ["comparison", "build", "--before", str(before), "--after", str(after),
                    "--comparison-id", RUN, "--output-root", str(first)]
            with patch.object(sys, "argv", args), redirect_stdout(output), \
                    patch("socket.socket", side_effect=AssertionError("Network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process invocation")):
                self.assertEqual(comparison.main(), 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["azureReads"], 0)
            self.assertLess(len(output.getvalue().encode()), 4000)
            directory = Path(receipt["comparison"])
            duplicate = comparison.build(before, after, RUN, second)
            self.assertEqual((directory / "comparison.json").read_bytes(), (duplicate / "comparison.json").read_bytes())
            self.assertEqual((directory / "comparison.md").read_bytes(), (duplicate / "comparison.md").read_bytes())
            self.assertNotIn("192.0.2.0/24", (directory / "comparison.md").read_text(encoding="utf-8"))
            with self.assertRaises(FileExistsError):
                comparison.build(before, after, RUN, first)
            with patch.object(sys, "argv", ["comparison", "verify", "--comparison", str(directory)]), \
                    redirect_stdout(io.StringIO()), patch("socket.socket", side_effect=AssertionError("Network access")), \
                    patch("subprocess.Popen", side_effect=AssertionError("Process invocation")):
                self.assertEqual(comparison.main(), 0)

    def test_missing_null_denied_and_one_sided_resources_are_not_defaults_or_deletions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER, {"allowBlobPublicAccess": None, "allowSharedKeyAccess": True})
            after = snapshot(root, AFTER, LATER, {"allowBlobPublicAccess": False})
            result = comparison.build(before, after, RUN, root)
            document = json.loads((result / "comparison.json").read_bytes())
            resource = document["resources"][0]
            self.assertEqual(document["statistics"]["settingsDifferences"], 1)
            self.assertEqual(resource["differences"][0]["before"]["value"], None)
            self.assertIn({"path": "/properties/allowSharedKeyAccess", "reason": "notReturnedAfter"}, resource["evidenceGaps"])
            denied = snapshot(root, "00000000-0000-4000-8000-000000000073", LATER, status=403)
            result = comparison.build(before, denied, "00000000-0000-4000-8000-000000000081", root)
            document = json.loads((result / "comparison.json").read_bytes())
            self.assertEqual(document["statistics"]["settingsDifferences"], 0)
            self.assertEqual(document["resources"][0]["status"], "UNKNOWN")
            self.assertEqual(document["resources"][0]["after"]["getOutcomes"][0]["status"], "permissionDenied")
            self.assertIn("permissionDenied", (result / "comparison.md").read_text(encoding="utf-8"))
            absent = snapshot(root, "00000000-0000-4000-8000-000000000074", LATER, present=False)
            result = comparison.build(before, absent, "00000000-0000-4000-8000-000000000082", root)
            document = json.loads((result / "comparison.json").read_bytes())
            self.assertEqual(document["resources"][0]["visibility"], "notObservedLater")
            self.assertEqual(document["resources"][0]["after"]["state"], "notObserved")
            self.assertNotIn("deleted", document["resources"][0])

    def test_membership_order_is_not_a_change_but_duplicate_membership_is(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = [{"value": "192.0.2.0/24", "action": "Allow"}, {"value": "198.51.100.0/24", "action": "Allow"}]
            before = snapshot(root, BEFORE, EARLIER, {"networkAcls": {"ipRules": rules}})
            after = snapshot(root, AFTER, LATER, {"networkAcls": {"ipRules": list(reversed(rules))}})
            result = comparison.build(before, after, RUN, root)
            self.assertEqual(json.loads((result / "comparison.json").read_bytes())["statistics"]["settingsDifferences"], 0)
            duplicate = snapshot(root, "00000000-0000-4000-8000-000000000073", LATER,
                                 {"networkAcls": {"ipRules": rules + [rules[0]]}})
            result = comparison.build(before, duplicate, "00000000-0000-4000-8000-000000000081", root)
            self.assertEqual(json.loads((result / "comparison.json").read_bytes())["statistics"]["settingsDifferences"], 1)

    def test_provider_state_inside_membership_arrays_is_metadata_not_a_settings_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = {"id": RESOURCE + "/privateEndpointConnections/endpoint",
                          "properties": {"provisioningState": "Updating", "groupIds": ["blob"]}}
            before = snapshot(root, BEFORE, EARLIER, {"privateEndpointConnections": [connection]})
            connection = copy.deepcopy(connection)
            connection["properties"]["provisioningState"] = "Succeeded"
            after = snapshot(root, AFTER, LATER, {"privateEndpointConnections": [connection]})
            result = comparison.build(before, after, RUN, root)
            document = json.loads((result / "comparison.json").read_bytes())
            self.assertEqual(document["statistics"]["settingsDifferences"], 0)
            self.assertEqual(document["statistics"]["metadataDifferences"], 2)

    def test_before_after_roles_and_forged_views_are_verified_and_output_cannot_mutate_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER)
            after = snapshot(root, AFTER, LATER)
            with self.assertRaisesRegex(ValueError, "chronological"):
                comparison.build(after, before, RUN, root)
            with self.assertRaisesRegex(ValueError, "outside"):
                comparison.build(before, after, RUN, before)
            self.assertEqual(fixture.capture.verify(before)["capsuleId"], BEFORE)
            result = comparison.build(before, after, RUN, root)
            document = json.loads((result / "comparison.json").read_bytes())
            document["statistics"]["settingsDifferences"] = 9000
            content = fixture.capture.ef.encoded(document)
            (result / "comparison.json").write_bytes(content)
            manifest = json.loads((result / "manifest.json").read_bytes())
            manifest["members"] = [
                fixture.capture.ef.descriptor("comparison.json", content) if value["name"] == "comparison.json" else value
                for value in manifest["members"]
            ]
            (result / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
            with self.assertRaisesRegex(ValueError, "views"):
                comparison.verify(result)

    def test_settings_and_metadata_differences_have_original_evidence_without_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root, BEFORE, EARLIER, {"allowBlobPublicAccess": False})
            after = snapshot(root, AFTER, LATER, {"allowBlobPublicAccess": True})
            original = {str(path): path.read_bytes() for source in (before, after) for path in source.iterdir()}
            result = comparison.build(before, after, RUN, root)
            manifest = comparison.verify(result)
            document = json.loads((result / "comparison.json").read_bytes())
            self.assertEqual(manifest["inputs"], {"before": BEFORE, "after": AFTER})
            self.assertEqual(document["statistics"]["settingsDifferences"], 1)
            self.assertEqual(document["statistics"]["metadataDifferences"], 1)
            resource = document["resources"][0]
            self.assertEqual(resource["status"], "compared")
            differences = {value["path"]: value for value in resource["differences"]}
            changed = differences["/properties/allowBlobPublicAccess"]
            self.assertEqual(changed["before"], {"state": "observed", "value": False})
            self.assertEqual(changed["after"], {"state": "observed", "value": True})
            self.assertEqual(changed["checkId"], "configuration-retained-value-difference")
            self.assertEqual(changed["checkVersion"], "1.0.0")
            self.assertTrue(resource["before"]["evidence"]["pointer"].startswith("/rows/0/configuration"))
            self.assertEqual(resource["before"]["evidence"]["capsuleId"], BEFORE)
            self.assertFalse(document["assessmentPerformed"])
            self.assertEqual(document["causalConclusions"], "notGenerated")
            self.assertEqual(document["desiredStateComparison"], "notPerformed")
            self.assertIn("not a defect", (result / "comparison.md").read_text(encoding="utf-8"))
            for path, content in original.items():
                self.assertEqual(Path(path).read_bytes(), content)
            self.assertTrue((result / "sources" / BEFORE / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
