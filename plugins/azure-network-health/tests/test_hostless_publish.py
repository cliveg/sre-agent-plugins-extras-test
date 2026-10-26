from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

import test_hostless_capture as fixture
import test_history as history_fixture
import test_workspace_activity as workspace_fixture
import test_comparison as snapshots


sys.path.insert(0, str(fixture.SCRIPTS))
import publish_evidence as publisher
import network_timeline as timeline
import network_comparison as comparison
import network_restriction as restriction


def git(directory: Path, *arguments: str) -> bytes:
    prefix = ["git", "-c", "core.longpaths=true"]
    prefix += ["--git-dir", str(directory)] if directory.name.endswith(".git") else ["-C", str(directory)]
    result = subprocess.run([*prefix, *arguments], capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    return result.stdout


def connected_repository(root: Path, expected_repo: str) -> tuple[Path, Path, Path]:
    remote, seed, clone = root / "remote.git", root / "seed", root / "connected"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    seed.mkdir()
    git(seed, "init", "-b", "main")
    git(seed, "config", "user.name", "Synthetic Fixture")
    git(seed, "config", "user.email", "fixture@example.invalid")
    (seed / "wara").mkdir()
    (seed / "wara" / "existing.json").write_bytes(b'{"preserve": true}\n')
    git(seed, "add", ".")
    git(seed, "commit", "-m", "Synthetic fixture\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>")
    git(seed, "remote", "add", "origin", str(remote))
    git(seed, "push", "origin", "main")
    git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    subprocess.run(["git", "clone", str(remote), str(clone)], check=True, capture_output=True)
    git(clone, "config", "remote.origin.url", "https://github.com/" + expected_repo + ".git")
    git(clone, "config", "url." + str(remote) + ".insteadOf", "https://github.com/" + expected_repo + ".git")
    return remote, seed, clone


class HostlessPublishTests(unittest.TestCase):
    def test_restriction_publication_keeps_all_four_views_and_original_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_repo = "example/evidence-output"
            remote, seed, clone = connected_repository(root, expected_repo)
            (clone / "unrelated-local.txt").write_text("preserve this")
            before = git(clone, "status", "--porcelain")
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER, {
                "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Allow"},
            })
            directory = restriction.build(source, snapshots.RUN, root)
            with self.assertRaisesRegex(ValueError, "Private"):
                publisher.publish(directory, clone, expected_repo, artifact_kind="restriction")
            receipt = publisher.publish(
                directory, clone, expected_repo, private_destination_reviewed=True, artifact_kind="restriction",
            )
            self.assertEqual(receipt["restrictionId"], snapshots.RUN)
            self.assertEqual(receipt["artifactKind"], "restriction")
            self.assertEqual(receipt["branch"], "network-restriction/" + snapshots.RUN)
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            self.assertEqual(git(remote, "rev-parse", "refs/heads/main"), git(seed, "rev-parse", "HEAD"))
            expected_names = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
            self.assertEqual({entry["name"] for entry in receipt["artifacts"]}, expected_names)
            self.assertTrue({"observed-network.json", "assessment.json", "network-assessment.md", "network-evidence.md"} <= expected_names)
            for entry in receipt["artifacts"]:
                self.assertEqual(entry["path"], "network-health/runs/" + snapshots.RUN + "/" + entry["name"])
                self.assertEqual(git(remote, "show", receipt["commit"] + ":" + entry["path"]),
                                 (directory / entry["name"]).read_bytes())
            self.assertIn(publisher.TRAILER.encode(), git(remote, "show", "-s", "--format=%B", receipt["commit"]))
            saved = root / "restriction-publication-receipt.json"
            stdout = io.StringIO()
            with patch.object(sys, "argv", [
                "publisher", "--restriction", str(directory), "--repository-root", str(clone),
                "--expected-repository", expected_repo, "--private-destination-reviewed", "--receipt", str(saved),
            ]), redirect_stdout(stdout):
                self.assertEqual(publisher.main(), 0)
            compact = json.loads(stdout.getvalue())
            self.assertEqual(compact["status"], "existing-remote-bytes-verified")
            self.assertEqual(compact["commit"], receipt["commit"])
            self.assertEqual(compact["artifactCount"], len(expected_names))
            self.assertNotIn("artifacts", compact)
            self.assertLess(len(stdout.getvalue().encode()), 4000)
            self.assertEqual(json.loads(saved.read_bytes())["restrictionId"], snapshots.RUN)

    def test_restriction_publication_rejects_a_rehashed_forged_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_repo = "example/evidence-output"
            remote, _, clone = connected_repository(root, expected_repo)
            source = snapshots.snapshot(root, snapshots.BEFORE, snapshots.EARLIER,
                                        {"publicNetworkAccess": "Disabled"})
            directory = restriction.build(source, snapshots.RUN, root)
            assessment = json.loads((directory / "assessment.json").read_bytes())
            assessment["results"][0]["criterionVerdict"] = "RESTRICTED"
            content = fixture.capture.ef.encoded(assessment)
            (directory / "assessment.json").write_bytes(content)
            manifest = json.loads((directory / "manifest.json").read_bytes())
            for entry in manifest["members"]:
                if entry["name"] == "assessment.json":
                    entry.update(fixture.capture.ef.descriptor("assessment.json", content))
            (directory / "manifest.json").write_bytes(fixture.capture.ef.encoded(manifest))
            refs = git(remote, "for-each-ref", "--format=%(refname):%(objectname)")
            before = git(clone, "status", "--porcelain")
            with self.assertRaisesRegex(ValueError, "differ from verified"):
                publisher.publish(
                    directory, clone, expected_repo, private_destination_reviewed=True, artifact_kind="restriction",
                )
            self.assertEqual(git(remote, "for-each-ref", "--format=%(refname):%(objectname)"), refs)
            self.assertEqual(git(clone, "status", "--porcelain"), before)

    def test_twenty_budget_compliant_configuration_capsules_can_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_repo = "example/evidence-output"
            remote, seed, clone = connected_repository(root, expected_repo)
            base = f"https://management.azure.com/subscriptions/{fixture.SUB}/providers/Microsoft.Storage/storageAccounts"
            resources = [{
                "id": f"/subscriptions/{fixture.SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/app{number}",
                "name": f"app{number}", "type": "Microsoft.Storage/storageAccounts", "location": "westus2",
                "properties": {"publicNetworkAccess": "Enabled"},
            } for number in range(3)]
            replies = {base + "?api-version=2023-05-01": {
                "statusCode": 200, "requestId": None, "body": {"value": resources},
            }} | {
                "https://management.azure.com" + resource["id"] + "?api-version=2023-05-01": {
                    "statusCode": 200, "requestId": None, "body": resource,
                } for resource in resources
            }
            sources = [fixture.capture.capture(
                fixture.ArmService(replies), fixture.TENANT, fixture.SUB, fixture.CLIENT,
                f"00000000-0000-4000-8000-{number:012}", root,
            ) for number in range(100, 120)]
            derived = timeline.build(sources, "00000000-0000-4000-8000-000000000070", root)
            document = json.loads((derived / "timeline.json").read_bytes())
            self.assertEqual(document["statistics"]["inputCapsules"], 20)
            self.assertEqual(document["statistics"]["configurationObservations"], 120)
            self.assertLessEqual((derived / "manifest.json").stat().st_size, 64 * 1024)
            self.assertLessEqual(sum(path.stat().st_size for path in derived.rglob("*") if path.is_file()), 20 * 1024 * 1024)
            receipt = publisher.publish(
                derived, clone, expected_repo, private_destination_reviewed=True, artifact_kind="timeline",
            )
            self.assertTrue(receipt["remoteReferenceConfirmed"])
            self.assertEqual(git(remote, "rev-parse", "refs/heads/main"), git(seed, "rev-parse", "HEAD"))
            self.assertEqual(len(receipt["artifacts"]), 223)

    def test_publication_preserves_original_worktree_and_verifies_exact_remote_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_repo = "example/evidence-output"
            remote, seed, clone = connected_repository(root, expected_repo)
            (clone / "unrelated-local.txt").write_text("do not stage")
            before = git(clone, "status", "--porcelain")
            directory = fixture.capture.capture(fixture.ArmService(), fixture.TENANT, fixture.SUB, fixture.CLIENT,
                                                fixture.RUN, root)
            receipt = publisher.publish(directory, clone, expected_repo, private_destination_reviewed=True)
            self.assertTrue(receipt["remoteReferenceConfirmed"])
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            self.assertEqual(git(remote, "rev-parse", "refs/heads/main"), git(seed, "rev-parse", "HEAD"))
            for entry in receipt["artifacts"]:
                blob = git(remote, "show", receipt["commit"] + ":" + entry["path"])
                self.assertEqual(hashlib.sha256(blob).hexdigest(), entry["sha256"])
                self.assertEqual(blob, (directory / entry["name"]).read_bytes())
            receipt_path = root / "publication-receipt.json"
            arguments = [
                "publisher", "--capsule", str(directory), "--repository-root", str(clone),
                "--expected-repository", expected_repo, "--private-destination-reviewed", "--receipt", str(receipt_path),
            ]
            stdout = io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(stdout):
                self.assertEqual(publisher.main(), 0)
            compact = json.loads(stdout.getvalue())
            self.assertNotIn("artifacts", compact)
            self.assertEqual(compact["artifactCount"], len(receipt["artifacts"]))
            self.assertEqual(compact["receiptSha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())
            self.assertLess(len(stdout.getvalue().encode()), 4000)
            self.assertEqual(len(json.loads(receipt_path.read_bytes())["artifacts"]), len(receipt["artifacts"]))
            history_id = "00000000-0000-4000-8000-000000000059"
            reader = history_fixture.HistoryService("activity-log", [{
                "statusCode": 200, "body": {"value": [history_fixture.activity()], "nextLink": None}, "requestId": None,
            }])
            historical = history_fixture.history.capture(
                reader, "activity-log", fixture.TENANT, fixture.SUB, fixture.CLIENT, history_id, root,
                history_fixture.START, history_fixture.END, planning_time=history_fixture.END,
            )
            historical_receipt = publisher.publish(historical, clone, expected_repo, private_destination_reviewed=True)
            self.assertTrue(historical_receipt["remoteReferenceConfirmed"])
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            for entry in historical_receipt["artifacts"]:
                blob = git(remote, "show", historical_receipt["commit"] + ":" + entry["path"])
                self.assertEqual(blob, (historical / entry["name"]).read_bytes())

            class WorkspaceRows(workspace_fixture.WorkspaceService):
                def workspace(self, operation, resource_id, workspace_id=None, window=None, cursor=None):
                    if operation == "page":
                        row = workspace_fixture.activity_row()
                        return {"statusCode": 200, "requestId": None, "body": workspace_fixture.table(
                            [[row[name] for name in workspace_fixture.workspace.EVENT_COLUMNS]],
                            workspace_fixture.workspace.EVENT_COLUMNS,
                        )}
                    return super().workspace(operation, resource_id, workspace_id, window, cursor)

            workspace_id = "00000000-0000-4000-8000-000000000062"
            law = workspace_fixture.workspace.capture(
                WorkspaceRows(), fixture.TENANT, fixture.SUB, fixture.CLIENT, workspace_id, root,
                workspace_fixture.RESOURCE, workspace_fixture.START, workspace_fixture.END, planning_time=workspace_fixture.END,
            )
            law_receipt = publisher.publish(law, clone, expected_repo, private_destination_reviewed=True)
            self.assertTrue(law_receipt["remoteReferenceConfirmed"])
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            for entry in law_receipt["artifacts"]:
                blob = git(remote, "show", law_receipt["commit"] + ":" + entry["path"])
                self.assertEqual(blob, (law / entry["name"]).read_bytes())

            timeline_id = "00000000-0000-4000-8000-000000000070"
            derived = timeline.build([directory, historical, law], timeline_id, root)
            with self.assertRaisesRegex(ValueError, "Private"):
                publisher.publish(derived, clone, expected_repo, artifact_kind="timeline")
            timeline_receipt = publisher.publish(
                derived, clone, expected_repo, private_destination_reviewed=True, artifact_kind="timeline",
            )
            self.assertEqual(timeline_receipt["timelineId"], timeline_id)
            self.assertNotIn("capsuleId", timeline_receipt)
            self.assertEqual(timeline_receipt["branch"], "network-timeline/" + timeline_id)
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            self.assertEqual(git(remote, "rev-parse", "refs/heads/main"), git(seed, "rev-parse", "HEAD"))
            expected_names = {"manifest.json", "timeline.json", "timeline.md"} | {
                "sources/" + source.name + "/" + path.name for source in (directory, historical, law)
                for path in source.iterdir()
            }
            self.assertEqual({entry["name"] for entry in timeline_receipt["artifacts"]}, expected_names)
            for entry in timeline_receipt["artifacts"]:
                self.assertEqual(entry["path"], "network-health/timelines/" + timeline_id + "/" + entry["name"])
                blob = git(remote, "show", timeline_receipt["commit"] + ":" + entry["path"])
                self.assertEqual(blob, (derived / entry["name"]).read_bytes())
            saved = root / "timeline-publication-receipt.json"
            stdout = io.StringIO()
            with patch.object(sys, "argv", [
                "publisher", "--timeline", str(derived), "--repository-root", str(clone),
                "--expected-repository", expected_repo, "--private-destination-reviewed", "--receipt", str(saved),
            ]), redirect_stdout(stdout):
                self.assertEqual(publisher.main(), 0)
            compact = json.loads(stdout.getvalue())
            self.assertEqual(compact["commit"], timeline_receipt["commit"])
            self.assertEqual(compact["status"], "existing-remote-bytes-verified")
            self.assertEqual(compact["artifactCount"], len(expected_names))
            self.assertNotIn("artifacts", compact)
            self.assertEqual(json.loads(saved.read_bytes())["timelineId"], timeline_id)
            self.assertLess(len(stdout.getvalue().encode()), 4000)

            newer = fixture.capture.capture(
                fixture.ArmService(), fixture.TENANT, fixture.SUB, fixture.CLIENT,
                "00000000-0000-4000-8000-000000000074", root,
            )
            derived_comparison = comparison.build(
                directory, newer, "00000000-0000-4000-8000-000000000075", root,
            )
            compared = publisher.publish(
                derived_comparison, clone, expected_repo, private_destination_reviewed=True, artifact_kind="comparison",
            )
            self.assertEqual(compared["branch"], "network-comparison/00000000-0000-4000-8000-000000000075")
            self.assertEqual(compared["comparisonId"], "00000000-0000-4000-8000-000000000075")
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            for entry in compared["artifacts"]:
                self.assertTrue(entry["path"].startswith("network-health/comparisons/" + compared["comparisonId"] + "/"))
                self.assertEqual(git(remote, "show", compared["commit"] + ":" + entry["path"]),
                                 (derived_comparison / entry["name"]).read_bytes())
            with patch.object(sys, "argv", [
                "publisher", "--comparison", str(derived_comparison), "--repository-root", str(clone),
                "--expected-repository", expected_repo, "--private-destination-reviewed",
                "--receipt", str(root / "comparison-publication-receipt.json"),
            ]), redirect_stdout(io.StringIO()):
                self.assertEqual(publisher.main(), 0)

            paged = timeline.build([directory, historical, law], "00000000-0000-4000-8000-000000000076",
                                   root, compact=True)
            paged_receipt = publisher.publish(
                paged, clone, expected_repo, private_destination_reviewed=True, artifact_kind="timeline",
            )
            self.assertTrue(paged_receipt["remoteReferenceConfirmed"])
            self.assertGreater(len(paged_receipt["artifacts"]), 12)
            for entry in paged_receipt["artifacts"]:
                self.assertEqual(git(remote, "show", paged_receipt["commit"] + ":" + entry["path"]),
                                 (paged / entry["name"]).read_bytes())
            self.assertEqual(git(clone, "status", "--porcelain"), before)
            self.assertEqual(git(remote, "rev-parse", "refs/heads/main"), git(seed, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
