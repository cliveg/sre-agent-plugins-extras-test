"""Offline reporting input-integrity and publication tests."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import openpyxl

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "wara-assessment" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import generate_reports as reports


class ReportingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "standard").mkdir()
        (self.root / "derived").mkdir()
        self.scope = {"type": "ResourceGroup", "subscriptionId": "sub", "resourceGroup": "rg"}
        self.findings = {
            "runId": "run", "scope": self.scope,
            "findings": [{"title": "Accepted recommendation", "findingKey": "one", "control": "HighAvailability",
                          "resource": {"name": "app", "id": "resource", "resourceGroup": "rg"},
                          "priority": {"band": "Accepted", "score": 3.6},
                          "evidence": {"classification": "OBSERVED"}}],
        }
        self.write("derived/prioritized-findings.json", self.findings)
        self.write("derived/delta.json", {})
        self.write("standard/WARA-File-test.json", {})
        wb = openpyxl.Workbook()
        wb.save(self.root / "standard" / "Expert-Analysis-test.xlsx")
        self.run = {
            "runId": "run", "scope": self.scope, "upstream": {},
            "outputs": {
                "collectorJson": self.entry("standard/WARA-File-test.json"),
                "analyzerWorkbook": self.entry("standard/Expert-Analysis-test.xlsx"),
                "derived/prioritized-findings.json": reports.sha(self.root / "derived" / "prioritized-findings.json"),
            },
        }
        self.write("run.json", self.run)
        self.write("evidence.json", {"scope": {"subscriptionId": "sub", "resourceGroup": "rg"},
                                    "resourceGroups": [{"name": "rg", "tags": {"Environment": "Dev"}}]})

    def write(self, relative, document):
        (self.root / relative).write_text(json.dumps(document), encoding="utf-8")

    def entry(self, relative):
        return {"path": relative, "sha256": reports.sha(self.root / relative)}

    def test_load_uses_recorded_files_not_extra_glob_matches(self):
        (self.root / "standard" / "Expert-Analysis-extra.xlsx").write_bytes(b"not a workbook")
        ctx = reports.load_run(str(self.root))
        self.assertEqual(Path(ctx["xlsx"]).name, "Expert-Analysis-test.xlsx")

    def test_hash_mismatch_is_rejected(self):
        self.write("standard/WARA-File-test.json", {"changed": True})
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            reports.load_run(str(self.root))

    def test_run_identity_mismatch_is_rejected(self):
        self.findings["runId"] = "other"
        self.write("derived/prioritized-findings.json", self.findings)
        with self.assertRaisesRegex(ValueError, "run/scope"):
            reports.load_run(str(self.root))

    def test_templates_resolve_exact_pin(self):
        cache = self.root / "cache"
        expected = cache / "src" / "wara-aaaaaaaaaaaa" / "src" / "modules" / "wara" / "reports" / "template"
        expected.parent.mkdir(parents=True)
        expected.write_text("pinned")
        with patch.dict("os.environ", {"WARA_CACHE": str(cache)}):
            self.assertEqual(reports.find_template("template", None, "a" * 40), str(expected))
            with self.assertRaises(SystemExit):
                reports.find_template("template", None, "b" * 40)

    def test_accepted_findings_publish_and_sources_stay_unchanged(self):
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.root.rglob("*") if p.is_file()}
        template = self.root / "template"
        template.write_bytes(b"template")
        argv = ["generate_reports.py", "--run-dir", str(self.root),
                "--environment-evidence", str(self.root / "evidence.json")]

        def build(ctx, template_or_path, output_or_work):
            path = output_or_work if str(template_or_path) == str(template) else template_or_path
            Path(path).write_bytes(b"generated")
            self.assertEqual(ctx["findings"][0]["priority"]["band"], "Accepted")
            self.assertTrue(ctx["findings"][0]["env"]["action"].startswith("Accepted risk"))
            return 1

        with patch.object(sys, "argv", argv), patch.object(reports, "find_template", return_value=str(template)), \
                patch.object(reports, "build_pptx", side_effect=build), \
                patch.object(reports, "build_docx", side_effect=build), \
                patch.object(reports, "build_xlsx", side_effect=build):
            reports.main()
            with self.assertRaisesRegex(ValueError, "already published"):
                reports.main()
        manifest = json.loads((self.root / "reports" / "report-manifest.json").read_text())
        for name, expected in manifest["outputs"].items():
            self.assertEqual(reports.sha(self.root / "reports" / name), expected)
        self.assertIn("wara-report-NOTICE.txt", manifest["outputs"])
        for path, expected in before.items():
            self.assertEqual(reports.sha(path), expected)

    def test_environment_scope_mismatch_is_rejected(self):
        self.write("evidence.json", {"scope": {"subscriptionId": "other"}})
        with patch.object(sys, "argv", ["generate_reports.py", "--run-dir", str(self.root),
                                      "--environment-evidence", str(self.root / "evidence.json")]):
            with self.assertRaisesRegex(ValueError, "evidence scope"):
                reports.main()
