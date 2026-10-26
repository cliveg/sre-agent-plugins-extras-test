"""Unit tests for the advisory environment/criticality classification (PyYAML only)."""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.join(HERE, "..", "skills", "wara-assessment")
sys.path.insert(0, os.path.join(SKILL, "scripts"))

from environment_classification import classify, load_config, overlay  # noqa: E402

CONFIG = os.path.join(SKILL, "config", "environment-classification.yaml")


def evidence(quota="PayAsYouGo_2014-09-01", sub_tags=None, rg_tags=None, res_tags=None):
    return {
        "subscription": {"id": "s", "name": "sub", "quotaId": quota, "tags": sub_tags or {}},
        "resourceGroups": [{"name": "rg1", "tags": rg_tags or {}}],
        "resources": [{"name": "app1", "type": "microsoft.web/sites", "resourceGroup": "rg1", "tags": res_tags or {}}],
    }


def finding(control="HighAvailability", name="app1"):
    return {"control": control, "resource": {"name": name, "type": "microsoft.web/sites", "resourceGroup": "rg1"}}


class ClassificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config(CONFIG)

    def res(self, ev):
        return next(iter(classify(self.cfg, ev)["resources"].values()))

    def test_no_signal_is_unknown_and_assessed_as_production(self):
        c = classify(self.cfg, evidence())
        self.assertEqual(next(iter(c["resources"].values()))["tier"], "UNKNOWN")
        o = overlay(self.cfg, c, finding(), "rg1")
        self.assertEqual(o["assessedAs"], "PROD-PRIMARY")
        self.assertEqual(o["requirement"], "Required")

    def test_internal_offer_is_dev(self):
        r = self.res(evidence(quota="Internal_2014-09-01"))
        self.assertEqual((r["tier"], r["confidence"]), ("DEV", "Medium"))
        self.assertIn("Internal_2014-09-01", r["basis"])

    def test_msdn_offer_is_dev(self):
        self.assertEqual(self.res(evidence(quota="MSDN_2014-09-01"))["tier"], "DEV")

    def test_explicit_resource_tag_beats_rg_tag_and_offer(self):
        r = self.res(evidence(quota="PayAsYouGo_2014-09-01", rg_tags={"Environment": "Dev"}, res_tags={"Environment": "UAT"}))
        self.assertEqual((r["tier"], r["confidence"]), ("UAT", "High"))

    def test_explicit_rg_tag_beats_offer(self):
        r = self.res(evidence(quota="Internal_2014-09-01", rg_tags={"env": "test"}))
        self.assertEqual(r["tier"], "TEST")

    def test_offer_beats_heuristic_tag(self):
        r = self.res(evidence(quota="Internal_2014-09-01", rg_tags={"azd-env-name": "prod-east"}))
        self.assertEqual(r["tier"], "DEV")

    def test_heuristic_lab_suffix(self):
        r = self.res(evidence(rg_tags={"azd-env-name": "onboardinglab"}))
        self.assertEqual((r["tier"], r["confidence"]), ("DEV", "Low"))

    def test_dr_and_prod_values(self):
        self.assertEqual(self.res(evidence(res_tags={"Criticality": "Prod-DR"}))["tier"], "PROD-DR")
        self.assertEqual(self.res(evidence(res_tags={"Environment": "Production"}))["tier"], "PROD-PRIMARY")

    def test_unrecognised_explicit_value_is_noted_and_ignored(self):
        c = classify(self.cfg, evidence(sub_tags={"Environment": "Hybrid"}))
        self.assertEqual(next(iter(c["resources"].values()))["tier"], "UNKNOWN")
        self.assertTrue(any("Environment=Hybrid" in n for n in c["notes"]))

    def test_production_tag_on_non_production_offer_is_conflict(self):
        r = self.res(evidence(quota="MSDN_2014-09-01", res_tags={"Environment": "prod"}))
        self.assertEqual(r["tier"], "PROD-PRIMARY")
        self.assertIsNotNone(r["conflict"])

    def test_dev_requirements(self):
        c = classify(self.cfg, evidence(quota="Internal_2014-09-01"))
        self.assertEqual(overlay(self.cfg, c, finding("HighAvailability"), "rg1")["requirement"], "NotRequired")
        self.assertEqual(overlay(self.cfg, c, finding("ServiceUpgradeAndRetirement"), "rg1")["requirement"], "Required")
        self.assertEqual(overlay(self.cfg, c, finding("SomethingNew"), "rg1")["requirement"], "Optional")

    def test_finding_for_resource_not_in_evidence_uses_rg(self):
        c = classify(self.cfg, evidence(rg_tags={"Environment": "UAT"}))
        self.assertEqual(overlay(self.cfg, c, finding(name="other"), "rg1")["tier"], "UAT")

    def test_duplicate_names_use_resource_ids(self):
        ev = evidence()
        ev["resources"] = [
            {"id": "/subscriptions/s/resourceGroups/rg1/providers/microsoft.web/sites/app1",
             "name": "app1", "type": "microsoft.web/sites", "resourceGroup": "rg1", "tags": {"Environment": "Dev"}},
            {"id": "/subscriptions/s/resourceGroups/rg2/providers/microsoft.web/sites/app1",
             "name": "app1", "type": "microsoft.web/sites", "resourceGroup": "rg2", "tags": {"Environment": "Production"}},
        ]
        cls = classify(self.cfg, ev)
        for resource, expected in zip(ev["resources"], ("DEV", "PROD-PRIMARY")):
            self.assertEqual(overlay(self.cfg, cls, {"resource": resource}, "")["tier"], expected)

    def test_unknown_action_remains_validation(self):
        cls = classify(self.cfg, evidence(res_tags={"Environment": "Production"}))
        f = dict(finding(), evidence={"classification": "UNKNOWN"})
        self.assertTrue(overlay(self.cfg, cls, f, "rg1")["action"].startswith("Validate"))

    def test_accepted_action_is_preserved(self):
        cls = classify(self.cfg, evidence())
        f = dict(finding(), priority={"band": "Accepted"})
        self.assertTrue(overlay(self.cfg, cls, f, "rg1")["action"].startswith("Accepted risk"))

    def test_conflicting_tags_are_order_independent(self):
        a = self.res(evidence(res_tags={"Environment": "Dev", "Criticality": "Production"}))
        b = self.res(evidence(res_tags={"Criticality": "Production", "Environment": "Dev"}))
        self.assertEqual(a, b)
        self.assertEqual(a["tier"], "PROD-PRIMARY")

    def test_unrelated_subscription_tags_are_not_retained(self):
        cls = classify(self.cfg, evidence(sub_tags={"Secret": "omit", "Environment": "Dev"}))
        self.assertEqual(cls["subscription"]["tags"], {"Environment": "Dev"})


if __name__ == "__main__":
    unittest.main()
