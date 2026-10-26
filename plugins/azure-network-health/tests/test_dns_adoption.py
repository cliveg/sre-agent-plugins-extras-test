from __future__ import annotations

import copy
import unittest

import test_dns_paths as paths


nh = paths.nh
SUB, RUN, TIME = paths.SUB, paths.RUN, paths.TIME


class ResolverAdoptionTests(unittest.TestCase):
    def reader(self):
        reader = paths.DNSPathFixtureReader()
        beta = next(row for row in reader.resources["vnets"] if row["name"] == "beta")
        reader.path_resources["vnet-dns-settings"].append({
            "id": beta["id"] + "/observedDnsSettings/summary", "name": "summary", "parentId": beta["id"],
            "properties": {"dnsServersKnown": True, "dnsServers": []},
        })
        return reader

    def make(self, reader=None):
        reader = reader or self.reader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1000, lambda: TIME, include_dns_paths=True)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def findings(self, assessment):
        return [finding for finding in assessment["findings"] if finding["checkId"] == "NET-DNS-ADOPT-001"]

    def test_partial_transition_has_consumer_matrix_and_context_not_defect(self):
        _, model, a, _ = self.make()
        view = a["dnsResolverAdoption"]
        self.assertEqual(len(view["consumers"]), 2)
        self.assertEqual(view["migrationIntent"], "UNKNOWN")
        self.assertEqual(view["actualClientUse"], "UNKNOWN")
        alpha = next(row for row in view["consumers"] if row["vnetId"].endswith("/alpha"))
        beta = next(row for row in view["consumers"] if row["vnetId"].endswith("/beta"))
        self.assertEqual(alpha["dnsMode"], "custom-configured")
        self.assertEqual(beta["dnsMode"], "azure-provided-configured")
        self.assertEqual(len(alpha["inboundEndpointCandidates"]), 1)
        self.assertEqual(len(alpha["rulesetsWithSucceededLinks"]), 1)
        self.assertEqual(beta["observedRulesetLinkIds"], [])
        findings = self.findings(a)
        self.assertTrue(any(f["title"] == "Resolver deployment has mixed configured consumer cohorts" for f in findings))
        mixed = next(f for f in findings if f["title"] == "Resolver deployment has mixed configured consumer cohorts")
        self.assertTrue({ref for row in view["consumers"] for ref in row["evidenceRefs"]} <= set(mixed["evidenceRefs"]))
        self.assertTrue(all(f["severity"] is None and f["recordType"] in ("contextValidation", "evidenceGap") for f in findings))
        self.assertFalse(any("clientUsesResolver" == r["relationshipType"] for r in model["relationships"]))

    def test_same_dns_mode_with_uneven_links_is_review_signal_not_required_links(self):
        reader = self.reader()
        reader.path_resources["vnet-dns-settings"][0]["properties"]["dnsServers"] = []
        _, _, a, _ = self.make(reader)
        finding = next(f for f in self.findings(a) if f["title"] == "Resolver deployment has mixed configured consumer cohorts")
        self.assertIn("without requiring every VNet", finding["recommendation"])
        self.assertIsNone(finding["severity"])

    def test_successful_empty_ruleset_link_list_invites_migration_context(self):
        reader = self.reader()
        reader.path_resources["dns-ruleset-links"] = []
        _, _, a, _ = self.make(reader)
        finding = next(f for f in self.findings(a) if f["title"] == "Ruleset association or enabled-rule configuration needs migration context")
        self.assertIn("No VNet link was observed", finding["observedState"])
        self.assertEqual(finding["recordType"], "contextValidation")
        self.assertIn("staged", finding["reasoning"])

    def test_inbound_only_design_does_not_require_outbound_or_ruleset_links(self):
        reader = self.reader()
        reader.path_resources["dns-rulesets"] = []
        reader.path_resources["dns-outbound-endpoints"] = []
        reader.path_resources["vnet-dns-settings"][1]["properties"]["dnsServers"] = ["10.0.2.4"]
        _, _, a, _ = self.make(reader)
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"], [])
        self.assertTrue(all(len(row["inboundEndpointCandidates"]) == 1 for row in a["dnsResolverAdoption"]["consumers"]))
        self.assertFalse(any(f["title"] == "Ruleset association or enabled-rule configuration needs migration context" for f in self.findings(a)))
        self.assertFalse(any(f["recordType"] == "verifiedProblem" for f in self.findings(a)))

    def test_disabled_rules_invite_context_but_future_states_remain_unknown(self):
        for state in ("Disabled", "Future", None):
            reader = self.reader()
            reader.path_resources["dns-forwarding-rules"][0]["properties"]["forwardingRuleState"] = state
            _, _, a, _ = self.make(reader)
            findings = self.findings(a)
            if state == "Disabled":
                self.assertTrue(any("No enabled forwarding rule" in f["observedState"] for f in findings))
            else:
                self.assertFalse(any("No enabled forwarding rule" in f["observedState"] for f in findings))
                self.assertTrue(any(f["recordType"] == "evidenceGap" for f in findings))

    def test_failed_link_collection_is_unknown_not_unlinked(self):
        reader = self.reader()
        reader.fail = "dns-ruleset-links"
        _, _, a, _ = self.make(reader)
        self.assertTrue(all(row["linkCoverage"] == "UNKNOWN" for row in a["dnsResolverAdoption"]["consumers"]))
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"][0]["linkCoverage"], "UNKNOWN")
        self.assertFalse(any("No VNet link was observed" in f["observedState"] for f in self.findings(a)))
        self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))

    def test_partial_continuation_does_not_infer_absent_links_or_enabled_rules(self):
        reader = self.reader()
        reader.continuation = True
        _, _, a, _ = self.make(reader)
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"][0]["ruleCoverage"], "UNKNOWN")
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"][0]["linkCoverage"], "UNKNOWN")
        self.assertFalse(any("No VNet link was observed" in f["observedState"] or "No enabled forwarding rule" in f["observedState"] for f in self.findings(a)))

    def test_missing_successful_parent_page_is_not_absence_evidence(self):
        _, model, _, _ = self.make()
        collection = next(c for c in model["collections"] if c["operationId"] == "dns-ruleset-links")
        collection["pages"] = []
        view = nh.resolver_adoption(model)
        self.assertEqual(view["rulesets"][0]["linkCoverage"], "UNKNOWN")
        self.assertTrue(all(row["linkCoverage"] == "UNKNOWN" for row in view["consumers"]))

    def test_missing_ruleset_root_page_does_not_certify_consumer_link_completeness(self):
        _, model, _, _ = self.make()
        next(c for c in model["collections"] if c["operationId"] == "dns-rulesets")["pages"] = []
        view = nh.resolver_adoption(model)
        self.assertTrue(all(row["linkCoverage"] == "UNKNOWN" for row in view["consumers"]))

    def test_link_with_unknown_target_is_not_a_ruleset_with_no_links(self):
        reader = self.reader()
        reader.path_resources["dns-ruleset-links"][0]["properties"]["virtualNetworkId"] = None
        _, _, a, _ = self.make(reader)
        row = a["dnsResolverAdoption"]["rulesets"][0]
        self.assertEqual(len(row["observedLinkIds"]), 1)
        self.assertEqual(len(row["unknownLinkTargetIds"]), 1)
        self.assertTrue(all(consumer["linkCoverage"] == "UNKNOWN" for consumer in a["dnsResolverAdoption"]["consumers"]))
        self.assertFalse(any("No VNet link was observed" in f["observedState"] for f in self.findings(a)))
        self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))

    def test_unready_link_is_not_succeeded_adoption_or_proof_missing_link(self):
        reader = self.reader()
        reader.path_resources["dns-ruleset-links"][0]["properties"]["provisioningState"] = "Updating"
        _, _, a, _ = self.make(reader)
        alpha = next(row for row in a["dnsResolverAdoption"]["consumers"] if row["vnetId"].endswith("/alpha"))
        self.assertEqual(alpha["rulesetsWithSucceededLinks"], [])
        self.assertEqual(len(alpha["unreadyLinkIds"]), 1)
        self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))

    def test_external_consumer_stays_reference_only_without_scope_expansion(self):
        reader = self.reader()
        external = "/subscriptions/00000000-0000-4000-8000-000000000099/resourceGroups/shared/providers/Microsoft.Network/virtualNetworks/consumer"
        reader.path_resources["dns-ruleset-links"][0]["properties"]["virtualNetworkId"] = external
        _, model, a, reader = self.make(reader)
        self.assertIn(external.lower(), a["dnsResolverAdoption"]["rulesets"][0]["observedVnetIds"])
        self.assertNotIn(external.lower(), [row["vnetId"] for row in a["dnsResolverAdoption"]["consumers"]])
        entity = next(e for e in model["entities"] if e["entityId"] == external.lower())
        self.assertEqual(entity["collectionState"], "referenceOnly")
        self.assertFalse(any("00000000-0000-4000-8000-000000000099" in command for command in reader.calls))

    def test_ambiguous_inbound_ip_matches_are_candidates_not_client_use(self):
        reader = self.reader()
        endpoint = copy.deepcopy(reader.path_resources["dns-inbound-endpoints"][0])
        endpoint["id"] = endpoint["id"].replace("/inboundEndpoints/inbound", "/inboundEndpoints/other")
        endpoint["name"] = "other"
        reader.path_resources["dns-inbound-endpoints"].append(endpoint)
        _, _, a, _ = self.make(reader)
        alpha = next(row for row in a["dnsResolverAdoption"]["consumers"] if row["vnetId"].endswith("/alpha"))
        self.assertEqual(len(alpha["inboundEndpointCandidates"]), 2)
        self.assertEqual(a["dnsResolverAdoption"]["actualClientUse"], "UNKNOWN")

    def test_unobserved_or_unready_outbound_reference_is_gap_not_working_forwarding(self):
        for state in (None, "Updating", "Failed", "Future"):
            reader = self.reader()
            if state is None:
                reader.path_resources["dns-outbound-endpoints"] = []
            else:
                reader.path_resources["dns-outbound-endpoints"][0]["properties"]["provisioningState"] = state
            _, _, a, _ = self.make(reader)
            self.assertEqual(len(a["dnsResolverAdoption"]["rulesets"][0]["unverifiedOutboundEndpointIds"]), 1)
            self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))
            self.assertFalse(any(f["recordType"] == "verifiedProblem" for f in self.findings(a)))

    def test_unavailable_or_invalid_outbound_references_are_explicit_not_empty_success(self):
        for refs in (None, [""], ["not-an-ARM-id"]):
            reader = self.reader()
            reader.path_resources["dns-rulesets"][0]["properties"]["outboundEndpointIds"] = refs
            _, _, a, _ = self.make(reader)
            row = a["dnsResolverAdoption"]["rulesets"][0]
            self.assertFalse(row["outboundReferencesKnown"])
            self.assertEqual(row["unknownOutboundReferenceCount"], 0 if refs is None else 1)
            self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))

    def test_unknown_or_invalid_dns_settings_do_not_enter_known_cohorts(self):
        for servers, known in ((None, False), (["not-an-IP"], True)):
            reader = self.reader()
            reader.path_resources["vnet-dns-settings"][0]["properties"].update({"dnsServers": servers, "dnsServersKnown": known})
            _, _, a, _ = self.make(reader)
            alpha = next(row for row in a["dnsResolverAdoption"]["consumers"] if row["vnetId"].endswith("/alpha"))
            self.assertEqual(alpha["dnsMode"], "UNKNOWN")
            self.assertTrue(any(f["recordType"] == "evidenceGap" for f in self.findings(a)))

    def test_no_deployment_does_not_invent_partial_migration_findings(self):
        reader = self.reader()
        reader.path_resources["dns-resolvers"] = []
        reader.path_resources["dns-rulesets"] = []
        _, _, a, _ = self.make(reader)
        self.assertEqual(a["dnsResolverAdoption"]["resolverIds"], [])
        self.assertEqual(self.findings(a), [])
        self.assertEqual(a["dnsResolverAdoption"]["migrationIntent"], "UNKNOWN")

    def test_assessment_and_markdown_adoption_matrix_are_verified(self):
        _, model, a, _ = self.make()
        altered = copy.deepcopy(a)
        altered["dnsResolverAdoption"]["consumers"] = []
        with self.assertRaisesRegex(ValueError, "Resolver adoption view"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("Resolver adoption and partial-transition review", engineering)
        with self.assertRaisesRegex(ValueError, "resolver adoption matrix"):
            nh.verify_reports(a, summary, engineering.replace("**Migration intent:** UNKNOWN", "**Migration intent:** completed"))
