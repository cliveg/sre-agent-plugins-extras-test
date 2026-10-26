from __future__ import annotations

import copy
import json
import unittest

import test_network_health as fixtures


nh = fixtures.nh
SUB, RUN, TIME = fixtures.SUB, fixtures.RUN, fixtures.TIME
HOST = "00000000-0000-4000-8000-000000000099"


class PlanningFixtureReader(fixtures.PrivateFixtureReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.2.0")["operations"])
        self.resources["private-link-services"] = [
            {"id": f"/subscriptions/{SUB}/resourceGroups/workload/providers/Microsoft.Storage/storageAccounts/storage",
             "name": "storage", "type": "microsoft.storage/storageaccounts", "properties": {"secret": "omit"}},
            {"id": f"/subscriptions/{SUB}/resourceGroups/workload/providers/Microsoft.KeyVault/vaults/no-endpoint",
             "name": "no-endpoint", "type": "microsoft.keyvault/vaults", "properties": {"secret": "omit"}},
        ]
        self.central = {
            key: json.loads(json.dumps(self.resources[key]).replace(SUB, HOST))
            for key in ("private-dns-zones", "private-dns-links")
        }
        self.failed_host = None

    def __call__(self, command):
        if command[:3] != ["az", "graph", "query"]:
            return super().__call__(command)
        subscription = command[command.index("--subscriptions") + 1]
        operation = next(op for op in self.operations if op.get("query") == command[command.index("-q") + 1])
        op_id = operation["operationId"]
        if subscription == SUB and op_id != "private-link-services":
            return super().__call__(command)
        self.calls.append(command)
        if subscription == self.failed_host or self.fail == op_id:
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        source = self.resources[op_id] if subscription == SUB else self.central[op_id]
        offset = int(command[command.index("--skip-token") + 1]) if "--skip-token" in command else 0
        rows = [
            {**row, "type": row.get("type", operation["entityType"]), "subscriptionId": subscription,
             "resourceGroup": "fixture", "location": "eastus", "parentId": row.get("parentId", "")}
            for row in source[offset:offset + self.page_size]
        ]
        next_offset = offset + len(rows)
        return nh.ReadResponse({
            "data": rows, "count": len(rows), "total_records": len(source),
            "skip_token": str(next_offset) if next_offset < len(source) else None,
        })


class DNSPlanningTests(unittest.TestCase):
    def make(self, reader=None, hosts=None):
        reader = reader or PlanningFixtureReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size, lambda: TIME,
                              include_dns_planning=True, dns_subscriptions=hosts)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_opt_in_preserves_default_and_private_modes(self):
        _, model, assessment, _ = self.make(hosts=[SUB])
        self.assertEqual(model["schemaVersion"], "0.3.0")
        self.assertEqual(model["run"]["queryCatalogVersion"], "1.2.0")
        self.assertEqual(len(model["collections"]), 15)
        self.assertEqual(len(assessment["checksExecuted"]), 10)
        self.assertEqual(assessment["checkCatalogVersion"], "1.4.0")
        self.assertEqual(len(nh.catalog()["operations"]), 9)
        self.assertEqual(len(nh.catalog("1.1.0")["operations"]), 14)

    def test_mapping_compares_services_connections_and_zones_separately(self):
        _, _, a, _ = self.make(hosts=[SUB])
        rows = a["dnsPlanning"]["serviceRows"]
        blob = next(row for row in rows if row["resourceType"] == "microsoft.storage/storageaccounts" and "blob" in row["subresources"])
        vault = next(row for row in rows if row["resourceType"] == "microsoft.keyvault/vaults")
        self.assertEqual(len(blob["serviceIds"]), 1)
        self.assertEqual(len(blob["connectionIds"]), 1)
        self.assertEqual(blob["serviceIdsWithoutObservedConnection"], [])
        self.assertEqual(blob["zoneMatches"][0]["status"], "observed-name")
        self.assertEqual(len(vault["serviceIdsWithoutObservedConnection"]), 1)
        self.assertEqual(vault["zoneMatches"][0]["status"], "not-observed-in-accessible-scopes")
        self.assertFalse(any(f["recordType"] == "verifiedProblem" and f["checkId"].startswith("NET-DNS") for f in a["findings"]))

    def test_undeclared_central_dns_never_becomes_absent(self):
        _, _, a, _ = self.make()
        plan = a["dnsPlanning"]
        self.assertEqual(plan["dnsHostingScopeStatus"], "not-declared")
        self.assertTrue(any(f["title"] == "Central DNS hosting coverage remains unverified" for f in a["findings"]))
        vault = next(row for row in plan["serviceRows"] if row["resourceType"] == "microsoft.keyvault/vaults")
        self.assertEqual(vault["zoneMatches"][0]["status"], "unknown-coverage")

    def test_zone_presence_does_not_mean_service_has_an_endpoint(self):
        reader = PlanningFixtureReader()
        base = f"/subscriptions/{SUB}/resourceGroups/dns/providers/Microsoft.Network"
        reader.resources["private-dns-zones"].append({
            "id": base + "/privateDnsZones/privatelink.vaultcore.azure.net",
            "name": "privatelink.vaultcore.azure.net",
            "properties": {"provisioningState": "Succeeded", "virtualNetworkLinkCount": 0},
        })
        _, _, a, _ = self.make(reader, [SUB])
        vault = next(row for row in a["dnsPlanning"]["serviceRows"] if row["resourceType"] == "microsoft.keyvault/vaults")
        self.assertEqual(vault["zoneMatches"][0]["status"], "observed-name")
        self.assertEqual(vault["connectionIds"], [])
        self.assertEqual(len(vault["serviceIdsWithoutObservedConnection"]), 1)

    def test_same_name_zones_in_distinct_resource_groups_are_review_candidates(self):
        reader = PlanningFixtureReader()
        zone = copy.deepcopy(reader.resources["private-dns-zones"][0])
        zone["id"] = zone["id"].replace("/resourceGroups/fixture/", "/resourceGroups/other/")
        zone["properties"]["virtualNetworkLinkCount"] = 0
        reader.resources["private-dns-zones"].append(zone)
        _, _, a, _ = self.make(reader, [SUB])
        self.assertEqual(len(a["dnsPlanning"]["repeatedZoneNames"]), 1)
        self.assertEqual(len(a["dnsPlanning"]["repeatedZoneNames"][0]["zoneIds"]), 2)

    def test_failed_connection_inventory_is_explicit_not_no_endpoint_certification(self):
        reader = PlanningFixtureReader()
        reader.fail = "private-endpoint-connections"
        _, _, a, _ = self.make(reader, [SUB])
        self.assertEqual(a["dnsPlanning"]["connectionInventoryStatus"], "permissionDenied")
        self.assertTrue(any(f["recordType"] == "evidenceGap" and f["checkId"] == "NET-PRIVATE-001" for f in a["findings"]))

    def test_extra_dns_host_scope_cannot_be_injected_into_observation(self):
        _, model, _, _ = self.make(hosts=[HOST])
        model["scope"]["dnsHostingSubscriptionIds"] = [SUB]
        with self.assertRaisesRegex(ValueError, "Observation collection scope"):
            nh.verify_observation(model)

    def test_approved_host_cannot_replace_workload_collection_or_evidence_scope(self):
        _, model, _, _ = self.make(hosts=[HOST])
        collection = next(c for c in model["collections"] if c["operationId"] == "private-link-services")
        collection["returnedSubscriptionIds"] = [HOST]
        with self.assertRaisesRegex(ValueError, "Collection returned scope"):
            nh.verify_observation(model)
        collection["returnedSubscriptionIds"] = [SUB]
        evidence = next(e for e in model["evidence"] if e["collectionId"] == collection["collectionId"])
        evidence["excerpt"]["subscriptionId"] = HOST
        evidence["sha256"] = nh.digest(evidence["excerpt"])
        with self.assertRaisesRegex(ValueError, "Evidence scope"):
            nh.verify_observation(model)

    def test_central_zone_found_without_collecting_central_workloads(self):
        reader = PlanningFixtureReader()
        reader.resources["private-dns-zones"] = []
        reader.resources["private-dns-links"] = []
        reader.resources["private-dns-groups"][0]["properties"]["privateDnsZoneIds"][0] = reader.central["private-dns-zones"][0]["id"]
        envelope, model, a, reader = self.make(reader, [HOST])
        central = [c for c in envelope["collections"] if c["requestedSubscriptionId"] == HOST]
        self.assertEqual({c["operationId"] for c in central}, {"private-dns-zones", "private-dns-links"})
        self.assertEqual(len(central), 2)
        self.assertEqual(model["scope"]["requestedSubscriptionIds"], [SUB])
        self.assertEqual(model["scope"]["dnsHostingSubscriptionIds"], [HOST])
        self.assertEqual(a["dnsPlanning"]["zones"][0]["subscriptionId"], HOST)
        blob = next(row for row in a["dnsPlanning"]["serviceRows"] if "blob" in row["subresources"])
        self.assertEqual(blob["zoneMatches"][0]["status"], "observed-name")
        self.assertEqual(len(a["dnsPlanning"]["zones"][0]["zoneGroupIds"]), 1)

    def test_failed_central_scope_is_unknown_but_retains_local_evidence(self):
        reader = PlanningFixtureReader()
        reader.failed_host = HOST
        _, _, a, _ = self.make(reader, [HOST])
        self.assertEqual(a["dnsPlanning"]["dnsHostingScopeStatus"], "declared-partial")
        self.assertEqual(len(a["dnsPlanning"]["zones"]), 1)
        vault = next(row for row in a["dnsPlanning"]["serviceRows"] if row["resourceType"] == "microsoft.keyvault/vaults")
        self.assertEqual(vault["zoneMatches"][0]["status"], "unknown-coverage")

    def test_repeated_names_across_scopes_are_contextual_cleanup_review(self):
        _, _, a, _ = self.make(hosts=[HOST, SUB])
        repeats = a["dnsPlanning"]["repeatedZoneNames"]
        self.assertEqual(len(repeats), 1)
        self.assertEqual(len(repeats[0]["zoneIds"]), 2)
        finding = next(f for f in a["findings"] if f["checkId"] == "NET-DNS-REPEAT-001")
        self.assertEqual(finding["recordType"], "contextValidation")
        self.assertIsNone(finding["severity"])
        self.assertEqual(finding["priority"]["band"], "P2")
        self.assertIn("before planning consolidation", finding["recommendation"])

    def test_repeated_names_normalize_case_and_trailing_dot_not_resource_identity(self):
        reader = PlanningFixtureReader()
        reader.central["private-dns-zones"][0]["name"] = "PRIVATELINK.BLOB.CORE.WINDOWS.NET."
        _, _, a, _ = self.make(reader, [HOST])
        self.assertEqual(a["dnsPlanning"]["repeatedZoneNames"][0]["name"], "privatelink.blob.core.windows.net")
        self.assertEqual(len(a["dnsPlanning"]["zones"]), 2)

    def test_sku_api_and_record_name_exceptions_are_not_required_zones(self):
        mapping = nh.load(nh.HERE / "private-dns-services.json")
        self.assertEqual(len(mapping["services"]), 91)
        self.assertEqual(len({row["resourceType"] for row in mapping["services"]}), 71)
        acr = next(row for row in mapping["services"] if row["resourceType"] == "microsoft.containerregistry/registries")
        web = next(row for row in mapping["services"] if row["resourceType"] == "microsoft.web/sites")
        self.assertEqual(acr["zones"], ["privatelink.azurecr.io"])
        self.assertEqual(web["zones"], ["privatelink.azurewebsites.net"])
        self.assertTrue(all(row.get("note") for row in mapping["services"] if row["resourceType"] == "microsoft.cache/redisenterprise"))

    def test_region_templates_remain_candidates_not_service_specific_proof(self):
        _, _, a, _ = self.make(hosts=[SUB])
        row = next(row for row in a["dnsPlanning"]["serviceRows"] if row["resourceType"] == "microsoft.sql/managedinstances")
        self.assertEqual(row["zoneMatches"][0]["status"], "template-candidates-require-context")
        self.assertEqual(row["zoneMatches"][0]["zoneValue"], "privatelink.{dnsPrefix}.database.windows.net")

    def test_service_metadata_omits_properties_and_unapproved_types(self):
        reader = PlanningFixtureReader()
        reader.resources["private-link-services"].append({
            "id": f"/subscriptions/{SUB}/resourceGroups/x/providers/Microsoft.Compute/virtualMachines/vm",
            "name": "vm", "type": "microsoft.compute/virtualmachines", "properties": {},
        })
        _, model, a, _ = self.make(reader, [SUB])
        self.assertNotIn('"secret"', json.dumps(model))
        collection = next(c for c in model["collections"] if c["operationId"] == "private-link-services")
        self.assertEqual(collection["status"], "partial")
        self.assertEqual(collection["retainedRowCount"], 2)
        self.assertNotIn("vm", [e["name"] for e in model["entities"] if e["collectionState"] == "collected"])

    def test_explicit_scope_mismatch_and_unrequested_extra_collections_fail(self):
        envelope, _, _, _ = self.make(hosts=[HOST])
        envelope["dnsHostingSubscriptionIds"] = [SUB]
        with self.assertRaisesRegex(ValueError, "explicit collection outcome"):
            nh.normalize(envelope)
        for values in ([], [SUB, SUB], [SUB] * 21):
            with self.assertRaises(ValueError):
                nh.dns_scopes(values)

    def test_assessment_matrix_and_markdown_tampering_are_rejected(self):
        _, model, a, _ = self.make(hosts=[SUB])
        altered = copy.deepcopy(a)
        altered["dnsPlanning"]["zones"] = []
        with self.assertRaisesRegex(ValueError, "DNS planning comparison"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("Private DNS service planning", engineering)
        with self.assertRaisesRegex(ValueError, "DNS planning matrix"):
            nh.verify_reports(a, summary, engineering.replace("### Repeated zone names", "### Removed zone review"))

    def test_failed_service_inventory_does_not_certify_no_service(self):
        reader = PlanningFixtureReader()
        reader.fail = "private-link-services"
        _, _, a, _ = self.make(reader, [SUB])
        self.assertEqual(a["status"], "incomplete-configuration-triage")
        self.assertTrue(any(f["title"] == "Collection or normalization coverage is partial" for f in a["findings"]))
        self.assertTrue(all(row["applicability"].startswith("planning-only") for row in a["dnsPlanning"]["serviceRows"]))

    def test_dns_host_allowlist_cannot_be_used_without_planning_mode(self):
        with self.assertRaisesRegex(ValueError, "require DNS planning"):
            nh.collect(SUB, RUN, PlanningFixtureReader(), dns_subscriptions=[HOST])
