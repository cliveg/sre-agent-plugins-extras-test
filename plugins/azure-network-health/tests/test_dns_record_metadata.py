from __future__ import annotations

import copy
import json
import unittest

import test_dns_planning as planning


nh = planning.nh
SUB, HOST, RUN, TIME = planning.SUB, planning.HOST, planning.RUN, planning.TIME


class MetadataFixtureReader(planning.PlanningFixtureReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.3.0")["operations"])
        zone = copy.deepcopy(self.resources["private-dns-zones"][0])
        zone["id"] = zone["id"].replace("/resourceGroups/fixture/", "/resourceGroups/other/")
        zone["properties"]["virtualNetworkLinkCount"] = 0
        self.resources["private-dns-zones"].append(zone)
        self.metadata = [
            {"type": "Microsoft.Network/privateDnsZones/A", "ttl": 10, "name": "secret-name", "aRecords": [{"ipv4Address": "secret-ip"}]},
            {"type": "Microsoft.Network/privateDnsZones/TXT", "ttl": 30, "txtRecords": ["secret-text"]},
            {"type": "Microsoft.Network/privateDnsZones/SOA", "ttl": 3600},
        ]
        self.declared_count = None
        self.metadata_failure = False

    def __call__(self, command):
        if nh.child_kind(command) != "private-dns-record-metadata":
            response = super().__call__(command)
            for row in response.payload.get("data", []):
                if "/resourceGroups/other/" in row.get("id", ""):
                    row["resourceGroup"] = "other"
            return response
        self.calls.append(command)
        if self.metadata_failure:
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        return nh.ReadResponse({
            "count": len(self.metadata) if self.declared_count is None else self.declared_count,
            "data": copy.deepcopy(self.metadata),
        })


class RecordMetadataTests(unittest.TestCase):
    def make(self, reader=None, hosts=None, progress=None, save_progress=None):
        reader = reader or MetadataFixtureReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size, lambda: TIME,
                              progress, save_progress, include_record_metadata=True, dns_subscriptions=hosts)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_mode_is_explicit_and_historical_modes_keep_their_catalogs(self):
        _, model, a, _ = self.make(hosts=[SUB])
        self.assertEqual(model["schemaVersion"], "0.4.0")
        self.assertEqual(len(model["collections"]), 16)
        self.assertEqual(a["checkCatalogVersion"], "1.5.0")
        self.assertEqual(len(a["checksExecuted"]), 11)
        self.assertEqual([len(nh.catalog(v)["operations"]) for v in ("1.0.0", "1.1.0", "1.2.0")], [9, 14, 15])

    def test_only_repeated_names_are_read_and_only_aggregates_are_retained(self):
        reader = MetadataFixtureReader()
        singleton = copy.deepcopy(reader.resources["private-dns-zones"][0])
        singleton.update({"id": singleton["id"].replace("privatelink.blob.core.windows.net", "unique.example.net"),
                          "name": "unique.example.net"})
        singleton["properties"]["virtualNetworkLinkCount"] = 0
        reader.resources["private-dns-zones"].append(singleton)
        envelope, model, a, reader = self.make(reader, [SUB])
        calls = [command for command in reader.calls if nh.child_kind(command) == "private-dns-record-metadata"]
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(command[command.index("--zone-name") + 1] == "privatelink.blob.core.windows.net" for command in calls))
        for document in (envelope, model, a):
            retained = json.dumps(document)
            self.assertNotIn("secret-name", retained)
            self.assertNotIn("secret-ip", retained)
            self.assertNotIn("secret-text", retained)
            self.assertNotIn("aRecords", retained)
        summaries = [e for e in model["entities"] if e["resourceType"] == "private-dns-record-metadata-summary"]
        self.assertEqual(len(summaries), 2)
        self.assertTrue(all(e["collectionState"] == "configurationObject" for e in summaries))
        props = summaries[0]["properties"]
        self.assertEqual((props["reportedRecordSetCount"], props["selectedRecordSetCount"]), (3, 3))
        self.assertEqual((props["aRecordSetCount"], props["txtRecordSetCount"], props["soaRecordSetCount"]), (1, 1, 1))
        self.assertEqual((props["minTtl"], props["maxTtl"]), (10, 3600))

    def test_no_repeated_zones_makes_no_record_metadata_calls(self):
        reader = MetadataFixtureReader()
        reader.resources["private-dns-zones"] = reader.resources["private-dns-zones"][:1]
        _, _, a, reader = self.make(reader)
        self.assertFalse(any(nh.child_kind(command) == "private-dns-record-metadata" for command in reader.calls))
        self.assertEqual(a["dnsPlanning"]["repeatedZoneNames"], [])
        self.assertFalse(any(f["checkId"] == "NET-DNS-META-001" for f in a["findings"]))

    def test_zero_selected_sets_has_explicit_parent_evidence_not_unused_claim(self):
        reader = MetadataFixtureReader()
        reader.metadata = []
        _, model, a, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        self.assertEqual(collection["retainedRowCount"], 2)
        self.assertEqual([page["itemCount"] for page in collection["pages"]], [1, 1])
        summaries = [e for e in model["entities"] if e["resourceType"] == "private-dns-record-metadata-summary"]
        self.assertTrue(all(e["properties"]["selectedRecordSetCount"] == 0 and e["properties"]["minTtl"] is None for e in summaries))
        findings = [f for f in a["findings"] if f["checkId"] == "NET-DNS-META-001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["recordType"], "contextValidation")
        self.assertIn("SOA-only", findings[0]["reasoning"])
        self.assertIsNone(findings[0]["severity"])

    def test_permission_failure_remains_not_collected_not_empty(self):
        reader = MetadataFixtureReader()
        reader.metadata_failure = True
        _, _, a, _ = self.make(reader)
        metadata = [zone["recordMetadata"] for zone in a["dnsPlanning"]["zones"]]
        self.assertTrue(all(item["status"] == "not-collected" and item["properties"] == {} for item in metadata))
        self.assertTrue(any(f["checkId"] == "NET-DNS-META-001" and f["recordType"] == "evidenceGap" for f in a["findings"]))
        self.assertFalse(any(f["checkId"] == "NET-DNS-META-001" and f["recordType"] == "contextValidation" for f in a["findings"]))

    def test_truncated_metadata_retains_observed_counts_and_explicit_gap(self):
        reader = MetadataFixtureReader()
        reader.declared_count = 2001
        _, model, a, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        self.assertEqual(collection["status"], "partial")
        self.assertIn("RecordSetSelectionIncomplete", collection["issues"])
        metadata = a["dnsPlanning"]["zones"][0]["recordMetadata"]
        self.assertEqual(metadata["status"], "partial")
        self.assertEqual(metadata["properties"]["reportedRecordSetCount"], 2001)
        self.assertEqual(metadata["properties"]["selectedRecordSetCount"], 3)

    def test_unknown_type_or_ttl_never_becomes_zero_or_success(self):
        reader = MetadataFixtureReader()
        reader.metadata = [{"type": None, "ttl": None}, {"type": "Microsoft.Network/privateDnsZones/Future", "ttl": True},
                           {"type": "Microsoft.Network/privateDnsZones/A", "ttl": -1}]
        _, _, a, _ = self.make(reader)
        props = a["dnsPlanning"]["zones"][0]["recordMetadata"]["properties"]
        self.assertEqual(props["unknownTypeCount"], 2)
        self.assertEqual(props["unknownTtlCount"], 3)
        self.assertIsNone(props["minTtl"])
        self.assertEqual(a["dnsPlanning"]["zones"][0]["recordMetadata"]["status"], "partial")

    def test_parent_discovery_partial_does_not_certify_no_repeated_names(self):
        reader = MetadataFixtureReader()
        reader.fail = "private-dns-zones"
        _, model, a, reader = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        self.assertIn("RepeatedZoneDiscoveryIncomplete", collection["issues"])
        self.assertEqual(collection["status"], "partial")
        self.assertFalse(any(nh.child_kind(command) == "private-dns-record-metadata" for command in reader.calls))
        self.assertTrue(any(f["checkId"] == "NET-DNS-META-001" and f["recordType"] == "evidenceGap" for f in a["findings"]))

    def test_invalid_summary_count_and_ttl_ranges_fail_validation(self):
        envelope, _, _, _ = self.make()
        collection = next(c for c in envelope["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        original = copy.deepcopy(collection["rows"][0]["properties"])
        for field, value in (("aRecordSetCount", 99), ("minTtl", 3601), ("unknownTtlCount", 4)):
            collection["rows"][0]["properties"] = {**original, field: value}
            with self.assertRaises(ValueError):
                nh.normalize(envelope)

    def test_success_cannot_hide_partial_selected_metadata_or_missing_parent(self):
        reader = MetadataFixtureReader()
        reader.declared_count = 2001
        envelope, _, _, _ = self.make(reader)
        collection = next(c for c in envelope["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        collection["status"] = "succeeded"
        with self.assertRaisesRegex(ValueError, "Successful record metadata"):
            nh.normalize(envelope)
        envelope, _, _, _ = self.make()
        collection = next(c for c in envelope["collections"] if c["operationId"] == "repeated-zone-record-metadata")
        collection["rows"].pop()
        collection["pages"].pop()
        collection["retainedRowCount"] = 1
        with self.assertRaisesRegex(ValueError, "Successful record metadata"):
            nh.normalize(envelope)

    def test_read_must_be_exact_parent_list_projection_not_show_or_values(self):
        op = next(op for op in nh.catalog("1.3.0")["operations"] if op["operationId"] == "repeated-zone-record-metadata")
        target = {"subscriptionId": SUB, "resourceGroup": "fixture", "name": "privatelink.blob.core.windows.net"}
        command = nh.command_for(op, SUB, 1, None, target)
        self.assertTrue(nh.matches_command(command, SUB, 1000))
        for changed in ([*command, "--top", "1"],
                        [value.replace("list", "delete") for value in command],
                        [value.replace(op["query"], "[].{name:name,records:aRecords}") for value in command]):
            self.assertFalse(nh.matches_command(changed, SUB, 1000))

    def test_metadata_planning_view_is_bound_to_assessment(self):
        _, model, a, _ = self.make()
        summary, engineering = nh.render(a)
        self.assertIn("Privacy-minimized repeated-zone record-set metadata", engineering)
        self.assertNotIn("secret-name", engineering)
        with self.assertRaisesRegex(ValueError, "DNS planning matrix"):
            nh.verify_reports(a, summary, engineering.replace("TTL range (seconds)", "Record contents"))
        altered = copy.deepcopy(a)
        altered["dnsPlanning"]["zones"][0]["recordMetadata"]["properties"] = dict(
            altered["dnsPlanning"]["zones"][0]["recordMetadata"]["properties"]
        )
        altered["dnsPlanning"]["zones"][0]["recordMetadata"]["properties"]["aRecordSetCount"] = 99
        with self.assertRaisesRegex(ValueError, "DNS planning comparison"):
            nh.verify_assessment(model, altered)

    def test_repeated_parent_across_explicit_hosts_is_scoped_and_preserves_zone_identity(self):
        _, model, a, reader = self.make(hosts=[HOST])
        collection_hosts = {c["requestedSubscriptionId"] for c in model["collections"] if c["operationId"] == "repeated-zone-record-metadata"}
        self.assertEqual(collection_hosts, {SUB, HOST})
        calls = [c for c in reader.calls if nh.child_kind(c) == "private-dns-record-metadata"]
        self.assertEqual(len(calls), 3)
        self.assertEqual({c[c.index("--subscription") + 1] for c in calls}, {SUB, HOST})
        self.assertTrue(all(z["recordMetadata"]["summaryEntityId"].startswith(z["zoneId"]) for z in a["dnsPlanning"]["zones"]))

    def test_selection_budget_and_unavailable_total_are_explicit(self):
        parent = {"id": f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Network/privateDnsZones/example.net",
                  "name": "example.net", "subscriptionId": SUB, "resourceGroup": "fixture"}
        op = next(op for op in nh.catalog("1.3.0")["operations"] if op["operationId"] == "repeated-zone-record-metadata")
        with self.assertRaisesRegex(ValueError, "selection budget"):
            nh.record_metadata_row({"data": [{}] * 2001, "count": 2001}, parent, op)
        row, issues = nh.record_metadata_row({"data": [], "count": None}, parent, op)
        self.assertIn("RecordSetTotalUnavailable", issues)
        self.assertIsNone(row["properties"]["reportedRecordSetCount"])
