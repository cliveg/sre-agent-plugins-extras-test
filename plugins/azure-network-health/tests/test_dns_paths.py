from __future__ import annotations

import copy
import json
import unittest

import test_dns_record_metadata as metadata


nh = metadata.nh
SUB, HOST, RUN, TIME = metadata.SUB, metadata.HOST, metadata.RUN, metadata.TIME


class DNSPathFixtureReader(metadata.MetadataFixtureReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.5.0")["operations"])
        base = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Network"
        vnet = base + "/virtualNetworks/alpha"
        resolver, ruleset = base + "/dnsResolvers/resolver", base + "/dnsForwardingRulesets/ruleset"
        self.path_resources = {
            "vnet-dns-settings": [
                {"id": vnet + "/observedDnsSettings/summary", "name": "summary", "parentId": vnet,
                 "properties": {"dnsServers": ["10.0.2.4"], "dnsServersKnown": True}},
            ],
            "dns-resolvers": [{"id": resolver, "name": "resolver",
                               "properties": {"virtualNetworkId": vnet, "provisioningState": "Succeeded"}}],
            "dns-rulesets": [{"id": ruleset, "name": "ruleset", "properties": {
                "outboundEndpointIds": [resolver + "/outboundEndpoints/outbound"], "provisioningState": "Succeeded"}}],
            "dns-inbound-endpoints": [{"id": resolver + "/inboundEndpoints/inbound", "name": "inbound", "properties": {
                "inboundSubnetIds": [vnet + "/subnets/dns-in"], "inboundIpAddresses": ["10.0.2.4"],
                "ipConfigurationCount": 1, "provisioningState": "Succeeded"}}],
            "dns-outbound-endpoints": [{"id": resolver + "/outboundEndpoints/outbound", "name": "outbound",
                                      "properties": {"subnetId": vnet + "/subnets/dns-out", "provisioningState": "Succeeded"}}],
            "dns-forwarding-rules": [{"id": ruleset + "/forwardingRules/onprem", "name": "onprem", "properties": {
                "domainName": "onprem.example.", "forwardingRuleState": "Enabled",
                "targetDnsServerIPs": ["10.10.0.1", "10.10.0.2"], "targetDnsServerPorts": [53, 5353],
                "targetDnsServersKnown": True, "provisioningState": "Succeeded", "secretMetadata": "omit-me"}}],
            "dns-ruleset-links": [{"id": ruleset + "/virtualNetworkLinks/alpha", "name": "alpha",
                                  "properties": {"virtualNetworkId": vnet, "provisioningState": "Succeeded"}}],
        }
        self.continuation = False

    def __call__(self, command):
        if command[:3] == ["az", "graph", "query"]:
            op = next(op for op in self.operations if op.get("query") == command[command.index("-q") + 1])
        elif command[:4] == ["az", "rest", "--method", "get"]:
            kind = nh.child_kind(command)
            query = command[command.index("--query") + 1]
            op = next(op for op in self.operations if op["kind"] == kind and op.get("query") == query)
        else:
            return super().__call__(command)
        if op["operationId"] not in nh.DNS_PATH_OPERATIONS:
            return super().__call__(command)
        self.calls.append(command)
        if self.fail == op["operationId"]:
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        rows = copy.deepcopy(self.path_resources[op["operationId"]])
        for row in rows:
            row.update({"type": op["entityType"], "subscriptionId": SUB, "resourceGroup": "fixture", "location": "eastus"})
            row.setdefault("parentId", "")
        return nh.ReadResponse({
            "data": rows, "count": len(rows), "total_records": len(rows),
            "hasContinuation": self.continuation, "skip_token": None,
            "nextLink": "https://unapproved.example/continuation" if self.continuation else None,
        })


class DNSPathTests(unittest.TestCase):
    def make(self, reader=None, hosts=None):
        reader = reader or DNSPathFixtureReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size, lambda: TIME,
                              include_dns_paths=True, dns_subscriptions=hosts)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_opt_in_preserves_older_catalogs_and_has_thirteen_checks(self):
        _, model, a, _ = self.make(hosts=[SUB])
        self.assertEqual(model["schemaVersion"], "0.6.0")
        self.assertEqual(model["run"]["queryCatalogVersion"], "1.5.0")
        self.assertEqual(len(model["collections"]), 23)
        self.assertEqual(len(a["checksExecuted"]), 13)
        self.assertEqual(a["checkCatalogVersion"], "1.7.0")
        self.assertEqual([len(nh.catalog(v)["operations"]) for v in ("1.0.0", "1.1.0", "1.2.0", "1.3.0")], [9, 14, 15, 16])

    def test_configured_references_are_not_dns_resolution_or_actual_client_use(self):
        _, model, a, _ = self.make()
        kinds = {rel["relationshipType"] for rel in model["relationships"]}
        self.assertTrue({"referencesResolverOutboundEndpoint", "resolverAttachedToVNet", "inboundAttachedToSubnet"} <= kinds)
        self.assertFalse({"dnsResolvesTo", "observedTrafficVia", "clientUsesResolver"} & kinds)
        self.assertNotIn("omit-me", json.dumps(model))
        self.assertNotIn("secretMetadata", json.dumps(a))
        self.assertEqual(len(a["dnsPaths"]["rows"]), 7)
        rows = {row["resourceType"]: row for row in a["dnsPaths"]["rows"]}
        rule = rows["microsoft.network/dnsforwardingrulesets/forwardingrules"]["properties"]
        self.assertEqual(rule["targetDnsServerIPs"], ["10.10.0.1", "10.10.0.2"])
        self.assertEqual(rule["targetDnsServerPorts"], [53, 5353])
        outbound = rows["microsoft.network/dnsresolvers/outboundendpoints"]["properties"]
        self.assertNotIn("privateIPAddress", outbound)
        vnet = next(e for e in model["entities"] if e["resourceType"] == "microsoft.network/virtualnetworks" and e["name"] == "alpha")
        self.assertIn("addressPrefixes", vnet["properties"])

    def test_scoped_zero_resolver_roots_do_not_imply_no_custom_dns(self):
        reader = DNSPathFixtureReader()
        reader.path_resources["dns-resolvers"] = []
        reader.path_resources["dns-rulesets"] = []
        _, model, a, reader = self.make(reader)
        self.assertFalse(any(nh.child_kind(command) in nh.DNS_ARM_CHILD_KINDS for command in reader.calls))
        path_findings = [f for f in a["findings"] if f["checkId"] == "NET-DNS-PATH-001"]
        self.assertTrue(any(f["recordType"] == "evidenceGap" for f in path_findings))
        self.assertFalse(any(f["recordType"] in ("verifiedProblem", "positiveObservation") for f in path_findings))
        self.assertTrue(all(f["severity"] is None for f in path_findings))

    def test_failed_parent_discovery_skips_child_reads_with_explicit_gap(self):
        reader = DNSPathFixtureReader()
        reader.fail = "dns-resolvers"
        _, model, a, reader = self.make(reader)
        children = [c for c in model["collections"] if c["operationId"] in ("dns-inbound-endpoints", "dns-outbound-endpoints")]
        self.assertTrue(all(c["status"] == "notAttempted" and "DnsParentDiscoveryIncomplete" in c["issues"] for c in children))
        self.assertTrue(any(f["title"] == "Collection or normalization coverage is partial" for f in a["findings"]))

    def test_arm_continuation_is_partial_and_not_followed(self):
        reader = DNSPathFixtureReader()
        reader.continuation = True
        _, model, a, _ = self.make(reader)
        collections = [c for c in model["collections"] if c["operationId"] in nh.DNS_PATH_OPERATIONS and c["operationId"] != "vnet-dns-settings"]
        self.assertTrue(all(c["status"] == "partial" and "DnsArmContinuationRejected" in c["issues"] for c in collections))
        self.assertEqual(a["status"], "incomplete-configuration-triage")

    def test_default_dns_and_unknown_fields_are_distinct(self):
        for known, servers in ((True, []), (False, None)):
            reader = DNSPathFixtureReader()
            reader.path_resources["vnet-dns-settings"][0]["properties"].update({"dnsServersKnown": known, "dnsServers": servers})
            _, _, a, _ = self.make(reader)
            settings = next(row for row in a["dnsPaths"]["rows"] if row["resourceType"] == "vnet-dns-settings")
            self.assertEqual(settings["properties"]["dnsServersKnown"], known)
            self.assertEqual(settings["properties"]["dnsServers"], servers)

    def test_null_target_ports_are_not_silently_defaulted_or_misaligned(self):
        reader = DNSPathFixtureReader()
        reader.path_resources["dns-forwarding-rules"][0]["properties"]["targetDnsServerPorts"] = [None, 5353]
        _, _, a, _ = self.make(reader)
        rule = next(row for row in a["dnsPaths"]["rows"] if row["resourceType"].endswith("/forwardingrules"))
        self.assertEqual(rule["properties"]["targetDnsServerPorts"], [None, 5353])
        self.assertTrue(any(f["title"] == "Selected DNS path configuration fields need authoritative context" for f in a["findings"]))
        reader.path_resources["dns-forwarding-rules"][0]["properties"]["targetDnsServerPorts"] = [53]
        _, model, _, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "dns-forwarding-rules")
        self.assertEqual(collection["status"], "partial")
        self.assertEqual(collection["retainedRowCount"], 0)

    def test_unavailable_target_array_is_unknown_not_observed_empty_targets(self):
        reader = DNSPathFixtureReader()
        reader.path_resources["dns-forwarding-rules"][0]["properties"].update({
            "targetDnsServersKnown": False, "targetDnsServerIPs": [], "targetDnsServerPorts": [],
        })
        _, model, a, _ = self.make(reader)
        targets = [assertion for assertion in model["assertions"] if assertion["property"] in ("targetDnsServerIPs", "targetDnsServerPorts")]
        self.assertTrue(all(assertion["classification"] == "UNKNOWN" for assertion in targets))
        self.assertTrue(any(f["title"] == "Selected DNS path configuration fields need authoritative context" for f in a["findings"]))

    def test_missing_inbound_configuration_arrays_do_not_prove_zero_configurations(self):
        reader = DNSPathFixtureReader()
        reader.path_resources["dns-inbound-endpoints"][0]["properties"].update({
            "inboundIpAddresses": None, "inboundSubnetIds": None, "ipConfigurationCount": 0,
        })
        _, model, a, _ = self.make(reader)
        counts = [assertion for assertion in model["assertions"] if assertion["property"] == "ipConfigurationCount"
                  and "/inboundendpoints/" in assertion["entityId"]]
        self.assertTrue(all(assertion["classification"] == "UNKNOWN" for assertion in counts))
        self.assertTrue(any(f["title"] == "Selected DNS path configuration fields need authoritative context" for f in a["findings"]))

    def test_rest_commands_reject_writes_wrong_origin_api_scope_and_extra_flags(self):
        _, _, _, reader = self.make()
        commands = [c for c in reader.calls if c[:2] == ["az", "rest"]]
        self.assertTrue(commands)
        for command in commands:
            self.assertTrue(nh.matches_command(command, SUB, 1000))
            for changed in ([*command, "--body", "{}"], [v.replace("get", "post") for v in command],
                            [v.replace("management.azure.com", "other.example") for v in command],
                            [v.replace("2022-07-01", "2099-01-01") for v in command]):
                self.assertFalse(nh.matches_command(changed, SUB, 1000))

    def test_additional_dns_hosts_do_not_collect_resolver_workloads_implicitly(self):
        envelope, _, _, reader = self.make(hosts=[HOST])
        self.assertFalse(any(c["operationId"] in nh.DNS_PATH_OPERATIONS and c["requestedSubscriptionId"] == HOST for c in envelope["collections"]))
        self.assertFalse(any(c[:2] == ["az", "rest"] and HOST in c for c in reader.calls))

    def test_dns_paths_json_and_markdown_are_bound_to_observations(self):
        _, model, a, _ = self.make()
        altered = copy.deepcopy(a)
        altered["dnsPaths"]["rows"] = []
        with self.assertRaisesRegex(ValueError, "DNS path view"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("onprem.example.", engineering)
        self.assertNotIn("onprem.example.", summary)
        with self.assertRaisesRegex(ValueError, "DNS path configuration"):
            nh.verify_reports(a, summary, engineering.replace("Configured DNS resolver and forwarding context", "Removed DNS context"))
