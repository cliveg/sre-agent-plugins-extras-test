from __future__ import annotations

import copy
import unittest
from urllib.parse import parse_qsl, urlsplit
from unittest.mock import patch

import test_dns_paths as paths


nh = paths.nh
SUB, RUN, TIME = paths.SUB, paths.RUN, paths.TIME


class PagedDNSReader(paths.DNSPathFixtureReader):
    def __init__(self):
        super().__init__()
        self.requests = []
        self.next_override = None
        self.fail_on_page = None
        self.empty_first = False
        self.second_resolver = self.path_resources["dns-resolvers"][0]["id"] + "-two"
        original = self.path_resources["dns-resolvers"][0]
        self.path_resources["dns-resolvers"].append({**copy.deepcopy(original), "id": self.second_resolver, "name": "resolver-two"})
        inbound = copy.deepcopy(self.path_resources["dns-inbound-endpoints"][0])
        extra = {**copy.deepcopy(inbound), "id": inbound["id"] + "-two", "name": "inbound-two"}
        second_parent = {**copy.deepcopy(inbound), "id": self.second_resolver + "/inboundEndpoints/second", "name": "second"}
        self.path_resources["dns-inbound-endpoints"] = [inbound, extra, second_parent]

    def __call__(self, command):
        if command[:4] != ["az", "rest", "--method", "get"]:
            return super().__call__(command)
        self.calls.append(command)
        url = command[command.index("--url") + 1]
        parsed = urlsplit(url)
        query = dict(parse_qsl(parsed.query))
        page = int(query.get("$skipToken", "0"))
        op = next(op for op in self.operations if op["kind"] == nh.child_kind(command)
                  and op.get("query") == command[command.index("--query") + 1])
        self.requests.append((op["operationId"], parsed.path, page))
        if self.fail_on_page == (op["operationId"], page):
            raise nh.ReadFailure("PermissionDenied", "permissionDenied")
        rows = copy.deepcopy(self.path_resources[op["operationId"]])
        if op["kind"] in nh.DNS_ARM_CHILD_KINDS:
            rows = [row for row in rows if row["id"].rsplit("/", 1)[0].lower() == parsed.path.lower()]
        if self.empty_first and op["operationId"] == "dns-resolvers":
            selected = [] if page == 0 else rows
            next_page = 1 if page == 0 else None
        else:
            selected = rows[page:page + 1]
            next_page = page + 1 if page + 1 < len(rows) else None
        for row in selected:
            row.update({"type": op["entityType"], "location": "eastus"})
            row.pop("parentId", None)
        next_link = "https://management.azure.com" + parsed.path + "?api-version=2022-07-01&$skipToken=" + str(next_page) if next_page is not None else None
        if self.next_override is not None and op["operationId"] == "dns-resolvers":
            next_link = self.next_override(url, page)
        return nh.ReadResponse({"count": len(selected), "data": selected, "nextLink": next_link})


class ArmPaginationTests(unittest.TestCase):
    def make(self, reader=None):
        reader = reader or PagedDNSReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_root_and_child_pages_keep_parent_iteration_separate(self):
        _, model, a, reader = self.make()
        root = next(c for c in model["collections"] if c["operationId"] == "dns-resolvers")
        child = next(c for c in model["collections"] if c["operationId"] == "dns-inbound-endpoints")
        self.assertEqual(root["retainedRowCount"], 2)
        self.assertEqual(len(root["pages"]), 2)
        self.assertEqual(child["retainedRowCount"], 3)
        self.assertEqual(len(child["pages"]), 3)
        self.assertEqual(child["pages"][0]["parentResourceId"], child["pages"][1]["parentResourceId"])
        self.assertNotEqual(child["pages"][1]["parentResourceId"], child["pages"][2]["parentResourceId"])
        self.assertTrue(child["pages"][0]["armHasContinuation"])
        self.assertFalse(child["pages"][1]["armHasContinuation"])
        self.assertTrue(all(c["status"] == "succeeded" for c in model["collections"]))
        self.assertTrue(all(nh.matches_command(command, SUB, 1000) for command in reader.calls))
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"][0]["linkCoverage"], "accessible-parent-list-collected")

    def test_complete_ruleset_child_paging_supports_adoption_not_unknown(self):
        reader = PagedDNSReader()
        link = copy.deepcopy(reader.path_resources["dns-ruleset-links"][0])
        link["id"] += "-second"
        link["name"] = "second"
        reader.path_resources["dns-ruleset-links"].append(link)
        _, model, a, _ = self.make(reader)
        links = next(c for c in model["collections"] if c["operationId"] == "dns-ruleset-links")
        self.assertEqual(len(links["pages"]), 2)
        self.assertEqual(a["dnsResolverAdoption"]["rulesets"][0]["linkCoverage"], "accessible-parent-list-collected")

    def test_empty_intermediate_arm_page_is_allowed_with_safe_continuation(self):
        reader = PagedDNSReader()
        reader.empty_first = True
        _, model, _, _ = self.make(reader)
        root = next(c for c in model["collections"] if c["operationId"] == "dns-resolvers")
        self.assertEqual(root["status"], "succeeded")
        self.assertEqual([p["itemCount"] for p in root["pages"]], [0, 2])

    def test_malicious_urls_are_never_dispatched_and_retained_evidence_is_partial(self):
        base = "https://management.azure.com/subscriptions/" + SUB + "/providers/microsoft.network/dnsresolvers"
        valid = base + "?api-version=2022-07-01&$skipToken=next"
        bad_urls = [
            valid.replace("management.azure.com", "other.example"),
            valid.replace("https:", "http:"),
            valid.replace(SUB, paths.HOST),
            valid.replace("dnsresolvers", "dnsforwardingrulesets"),
            valid.replace("2022-07-01", "2025-05-01"),
            valid + "&sig=credential", valid + "&api-version=2022-07-01", valid + "#fragment",
            valid.replace("management.azure.com", "user:password@management.azure.com"),
            valid.replace("/providers/", "/%70roviders/"), valid + "%", valid.replace("=next", "=%0Avalue"),
            base + "?api-version=2022-07-01", valid.replace("management.azure.com", "management.azure.com:443"),
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                reader = PagedDNSReader()
                reader.next_override = lambda requested, page: url
                _, model, _, reader = self.make(reader)
                root = next(c for c in model["collections"] if c["operationId"] == "dns-resolvers")
                self.assertEqual(root["status"], "partial")
                self.assertEqual(root["retainedRowCount"], 1)
                self.assertIn("DnsArmContinuationRejected", root["issues"])
                self.assertEqual(sum(op == "dns-resolvers" for op, _, _ in reader.requests), 1)

    def test_repeated_tokens_stop_bounded_with_gap(self):
        reader = PagedDNSReader()
        reader.next_override = lambda url, page: urlsplit(url)._replace(
            query="api-version=2022-07-01&$skipToken=1").geturl()
        _, model, _, reader = self.make(reader)
        root = next(c for c in model["collections"] if c["operationId"] == "dns-resolvers")
        self.assertEqual(root["status"], "partial")
        self.assertIn("RepeatedOrEmptyContinuation", root["issues"])
        self.assertEqual(sum(op == "dns-resolvers" for op, _, _ in reader.requests), 2)

    def test_permission_failure_after_first_page_keeps_selected_rows(self):
        reader = PagedDNSReader()
        reader.fail_on_page = ("dns-resolvers", 1)
        _, model, _, _ = self.make(reader)
        root = next(c for c in model["collections"] if c["operationId"] == "dns-resolvers")
        self.assertEqual(root["status"], "partial")
        self.assertEqual(root["retainedRowCount"], 1)
        self.assertIn("PermissionDenied", root["issues"])

    def test_page_budget_keeps_pending_continuation_as_explicit_partial(self):
        real_catalog = nh.catalog
        reader = PagedDNSReader()
        config = copy.deepcopy(real_catalog("1.5.0"))
        config["maxPagesPerOperation"] = 1
        with patch.object(nh, "catalog", side_effect=lambda version="1.0.0": config if version == "1.5.0" else real_catalog(version)):
            envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True)
        root = next(c for c in envelope["collections"] if c["operationId"] == "dns-resolvers")
        self.assertEqual(root["status"], "partial")
        self.assertIn("PageBudgetExceeded", root["issues"])
        self.assertTrue(root["pages"][-1]["armHasContinuation"])

    def test_encoded_checkpoint_cursor_is_canonical_bounded_and_not_trusted_url(self):
        for token in ("bad", nh.arm_cursor(-1, None), nh.arm_cursor(101, None), "a" * 12001):
            with self.assertRaises(ValueError):
                nh.read_arm_cursor(token)
        cursor = nh.arm_cursor(1, "https://management.azure.com/sample?api-version=2022-07-01&$skipToken=one%2Btwo")
        self.assertEqual(nh.read_arm_cursor(cursor)[0], 1)
        with self.assertRaises(ValueError):
            nh.validated_arm_url(nh.read_arm_cursor(cursor)[1], "/other")

    def test_encoded_opaque_token_is_preserved_without_interpreting_or_expanding_it(self):
        op = next(op for op in nh.catalog("1.5.0")["operations"] if op["operationId"] == "dns-resolvers")
        path = "/subscriptions/" + SUB + "/providers/microsoft.network/dnsresolvers"
        url = "https://management.azure.com" + path + "?%24skipToken=one%2Btwo%2Fthree%3D&api-version=2022-07-01"
        self.assertEqual(nh.validated_arm_url(url, path), url)
        command = nh.command_for(op, SUB, 1000, nh.arm_cursor(0, url))
        self.assertEqual(command[command.index("--url") + 1], url)
        self.assertTrue(nh.matches_command(command, SUB, 1000))

    def test_child_continuation_cannot_jump_to_a_different_parent(self):
        op = next(op for op in nh.catalog("1.5.0")["operations"] if op["operationId"] == "dns-inbound-endpoints")
        parent = {"subscriptionId": SUB, "id": f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Network/dnsResolvers/one"}
        wrong = "https://management.azure.com" + parent["id"].replace("/one", "/two") + "/inboundEndpoints?api-version=2022-07-01&$skipToken=next"
        with self.assertRaisesRegex(ValueError, "approved origin/resource path"):
            nh.command_for(op, SUB, 1000, nh.arm_cursor(0, wrong), parent)

    def test_terminal_empty_child_page_does_not_skip_the_next_parent(self):
        reader = PagedDNSReader()
        original = reader.__class__.__call__
        def empty_page(instance, command):
            response = original(instance, command)
            if nh.child_kind(command) == "dns-inbound-endpoints" and nh.request_token(command):
                response.payload.update({"data": [], "count": 0, "nextLink": None})
            return response
        with patch.object(PagedDNSReader, "__call__", empty_page):
            _, model, _, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "dns-inbound-endpoints")
        self.assertEqual(collection["retainedRowCount"], 2)
        self.assertEqual([page["itemCount"] for page in collection["pages"]], [1, 0, 1])
        self.assertEqual(collection["status"], "succeeded")

    def test_missing_continuation_or_nonnumeric_page_count_cannot_claim_complete_inventory(self):
        original = PagedDNSReader.__call__
        for field in ("nextLink", "count"):
            def incomplete(instance, command):
                response = original(instance, command)
                if command[:2] == ["az", "rest"]:
                    response.payload.pop(field, None)
                return response
            with patch.object(PagedDNSReader, "__call__", incomplete):
                _, model, _, _ = self.make()
            roots = [c for c in model["collections"] if c["operationId"] in ("dns-resolvers", "dns-rulesets")]
            self.assertTrue(all(c["status"] == "partial" for c in roots))
            issue = "DnsArmContinuationUnavailable" if field == "nextLink" else "DnsArmPageCountUnavailable"
            self.assertTrue(all(issue in c["issues"] for c in roots))

    def test_resume_after_committed_child_page_does_not_repeat_parent_or_page(self):
        reader = PagedDNSReader()
        progress = {}
        def save(state):
            current = state["current"]
            if current and current["collection"]["operationId"] == "dns-inbound-endpoints":
                raise RuntimeError("Injected checkpoint interruption")
        with self.assertRaisesRegex(RuntimeError, "checkpoint interruption"):
            nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True,
                       progress=progress, save_progress=save)
        first_calls = list(reader.calls)
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True,
                              progress=progress)
        self.assertEqual(len(reader.calls), len({tuple(c) for c in reader.calls}))
        self.assertTrue(len(reader.calls) > len(first_calls))
        self.assertEqual(next(c for c in envelope["collections"] if c["operationId"] == "dns-inbound-endpoints")["retainedRowCount"], 3)
