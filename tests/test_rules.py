import json
import unittest

import yaml

from rkit.parsers import parse
from rkit.renderers import render
from rkit.transform import exclude, optimize


class RuleTests(unittest.TestCase):
    def parse(self, text, **kw):
        return parse(text, "classical", "test", **kw)

    def test_ipv4_ipv6_normalization_and_idempotence(self):
        rules = self.parse("IP-CIDR,192.0.2.129/24\nIP-CIDR6,2001:db8::1/32,no-resolve,no-resolve")
        for target, path in [("loon", "lq/generated/x.list"), ("mihomo", "cat/x.yaml")]:
            files, _ = render(rules, target, "x")
            text = files[path]
            if target == "mihomo":
                text = "\n".join(yaml.safe_load(text)["payload"])
            lines = [v for v in text.splitlines() if not v.startswith("#")]
            self.assertEqual(lines, ["IP-CIDR,192.0.2.0/24,no-resolve", "IP-CIDR6,2001:db8::/32,no-resolve"])
            self.assertEqual(self.parse(text), rules)

    def test_all_mihomo_destination_ip_types(self):
        rules = self.parse("IP-CIDR,10.0.0.0/8\nIP-CIDR6,::/0\nIP-ASN,13335\nGEOIP,CN\nSRC-IP-CIDR,192.0.2.0/24\nDOMAIN,a.example")
        lines = yaml.safe_load(render(rules, "mihomo", "x")[0]["cat/x.yaml"])["payload"]
        self.assertTrue(all(s.count("no-resolve") == 1 for s in lines[:4]))
        self.assertTrue(all("no-resolve" not in s for s in lines[4:]))

    def test_manual_ip_policy(self):
        for text in ["IP-CIDR,10.0.0.0/8", "IP-CIDR,10.0.0.0/8,no-resolve,no-resolve"]:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                self.parse(text, manual=True)
        self.parse("IP-CIDR6,::/0,no-resolve", manual=True)

    def test_singbox_or_semantics_and_empty_category(self):
        rules = self.parse("DOMAIN,a.example\nDOMAIN-SUFFIX,b.example\nIP-CIDR,10.0.0.0/8,no-resolve")
        files, _ = render(rules, "singbox", "x")
        self.assertNotIn("no-resolve", str(files))
        self.assertEqual(json.loads(files["singbox/x_domain.json"])["rules"], [{"domain": ["a.example"]}, {"domain_suffix": ["b.example"]}])
        empty = render(self.parse("DOMAIN,a.example"), "singbox", "x")[0]["singbox/x_ip.json"]
        self.assertEqual(json.loads(empty)["rules"], [])

    def test_unsupported_requires_explicit_omission(self):
        rules = self.parse("DOMAIN,a.example\nUSER-AGENT,Agent  With  Spaces*\nURL-REGEX,^https://x/(a,b)")
        for target in ("mihomo", "singbox"):
            with self.assertRaisesRegex(ValueError, "cannot represent"):
                render(rules, target, "x")
            _, report = render(rules, target, "x", omit=["USER-AGENT", "URL-REGEX"])
            self.assertEqual(len(report), 2)
        loon = render(rules, "loon", "x")[0]["lq/generated/x.list"]
        self.assertIn("Agent  With  Spaces*", loon)
        self.assertIn("^https://x/(a,b)", loon)

    def test_invalid_or_policy_bearing_rules_fail(self):
        bad = ["IP-CIDR,bad", "IP-CIDR6,192.0.2.0/24", "IP-CIDR,10.0.0.0/8,DIRECT",
               "DOMAIN,a.example,PROXY", "DOMAIN,a.*.example", "UNKNOWN,x", "IP-ASN,4294967296",
               "GEOIP,", "IP-CIDR,10.0.0.0/8,", "DOMAIN,a.example\x00"]
        for text in bad:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "test:1"):
                self.parse(text)

    def test_coverage_respects_label_boundaries_and_exact_domains(self):
        rules = self.parse("DOMAIN-SUFFIX,example.com\nDOMAIN,example.com\nDOMAIN,a.example.com\nDOMAIN,notexample.com\nDOMAIN,x.test\nDOMAIN,a.x.test\nDOMAIN-SUFFIX,A.example.com")
        values = [(r.kind, r.value) for r in optimize(rules)]
        self.assertEqual(values, [("DOMAIN-SUFFIX", "example.com"), ("DOMAIN", "notexample.com"),
                                  ("DOMAIN", "x.test"), ("DOMAIN", "a.x.test"), ("DOMAIN-SUFFIX", "A.example.com")])

    def test_exclusion_does_not_subtract_from_broader_suffix(self):
        rules = self.parse("DOMAIN-SUFFIX,example.com\nDOMAIN,a.example.com\nDOMAIN,b.example.com")
        excluded = exclude(rules, self.parse("DOMAIN,a.example.com"))
        self.assertEqual([r.value for r in excluded], ["example.com", "b.example.com"])

    def test_ip_collapse_exact_union(self):
        rules = self.parse("IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\nIP-CIDR6,2001:db8::/33\nIP-CIDR6,2001:db8:8000::/33")
        self.assertEqual([r.value for r in optimize(rules, collapse_ip=True)], ["192.0.2.0/24", "2001:db8::/32"])

    def test_fakeip_wildcards_are_not_suffixes(self):
        rules = parse("+.example.com\na.example.com\n*.other.example\nexact.test", "domain-list", "test")
        rules = optimize(rules)
        values = yaml.safe_load(render(rules, "mihomo", "fake", purpose="fakeip")[0]["cat/fake.yaml"])["payload"]
        self.assertEqual(values, ["+.example.com", "*.other.example", "exact.test"])
        with self.assertRaises(ValueError):
            render(rules, "loon", "fake")

    def test_clash_payload_rejects_structures_and_embedded_lines(self):
        for text in ["payload: [true]", "payload: [{}]", 'payload: ["DOMAIN,x\\nDOMAIN,y"]', "payload: []", "payload: [x]\nextra: true"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text, "clash-classical", "test")

    def test_split_keeps_other_rules_separate(self):
        rules = self.parse("DOMAIN,x.test\nIP-CIDR,10.0.0.0/8\nUSER-AGENT,Test*")
        files, _ = render(rules, "loon", "x", layout="split")
        self.assertEqual(set(files), {f"lq/generated/x_{group}.list" for group in ("domain", "ip", "other")})


if __name__ == "__main__":
    unittest.main()
