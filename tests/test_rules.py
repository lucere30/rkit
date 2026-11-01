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

    def test_keyword_covers_exact_suffix_and_longer_keyword(self):
        rules = self.parse("DOMAIN-KEYWORD,google\nDOMAIN,google.com\n"
                           "DOMAIN-SUFFIX,google.com\nDOMAIN-SUFFIX,api.google.com\n"
                           "DOMAIN,notgoogle.com\nDOMAIN-KEYWORD,googleservices\n"
                           "DOMAIN,unrelated.example")
        self.assertEqual([(r.kind, r.value) for r in optimize(rules)],
                         [("DOMAIN-KEYWORD", "google"), ("DOMAIN", "unrelated.example")])

    def test_keyword_coverage_is_one_way_and_case_conservative(self):
        rules = self.parse("DOMAIN-SUFFIX,example.com\nDOMAIN-KEYWORD,example\n"
                           "DOMAIN-KEYWORD,EXAMPLE\nDOMAIN,EXAMPLE.com\n"
                           "DOMAIN-SUFFIX,EXAMPLE.com\nDOMAIN-KEYWORD,x.y\n"
                           "DOMAIN,x.y.example\nDOMAIN,other.test")
        result = [(r.kind, r.value) for r in optimize(rules)]
        self.assertIn(("DOMAIN-KEYWORD", "example"), result)
        self.assertIn(("DOMAIN-KEYWORD", "EXAMPLE"), result)
        self.assertIn(("DOMAIN-KEYWORD", "x.y"), result)
        self.assertIn(("DOMAIN", "EXAMPLE.com"), result)
        self.assertIn(("DOMAIN-SUFFIX", "EXAMPLE.com"), result)
        self.assertNotIn(("DOMAIN-SUFFIX", "example.com"), result)
        self.assertIn(("DOMAIN", "other.test"), result)

    def test_keyword_does_not_collapse_source_ip_cidrs(self):
        rules = self.parse("DOMAIN-KEYWORD,foo\nDOMAIN-KEYWORD,foo*\n"
                           "SRC-IP-CIDR,192.0.2.0/25\nSRC-IP-CIDR,192.0.2.128/25\n"
                           "IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25")
        result = optimize(rules, collapse_ip=True)
        self.assertIn(("DOMAIN-KEYWORD", "foo*"), [(r.kind, r.value) for r in result])
        self.assertEqual([r.value for r in result if r.kind == "SRC-IP-CIDR"],
                         ["192.0.2.0/25", "192.0.2.128/25"])
        self.assertEqual([r.value for r in result if r.kind == "IP-CIDR"],
                         ["192.0.2.0/24"])

    def test_optimization_idempotence(self):
        rules = self.parse("DOMAIN-SUFFIX,example.com\nDOMAIN-SUFFIX,a.example.com\n"
                           "DOMAIN,sub.example.com\nDOMAIN-KEYWORD,foo\n"
                           "DOMAIN-SUFFIX,foo.test\nDOMAIN,foo.test\n"
                           "IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\n"
                           "IP-CIDR6,2001:db8::/33\nIP-CIDR6,2001:db8:8000::/33")
        once = optimize(rules, collapse_ip=True)
        twice = optimize(once, collapse_ip=True)
        self.assertEqual([(r.kind, r.value) for r in once],
                         [(r.kind, r.value) for r in twice])
        self.assertEqual([r.value for r in once if r.kind == "IP-CIDR6"],
                         ["2001:db8::/32"])

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

    def test_loon_domain_file_preserves_exact_and_suffix(self):
        rules = parse(".example.com\nexact.test\n# comment\n", "loon-domain", "loon")
        self.assertEqual([(r.kind, r.value) for r in rules],
                         [("DOMAIN-SUFFIX", "example.com"), ("DOMAIN", "exact.test")])
        with self.assertRaisesRegex(ValueError, "loon:1"):
            parse("*.invalid.test", "loon-domain", "loon")

    def test_native_mihomo_split_keeps_legacy_and_types(self):
        rules = self.parse("DOMAIN,x.test\nDOMAIN-SUFFIX,example.com\nDOMAIN-KEYWORD,spot\n"
                           "IP-CIDR,192.0.2.1/24\nIP-CIDR6,2001:db8::/32\nPROCESS-NAME,program")
        files, _ = render(rules, "mihomo", "x", layout="native-split")
        self.assertEqual(set(files), {"cat/x.yaml", "cat/x_domain.yaml",
                                       "cat/x_ip.yaml", "cat/x_classical.yaml"})
        self.assertEqual(yaml.safe_load(files["cat/x_domain.yaml"])["payload"],
                         ["x.test", "+.example.com"])
        self.assertEqual(yaml.safe_load(files["cat/x_ip.yaml"])["payload"],
                         ["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(yaml.safe_load(files["cat/x_classical.yaml"])["payload"],
                         ["DOMAIN-KEYWORD,spot", "PROCESS-NAME,program"])
        self.assertIn("IP-CIDR,192.0.2.0/24,no-resolve", files["cat/x.yaml"])

    def test_native_split_dash_uses_hyphenated_filenames_without_semantic_changes(self):
        rules = self.parse("DOMAIN,x.test\nDOMAIN-SUFFIX,example.com\nDOMAIN-KEYWORD,spot\nIP-CIDR,192.0.2.0/24")
        old, _ = render(rules, "mihomo", "proxy-merged", layout="native-split")
        new, _ = render(rules, "mihomo", "proxy-merged", layout="native-split-dash")
        self.assertEqual(set(new), {"cat/proxy-merged.yaml", "cat/proxy-merged-domain.yaml",
                                     "cat/proxy-merged-ip.yaml", "cat/proxy-merged-classical.yaml"})
        self.assertEqual(new["cat/proxy-merged.yaml"], old["cat/proxy-merged.yaml"])
        for segment in ("domain", "ip", "classical"):
            self.assertEqual(new[f"cat/proxy-merged-{segment}.yaml"],
                             old[f"cat/proxy-merged_{segment}.yaml"])

    def test_split_keeps_other_rules_separate(self):
        rules = self.parse("DOMAIN,x.test\nIP-CIDR,10.0.0.0/8\nUSER-AGENT,Test*")
        files, _ = render(rules, "loon", "x", layout="split")
        self.assertEqual(set(files), {f"lq/generated/x_{group}.list" for group in ("domain", "ip", "other")})


if __name__ == "__main__":
    unittest.main()
