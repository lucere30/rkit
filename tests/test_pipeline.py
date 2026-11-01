from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import yaml

from rkit.build import build, fingerprint, stage, validate_local
from rkit.config import load, safe_file
from rkit.fetch import snapshots
from rkit.publish import apply


class Project(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.cfg = {"version": 1, "targets": {"loon": True, "mihomo": True, "singbox": True}, "rulesets": {
            "x": {"sources": [{"url": "https://example.test/x", "format": "classical"}], "targets": ["loon", "mihomo", "singbox"]}}}
        self.write("pyproject.toml", "# fixture\n")
        self.write("src/rkit/__init__.py", "# fixture\n")
        self.save()
        self.data = b"DOMAIN-SUFFIX,example.com\nDOMAIN,a.example.com\nIP-CIDR,192.0.2.0/24\n"
        self.counter = 0

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def save(self):
        self.write("rkit.yaml", yaml.safe_dump(self.cfg, sort_keys=False))

    def run_build(self, fetcher=None):
        return build(self.root, fetcher=fetcher or (lambda url: self.data))

    def accept(self, result):
        self.counter += 1
        directory = Path(self.temp.name) / f"stage{self.counter}"
        stage(result, directory)
        apply(self.root, directory)
        return directory


class PipelineTests(Project):
    def test_filtered_source_merges_deduplicates_and_tracks_both_upstreams(self):
        cdn_url = "https://example.test/cdn"
        self.cfg["rulesets"]["x"]["sources"].append({
            "url": cdn_url, "format": "classical", "include_types": ["DOMAIN"]})
        self.save()
        data = {
            "https://example.test/x": b"DOMAIN-SUFFIX,formula1.com\nDOMAIN,cdn.example.net\n",
            cdn_url: b"DOMAIN-SUFFIX,bitmovin.com\nDOMAIN,cdn.example.net\nDOMAIN,old.cloudfront.net\n"}
        first = self.run_build(data.__getitem__)
        self.assertFalse(first["report"]["failed"])
        self.assertEqual(first["report"]["successful"]["x"]["output_rules"], 3)
        payload = yaml.safe_load(first["outputs"]["cat/x.yaml"])["payload"]
        self.assertEqual(payload.count("DOMAIN,cdn.example.net"), 1)
        self.assertNotIn("DOMAIN-SUFFIX,bitmovin.com", payload)
        inputs = json.loads(first["outputs"]["manifest.json"])["rulesets"]["x"]["mihomo"]["inputs"]
        self.assertEqual((inputs[1]["parsed_rules"], inputs[1]["selected_rules"]), (3, 2))
        self.accept(first)
        data["https://example.test/x"] = b"DOMAIN-SUFFIX,f1tv.com\n"
        data[cdn_url] = b"DOMAIN,new.cloudfront.net\nDOMAIN-SUFFIX,racetrack.test\n"
        second = self.run_build(data.__getitem__)
        payload = yaml.safe_load(second["outputs"]["cat/x.yaml"])["payload"]
        self.assertEqual(payload, ["DOMAIN-SUFFIX,f1tv.com", "DOMAIN,new.cloudfront.net"])

    def test_empty_source_filter_preserves_previous_complete_union(self):
        cdn_url = "https://example.test/cdn"
        self.cfg["rulesets"]["x"]["sources"].append({
            "url": cdn_url, "format": "classical", "include_types": ["DOMAIN"]})
        self.save()
        first = self.run_build(lambda _: b"DOMAIN,old.example.net\n")
        self.accept(first)
        old = json.loads(first["outputs"]["manifest.json"])["rulesets"]["x"]
        result = self.run_build(lambda _: b"DOMAIN-SUFFIX,new.example.net\n")
        self.assertIn("include_types matched no rules", result["report"]["failed"]["x"])
        self.assertEqual(set(result["outputs"]), {"manifest.json"})
        self.assertEqual(json.loads(result["outputs"]["manifest.json"])["rulesets"]["x"], old)
        self.assertFalse(result["delete"])

    def test_source_filters_reject_invalid_types_and_direct_subscription_filters(self):
        for kinds in (None, [], "DOMAIN", ["UNKNOWN"], ["DOMAIN", "DOMAIN"], [{}]):
            self.cfg["rulesets"]["x"]["sources"][0]["include_types"] = kinds
            self.save()
            with self.assertRaisesRegex(ValueError, "include_types"):
                load(self.root)
        self.write("lq/manual/x.list", "DOMAIN,example.net\n")
        self.cfg["rulesets"]["x"]["sources"] = [{
            "path": "lq/manual/x.list", "format": "classical", "include_types": ["DOMAIN"]}]
        self.save()
        with self.assertRaisesRegex(ValueError, "include_types"):
            load(self.root)

    def test_build_is_deterministic_and_input_files_untouched(self):
        before = fingerprint(self.root)
        first = self.run_build()
        self.assertFalse(first["report"]["failed"])
        self.accept(first)
        second = self.run_build()
        self.assertEqual(first["outputs"], second["outputs"])
        self.assertEqual(fingerprint(self.root), before)

    def test_additions_survive_upstream_removal_and_override_exclusion(self):
        self.cfg["rulesets"]["x"].update(additions="custom/x.list", exclusions="custom/x-exclude.list")
        self.write("custom/x.list", "DOMAIN,keep.example.com\n")
        self.write("custom/x-exclude.list", "DOMAIN-SUFFIX,example.com\n")
        self.save()
        first = self.run_build()
        self.assertIn("DOMAIN,keep.example.com", first["outputs"]["cat/x.yaml"])
        self.accept(first)
        self.data = b"DOMAIN,unrelated.test\n"
        self.assertIn("DOMAIN,keep.example.com", self.run_build()["outputs"]["cat/x.yaml"])
        self.assertEqual((self.root / "custom/x.list").read_text(), "DOMAIN,keep.example.com\n")

    def test_source_failure_retains_entire_ruleset_but_not_other_updates(self):
        self.accept(self.run_build())
        old = json.loads((self.root / "manifest.json").read_text())["rulesets"]["x"]
        self.cfg["rulesets"]["y"] = deepcopy(self.cfg["rulesets"]["x"])
        self.cfg["rulesets"]["y"]["sources"][0]["url"] = "https://example.test/y"
        self.save()
        def fetch(url):
            if url.endswith("/x"):
                raise ValueError("offline")
            return b"DOMAIN,new.test\n"
        result = self.run_build(fetch)
        self.assertIn("x", result["report"]["failed"])
        self.assertIn("cat/y.yaml", result["outputs"])
        self.assertNotIn("cat/x.yaml", result["outputs"])
        self.assertEqual(json.loads(result["outputs"]["manifest.json"])["rulesets"]["x"], old)
        self.assertFalse(result["delete"])

    def test_one_missing_source_cannot_publish_partial_union(self):
        self.cfg["rulesets"]["x"]["sources"].append({"url": "https://example.test/missing", "format": "classical"})
        self.save()
        def fetch(url):
            if "missing" in url:
                raise OSError("network failure")
            return self.data
        result = self.run_build(fetch)
        self.assertEqual(set(result["outputs"]), {"manifest.json"})
        self.assertIn("x", result["report"]["failed"])

    def test_unsupported_target_is_atomic(self):
        self.data += b"USER-AGENT,Test*\n"
        result = self.run_build()
        self.assertIn("x", result["report"]["failed"])
        self.assertEqual(set(result["outputs"]), {"manifest.json"})

    def test_yaml_error_is_local_to_ruleset(self):
        self.cfg["rulesets"]["bad"] = {"sources": [{"url": "https://example.test/bad", "format": "clash-classical"}], "targets": ["mihomo"]}
        self.save()
        result = self.run_build(lambda u: b"payload: [" if u.endswith("bad") else self.data)
        self.assertIn("bad", result["report"]["failed"])
        self.assertIn("x", result["report"]["successful"])

    def test_disabled_target_is_retained_without_relabeling_provenance(self):
        self.accept(self.run_build())
        old = json.loads((self.root / "manifest.json").read_text())["rulesets"]["x"]["singbox"]
        self.cfg["targets"]["singbox"] = False
        self.save()
        self.data = b"DOMAIN,new.test\n"
        result = self.run_build()
        self.assertNotIn("singbox/x_domain.json", result["outputs"])
        self.assertFalse(any(p.startswith("singbox/") for p in result["delete"]))
        self.assertEqual(json.loads(result["outputs"]["manifest.json"])["rulesets"]["x"]["singbox"], old)

    def test_managed_layout_cleanup_and_unknown_file_preserved(self):
        self.accept(self.run_build())
        self.write("cat/unknown.yaml", "personal file")
        self.cfg["rulesets"]["x"]["layout"] = "split"
        self.save()
        result = self.run_build()
        self.assertIn("cat/x.yaml", result["delete"])
        self.assertNotIn("cat/unknown.yaml", result["delete"])
        self.accept(result)
        self.assertFalse((self.root / "cat/x.yaml").exists())
        self.assertEqual((self.root / "cat/unknown.yaml").read_text(), "personal file")

    def test_definition_retirement_only_deletes_managed_outputs(self):
        self.accept(self.run_build())
        self.cfg["rulesets"]["y"] = self.cfg["rulesets"].pop("x")
        self.save()
        result = self.run_build()
        self.assertIn("cat/x.yaml", result["delete"])
        self.accept(result)
        self.assertFalse((self.root / "cat/x.yaml").exists())
        self.assertTrue((self.root / "cat/y.yaml").exists())

    def test_edited_generated_file_prevents_whole_ruleset_replacement(self):
        self.accept(self.run_build())
        self.write("cat/x.yaml", "my edit")
        result = self.run_build()
        self.assertIn("x", result["report"]["failed"])
        self.assertEqual(set(result["outputs"]), {"manifest.json"})

    def test_unmanaged_destination_cannot_be_overwritten(self):
        self.write("cat/x.yaml", "unknown")
        result = self.run_build()
        self.assertIn("unmanaged", result["report"]["failed"]["x"])
        self.assertEqual((self.root / "cat/x.yaml").read_text(), "unknown")

    def test_manual_is_direct_subscription_and_not_managed_output(self):
        text = "# Keep my comments\nDOMAIN,a.test\nIP-CIDR,10.0.0.0/8,no-resolve\n"
        self.write("lq/manual/x.list", text)
        self.cfg["rulesets"]["x"]["sources"] = [{"path": "lq/manual/x.list", "format": "classical"}]
        self.save()
        validate_local(self.root, load(self.root))
        result = self.run_build()
        self.assertNotIn("lq/generated/x.list", result["outputs"])
        self.accept(result)
        self.assertEqual((self.root / "lq/manual/x.list").read_text(), text)

    def test_empty_result_preserves_previous_outputs(self):
        self.accept(self.run_build())
        self.data = b"# nothing\n"
        self.assertIn("x", self.run_build()["report"]["failed"])

    def test_target_specific_sources_preserve_client_semantics(self):
        spec = self.cfg["rulesets"]["x"]
        spec["sources_by_target"] = {"loon": [
            {"url": "https://example.test/loon", "format": "classical"},
            {"url": "https://example.test/loon-domain", "format": "loon-domain"}]}
        spec["target_layouts"] = {"mihomo": "native-split"}
        self.save()
        feeds = {
            "https://example.test/x": b"DOMAIN-SUFFIX,clash.test\nDOMAIN-KEYWORD,keyword\nIP-CIDR,192.0.2.0/24\n",
            "https://example.test/loon": b"USER-AGENT,LoonAgent*\nDOMAIN-KEYWORD,keyword\n",
            "https://example.test/loon-domain": b".loon.test\nexact.loon.test\n",
        }
        calls = []
        def fetch(url):
            calls.append(url)
            return feeds[url]
        result = self.run_build(fetch)
        self.assertFalse(result["report"]["failed"])
        self.assertEqual(len(calls), 3)
        loon = result["outputs"]["lq/generated/x.list"]
        self.assertIn("DOMAIN-SUFFIX,loon.test", loon)
        self.assertIn("USER-AGENT,LoonAgent*", loon)
        self.assertNotIn("clash.test", loon)
        self.assertIn("DOMAIN-SUFFIX,clash.test", result["outputs"]["cat/x.yaml"])
        self.assertEqual(yaml.safe_load(result["outputs"]["cat/x_domain.yaml"])["payload"],
                         ["+.clash.test"])
        self.assertEqual(yaml.safe_load(result["outputs"]["cat/x_ip.yaml"])["payload"],
                         ["192.0.2.0/24"])
        self.assertEqual(yaml.safe_load(result["outputs"]["cat/x_classical.yaml"])["payload"],
                         ["DOMAIN-KEYWORD,keyword"])
        manifest = json.loads(result["outputs"]["manifest.json"])["rulesets"]["x"]
        self.assertEqual(len(manifest["loon"]["inputs"]), 2)
        self.assertEqual(len(manifest["mihomo"]["inputs"]), 1)
        self.assertEqual(len(manifest["singbox"]["inputs"]), 1)
        self.accept(result)
        self.assertEqual(self.run_build(fetch)["outputs"]["cat/x_domain.yaml"],
                         result["outputs"]["cat/x_domain.yaml"])

    def test_invalid_target_override_is_rejected(self):
        self.cfg["rulesets"]["x"]["sources_by_target"] = {"unknown": []}
        self.save()
        with self.assertRaises(ValueError):
            load(self.root)
        self.cfg["rulesets"]["x"]["sources_by_target"] = {}
        self.cfg["rulesets"]["x"]["target_layouts"] = {"loon": "native-split"}
        self.save()
        with self.assertRaisesRegex(ValueError, "invalid layout"):
            load(self.root)

    def test_shared_url_downloaded_once(self):
        self.cfg["rulesets"]["y"] = deepcopy(self.cfg["rulesets"]["x"])
        self.save()
        calls = []
        def fetch(url):
            calls.append(url)
            return self.data
        self.assertFalse(self.run_build(fetch)["report"]["failed"])
        self.assertEqual(len(calls), 1)

    def test_staged_output_tampering_and_input_changes_are_rejected(self):
        directory = Path(self.temp.name) / "stage"
        stage(self.run_build(), directory)
        (directory / "files/cat/x.yaml").write_text("corrupt")
        with self.assertRaisesRegex(ValueError, "staged output changed"):
            apply(self.root, directory)
        self.assertFalse((self.root / "cat/x.yaml").exists())
        self.write("custom/new.list", "DOMAIN,new.test")
        with self.assertRaisesRegex(ValueError, "inputs no longer match"):
            apply(self.root, directory)

    def test_config_rejects_traversal_unknown_fields_duplicate_keys(self):
        for path in ["../outside.list", "/tmp/outside.list", "cat/input.yaml"]:
            self.cfg["rulesets"]["x"]["additions"] = path
            self.save()
            with self.assertRaises(ValueError):
                load(self.root)
        self.write("rkit.yaml", "version: 1\nversion: 2\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load(self.root)

    def test_symlink_input_rejected(self):
        (self.root / "custom").mkdir()
        (self.root / "custom/link.list").symlink_to(Path(self.temp.name) / "external")
        with self.assertRaises(ValueError):
            safe_file(self.root, "custom/link.list")

    def test_output_name_collision_fails_before_download(self):
        self.cfg["rulesets"]["x"]["layout"] = "split"
        self.cfg["rulesets"]["x_domain"] = {"sources": [{"url": "https://example.test/other", "format": "classical"}], "targets": ["mihomo"]}
        self.save()
        with self.assertRaisesRegex(ValueError, "collision"):
            self.run_build(lambda _: self.fail("must not download invalid config"))

    def test_failed_rename_does_not_retire_old_subscription(self):
        self.accept(self.run_build())
        self.cfg["rulesets"]["new"] = self.cfg["rulesets"].pop("x")
        self.save()
        self.data = b"INVALID,data"
        result = self.run_build()
        self.assertIn("new", result["report"]["failed"])
        self.assertFalse(result["delete"])
        self.assertIn("x", json.loads(result["outputs"]["manifest.json"])["rulesets"])

    def test_online_failure_does_not_fall_back_to_cached_source(self):
        cache = Path(self.temp.name) / "cache"
        url = "https://example.test/x"
        snapshots([url], cache_dir=cache, fetcher=lambda _: self.data)
        def fail(_):
            raise OSError("fail")
        self.assertIsInstance(snapshots([url], cache_dir=cache, fetcher=fail)[url], Exception)
        self.assertEqual(snapshots([url], cache_dir=cache, offline=True)[url], self.data)


if __name__ == "__main__":
    unittest.main()
