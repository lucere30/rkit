import unittest
from unittest.mock import patch

import yaml

from rkit import yamlio
from rkit.config import UniqueLoader
from rkit.parsers import parse
from rkit.renderers import render


class SafeYamlTests(unittest.TestCase):
    def test_safe_backends_preserve_payload_and_reject_python_objects(self):
        loaders = [yaml.SafeLoader]
        if hasattr(yaml, "CSafeLoader"):
            loaders.append(yaml.CSafeLoader)
        for loader in loaders:
            with self.subTest(loader=loader.__name__), patch.object(yamlio, "SAFE_LOADER", loader):
                rules = parse('payload:\n  - "DOMAIN,yes.example"\n  - "DOMAIN-KEYWORD,001"\n',
                              "clash-classical", "fixture")
                output = render(rules, "mihomo", "test")[0]["cat/test.yaml"]
                self.assertEqual(parse(output, "clash-classical", "roundtrip"), rules)
                with self.assertRaises(yaml.YAMLError):
                    yamlio.safe_load('!!python/object/apply:builtins.eval ["1+1"]')

    def test_unique_config_loader_still_rejects_nested_duplicates(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            yaml.load("targets:\n  mihomo: true\n  mihomo: false\n", Loader=UniqueLoader)
