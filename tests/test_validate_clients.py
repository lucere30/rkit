import os
from pathlib import Path
import socket
import secrets
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import yaml

from tools.validate_clients import check_provider_snapshot, controller_port, provider_status, validate_loaded_providers


class ProviderSnapshotTests(unittest.TestCase):
    def test_api_enum_names_and_exact_rule_counts(self):
        expected = {"test": {"behavior": "domain", "format": "yaml", "ruleCount": 2}}
        actual = {"test": {"behavior": "Domain", "format": "YamlRule", "ruleCount": 2}}
        check_provider_snapshot(actual, expected)
        for field, value in [("ruleCount", 1), ("behavior", "Classical"), ("format", "MrsRule")]:
            with self.subTest(field=field):
                bad = {"test": dict(actual["test"], **{field: value})}
                with self.assertRaisesRegex(ValueError, field):
                    check_provider_snapshot(bad, expected)
        with self.assertRaisesRegex(ValueError, "names differ"):
            check_provider_snapshot({}, expected)


@unittest.skipUnless(os.environ.get("RKIT_MIHOMO_BINARY"), "set RKIT_MIHOMO_BINARY for native tests")
class NativeProviderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rkit-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.binary = str(Path(os.environ["RKIT_MIHOMO_BINARY"]).resolve())

    def config(self, behavior, payload):
        if payload is not None:
            (self.root / "rules.yaml").write_text(payload)
        config = {"mode": "rule", "rule-providers": {
            "test": {"type": "file", "behavior": behavior, "format": "yaml",
                     "path": str(self.root / "rules.yaml")}},
                  "rules": ["RULE-SET,test,REJECT,no-resolve", "MATCH,REJECT"]}
        return config

    def validate(self, behavior, payload, count):
        validate_loaded_providers(self.binary, self.root, self.config(behavior, payload),
                                  {"test": {"behavior": behavior, "format": "yaml", "ruleCount": count}},
                                  timeout=3)

    def test_valid_domain_ip_and_classical_providers(self):
        for behavior, payload in [
            ("domain", 'payload:\n  - "example.com"\n  - "+.example.net"\n'),
            ("ipcidr", 'payload:\n  - "192.0.2.0/24"\n  - "2001:db8::/32"\n'),
            ("classical", 'payload:\n  - "DOMAIN-KEYWORD,example"\n  - "PROCESS-NAME,example.exe"\n'),
        ]:
            with self.subTest(behavior=behavior):
                self.validate(behavior, payload, 2)

    def test_silently_skipped_rules_fail_native_validation(self):
        for behavior, payload in [
            ("classical", 'payload:\n  - "INVALID-RULE,example.com"\n'),
            ("classical", 'payload:\n  - "DOMAIN,example.com"\n  - "INVALID-RULE,example.net"\n'),
            ("domain", 'payload:\n  - "example.com"\n  - "https://invalid.example"\n'),
            ("ipcidr", 'payload:\n  - "192.0.2.0/24"\n  - "not-a-cidr"\n'),
        ]:
            with self.subTest(behavior=behavior, payload=payload):
                with self.assertRaisesRegex(ValueError, "initialization failed|ruleCount"):
                    self.validate(behavior, payload, len(payload.splitlines()) - 1)

    def test_missing_provider_file_fails(self):
        with self.assertRaisesRegex(ValueError, "initialization failed"):
            self.validate("domain", None, 1)

    def test_count_mismatch_fails_even_without_parser_warning(self):
        with self.assertRaisesRegex(ValueError, "ruleCount"):
            self.validate("domain", 'payload:\n  - "example.com"\n', 2)

    def test_timeout_terminates_child(self):
        children = []
        original = subprocess.Popen

        def track(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with patch("tools.validate_clients.provider_status", return_value={}), \
                patch("tools.validate_clients.subprocess.Popen", side_effect=track):
            with self.assertRaisesRegex(ValueError, "timed out"):
                validate_loaded_providers(self.binary, self.root,
                                          self.config("domain", 'payload:\n  - "example.com"\n'),
                                          {"test": {"behavior": "domain", "format": "yaml", "ruleCount": 1}},
                                          timeout=0.2)
        self.assertTrue(children)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_dns_policy_keeps_keyword_coverage(self):
        # Two local DNS responders identify which resolver the policy selected.
        # No upstream network or credentials are used in this regression test.
        stop = threading.Event()
        sockets, threads = [], []

        def responder(sock, address):
            sock.settimeout(0.1)
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                question = data[12:]
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(address)
                reply = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
                sock.sendto(reply, peer)

        process = None
        try:
            for address in ["192.0.2.1", "192.0.2.2"]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                sockets.append(sock)
                thread = threading.Thread(target=responder, args=(sock, address), daemon=True)
                thread.start()
                threads.append(thread)
            config = {
                "rule-providers": {
                    "proxy-merged-" + kind: {"behavior": behavior, "format": "yaml"}
                    for kind, behavior in (("domain", "domain"), ("classical", "classical"), ("ip", "ipcidr"))
                },
                "rules": ["RULE-SET,proxy-merged-domain,PROXY",
                          "RULE-SET,proxy-merged-classical,PROXY",
                          "RULE-SET,proxy-merged-ip,PROXY,no-resolve"],
                "dns": {"nameserver-policy": {"rule-set:proxy-merged-domain,proxy-merged-classical": []}},
            }
            fixtures = {
                "proxy-merged-domain": 'payload:\n  - "exact.example"\n  - "+.suffix.example"\n',
                "proxy-merged-classical": 'payload:\n  - "DOMAIN-KEYWORD,google"\n',
                "proxy-merged-ip": 'payload:\n  - "192.0.2.0/24"\n',
            }
            for name, provider in config["rule-providers"].items():
                path = self.root / (name + ".yaml")
                path.write_text(fixtures[name])
                provider.update(type="file", path=str(path))
            config["proxy-groups"] = [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}]
            config["rules"].append("MATCH,REJECT")
            controller = controller_port()
            secret = secrets.token_urlsafe(32)
            config["external-controller"] = f"127.0.0.1:{controller}"
            config["secret"] = secret
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            dns = config["dns"]
            dns.update(enable=True, listen=f"127.0.0.1:{port}", ipv6=False,
                       nameserver=[f"udp://127.0.0.1:{sockets[0].getsockname()[1]}"],
                       **{"enhanced-mode": "redir-host", "use-hosts": False})
            for key in dns["nameserver-policy"]:
                dns["nameserver-policy"][key] = [f"udp://127.0.0.1:{sockets[1].getsockname()[1]}"]
            path = self.root / "dns-test.yaml"
            path.write_text(yaml.safe_dump(config))
            with (self.root / "dns-test.log").open("wb") as log:
                process = subprocess.Popen([self.binary, "-d", str(self.root), "-f", str(path)],
                                           stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 5
            while True:
                self.assertIsNone(process.poll(), (self.root / "dns-test.log").read_text())
                try:
                    status = provider_status(controller, secret)
                    if len(status) == 3 and all(p["ruleCount"] > 0 for p in status.values()):
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    self.fail("DNS fixture providers did not load")
                time.sleep(0.05)
            for host, expected in [("exact.example", "192.0.2.2"),
                                   ("sub.suffix.example", "192.0.2.2"),
                                   ("google.com", "192.0.2.2"),
                                   ("notgoogle.invalid", "192.0.2.2"),
                                   ("unmatched.invalid", "192.0.2.1")]:
                with self.subTest(host=host), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    question = b"".join(bytes([len(label)]) + label.encode() for label in host.split("."))
                    query = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0) + question + b"\x00\x00\x01\x00\x01"
                    client.sendto(query, ("127.0.0.1", port))
                    reply = client.recv(4096)
                    self.assertEqual(socket.inet_ntoa(reply[-4:]), expected)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            stop.set()
            for sock in sockets:
                sock.close()
            for thread in threads:
                thread.join(timeout=1)
