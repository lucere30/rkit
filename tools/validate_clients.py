#!/usr/bin/env python3
"""Validate staged outputs with pinned, checksum-verified Linux amd64 clients."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import io
import http.client
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time

import yaml

from rkit.yamlio import safe_load

CLIENTS = {
    "mihomo": (
        "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1-v1.19.33.gz",
        "8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524",
    ),
    "sing-box": (
        "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz",
        "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
    ),
}


def controller_port():
    """Ask the OS for a free loopback port; bind failure is caught at startup."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def provider_status(port, secret):
    # HTTPConnection uses a direct socket; environment HTTP proxies are ignored.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request("GET", "/providers/rules", headers={"Authorization": "Bearer " + secret})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"provider API returned HTTP {response.status}")
        data = json.loads(response.read())
        providers = data.get("providers")
        if providers is None:  # Controller may start before ApplyConfig.
            return {}
        if not isinstance(providers, dict):
            raise ValueError("invalid provider API response")
        return providers
    finally:
        connection.close()


def check_provider_snapshot(actual, expected):
    """Reject silent rule skips, wrong behaviors/formats, and missing providers."""
    if set(actual) != set(expected):
        raise ValueError(f"provider names differ: expected {sorted(expected)}, got {sorted(actual)}")
    for name, wanted in expected.items():
        found = actual[name]
        for field, value in wanted.items():
            got = found.get(field)
            if isinstance(got, str) and field in {"behavior", "format"}:
                got = got.lower()
                if field == "format":
                    got = {"yamlrule": "yaml", "textrule": "text", "mrsrule": "mrs"}.get(got, got)
            if got != value:
                raise ValueError(f"{name}: loaded {field}={got!r}, expected {value!r}")


LOAD_ERROR = re.compile(
    r"level=(?:error|fatal)|parse classical rule .* error:|"
    r"skip invalid domain from rule provider:|invalid Ipcidr:|initial rule provider .* error:",
    re.IGNORECASE,
)


def validate_loaded_providers(executable, temp, config, expected, *, timeout=30):
    """Unlike -t, normal startup actually reads and parses provider files."""
    temp = Path(temp)
    controller = controller_port()
    secret = secrets.token_urlsafe(32)
    config = dict(config, **{"external-controller": f"127.0.0.1:{controller}",
                             "secret": secret, "log-level": "info"})
    path = temp / "mihomo.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    command = [str(executable), "-d", str(temp), "-f", str(path)]
    parsed = subprocess.run(command + ["-t"], timeout=120, capture_output=True, text=True)
    if parsed.returncode:
        raise ValueError("Mihomo configuration validation failed:\n" + parsed.stdout + parsed.stderr)
    log_path = temp / "mihomo-startup.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + timeout
            last = {}
            while time.monotonic() < deadline:
                errors = [line for line in log_path.read_text(errors="replace").splitlines()
                          if LOAD_ERROR.search(line)]
                if errors:
                    raise ValueError("Mihomo provider initialization failed:\n" + "\n".join(errors))
                if process.poll() is not None:
                    raise ValueError(f"Mihomo exited before validation ({process.returncode}):\n"
                                     + log_path.read_text(errors="replace"))
                try:
                    last = provider_status(controller, secret)
                except (OSError, http.client.HTTPException):
                    time.sleep(0.05)
                    continue
                # A provider exists before its file is loaded. UpdatedAt separates
                # pending initialization from a completed load containing zero rules.
                if set(last) == set(expected) and all(
                    entry.get("updatedAt") and not entry["updatedAt"].startswith("0001-")
                    for entry in last.values()
                ):
                    check_provider_snapshot(last, expected)
                    # Recheck the log after the snapshot so parser warnings cannot
                    # race the earlier read (even if rule counts happen to agree).
                    errors = [line for line in log_path.read_text(errors="replace").splitlines()
                              if LOAD_ERROR.search(line)]
                    if errors:
                        raise ValueError("Mihomo provider initialization failed:\n" + "\n".join(errors))
                    return
                time.sleep(0.05)
            raise ValueError(f"Mihomo provider initialization timed out; expected {expected}, last {last}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def binary(name, directory):
    url, expected = CLIENTS[name]
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / (name + ".archive")
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        subprocess.run(["curl", "-fLsS", "--connect-timeout", "10", "--max-time", "120", "--retry", "2", url, "-o", str(archive)], check=True, timeout=300)
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{name}: official release checksum mismatch")
    executable = directory / name
    if name == "mihomo":
        executable.write_bytes(gzip.decompress(data))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive_file:
            members = [m for m in archive_file.getmembers() if m.isfile() and Path(m.name).name == name]
            if len(members) != 1:
                raise ValueError("unexpected sing-box archive layout")
            executable.write_bytes(archive_file.extractfile(members[0]).read())
    executable.chmod(0o755)
    return executable.resolve()


def validate(stage, cache):
    stage = Path(stage)
    plan = json.loads((stage / "plan.json").read_text())
    files = stage / "files"
    targets = set()
    if any(p.startswith("cat/") for p in plan["files"]):
        targets.add("mihomo")
    if any(p.startswith("singbox/") for p in plan["files"]):
        targets.add("sing-box")
    with ThreadPoolExecutor(max_workers=2) as pool:
        clients = dict(zip(sorted(targets), pool.map(lambda name: binary(name, Path(cache)), sorted(targets))))
    with tempfile.TemporaryDirectory(prefix="rkit-native-") as directory:
        temp = Path(directory)
        providers, route_rules, filters, expected = {}, [], [], {}
        for name in plan["files"]:
            if name.startswith("cat/"):
                payload = safe_load((files / name).read_text())
                if (not isinstance(payload, dict) or set(payload) != {"payload"}
                        or not isinstance(payload["payload"], list) or not payload["payload"]
                        or not all(isinstance(v, str) and v and "\n" not in v and "\r" not in v
                                   for v in payload["payload"])):
                    raise ValueError(f"{name}: expected nonempty payload of single-line strings")
                values = payload["payload"]
                stem = Path(name).stem
                if name.endswith(("_domain.yaml", "-domain.yaml")):
                    behavior = "domain"
                elif name.endswith(("_ip.yaml", "-ip.yaml")):
                    behavior = "ipcidr"
                elif name.endswith(("_classical.yaml", "-classical.yaml")) or any("," in v for v in values):
                    behavior = "classical"
                else:
                    behavior = "domain"
                destination = temp / "rules" / Path(name).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((files / name).read_bytes())
                providers[stem] = {"type": "file", "behavior": behavior, "format": "yaml",
                                   "path": str(destination)}
                expected[stem] = {"behavior": behavior, "format": "yaml", "ruleCount": len(values)}
                if name.endswith(("_ip.yaml", "-ip.yaml")):
                    route_rules.append(f"RULE-SET,{stem},DIRECT,no-resolve")
                elif behavior == "domain" and not name.endswith(("_domain.yaml", "-domain.yaml")):
                    filters.append(f"rule-set:{stem}")
                else:
                    route_rules.append(f"RULE-SET,{stem},DIRECT")
            elif name.startswith("singbox/") and name.endswith(".json"):
                subprocess.run([str(clients["sing-box"]), "rule-set", "compile", "--output", str(temp / "check.srs"), str((files / name).resolve())], check=True, timeout=120)
        if "mihomo" in clients:
            config = {"mode": "rule", "rule-providers": providers, "rules": route_rules + ["MATCH,DIRECT"],
                      "dns": {"enable": True, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                              "nameserver": ["1.1.1.1"], "fake-ip-filter": filters}}
            validate_loaded_providers(clients["mihomo"], temp, config, expected)
    print("Pinned native validation passed for staged targets: " + (", ".join(sorted(targets)) or "none"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".rkit-cache/clients"))
    args = parser.parse_args()
    validate(args.stage, args.cache)
