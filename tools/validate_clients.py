#!/usr/bin/env python3
"""Validate staged outputs with pinned, checksum-verified Linux amd64 clients."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

import yaml

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
        providers, route_rules, filters = {}, [], []
        for name in plan["files"]:
            if name.startswith("cat/"):
                values = yaml.safe_load((files / name).read_text())["payload"]
                if not values:
                    raise ValueError(f"{name}: empty rule provider")
                stem = Path(name).stem
                if name.endswith("_domain.yaml"):
                    behavior = "domain"
                elif name.endswith("_ip.yaml"):
                    behavior = "ipcidr"
                elif name.endswith("_classical.yaml") or any("," in v for v in values):
                    behavior = "classical"
                else:
                    behavior = "domain"
                destination = temp / "rules" / Path(name).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((files / name).read_bytes())
                providers[stem] = {"type": "file", "behavior": behavior, "format": "yaml",
                                   "path": str(destination)}
                if name.endswith("_ip.yaml"):
                    route_rules.append(f"RULE-SET,{stem},DIRECT,no-resolve")
                elif behavior == "domain" and not name.endswith("_domain.yaml"):
                    filters.append(f"rule-set:{stem}")
                else:
                    route_rules.append(f"RULE-SET,{stem},DIRECT")
            elif name.startswith("singbox/") and name.endswith(".json"):
                subprocess.run([str(clients["sing-box"]), "rule-set", "compile", "--output", str(temp / "check.srs"), str((files / name).resolve())], check=True, timeout=120)
        if "mihomo" in clients:
            config = {"mode": "rule", "rule-providers": providers, "rules": route_rules + ["MATCH,DIRECT"],
                      "dns": {"enable": True, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                              "nameserver": ["1.1.1.1"], "fake-ip-filter": filters}}
            path = temp / "mihomo.yaml"
            path.write_text(yaml.safe_dump(config, sort_keys=False))
            subprocess.run([str(clients["mihomo"]), "-t", "-d", str(temp), "-f", str(path)], check=True, timeout=120)
    print("Pinned Mihomo and sing-box native validation passed for staged targets.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".rkit-cache/clients"))
    args = parser.parse_args()
    validate(args.stage, args.cache)
