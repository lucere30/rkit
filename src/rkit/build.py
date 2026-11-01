"""Build rulesets independently, then assemble one guarded publication plan."""
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

import yaml

from .config import load, managed_path, safe_file, sources_for, layout_for
from .fetch import digest, snapshots
from .parsers import parse
from .renderers import CAPABILITIES, render
from .transform import exclude, optimize


def json_text(data):
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def fingerprint(root):
    root = Path(root)
    paths = [root / "rkit.yaml", root / "pyproject.toml"]
    for directory in ("src/rkit", "tools", "custom", "lq/manual", ".github/workflows"):
        paths += [p for p in (root / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    values = {p.relative_to(root).as_posix(): digest(safe_file(root, p.relative_to(root).as_posix()).read_bytes()) for p in paths if p.exists()}
    return digest(json_text(values).encode())


def engine_hash(root):
    paths = sorted((Path(root) / "src/rkit").glob("*.py"))
    return digest(b"".join(p.name.encode() + b"\0" + p.read_bytes() for p in paths))


def read_manifest(root):
    path = Path(root) / "manifest.json"
    if not path.exists():
        return {"version": 1, "rulesets": {}}
    data = json.loads(path.read_text())
    if data.get("version") != 1 or not isinstance(data.get("rulesets"), dict):
        raise ValueError("invalid managed-output manifest")
    owners = {}
    for name, targets in data["rulesets"].items():
        if not isinstance(targets, dict):
            raise ValueError("invalid manifest targets")
        for target, entry in targets.items():
            if target not in CAPABILITIES or not isinstance(entry.get("outputs"), dict):
                raise ValueError("invalid manifest target entry")
            for path, sha in entry["outputs"].items():
                if not managed_path(path) or path in owners or not isinstance(sha, str) or len(sha) != 64:
                    raise ValueError(f"invalid/duplicate managed output: {path}")
                owners[path] = (name, target)
                safe_file(root, path)
    return data


def validate_local(root, cfg):
    """Offline CI validates editable files, including direct-use no-resolve policy."""
    for name, spec in cfg["rulesets"].items():
        purpose = spec.get("purpose", "route")
        for source in spec["sources"]:
            if "path" not in source:
                continue
            path = source["path"]
            kwargs = {"manual": True} if path.startswith("lq/manual/") else {}
            rules = parse(safe_file(root, path).read_text(encoding="utf-8-sig"), source["format"], path, **kwargs)
            for target in spec["targets"]:
                render(rules, target, name, purpose=purpose, omit=spec.get("omit", {}).get(target, []))
        for field in ("additions", "exclusions"):
            if field in spec:
                path = spec[field]
                parse(safe_file(root, path).read_text(encoding="utf-8-sig"),
                      "domain-list" if purpose == "fakeip" else "classical", path, allow_empty=True)


def build_one(root, name, spec, enabled, remote, engine):
    """Process every target's native upstream as a complete, guarded unit."""
    files, entries = {}, {}
    report = {"targets": {}}
    purpose = spec.get("purpose", "route")
    overlays, extra_inputs = {}, []
    for field in ("exclusions", "additions"):
        path = spec.get(field)
        data = safe_file(root, path).read_bytes() if path else b""
        overlays[field] = parse(data.decode("utf-8-sig"), "domain-list" if purpose == "fakeip" else "classical", path or field, allow_empty=True)
        if path:
            extra_inputs.append({"source": path, "sha256": digest(data)})
    for target in enabled:
        sources = sources_for(spec, target)
        upstream, inputs = [], []
        for source in sources:
            ref = source.get("url", source.get("path"))
            data = remote[ref] if "url" in source else safe_file(root, ref).read_bytes()
            if isinstance(data, Exception):
                raise ValueError(f"{target}: {ref}: {data}")
            kwargs = {"manual": True} if source.get("path", "").startswith("lq/manual/") else {}
            parsed = parse(data.decode("utf-8-sig"), source["format"], ref, **kwargs)
            entry = {"source": ref, "sha256": digest(data)}
            if "include_types" in source:
                selected = [r for r in parsed if r.kind in source["include_types"]]
                if not selected:
                    raise ValueError(f"{target}: {ref}: include_types matched no rules; retaining previous subscription")
                entry.update(parsed_rules=len(parsed), selected_rules=len(selected))
                parsed = selected
            upstream.extend(parsed)
            inputs.append(entry)
        retained = exclude(upstream, overlays["exclusions"])
        rules = optimize(retained + overlays["additions"], collapse_ip=spec.get("collapse_ip", False))
        if not rules:
            raise ValueError(f"{target}: {name}: empty result; refusing to erase subscription")
        outputs, skipped = render(rules, target, name, purpose=purpose,
                                  layout=layout_for(spec, target), omit=spec.get("omit", {}).get(target, []))
        manual = sources[0].get("path", "").startswith("lq/manual/")
        if target == "loon" and manual:
            outputs = {}
        files.update(outputs)
        entry = {"engine": engine, "config_sha256": digest(json_text(spec).encode()),
                 "inputs": inputs + extra_inputs,
                 "outputs": {p: digest(v.encode()) for p, v in outputs.items()},
                 "omitted": dict(Counter(r["type"] for r in skipped)), "rules": len(rules) - len(skipped)}
        if target == "loon" and manual:
            entry["subscription"] = sources[0]["path"]
        entries[target] = entry
        report["targets"][target] = {"input_rules": len(upstream), "output_rules": len(rules),
                                     "omitted": skipped, "outputs": list(outputs)}
        if "input_rules" not in report:
            report.update(input_rules=len(upstream), excluded=len(upstream) - len(retained),
                          added=len(overlays["additions"]), output_rules=len(rules))
    return files, entries, report


def build(root, *, cache_dir=None, offline=False, fetcher=None):
    root = Path(root).resolve()
    start = fingerprint(root)
    cfg = load(root)
    previous = read_manifest(root)
    manifest = deepcopy(previous)
    owners = {path: (name, target) for name, targets in previous["rulesets"].items()
              for target, entry in targets.items() for path in entry["outputs"]}
    selected = {name: [t for t in spec["targets"] if cfg["targets"][t]] for name, spec in cfg["rulesets"].items()}
    urls = [source["url"] for name, spec in cfg["rulesets"].items()
            for target in selected[name] for source in sources_for(spec, target) if "url" in source]
    kwargs = {"fetcher": fetcher} if fetcher is not None else {}
    remote = snapshots(urls, cache_dir=cache_dir, offline=offline, **kwargs)
    engine = engine_hash(root)
    outputs, deletions, preconditions = {}, set(), {}
    reports, failed = {}, {}

    def check_old(path, sha):
        file = safe_file(root, path)
        actual = digest(file.read_bytes()) if file.exists() else None
        if actual is not None and actual != sha:
            raise ValueError(f"managed file edited outside generator; preserve it before rebuilding: {path}")
        return actual

    def job(item):
        name, spec = item
        try:
            return build_one(root, name, spec, selected[name], remote, engine)
        except (ValueError, OSError, UnicodeError, TypeError, yaml.YAMLError) as error:
            return error

    items = [(name, spec) for name, spec in cfg["rulesets"].items() if selected[name]]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(job, items))
    for (name, spec), result in zip(items, results):
        if isinstance(result, Exception):
            failed[name] = str(result)
            continue
        files, entries, report = result
        try:
            old = {p: sha for t in selected[name] for p, sha in previous["rulesets"].get(name, {}).get(t, {}).get("outputs", {}).items()}
            conditions = {p: check_old(p, sha) for p, sha in old.items()}
            for p in files:
                if p in outputs or (p in owners and owners[p] != (name, next(t for t, e in entries.items() if p in e["outputs"]))):
                    raise ValueError(f"output ownership collision: {p}")
                if p not in old and safe_file(root, p).exists():
                    raise ValueError(f"unmanaged output exists; refusing overwrite: {p}")
                conditions.setdefault(p, None)
            outputs.update(files)
            deletions.update(set(old) - set(files))
            preconditions.update(conditions)
            manifest["rulesets"].setdefault(name, {}).update(entries)
            reports[name] = report
        except ValueError as error:
            failed[name] = str(error)
    # A removed definition is explicit retirement. Disabled targets retain old outputs.
    for name in set(previous["rulesets"]) - set(cfg["rulesets"]):
        if failed:
            continue  # A failed migration must not retire the previous subscriptions.
        entries = previous["rulesets"][name]
        # An explicitly retired ruleset must remove all its managed outputs,
        # including artifacts left by globally disabled targets.
        try:
            conditions = {p: check_old(p, sha) for e in entries.values() for p, sha in e["outputs"].items()}
            deletions.update(conditions)
            preconditions.update(conditions)
            del manifest["rulesets"][name]
        except ValueError as error:
            failed[name] = str(error)
    # Detect new-new name collisions (e.g. foo split vs foo_domain combined) globally.
    claimed = []
    for targets in manifest["rulesets"].values():
        claimed.extend(p for e in targets.values() for p in e["outputs"])
    if len(claimed) != len(set(claimed)):
        raise ValueError("duplicate output paths in resulting manifest")
    if fingerprint(root) != start:
        raise ValueError("inputs changed during build; discard this snapshot and rebuild")
    outputs["manifest.json"] = json_text(manifest)
    old_manifest = root / "manifest.json"
    preconditions["manifest.json"] = digest(old_manifest.read_bytes()) if old_manifest.exists() else None
    return {"outputs": outputs, "delete": sorted(deletions), "preconditions": preconditions,
            "fingerprint": start, "report": {"successful": reports, "failed": failed,
            "disabled": [t for t, enabled in cfg["targets"].items() if not enabled]}}


def stage(result, directory):
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise ValueError(f"staging directory must be empty: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    plan = {k: v for k, v in result.items() if k != "outputs"}
    plan["files"] = {p: digest(text.encode()) for p, text in result["outputs"].items()}
    for path, text in result["outputs"].items():
        file = safe_file(directory / "files", path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
    (directory / "plan.json").write_text(json_text(plan), encoding="utf-8")
