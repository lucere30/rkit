"""Strict declarative configuration and file ownership boundaries."""
from pathlib import Path, PurePosixPath
import re

import yaml

from .model import RULE_TYPES
from .parsers import PARSERS
from .renderers import CAPABILITIES, OUTPUT_DIRS, planned_paths


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError(f"duplicate or non-string config key: {key!r}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError(f"invalid config fields; allowed={sorted(allowed)}, required={sorted(required)}")


def relative(path):
    if not isinstance(path, str) or not path or "\\" in path:
        raise ValueError(f"invalid relative path: {path!r}")
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or str(p) != path or path == ".":
        raise ValueError(f"unsafe path: {path}")
    return path


def input_path(path):
    relative(path)
    if not path.startswith(("custom/", "lq/manual/")):
        raise ValueError(f"input must be under custom/ or lq/manual/: {path}")
    return path


def managed_path(path):
    relative(path)
    # Root lq files are allowed only for migration/previous manifests.
    return (path.startswith(tuple(directory + "/" for directory in OUTPUT_DIRS.values()))
            or (path.startswith("lq/") and path.count("/") == 1)) and Path(path).suffix in {".list", ".txt", ".yaml", ".json"}


def safe_file(root, path):
    relative(path)
    root = Path(root).resolve()
    candidate = root / path
    if not candidate.resolve().is_relative_to(root):
        raise ValueError(f"path escapes repository: {path}")
    if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root and p.is_relative_to(root)):
        raise ValueError(f"symlink is not allowed: {path}")
    return candidate


def sources_for(spec, target):
    return spec.get("sources_by_target", {}).get(target, spec["sources"])


def layout_for(spec, target):
    return spec.get("target_layouts", {}).get(target, spec.get("layout", "combined"))


def load(root):
    cfg = yaml.load((Path(root) / "rkit.yaml").read_text(), Loader=UniqueLoader)
    keys(cfg, {"version", "targets", "rulesets"}, {"version", "targets", "rulesets"})
    if type(cfg["version"]) is not int or cfg["version"] != 1 or not isinstance(cfg["rulesets"], dict) or not cfg["rulesets"]:
        raise ValueError("expected version 1 and nonempty rulesets")
    keys(cfg["targets"], CAPABILITIES, CAPABILITIES)
    if any(type(v) is not bool for v in cfg["targets"].values()):
        raise ValueError("target switches must be booleans")
    for name, spec in cfg["rulesets"].items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
            raise ValueError(f"invalid ruleset name: {name}")
        keys(spec, {"sources", "sources_by_target", "additions", "exclusions", "targets", "purpose", "collapse_ip", "layout", "target_layouts", "omit"}, {"sources", "targets"})
        targets = spec["targets"]
        if not isinstance(targets, list) or not targets or any(t not in CAPABILITIES for t in targets) or len(set(targets)) != len(targets):
            raise ValueError(f"{name}: invalid targets")
        overrides = spec.get("sources_by_target", {})
        keys(overrides, targets)
        for target in targets:
            if not isinstance(sources_for(spec, target), list) or not sources_for(spec, target):
                raise ValueError(f"{name}: missing sources for {target}")
        layouts = spec.get("target_layouts", {})
        keys(layouts, targets)
        for target, layout in layouts.items():
            if layout not in {"combined", "split", "native-split"} or (layout == "native-split" and target != "mihomo"):
                raise ValueError(f"{name}: invalid layout for {target}")
        if spec.get("purpose", "route") not in {"route", "fakeip"}:
            raise ValueError(f"{name}: invalid purpose")
        if spec.get("purpose") == "fakeip" and targets != ["mihomo"]:
            raise ValueError("Fake-IP is currently a Mihomo-only purpose")
        if spec.get("layout", "combined") not in {"combined", "split"}:
            raise ValueError("layout must be combined or split")
        if type(spec.get("collapse_ip", False)) is not bool:
            raise ValueError("collapse_ip must be boolean")
        omit = spec.get("omit", {})
        keys(omit, targets)
        for target, kinds in omit.items():
            if not isinstance(kinds, list) or any(k not in RULE_TYPES or k in CAPABILITIES[target] for k in kinds):
                raise ValueError(f"{name}: omission list must name known unsupported types")
        sources = spec["sources"]
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"{name}: missing sources")
        for source in sources + [item for group in overrides.values() for item in group]:
            keys(source, {"url", "path", "format", "include_types"}, {"format"})
            if ("url" in source) == ("path" in source) or source["format"] not in PARSERS:
                raise ValueError(f"{name}: source requires one url/path and known format")
            if "include_types" in source:
                kinds = source["include_types"]
                if ("url" not in source or not isinstance(kinds, list) or not kinds
                        or any(not isinstance(k, str) or k not in RULE_TYPES for k in kinds)
                        or len(set(kinds)) != len(kinds)):
                    raise ValueError(f"{name}: include_types requires a remote source and unique known rule types")
            if "url" in source:
                if not isinstance(source["url"], str) or not source["url"].startswith("https://"):
                    raise ValueError("remote sources must use HTTPS")
            else:
                input_path(source["path"])
                if source["path"].startswith("lq/manual/") and source["format"] != "classical":
                    raise ValueError("manual Loon subscriptions must use classical format")
        for field in ("additions", "exclusions"):
            if field in spec:
                input_path(spec[field])
        manual = [s for s in sources if s.get("path", "").startswith("lq/manual/")]
        if manual and (len(sources) != 1 or "additions" in spec or "exclusions" in spec or spec.get("layout", "combined") != "combined"):
            raise ValueError("directly subscribed manual lists cannot be mixed with overlays, sources or split layout")
    claimed = {}
    registered = {s["path"] for spec in cfg["rulesets"].values() for s in spec["sources"] if "path" in s}
    for path in (Path(root) / "lq/manual").rglob("*"):
        if path.suffix in {".list", ".txt"} and path.relative_to(root).as_posix() not in registered:
            raise ValueError(f"unregistered manual subscription: {path}")
    for name, spec in cfg["rulesets"].items():
        for target in spec["targets"]:
            if target == "loon" and sources_for(spec, target)[0].get("path", "").startswith("lq/manual/"):
                paths = []
            else:
                paths = planned_paths(target, name, layout_for(spec, target), spec.get("purpose", "route"))
            for path in paths:
                if path in claimed:
                    raise ValueError(f"output path collision between {claimed[path]} and {name}: {path}")
                claimed[path] = name
    return cfg
