"""Conservative set operations, restricted to one policy-free ruleset."""
import ipaddress
import re

from .model import Rule

PLAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def plain(value):
    labels = value.split(".")
    if len(labels) < 2 or not all(PLAIN.fullmatch(label) for label in labels):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def ancestors(value, include_self=True):
    labels = value.split(".")
    return (".".join(labels[i:]) for i in range(0 if include_self else 1, len(labels)))


def exclude(rules, exclusions):
    exact = set(exclusions)
    suffixes = {r.value for r in exclusions if r.kind == "DOMAIN-SUFFIX" and plain(r.value)}
    return [r for r in rules if r not in exact and not (
        r.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and plain(r.value)
        and any(parent in suffixes for parent in ancestors(r.value))
    )]


def optimize(rules, *, collapse_ip=False):
    rules = list(dict.fromkeys(rules))
    suffixes = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX" and plain(r.value)}
    rules = [r for r in rules if not (
        r.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and plain(r.value)
        and any(parent in suffixes for parent in ancestors(r.value, r.kind == "DOMAIN"))
    )]
    if collapse_ip:
        # Destination and source address predicates must never be merged together.
        groups = {("dst", 4): [], ("dst", 6): [], ("src", 4): []}
        kept = []
        for r in rules:
            if r.kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
                network = ipaddress.ip_network(r.value)
                direction = "src" if r.kind == "SRC-IP-CIDR" else "dst"
                groups[(direction, network.version)].append(network)
            else:
                kept.append(r)
        for (direction, version), networks in groups.items():
            kind = "SRC-IP-CIDR" if direction == "src" else ("IP-CIDR" if version == 4 else "IP-CIDR6")
            kept.extend(Rule(kind, str(n), "collapsed") for n in ipaddress.collapse_addresses(networks))
        rules = kept
    return rules
