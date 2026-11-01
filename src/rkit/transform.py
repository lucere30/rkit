"""Conservative set operations, restricted to one policy-free ruleset."""
import ipaddress
import re

from .model import Rule

PLAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SAFE_KEYWORD = re.compile(r"[a-z0-9-]+\Z")


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


def _keyword_coverage(rules):
    """Find conservative literal keywords that subsume other rules."""
    keywords = {r.value for r in rules if r.kind == "DOMAIN-KEYWORD"
                and SAFE_KEYWORD.fullmatch(r.value)}
    # Check shortest keywords first. A surviving shorter keyword can cover
    # a longer keyword and every hostname containing it.
    minimal = []
    for keyword in sorted(keywords, key=lambda value: (len(value), value)):
        if not any(shorter in keyword for shorter in minimal):
            minimal.append(keyword)
    return minimal


def _domain_covered(rule, suffixes, keywords):
    """Only eliminate domain rules when coverage is provable."""
    if not plain(rule.value):
        return False
    if rule.kind == "DOMAIN":
        if any(parent in suffixes for parent in ancestors(rule.value)):
            return True
    elif rule.kind == "DOMAIN-SUFFIX":
        if any(parent in suffixes for parent in ancestors(rule.value, include_self=False)):
            return True
    else:
        return False
    return any(keyword in rule.value for keyword in keywords)


def _collapse_destination_ip(rules):
    """Collapse destination IPv4 and IPv6 separately; leave source IP alone."""
    networks = {4: [], 6: []}
    retained = []
    for rule in rules:
        if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(rule.value)
            networks[network.version].append(network)
        else:
            retained.append(rule)
    for version, group in networks.items():
        kind = "IP-CIDR" if version == 4 else "IP-CIDR6"
        retained.extend(Rule(kind, str(network), "collapsed")
                        for network in ipaddress.collapse_addresses(group))
    return retained


def optimize(rules, *, collapse_ip=False):
    """Deduplicate within a single ruleset, preserving matching coverage."""
    rules = list(dict.fromkeys(rules))
    suffixes = {rule.value for rule in rules
                if rule.kind == "DOMAIN-SUFFIX" and plain(rule.value)}
    keywords = _keyword_coverage(rules)
    eligible_keywords = {rule.value for rule in rules\n                         if rule.kind == "DOMAIN-KEYWORD"\n                         and SAFE_KEYWORD.fullmatch(rule.value)}\n    optimized = [
        rule for rule in rules
        if not (rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}
                and _domain_covered(rule, suffixes, keywords))
        and not (rule.kind == "DOMAIN-KEYWORD"
                 and rule.value in eligible_keywords
                 and any(keyword != rule.value and keyword in rule.value
                         for keyword in keywords))
    ]
    return _collapse_destination_ip(optimized) if collapse_ip else optimized
