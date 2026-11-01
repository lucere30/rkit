"""Input adapters preserve distinctions between exact, suffix and wildcard rules."""
import ipaddress
import re

import yaml

from .model import CIDR_TYPES, DOMAIN_TYPES, Rule, TARGET_IP_TYPES, TEXT_TYPES

LABEL = re.compile(r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\Z")


def domain(value, *, pattern=False):
    body = value[2:] if value.startswith("+.") and pattern else value
    body = body.removeprefix(".")
    if (not body or len(body) > 253 or any(
        not (pattern and label == "*") and not LABEL.fullmatch(label)
        for label in body.split(".")
    )):
        raise ValueError(f"invalid domain or unsupported pattern: {value!r}")


def classical(text, source, *, allow_empty=False, manual=False):
    result = []
    for number, raw in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            kind, sep, rest = line.partition(",")
            kind = kind.strip().upper()
            if not sep or not rest.strip() or any(ord(c) < 32 for c in line):
                raise ValueError("expected TYPE,value without control characters")
            if kind in TEXT_TYPES:
                # Expressions can contain spaces and commas; do not split or rewrite.
                value = rest.strip()
            else:
                fields = [s.strip() for s in rest.split(",")]
                value, options = fields[0], fields[1:]
                if kind in TARGET_IP_TYPES:
                    if any(option != "no-resolve" for option in options):
                        raise ValueError("only no-resolve is supported; policies belong in client config")
                    if manual and options != ["no-resolve"]:
                        raise ValueError("directly subscribed manual IP rules require exactly one no-resolve")
                elif options:
                    raise ValueError("unexpected options or embedded policy")
                if kind in CIDR_TYPES:
                    network = ipaddress.ip_network(value, strict=False)
                    if kind == "IP-CIDR6" and network.version != 6:
                        raise ValueError("IP-CIDR6 requires IPv6")
                    if kind == "IP-CIDR" and network.version == 6:
                        kind = "IP-CIDR6"
                    value = str(network)
                elif kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    domain(value)
                elif kind == "DOMAIN-KEYWORD":
                    if not value or re.search(r"[\s,/:<>#]", value):
                        raise ValueError("invalid domain keyword")
                elif kind == "IP-ASN":
                    if not value.isascii() or not value.isdecimal() or not 0 <= int(value) <= 4294967295:
                        raise ValueError("invalid ASN")
                elif kind == "GEOIP":
                    if not re.fullmatch(r"[A-Za-z]{2}|LAN", value):
                        raise ValueError("invalid GEOIP code")
                else:
                    raise ValueError(f"unsupported rule type: {kind}")
            result.append(Rule(kind, value, source, number))
        except ValueError as error:
            raise ValueError(f"{source}:{number}: {error}") from error
    if not result and not allow_empty:
        raise ValueError(f"{source}: empty ruleset")
    return result


def domain_list(text, source, *, allow_empty=False):
    result = []
    for number, raw in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            domain(value, pattern=True)
        except ValueError as error:
            raise ValueError(f"{source}:{number}: {error}") from error
        if value.startswith("+.") and "*" not in value:
            kind, value = "DOMAIN-SUFFIX", value[2:]
        elif "*" in value or value.startswith("."):
            kind = "DOMAIN-PATTERN"
        else:
            kind = "DOMAIN"
        result.append(Rule(kind, value, source, number))
    if not result and not allow_empty:
        raise ValueError(f"{source}: empty domain list")
    return result


def payload(text, source, parser, **kwargs):
    data = yaml.safe_load(text)
    if (not isinstance(data, dict) or set(data) != {"payload"}
            or not isinstance(data["payload"], list)
            or not all(isinstance(v, str) and "\n" not in v and "\r" not in v for v in data["payload"])):
        raise ValueError(f"{source}: expected a payload array of single-line strings")
    return parser("\n".join(data["payload"]), source, **kwargs)


PARSERS = {
    "classical": classical,
    "domain-list": domain_list,
    "clash-classical": lambda text, source, **kw: payload(text, source, classical, **kw),
    "clash-domain": lambda text, source, **kw: payload(text, source, domain_list, **kw),
}


def parse(text, format, source, **kwargs):
    return PARSERS[format](text, source, **kwargs)
