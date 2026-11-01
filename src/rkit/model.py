"""Client-neutral matching semantics; DNS resolution is a renderer policy."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    source: str = field(default="", compare=False)
    line: int = field(default=0, compare=False)

    @property
    def location(self):
        return f"{self.source}:{self.line}"


DOMAIN_TYPES = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"})
TARGET_IP_TYPES = frozenset({"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"})
CIDR_TYPES = frozenset({"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"})
TEXT_TYPES = frozenset({"USER-AGENT", "URL-REGEX"})
RULE_TYPES = DOMAIN_TYPES | TARGET_IP_TYPES | CIDR_TYPES | TEXT_TYPES | {"DOMAIN-PATTERN"}
