"""Deterministic generation context.

All randomness flows through a single seeded :class:`random.Random` so that the
same ``seed`` + ``start`` always produce byte-identical output. This is a
simulation PRNG, not a security primitive.

Every address and domain produced here comes from ranges reserved for
documentation or private use (RFC 5737, RFC 1918, RFC 2606), so generated
datasets never point at real infrastructure.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# RFC 5737 documentation ranges, used for "external" / attacker addresses.
_EXTERNAL_NETS = ("203.0.113", "198.51.100", "192.0.2")
# RFC 1918 range used for internal hosts.
_INTERNAL_NET = "10.20"

DOMAIN = "CORP"
DNS_SUFFIX = "corp.example.com"  # RFC 2606 reserved

_FIRST_NAMES = (
    "ana", "luis", "maria", "jose", "carla", "diego", "sofia", "pablo",
    "laura", "andres", "valeria", "jorge", "elena", "mateo", "paula", "ricardo",
)  # fmt: skip
_LAST_NAMES = (
    "mora", "rojas", "vargas", "jimenez", "solis", "castro", "araya", "chaves",
    "quesada", "alfaro", "brenes", "campos",
)  # fmt: skip

COMMON_BAD_USERNAMES = (
    "administrator", "admin", "user", "test", "guest", "scanner",
    "backup", "support", "sql", "ftp", "oracle", "postgres", "root", "ubuntu",
)  # fmt: skip


@dataclass
class GenContext:
    """Shared state for one generation run."""

    seed: int
    start: datetime
    rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.start.tzinfo is None:
            raise ValueError("start must be timezone-aware")
        self.rng = random.Random(self.seed)  # noqa: S311 - simulation, not crypto

    # --- time -----------------------------------------------------------------
    def at(self, seconds: float) -> datetime:
        return self.start + timedelta(seconds=seconds)

    def jitter(self, low: float, high: float) -> float:
        return self.rng.uniform(low, high)

    # --- identities -----------------------------------------------------------
    def username(self) -> str:
        return f"{self.rng.choice(_FIRST_NAMES)}.{self.rng.choice(_LAST_NAMES)}"

    def users(self, n: int) -> list[str]:
        seen: dict[str, None] = {}
        while len(seen) < n:
            seen[self.username()] = None
        return list(seen)

    def bad_username(self) -> str:
        return self.rng.choice(COMMON_BAD_USERNAMES)

    def workstation(self) -> str:
        return f"WS{self.rng.randint(1, 250):03d}"

    def server(self, role: str = "SRV") -> str:
        return f"{role}{self.rng.randint(1, 20):02d}"

    def fqdn(self, host: str) -> str:
        return f"{host}.{DNS_SUFFIX}"

    # --- network --------------------------------------------------------------
    def external_ip(self) -> str:
        return f"{self.rng.choice(_EXTERNAL_NETS)}.{self.rng.randint(1, 254)}"

    def internal_ip(self) -> str:
        return f"{_INTERNAL_NET}.{self.rng.randint(0, 31)}.{self.rng.randint(2, 254)}"

    def ephemeral_port(self) -> int:
        return self.rng.randint(49152, 65535)

    # --- misc -----------------------------------------------------------------
    def pid(self) -> int:
        return self.rng.randint(300, 65000)

    def logon_id(self) -> str:
        return f"0x{self.rng.getrandbits(32):x}"
