"""T1110.001 - Password guessing against a single account over the network."""

from __future__ import annotations

from collections.abc import Iterator

from trazas import windows
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Scenario


class WindowsBruteForce(Scenario):
    id = "windows-bruteforce"
    name = "Windows password guessing"
    description = (
        "An external IP sends dozens of failed network logons (4625, LogonType 3) "
        "against one account on an exposed server, then succeeds (4624)."
    )
    platform = "windows"
    techniques = ("T1110.001",)

    def generate(self, ctx: GenContext) -> Iterator[Event]:
        target = ctx.server("RDS")
        attacker_ip = ctx.external_ip()
        attacker_ws = ctx.rng.choice(("kali", "DESKTOP-4F2K9QZ", "WIN-AB12CD34EF", "-"))
        victim = ctx.username()
        attempts = ctx.rng.randint(30, 80)
        t = ctx.jitter(60, 600)

        for _ in range(attempts):
            t += ctx.jitter(0.5, 4.0)
            yield windows.logon_failure(
                ctx, ctx.at(t), computer=target, user=victim, user_exists=True, logon_type=3,
                ip=attacker_ip, workstation=attacker_ws, scenario=self.id, malicious=True,
                technique="T1110.001",
            )  # fmt: skip

        t += ctx.jitter(1.0, 5.0)
        yield windows.logon_success(
            ctx, ctx.at(t), computer=target, user=victim, logon_type=3, ip=attacker_ip,
            workstation=attacker_ws, scenario=self.id, malicious=True, technique="T1110.001",
        )  # fmt: skip
