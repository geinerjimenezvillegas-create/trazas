"""T1110.003 - Password spraying: few attempts against many accounts."""

from __future__ import annotations

from collections.abc import Iterator

from trazas import windows
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Scenario


class WindowsPasswordSpray(Scenario):
    id = "windows-spray"
    name = "Windows password spraying"
    description = (
        "One external IP tries a single password against many accounts on a domain "
        "controller (one 4625 per account, mixing real and non-existent users), "
        "and one account eventually succeeds."
    )
    platform = "windows"
    techniques = ("T1110.003",)

    def generate(self, ctx: GenContext) -> Iterator[Event]:
        dc = ctx.server("DC")
        attacker_ip = ctx.external_ip()
        real_users = ctx.users(ctx.rng.randint(15, 40))
        fake_users = [ctx.bad_username() for _ in range(ctx.rng.randint(3, 8))]
        targets = [(u, True) for u in real_users] + [(u, False) for u in dict.fromkeys(fake_users)]
        ctx.rng.shuffle(targets)
        winner = ctx.rng.choice(real_users)
        t = ctx.jitter(60, 900)

        for user, exists in targets:
            t += ctx.jitter(30.0, 180.0)  # low and slow to stay under lockout thresholds
            if user == winner:
                yield windows.logon_success(
                    ctx, ctx.at(t), computer=dc, user=user, logon_type=3, ip=attacker_ip,
                    workstation="-", scenario=self.id, malicious=True, technique="T1110.003",
                )  # fmt: skip
            else:
                yield windows.logon_failure(
                    ctx, ctx.at(t), computer=dc, user=user, user_exists=exists, logon_type=3,
                    ip=attacker_ip, workstation="-", scenario=self.id, malicious=True,
                    technique="T1110.003",
                )  # fmt: skip
