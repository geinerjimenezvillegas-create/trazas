"""T1110.001 - SSH brute force against an internet-facing Linux host."""

from __future__ import annotations

from collections.abc import Iterator

from trazas import linux
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Scenario


class SshBruteForce(Scenario):
    id = "ssh-bruteforce"
    name = "SSH brute force"
    description = (
        "An external IP hammers sshd with common usernames (mostly invalid), then "
        "guesses the password of a real account and logs in."
    )
    platform = "linux"
    techniques = ("T1110.001",)

    def generate(self, ctx: GenContext) -> Iterator[Event]:
        host = ctx.rng.choice(("web01", "vpn-gw", "bastion", "app02"))
        attacker_ip = ctx.external_ip()
        victim = ctx.rng.choice(("deploy", "ubuntu", "admin"))
        t = ctx.jitter(30, 600)

        for _ in range(ctx.rng.randint(40, 120)):
            t += ctx.jitter(0.3, 3.0)
            guess_real = ctx.rng.random() < 0.25
            user = victim if guess_real else ctx.bad_username()
            yield linux.failed_password(
                ctx, ctx.at(t), host=host, user=user, user_exists=user in {victim, "root"},
                src_ip=attacker_ip, scenario=self.id, malicious=True, technique="T1110.001",
            )  # fmt: skip

        t += ctx.jitter(1.0, 4.0)
        yield linux.accepted(
            ctx, ctx.at(t), host=host, user=victim, src_ip=attacker_ip, method="password",
            scenario=self.id, malicious=True, technique="T1110.001",
        )  # fmt: skip
