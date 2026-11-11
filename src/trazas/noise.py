"""Benign background activity.

Noise matters: a detection that only works on attack-only data is untested.
It deliberately includes look-alikes (a user mistyping a password, admins
using SMB shares) so rules have to tell the difference.
"""

from __future__ import annotations

from collections.abc import Iterator

from trazas import linux, windows
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Platform

NOISE_SCENARIO = "benign"


def windows_noise(ctx: GenContext, count: int, window_s: float) -> Iterator[Event]:
    users = ctx.users(12)
    hosts = [ctx.workstation() for _ in range(8)] + [ctx.server("FS"), ctx.server("DC")]
    for _ in range(count):
        ts = ctx.at(ctx.jitter(0, window_s))
        user = ctx.rng.choice(users)
        host = ctx.rng.choice(hosts)
        roll = ctx.rng.random()
        if roll < 0.08:  # honest typo
            yield windows.logon_failure(
                ctx, ts, computer=host, user=user, user_exists=True, logon_type=2, ip="127.0.0.1",
                workstation=host, scenario=NOISE_SCENARIO,
            )  # fmt: skip
        elif roll < 0.15:
            yield windows.share_access(
                ts, computer=ctx.rng.choice(hosts), user=user, share="IPC$",
                ip=ctx.internal_ip(), scenario=NOISE_SCENARIO,
            )  # fmt: skip
        elif roll < 0.35:
            yield windows.logoff(ctx, ts, computer=host, user=user, logon_type=3, scenario=NOISE_SCENARIO)
        else:
            logon_type = ctx.rng.choice((2, 3, 3, 3, 7, 11))
            ip = "-" if logon_type in (2, 7, 11) else ctx.internal_ip()
            yield windows.logon_success(
                ctx, ts, computer=host, user=user, logon_type=logon_type, ip=ip, workstation=host,
                scenario=NOISE_SCENARIO, auth_package=ctx.rng.choice(("Kerberos", "Kerberos", "NTLM")),
            )  # fmt: skip


def linux_noise(ctx: GenContext, count: int, window_s: float) -> Iterator[Event]:
    admins = ["deploy", "ansible", ctx.username().split(".")[0]]
    hosts = ["web01", "app02", "bastion", "db01"]
    for _ in range(count):
        ts = ctx.at(ctx.jitter(0, window_s))
        user = ctx.rng.choice(admins)
        src = ctx.internal_ip()
        if ctx.rng.random() < 0.05:  # someone fat-fingers a password once
            yield linux.failed_password(
                ctx, ts, host=ctx.rng.choice(hosts), user=user, user_exists=True, src_ip=src,
                scenario=NOISE_SCENARIO,
            )  # fmt: skip
        else:
            yield linux.accepted(
                ctx, ts, host=ctx.rng.choice(hosts), user=user, src_ip=src, method="publickey",
                scenario=NOISE_SCENARIO,
            )  # fmt: skip


def noise_for(platform: Platform, ctx: GenContext, count: int, window_s: float) -> Iterator[Event]:
    if platform == "windows":
        return windows_noise(ctx, count, window_s)
    return linux_noise(ctx, count, window_s)
