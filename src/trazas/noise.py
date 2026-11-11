"""Benign background activity.

Noise matters: a detection that only works on attack-only data is untested.
It deliberately includes look-alikes (a user mistyping a password, admins
using SMB shares) so rules have to tell the difference.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from trazas import linux, windows
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Platform

NOISE_SCENARIO = "benign"

_DEFENDER_DIR = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0"
_SENSE_DIR = "C:\\Program Files\\Windows Defender Advanced Threat Protection"
# Legitimate processes that routinely open lsass.exe. Defender uses the same access
# mask as Mimikatz and the EDR sensor asks for full access, so a rule keyed only on
# GrantedAccess will fire on these.
_LSASS_READERS = (
    (f"{_DEFENDER_DIR}\\MsMpEng.exe", "0x1010", f"{_DEFENDER_DIR}\\MpSvc.dll"),
    (f"{_SENSE_DIR}\\MsSense.exe", "0x1fffff", f"{_SENSE_DIR}\\MsSense.exe"),
    ("C:\\Windows\\System32\\svchost.exe", "0x1000", "C:\\Windows\\System32\\RPCRT4.dll"),
)


def _benign_lsass_access(ctx: GenContext, ts: datetime, host: str, lsass_pids: dict[str, int]) -> Event:
    image, access, module = ctx.rng.choice(_LSASS_READERS)
    lsass_pid = lsass_pids.setdefault(host, ctx.rng.randint(600, 1200))
    return windows.sysmon_process_access(
        ctx, ts, computer=host, source_image=image, source_pid=ctx.pid(),
        source_user="NT AUTHORITY\\SYSTEM", target_image=windows.LSASS_IMAGE, target_pid=lsass_pid,
        granted_access=access, trace=windows.call_trace(ctx, (windows.NTDLL, windows.KERNELBASE, module)),
        scenario=NOISE_SCENARIO,
    )  # fmt: skip


def windows_noise(ctx: GenContext, count: int, window_s: float) -> Iterator[Event]:
    users = ctx.users(12)
    hosts = [ctx.workstation() for _ in range(8)] + [ctx.server("FS"), ctx.server("DC")]
    lsass_pids: dict[str, int] = {}
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
        elif roll < 0.21:  # AV/EDR touching lsass: look-alike for credential dumping
            yield _benign_lsass_access(ctx, ts, host, lsass_pids)
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
