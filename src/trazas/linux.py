"""Builders for Linux ``auth.log`` (sshd) events."""

from __future__ import annotations

from datetime import datetime

from trazas.context import GenContext
from trazas.events import Event


def _syslog_ts(ts: datetime) -> str:
    # Classic BSD syslog format, e.g. "Nov  1 03:04:05".
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"


def sshd(
    ctx: GenContext,
    ts: datetime,
    *,
    host: str,
    message: str,
    user: str,
    src_ip: str,
    outcome: str,
    scenario: str,
    pid: int | None = None,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    pid = pid if pid is not None else ctx.pid()
    raw = f"{_syslog_ts(ts)} {host} sshd[{pid}]: {message}"
    fields = {
        "HostName": host,
        "ProcessName": "sshd",
        "ProcessID": pid,
        "SyslogMessage": message,
        "User": user,
        "SrcIp": src_ip,
        "Outcome": outcome,
    }
    return Event(ts, "linux_auth", fields, scenario, malicious, technique, raw=raw)


def failed_password(
    ctx: GenContext,
    ts: datetime,
    *,
    host: str,
    user: str,
    user_exists: bool,
    src_ip: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    who = user if user_exists else f"invalid user {user}"
    msg = f"Failed password for {who} from {src_ip} port {ctx.ephemeral_port()} ssh2"
    return sshd(
        ctx, ts, host=host, message=msg, user=user, src_ip=src_ip, outcome="failure",
        scenario=scenario, malicious=malicious, technique=technique,
    )  # fmt: skip


def accepted(
    ctx: GenContext,
    ts: datetime,
    *,
    host: str,
    user: str,
    src_ip: str,
    method: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    msg = f"Accepted {method} for {user} from {src_ip} port {ctx.ephemeral_port()} ssh2"
    return sshd(
        ctx, ts, host=host, message=msg, user=user, src_ip=src_ip, outcome="success",
        scenario=scenario, malicious=malicious, technique=technique,
    )  # fmt: skip
