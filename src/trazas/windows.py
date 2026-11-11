"""Builders for Windows events (Sentinel ``SecurityEvent``-style column names)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from trazas.context import DOMAIN, GenContext
from trazas.events import Event

# NTSTATUS codes seen in 4625 events.
STATUS_LOGON_FAILURE = "0xc000006d"
SUB_BAD_PASSWORD = "0xc000006a"  # noqa: S105 - NTSTATUS code, not a secret
SUB_NO_SUCH_USER = "0xc0000064"

_ACTIVITY = {
    4624: "4624 - An account was successfully logged on.",
    4625: "4625 - An account failed to log on.",
    4634: "4634 - An account was logged off.",
    5140: "5140 - A network share object was accessed.",
    7045: "7045 - A service was installed in the system.",
}


def _base(computer: str, event_id: int, channel: str = "Security") -> dict[str, Any]:
    return {
        "Computer": computer,
        "EventID": event_id,
        "Activity": _ACTIVITY.get(event_id, str(event_id)),
        "Channel": channel,
    }


def logon_success(
    ctx: GenContext,
    ts: datetime,
    *,
    computer: str,
    user: str,
    logon_type: int,
    ip: str,
    workstation: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
    auth_package: str = "NTLM",
) -> Event:
    fields = _base(computer, 4624)
    fields.update(
        Account=f"{DOMAIN}\\{user}",
        TargetUserName=user,
        TargetDomainName=DOMAIN,
        TargetLogonId=ctx.logon_id(),
        LogonType=logon_type,
        LogonProcessName="NtLmSsp" if auth_package == "NTLM" else "Kerberos",
        AuthenticationPackageName=auth_package,
        WorkstationName=workstation,
        IpAddress=ip,
        IpPort=ctx.ephemeral_port() if ip != "-" else 0,
    )
    return Event(ts, "windows_security", fields, scenario, malicious, technique)


def logon_failure(
    ctx: GenContext,
    ts: datetime,
    *,
    computer: str,
    user: str,
    user_exists: bool,
    logon_type: int,
    ip: str,
    workstation: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    fields = _base(computer, 4625)
    fields.update(
        Account=f"{DOMAIN}\\{user}",
        TargetUserName=user,
        TargetDomainName=DOMAIN,
        LogonType=logon_type,
        LogonProcessName="NtLmSsp",
        AuthenticationPackageName="NTLM",
        Status=STATUS_LOGON_FAILURE,
        SubStatus=SUB_BAD_PASSWORD if user_exists else SUB_NO_SUCH_USER,
        WorkstationName=workstation,
        IpAddress=ip,
        IpPort=ctx.ephemeral_port(),
    )
    return Event(ts, "windows_security", fields, scenario, malicious, technique)


def logoff(
    ctx: GenContext, ts: datetime, *, computer: str, user: str, logon_type: int, scenario: str
) -> Event:
    fields = _base(computer, 4634)
    fields.update(
        Account=f"{DOMAIN}\\{user}",
        TargetUserName=user,
        TargetDomainName=DOMAIN,
        TargetLogonId=ctx.logon_id(),
        LogonType=logon_type,
    )
    return Event(ts, "windows_security", fields, scenario)


def share_access(
    ts: datetime,
    *,
    computer: str,
    user: str,
    share: str,
    ip: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    fields = _base(computer, 5140)
    fields.update(
        Account=f"{DOMAIN}\\{user}",
        SubjectUserName=user,
        SubjectDomainName=DOMAIN,
        ShareName=f"\\\\*\\{share}",
        ShareLocalPath="C:\\Windows" if share == "ADMIN$" else "",
        IpAddress=ip,
    )
    return Event(ts, "windows_security", fields, scenario, malicious, technique)


def service_install(
    ts: datetime,
    *,
    computer: str,
    service_name: str,
    image_path: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    fields = _base(computer, 7045, channel="System")
    fields.update(
        ServiceName=service_name,
        ImagePath=image_path,
        ServiceType="user mode service",
        StartType="demand start",
        AccountName="LocalSystem",
    )
    return Event(ts, "windows_system", fields, scenario, malicious, technique)


def sysmon_process(
    ctx: GenContext,
    ts: datetime,
    *,
    computer: str,
    image: str,
    command_line: str,
    parent_image: str,
    user: str,
    scenario: str,
    malicious: bool = False,
    technique: str | None = None,
) -> Event:
    fields: dict[str, Any] = {
        "Computer": computer,
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": image,
        "CommandLine": command_line,
        "ParentImage": parent_image,
        "ProcessId": ctx.pid(),
        "ParentProcessId": ctx.pid(),
        "User": user,
        "IntegrityLevel": "System" if user == "NT AUTHORITY\\SYSTEM" else "High",
    }
    return Event(ts, "sysmon", fields, scenario, malicious, technique)
