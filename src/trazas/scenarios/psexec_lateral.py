"""T1021.002 / T1569.002 - PsExec-style lateral movement over SMB."""

from __future__ import annotations

from collections.abc import Iterator

from trazas import windows
from trazas.context import GenContext
from trazas.events import Event
from trazas.scenarios.base import Scenario

_RECON = (
    "cmd.exe /c whoami /all",
    'cmd.exe /c net group "Domain Admins" /domain',
    "cmd.exe /c ipconfig /all",
    "cmd.exe /c tasklist /v",
)


class PsExecLateralMovement(Scenario):
    id = "psexec-lateral"
    name = "PsExec lateral movement"
    description = (
        "A compromised workstation authenticates to a server over SMB (4624 type 3), "
        "touches IPC$ and ADMIN$ (5140), installs the PSEXESVC service (7045) and runs "
        "recon commands as SYSTEM (Sysmon 1)."
    )
    platform = "windows"
    techniques = ("T1021.002", "T1569.002")

    def generate(self, ctx: GenContext) -> Iterator[Event]:
        src_host = ctx.workstation()
        src_ip = ctx.internal_ip()
        target = ctx.server("FS")
        user = ctx.username()
        t = ctx.jitter(120, 1200)
        lm = "T1021.002"
        svc = "T1569.002"

        yield windows.logon_success(
            ctx, ctx.at(t), computer=target, user=user, logon_type=3, ip=src_ip,
            workstation=src_host, scenario=self.id, malicious=True, technique=lm,
        )  # fmt: skip
        for share in ("IPC$", "ADMIN$"):
            t += ctx.jitter(0.05, 0.5)
            yield windows.share_access(
                ctx.at(t), computer=target, user=user, share=share, ip=src_ip,
                scenario=self.id, malicious=True, technique=lm,
            )  # fmt: skip

        t += ctx.jitter(0.2, 1.5)
        yield windows.service_install(
            ctx.at(t), computer=target, service_name="PSEXESVC",
            image_path="%SystemRoot%\\PSEXESVC.exe", scenario=self.id, malicious=True,
            technique=svc,
        )  # fmt: skip
        t += ctx.jitter(0.1, 0.8)
        yield windows.sysmon_process(
            ctx, ctx.at(t), computer=target, image="C:\\Windows\\PSEXESVC.exe",
            command_line="C:\\Windows\\PSEXESVC.exe", parent_image="C:\\Windows\\System32\\services.exe",
            user="NT AUTHORITY\\SYSTEM", scenario=self.id, malicious=True, technique=svc,
        )  # fmt: skip

        for cmd in ctx.rng.sample(_RECON, k=ctx.rng.randint(2, len(_RECON))):
            t += ctx.jitter(3.0, 40.0)
            yield windows.sysmon_process(
                ctx, ctx.at(t), computer=target, image="C:\\Windows\\System32\\cmd.exe",
                command_line=cmd, parent_image="C:\\Windows\\PSEXESVC.exe",
                user="NT AUTHORITY\\SYSTEM", scenario=self.id, malicious=True, technique=svc,
            )  # fmt: skip
