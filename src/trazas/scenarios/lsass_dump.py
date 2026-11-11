"""T1003.001 - Credential dumping from LSASS process memory."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from trazas import windows
from trazas.context import DOMAIN, GenContext
from trazas.events import Event
from trazas.scenarios.base import Scenario

TECHNIQUE = "T1003.001"


@dataclass(frozen=True, slots=True)
class _Tool:
    image: str
    # Formatted with ``pid`` (lsass PID), ``dump`` (dump path) and ``exe`` (image basename).
    command: str
    granted_access: str
    modules: tuple[str, ...]
    unknown_frame: bool  # in-memory code shows up as UNKNOWN(...) in CallTrace
    writes_dump: bool


_RUNDLL32 = "C:\\Windows\\System32\\rundll32.exe"
_PROCDUMP = "C:\\Users\\Public\\procdump64.exe"

_TOOLS = (
    # LOLBin: comsvcs.dll exports MiniDump, so no tool needs to be dropped on disk.
    _Tool(
        image=_RUNDLL32,
        command="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {pid} {dump} full",
        granted_access="0x1fffff",
        modules=(
            windows.NTDLL,
            windows.KERNELBASE,
            "C:\\Windows\\SYSTEM32\\dbgcore.DLL",
            "C:\\Windows\\System32\\comsvcs.dll",
            _RUNDLL32,
        ),
        unknown_frame=False,
        writes_dump=True,
    ),
    # Signed Sysinternals binary abused to write a full memory dump.
    _Tool(
        image=_PROCDUMP,
        command="{exe} -accepteula -ma lsass.exe {dump}",
        granted_access="0x1fffff",
        modules=(windows.NTDLL, windows.KERNELBASE, "C:\\Windows\\SYSTEM32\\dbghelp.dll", _PROCDUMP),
        unknown_frame=False,
        writes_dump=True,
    ),
    # Renamed Mimikatz reading credentials straight out of lsass memory.
    _Tool(
        image="C:\\Users\\Public\\svchelper.exe",
        command='{exe} "privilege::debug" "sekurlsa::logonpasswords" exit',
        granted_access="0x1010",
        modules=(windows.NTDLL, windows.KERNELBASE, "C:\\Users\\Public\\svchelper.exe"),
        unknown_frame=True,
        writes_dump=False,
    ),
)

_DUMP_NAMES = ("lsass", "debug", "report", "mem", "out")
_PARENTS = (
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
)


class LsassCredentialDump(Scenario):
    id = "lsass-dump"
    name = "LSASS credential dumping"
    description = (
        "A local admin runs a dumping tool (comsvcs.dll MiniDump, procdump -ma, or a "
        "renamed Mimikatz) that opens lsass.exe with read access (Sysmon 10) and, for the "
        "dump variants, writes a .dmp file (Sysmon 11). Background noise contains benign "
        "lsass access from Defender, the EDR sensor and svchost."
    )
    platform = "windows"
    techniques = (TECHNIQUE,)

    def generate(self, ctx: GenContext) -> Iterator[Event]:
        tool = ctx.rng.choice(_TOOLS)
        host = ctx.workstation()
        user = f"{DOMAIN}\\{ctx.username()}"
        lsass_pid = ctx.rng.randint(600, 1200)
        tool_pid = ctx.pid()
        dump = f"C:\\Windows\\Temp\\{ctx.rng.choice(_DUMP_NAMES)}{ctx.rng.randint(1, 99)}.dmp"
        exe = tool.image.rsplit("\\", 1)[-1]
        t = ctx.jitter(300, 2400)

        yield windows.sysmon_process(
            ctx, ctx.at(t), computer=host, image=tool.image,
            command_line=tool.command.format(pid=lsass_pid, dump=dump, exe=exe),
            parent_image=ctx.rng.choice(_PARENTS), user=user, scenario=self.id,
            malicious=True, technique=TECHNIQUE, pid=tool_pid,
        )  # fmt: skip

        t += ctx.jitter(0.2, 1.5)
        yield windows.sysmon_process_access(
            ctx, ctx.at(t), computer=host, source_image=tool.image, source_pid=tool_pid,
            source_user=user, target_image=windows.LSASS_IMAGE, target_pid=lsass_pid,
            granted_access=tool.granted_access,
            trace=windows.call_trace(ctx, tool.modules, unknown_frame=tool.unknown_frame),
            scenario=self.id, malicious=True, technique=TECHNIQUE,
        )  # fmt: skip

        if tool.writes_dump:
            t += ctx.jitter(1.0, 6.0)
            yield windows.sysmon_file_create(
                ctx.at(t), computer=host, image=tool.image, pid=tool_pid, user=user,
                target_filename=dump, scenario=self.id, malicious=True, technique=TECHNIQUE,
            )  # fmt: skip
