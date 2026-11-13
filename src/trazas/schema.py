"""Column schema of the JSON output.

Creating the tables before ingesting avoids a common pitfall: tools such as Azure Data
Explorer infer columns from the first rows of a file, so columns that appear only in
rarer events (Sysmon's ``CallTrace``, for instance) can be silently left out.
``tests/test_schema.py`` checks that this list matches what the generators emit.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

Column = tuple[str, str]  # (name, KQL type)

EVENT_COLUMNS: Final[tuple[Column, ...]] = (
    # Common to every record
    ("TimeGenerated", "datetime"),
    ("Source", "string"),
    ("TrazasEventId", "long"),
    ("Computer", "string"),
    ("EventID", "long"),
    ("Activity", "string"),
    ("Channel", "string"),
    # Windows Security / System (Sentinel SecurityEvent names)
    ("Account", "string"),
    ("TargetUserName", "string"),
    ("TargetDomainName", "string"),
    ("TargetLogonId", "string"),
    ("LogonType", "long"),
    ("LogonProcessName", "string"),
    ("AuthenticationPackageName", "string"),
    ("WorkstationName", "string"),
    ("IpAddress", "string"),
    ("IpPort", "long"),
    ("Status", "string"),
    ("SubStatus", "string"),
    ("SubjectUserName", "string"),
    ("SubjectDomainName", "string"),
    ("ShareName", "string"),
    ("ShareLocalPath", "string"),
    ("ServiceName", "string"),
    ("ImagePath", "string"),
    ("ServiceType", "string"),
    ("StartType", "string"),
    ("AccountName", "string"),
    # Sysmon (1 process creation, 10 process access, 11 file create)
    ("Image", "string"),
    ("CommandLine", "string"),
    ("ParentImage", "string"),
    ("ProcessId", "long"),
    ("ParentProcessId", "long"),
    ("User", "string"),
    ("IntegrityLevel", "string"),
    ("SourceImage", "string"),
    ("SourceProcessId", "long"),
    ("SourceThreadId", "long"),
    ("SourceUser", "string"),
    ("TargetImage", "string"),
    ("TargetProcessId", "long"),
    ("TargetUser", "string"),
    ("GrantedAccess", "string"),
    ("CallTrace", "string"),
    ("TargetFilename", "string"),
    # Linux auth.log (sshd)
    ("HostName", "string"),
    ("ProcessName", "string"),
    ("ProcessID", "long"),  # auth.log naming; distinct from Sysmon's ProcessId in KQL
    ("SyslogMessage", "string"),
    ("SrcIp", "string"),
    ("Outcome", "string"),
    # Ground truth, present with --labels
    ("_trazas", "dynamic"),
)

LABEL_COLUMNS: Final[tuple[Column, ...]] = (
    ("TrazasEventId", "long"),
    ("scenario", "string"),
    ("malicious", "bool"),
    ("technique", "string"),
    ("degraded", "dynamic"),
)

DEFAULT_EVENT_TABLE: Final = "SecurityEvent"
DEFAULT_LABEL_TABLE: Final = "TrazasLabels"

_TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def kql_create_table(table: str, columns: Sequence[Column]) -> str:
    """Return a ``.create-merge table`` command (safe to run more than once)."""
    if not _TABLE_NAME.match(table):
        raise ValueError(f"invalid table name: {table!r}")
    cols = ", ".join(f"{name}: {kql_type}" for name, kql_type in columns)
    return f".create-merge table {table} ({cols})"
