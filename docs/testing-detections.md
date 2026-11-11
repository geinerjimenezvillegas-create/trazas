# Testing detections with trazas

The idea: generate a dataset with known ground truth, run your rule over it, and
measure what it catches and what it wrongly flags.

## 1. Generate a labelled dataset

```console
trazas generate windows-bruteforce windows-spray psexec-lateral \
  --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 --labels -o events.jsonl
```

Pin `--seed` and `--start` so the same dataset can be regenerated in CI.

## 2. Load it into Azure Data Explorer (free, KQL)

In the ADX web UI: **Get data → Local file → events.jsonl**, new table `SecurityEvent`,
format JSON. ADX infers the columns; `_trazas` becomes a `dynamic` column.

## 3. Run the rule and score it

```kql
let detections =
    SecurityEvent
    | where EventID == 4625
    | summarize Failures = count() by IpAddress, bin(TimeGenerated, 10m)
    | where Failures > 20
    | distinct IpAddress;
SecurityEvent
| where EventID == 4625
| extend Flagged = IpAddress in (detections), Malicious = tobool(_trazas.malicious)
| summarize count() by Flagged, Malicious
```

- `Flagged=true, Malicious=true` → true positives
- `Flagged=true, Malicious=false` → false positives
- `Flagged=false, Malicious=true` → missed attacks

Notice that this rule catches `windows-bruteforce` but misses
`windows-spray` entirely, which is low-and-slow by design — exactly the kind of gap this tool is
meant to reveal. A spray rule looks at distinct accounts per source instead:

```kql
SecurityEvent
| where EventID == 4625
| summarize Accounts = dcount(TargetUserName), Attempts = count() by IpAddress, bin(TimeGenerated, 1h)
| where Accounts >= 10
```

## Example: LSASS dumping and look-alikes

Sysmon events share the table in this setup, with Sysmon's own field names
(`SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`). In Sentinel they live in the
`Event` table; the common Sysmon parsers expose the same names.

```console
trazas generate lsass-dump --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 --labels -o lsass.jsonl
```

**Attempt 1: access mask only.** Append a scoring line to the rule:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| summarize count() by Malicious = tobool(_trazas.malicious)
```

| Malicious | count |
|---|---|
| true | 1 |
| false | 89 |

The 89 are noise that `trazas` adds on purpose: Defender (`MsMpEng.exe`, `0x1010`, the same
mask as Mimikatz), the EDR sensor (`MsSense.exe`, `0x1fffff`, same as procdump and comsvcs)
and `svchost.exe` (`0x1000`, filtered out by the mask). In production this rule would be
muted within a week.

**Attempt 2: how lsass was opened.** Dumpers go through the minidump APIs
(`dbgcore.dll`, `dbghelp.dll`, `comsvcs.dll`) or run from memory, which Sysmon shows as an
`UNKNOWN(...)` frame. Security products do neither:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
// Look at HOW lsass was opened, not only the access mask:
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "comsvcs.dll")  // minidump APIs
     or CallTrace contains "UNKNOWN("                                     // code running from memory
| summarize count() by Malicious = tobool(_trazas.malicious)
```

| Malicious | count |
|---|---|
| true | 1 |

**Check every variant.** `lsass-dump` picks one tool per seed: seed 1 is comsvcs
`MiniDump`, 5 is a renamed Mimikatz and 7 is `procdump -ma`. Run the rule on all three. A
tempting shortcut such as `GrantedAccess == "0x1fffff"` misses the Mimikatz one.

This rule is a better starting point, not a guarantee: a careful attacker can hide the call
stack, so pair it with other signals (dump files in Sysmon 11, unusual parent processes).

## 4. Other tools

- **Splunk / Elastic**: ingest the JSONL as-is; field names stay the same.
- **Sigma**: convert your rule with `sigma-cli` to the backend you loaded the data into.
- **Linux**: `trazas generate ssh-bruteforce -f raw > auth.log` and point any
  syslog-aware tool (or `grep`) at it.
