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

**Create the tables first.** Run `trazas schema`, then paste its output into the ADX query
editor and run each command on its own (put the cursor inside it and press Shift+Enter).
The commands use `.create-merge`, so running them again is harmless.

Why: if you let the ingestion wizard create the table, ADX infers columns from the first
rows of the file. Columns that only appear in rarer events (Sysmon's `CallTrace`, for
example) can be left out, and rules then fail with *"Failed to resolve ... 'CallTrace'"*.

Then in the ADX web UI: **Get data → Local file → events.jsonl**, choose the **existing**
table `SecurityEvent`, format JSON.

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

### Blind testing with a separate labels file

With `--labels` the answers sit next to the data, which makes it tempting to peek. To
test a rule blind, keep the ground truth in another file:

```console
trazas generate lsass-dump --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 \
  -o events.jsonl --labels-file truth.jsonl
```

Ingest `events.jsonl` into `SecurityEvent` and `truth.jsonl` into `TrazasLabels` (both
created by `trazas schema`). Write the rule against `SecurityEvent` only, then score it by
joining on `TrazasEventId`:

```kql
let flagged =
    SecurityEvent
    | where EventID == 10 and TargetImage endswith "lsass.exe"
    | where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
    | project TrazasEventId;
TrazasLabels
| extend Flagged = TrazasEventId in (flagged)
| where Flagged or malicious
| summarize count() by Flagged, malicious
```

| Flagged | malicious | count |
|---|---|---|
| true | true | 1 |
| true | false | 89 |
| false | true | 2 |

The last row is the Sysmon 1 and 11 events of the attack: this rule only looks at
event 10, so it "misses" them by design. Scoring by event id makes that visible.

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

## Example: incomplete telemetry

Noise produces false positives, which get noticed. Missing data produces **false
negatives**, which nobody notices. Collectors drop long fields, parsers fail, size limits
cut values. `--drop-field` and `--truncate-field` simulate that, reproducibly from the
seed. Only the named field changes; the rest of the dataset is identical. With `--labels`,
each affected event records it in `_trazas.degraded`.

**Attempt 3: the CallTrace rule without CallTrace.** Remove the field from 30% of the
events that carry it:

```console
trazas generate lsass-dump --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 \
  --drop-field CallTrace:0.3 --labels -o lsass-gaps.jsonl
```

Across 100 seeds, the rule from attempt 2 detects only **64 of 100** attacks, with no
error and no warning. When the attack's `CallTrace` is missing, both conditions are false.

**Attempt 4: fail closed.** Treat a missing `CallTrace` as suspicious unless the process
runs from a trusted install path:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "comsvcs.dll")
     or CallTrace contains "UNKNOWN("
     // no call stack: alert unless it comes from a trusted install path
     or (isempty(CallTrace)
         and not(SourceImage startswith @"C:\Program Files\"
                 or SourceImage startswith @"C:\ProgramData\Microsoft\Windows Defender\"))
| summarize count() by Malicious = tobool(_trazas.malicious)
```

→ **100 of 100** detected across the same seeds, still 0 false positives. Trusting paths is
weaker than the call stack (an admin can write to `Program Files`), so this branch only
covers the gap; it does not replace the CallTrace check.

**Truncation is harder.** With `--truncate-field CallTrace:60:1` the stack is cut before
the interesting module, so both rules miss the attack: the value is present, just useless.
No detection rule can fix that. Watch the telemetry itself instead:

```kql
SecurityEvent
| where EventID == 10
| summarize Events = count(), MissingCallTrace = countif(isempty(CallTrace)),
            MinLength = min(strlen(CallTrace)), MaxLength = max(strlen(CallTrace))
```

| Dataset | Events | MissingCallTrace | MinLength | MaxLength |
|---|---|---|---|---|
| clean | 145 | 0 | 112 | 191 |
| `--drop-field CallTrace:0.3` | 145 | 47 | 112 | 159 |
| `--truncate-field CallTrace:60:1` | 145 | 0 | 60 | 60 |

A flat `MaxLength` is the tell-tale sign of a size limit somewhere in the pipeline.

## 4. Other tools

- **Splunk / Elastic**: ingest the JSONL as-is; field names stay the same.
- **Sigma**: convert your rule with `sigma-cli` to the backend you loaded the data into.
- **Linux**: `trazas generate ssh-bruteforce -f raw > auth.log` and point any
  syslog-aware tool (or `grep`) at it.
