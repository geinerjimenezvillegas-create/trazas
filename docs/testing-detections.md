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

## 4. Other tools

- **Splunk / Elastic**: ingest the JSONL as-is; field names stay the same.
- **Sigma**: convert your rule with `sigma-cli` to the backend you loaded the data into.
- **Linux**: `trazas generate ssh-bruteforce -f raw > auth.log` and point any
  syslog-aware tool (or `grep`) at it.
