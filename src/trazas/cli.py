"""Command-line interface."""

from __future__ import annotations

import argparse
import secrets
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from trazas import __version__, engine
from trazas.degrade import FieldDegradation
from trazas.scenarios import REGISTRY
from trazas.schema import (
    DEFAULT_EVENT_TABLE,
    DEFAULT_LABEL_TABLE,
    EVENT_COLUMNS,
    LABEL_COLUMNS,
    kql_create_table,
)
from trazas.writers import FORMATS, UnsupportedFormatError, write, write_labels


def _parse_start(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _non_negative_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _drop_spec(value: str) -> FieldDegradation:
    try:
        return FieldDegradation.parse_drop(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _truncate_spec(value: str) -> FieldDegradation:
    try:
        return FieldDegradation.parse_truncate(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trazas",
        description="Generate realistic, labelled attack logs for testing detections.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available scenarios")

    desc = sub.add_parser("describe", help="show details of a scenario")
    desc.add_argument("scenario", choices=sorted(REGISTRY))

    gen = sub.add_parser("generate", help="generate a dataset")
    gen.add_argument("scenarios", nargs="+", choices=sorted(REGISTRY), metavar="SCENARIO")
    gen.add_argument("-s", "--seed", type=int, help="PRNG seed (random if omitted, printed to stderr)")
    gen.add_argument("--start", type=_parse_start, help="ISO 8601 start time (default: now, UTC)")
    gen.add_argument("-n", "--noise", type=_non_negative_int, default=200,
                     help="benign events per platform (default: 200)")  # fmt: skip
    gen.add_argument("-f", "--format", choices=FORMATS, default="jsonl")
    gen.add_argument("-o", "--output", type=Path, help="output file (default: stdout)")
    gen.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    gen.add_argument("--labels", action="store_true",
                     help="add a _trazas ground-truth field to each JSON record")  # fmt: skip
    gen.add_argument("--drop-field", type=_drop_spec, action="append", default=[], metavar="NAME:RATIO",
                     help="remove field NAME from that share of the events carrying it, "
                          "e.g. CallTrace:0.3 (repeatable)")  # fmt: skip
    gen.add_argument("--truncate-field", type=_truncate_spec, action="append", default=[],
                     metavar="NAME:LEN:RATIO",
                     help="cut string field NAME to LEN characters in that share of the events "
                          "where it is longer, e.g. CallTrace:60:0.5 "
                          "(repeatable; applied after drops)")  # fmt: skip
    gen.add_argument("--labels-file", type=Path, metavar="PATH",
                     help="write ground truth to a separate JSONL file keyed by TrazasEventId, "
                          "so rules can be tested blind and scored afterwards")  # fmt: skip

    schema = sub.add_parser("schema", help="print KQL commands that create the tables before ingesting")
    schema.add_argument("--table", default=DEFAULT_EVENT_TABLE,
                        help=f"events table name (default: {DEFAULT_EVENT_TABLE})")  # fmt: skip
    schema.add_argument("--labels-table", default=DEFAULT_LABEL_TABLE,
                        help=f"labels table name (default: {DEFAULT_LABEL_TABLE})")  # fmt: skip
    return parser


def _cmd_list() -> int:
    width = max(len(sid) for sid in REGISTRY)
    for sid, cls in sorted(REGISTRY.items()):
        print(f"{sid:<{width}}  {cls.platform:<8} {','.join(cls.techniques):<22} {cls.name}")
    return 0


def _cmd_describe(scenario_id: str) -> int:
    cls = REGISTRY[scenario_id]
    print(f"{cls.name} ({cls.id})")
    print(f"Platform:   {cls.platform}")
    print(f"Techniques: {', '.join(cls.techniques)}")
    for t in cls.techniques:
        print(f"            https://attack.mitre.org/techniques/{t.replace('.', '/')}/")
    print(f"\n{cls.description}")
    return 0


def _cmd_schema(table: str, labels_table: str) -> int:
    # Commands go to stdout (pipe-friendly); the hint goes to stderr. Each command is
    # its own block so it can be run separately in the ADX query editor.
    events_cmd = kql_create_table(table, EVENT_COLUMNS)
    labels_cmd = kql_create_table(labels_table, LABEL_COLUMNS)
    print(f"{events_cmd}\n\n{labels_cmd}")
    print(
        "trazas: run each command on its own (cursor inside it, then Shift+Enter) BEFORE the "
        "first ingestion; the second is only needed with --labels-file. A table created "
        "earlier by the ingestion wizard may have other column types (e.g. EventID as "
        "string), which .create-merge cannot change: use a new name with --table, or drop "
        "that table first.",
        file=sys.stderr,
    )
    return 0


def _check_generate_args(args: argparse.Namespace, degrade: list[FieldDegradation]) -> int | None:
    """Validate option combinations; return an exit code to stop, or None to go on."""
    output: Path | None = args.output
    labels_file: Path | None = args.labels_file
    if args.format == "raw":
        # Raw lines are pre-rendered text: degrading fields would not change them, and
        # they carry no TrazasEventId to join a labels file on.
        if degrade:
            print("error: --drop-field/--truncate-field need --format jsonl", file=sys.stderr)
            return 2
        if labels_file is not None:
            print("error: --labels-file needs --format jsonl", file=sys.stderr)
            return 2
    if labels_file is not None and output is not None and labels_file.resolve() == output.resolve():
        print("error: --labels-file must differ from --output", file=sys.stderr)
        return 2
    # Check every target before writing anything, so a refusal never leaves half a dataset.
    if not args.force:
        for path in (output, labels_file):
            if path is not None and path.exists():
                print(f"error: {path} exists (use --force to overwrite)", file=sys.stderr)
                return 1
    return None


def _cmd_generate(args: argparse.Namespace) -> int:
    seed: int = args.seed if args.seed is not None else secrets.randbits(63)
    start: datetime = args.start or datetime.now(timezone.utc).replace(microsecond=0)
    degrade: list[FieldDegradation] = [*args.drop_field, *args.truncate_field]
    if (code := _check_generate_args(args, degrade)) is not None:
        return code
    events = engine.generate(args.scenarios, seed=seed, start=start, noise=args.noise, degrade=degrade)

    if args.format == "raw" and any(e.raw is None for e in events):
        print("error: --format raw only supports Linux scenarios; use jsonl", file=sys.stderr)
        return 2

    labels_file: Path | None = args.labels_file
    mode: Literal["w", "x"] = "w" if args.force else "x"  # "x" never clobbers a file
    try:
        if args.output is None:
            count = write(events, sys.stdout, args.format, labels=args.labels)
        else:
            with args.output.open(mode, encoding="utf-8", newline="\n") as fh:
                count = write(events, fh, args.format, labels=args.labels)
        if labels_file is not None:
            with labels_file.open(mode, encoding="utf-8", newline="\n") as fh:
                write_labels(events, fh)
    # Only reachable if another process creates a target after the check above.
    except FileExistsError as exc:  # pragma: no cover - race, not deterministically testable
        print(f"error: {exc.filename} exists (use --force to overwrite)", file=sys.stderr)
        return 1

    summary = f"trazas: {count} events, seed={seed}, start={start.isoformat()}"
    if degrade:
        summary += f", degraded={sum(1 for e in events if e.degraded)}"
    print(summary, file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            return _cmd_list()
        if args.command == "describe":
            return _cmd_describe(args.scenario)
        if args.command == "schema":
            return _cmd_schema(args.table, args.labels_table)
        return _cmd_generate(args)
    except (ValueError, UnsupportedFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover - e.g. `trazas generate ... | head`
        sys.stderr.close()
        return 0
