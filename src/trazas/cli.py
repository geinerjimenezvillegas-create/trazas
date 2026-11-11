"""Command-line interface."""

from __future__ import annotations

import argparse
import secrets
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from trazas import __version__, engine
from trazas.scenarios import REGISTRY
from trazas.writers import FORMATS, UnsupportedFormatError, write


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


def _cmd_generate(args: argparse.Namespace) -> int:
    seed: int = args.seed if args.seed is not None else secrets.randbits(63)
    start: datetime = args.start or datetime.now(timezone.utc).replace(microsecond=0)
    events = engine.generate(args.scenarios, seed=seed, start=start, noise=args.noise)

    if args.format == "raw" and any(e.raw is None for e in events):
        print("error: --format raw only supports Linux scenarios; use jsonl", file=sys.stderr)
        return 2

    if args.output is None:
        count = write(events, sys.stdout, args.format, labels=args.labels)
    else:
        mode = "w" if args.force else "x"  # "x" refuses to clobber existing files
        try:
            with args.output.open(mode, encoding="utf-8", newline="\n") as fh:
                count = write(events, fh, args.format, labels=args.labels)
        except FileExistsError:
            print(f"error: {args.output} exists (use --force to overwrite)", file=sys.stderr)
            return 1

    print(
        f"trazas: {count} events, seed={seed}, start={start.isoformat()}",
        file=sys.stderr,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            return _cmd_list()
        if args.command == "describe":
            return _cmd_describe(args.scenario)
        return _cmd_generate(args)
    except (ValueError, UnsupportedFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover - e.g. `trazas generate ... | head`
        sys.stderr.close()
        return 0
