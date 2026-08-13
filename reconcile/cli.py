"""Command-line entry point for the RECONCILE baseline."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog="reconcile")


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
