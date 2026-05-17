"""Command line interface for binary-comp."""

from __future__ import annotations

import argparse
import sys

from binary_comp.analyzers.data import (
    DataOptions,
    compare_address,
    compare_global_data,
    find_missing_globals,
    format_address_comparison,
    format_comparison,
    format_missing_globals,
    require_globals_source,
)
from binary_comp.analyzers.globals import GlobalsAuditOptions, audit_globals, format_report
from binary_comp.analyzers.values import ValuesOptions, check_values, format_summary, load_policy
from binary_comp.config import ConfigError, DEFAULT_CONFIG_PATH, load_project_target


def add_values_parser(subparsers) -> None:
    parser = subparsers.add_parser("values", help="Check operand value mismatches with Capstone")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--policy", help="Value-check policy JSON override")
    parser.add_argument("--filter", dest="file_filter", help="Only include functions or source files containing this text")
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.add_argument("--min-similarity", type=float, default=0.0,
                        help="Only report mismatches at or above this similarity percentage")
    parser.add_argument("--boundary-report", action="store_true", help="Print function-boundary inventory")
    parser.add_argument("--strings-only", action="store_true", help="Only report string literal mismatches")
    parser.add_argument("--no-strings", action="store_true", help="Do not report string literal mismatches")
    parser.add_argument("--no-immediates", action="store_true", help="Do not report small numeric immediate mismatches")
    parser.add_argument("--no-offsets", action="store_true", help="Do not report member displacement mismatches")
    parser.set_defaults(handler=run_values)


def add_data_parser(subparsers) -> None:
    parser = subparsers.add_parser("data", help="Compare global data between original and rebuilt PE files")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--globals-source", help="Global declarations source override")
    parser.add_argument("--section", default=".data", help="Section to scan for --find-missing (default: .data)")
    parser.add_argument("--verbose", action="store_true", help="Show data bytes for all globals")
    parser.add_argument("--address", type=lambda value: int(value, 0), help="Compare one original VA")
    parser.add_argument("--size", type=int, default=32, help="Byte count for --address (default: 32)")
    parser.add_argument("--find-missing", action="store_true", help="Scan original section for untracked non-zero dwords")
    parser.set_defaults(handler=run_data)


def add_globals_parser(subparsers) -> None:
    parser = subparsers.add_parser("globals", help="Audit global declarations against original PE data")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--globals-source", "--globals-c", dest="globals_source", help="Global definitions source override")
    parser.add_argument("--globals-h", dest="globals_header", help="Global declarations header override")
    parser.add_argument("--code-globals-h", dest="code_globals_header", help="Code export globals header override")
    parser.add_argument("--code-dir", help="Code export directory used for function-boundary hints")
    parser.add_argument("--auto-complete", help="Function list for global side-effect auditing")
    parser.add_argument("--data-section", action="append", dest="data_sections",
                        help="Writable section to scan for auto-complete side effects; defaults to .data")
    parser.add_argument("--min-address", type=lambda value: int(value, 0), help="Ignore lower original addresses")
    parser.add_argument("--max-issues", type=int, default=200, help="Maximum issues to print; 0 prints all")
    parser.add_argument("--max-auto-facts", type=int, default=12,
                        help="Maximum auto-complete facts to print per function; 0 prints all")
    parser.add_argument("--auto-complete-max-function-bytes", type=int, default=4096,
                        help="Maximum bytes to disassemble per auto-complete function")
    parser.add_argument("--include-code-globals", action="store_true",
                        help="Report nonzero code-export globals not covered by source")
    parser.add_argument("--include-symbolic", action="store_true",
                        help="Report nonzero globals with symbolic or unparsed initializers")
    parser.add_argument("--include-auto-complete-data-args", action="store_true",
                        help="Report generic PUSH data-address arguments in listed functions")
    parser.add_argument("--no-auto-complete-this-calls", action="store_true",
                        help="Do not report MOV ECX,global followed by CALL/JMP in listed functions")
    parser.add_argument("--no-auto-complete-global-effects", action="store_true",
                        help="Disable listed-function global side-effect auditing")
    parser.add_argument("--show-auto-complete-reviewed", action="store_true",
                        help="Print reviewed listed-function global side-effect details")
    parser.add_argument("--no-source-order", action="store_true",
                        help="Disable source-order decrease warnings for implicit-zero globals")
    parser.add_argument("--source-order-all", action="store_true",
                        help="Warn on source-order decreases for initialized globals too")
    parser.add_argument("--fail-on-issues", action="store_true", help="Exit 1 when suspicious issues are found")
    parser.add_argument("--fail-on-warnings", action="store_true",
                        help="Exit 1 when globals without address annotations are found")
    parser.set_defaults(handler=run_globals)


def enabled_kinds_from_args(args) -> frozenset[str]:
    enabled = {"strings", "immediates", "offsets"}
    if args.strings_only:
        return frozenset({"strings"})
    if args.no_strings:
        enabled.discard("strings")
    if args.no_immediates:
        enabled.discard("immediates")
    if args.no_offsets:
        enabled.discard("offsets")
    return frozenset(enabled)


def run_values(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        policy = load_policy(args.policy or target.values_policy)
        summary = check_values(
            target,
            policy,
            ValuesOptions(
                file_filter=args.file_filter,
                min_similarity=args.min_similarity,
                build=not args.no_build,
                enabled_kinds=enabled_kinds_from_args(args),
                boundary_report=args.boundary_report,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_summary(summary, min_similarity=args.min_similarity))
    return 0


def run_data(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        globals_source = require_globals_source(args.globals_source or target.globals_source)
        if args.find_missing:
            summary = find_missing_globals(target.original_exe, globals_source, section_name=args.section)
            print(format_missing_globals(summary))
            return 0
        if args.address is not None:
            comparison = compare_address(
                target.original_exe,
                target.rebuilt_exe,
                target.map_path,
                args.address,
                args.size,
            )
            print(format_address_comparison(comparison))
            return 0 if comparison.matches else 1

        summary = compare_global_data(
            target.original_exe,
            target.rebuilt_exe,
            target.map_path,
            globals_source,
            DataOptions(section_name=args.section, verbose=args.verbose),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_comparison(summary, verbose=args.verbose))
    return 0 if summary.mismatches == 0 else 1


def run_globals(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = audit_globals(
            config,
            target,
            GlobalsAuditOptions(
                globals_source=args.globals_source,
                globals_header=args.globals_header,
                code_globals_header=args.code_globals_header,
                code_dir=args.code_dir,
                auto_complete=args.auto_complete,
                data_sections=tuple(args.data_sections or [".data"]),
                min_address=args.min_address,
                max_issues=args.max_issues,
                max_auto_facts=args.max_auto_facts,
                auto_complete_max_function_bytes=args.auto_complete_max_function_bytes,
                include_code_globals=args.include_code_globals,
                include_symbolic=args.include_symbolic,
                include_auto_complete_data_args=args.include_auto_complete_data_args,
                no_auto_complete_this_calls=args.no_auto_complete_this_calls,
                no_auto_complete_global_effects=args.no_auto_complete_global_effects,
                show_auto_complete_reviewed=args.show_auto_complete_reviewed,
                no_source_order=args.no_source_order,
                source_order_all=args.source_order_all,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_report(summary))
    if args.fail_on_issues and (summary.issues or summary.unreviewed_auto_complete_count):
        return 1
    if args.fail_on_warnings and summary.address_warnings:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binary-comp")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_data_parser(subparsers)
    add_globals_parser(subparsers)
    add_values_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
