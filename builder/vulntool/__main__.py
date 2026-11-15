#!/usr/bin/env python3
"""Entry point for `python3 -m vulntool <subcommand>`."""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys

# Ensure `vulntool` package is importable whether invoked via `python3 -m vulntool` or file path
_BUILDER_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_BUILDER_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILDER_DIR))

from vulntool import cpe, override, ports, scan, versions, vex  # noqa: E402


def _cmd_ports(args: argparse.Namespace) -> int:
    resolved, missing = ports.resolve_ports(
        targets=args.packages if args.packages else None,
        include_all=args.all,
        use_mirror=not args.offline,
    )
    if args.json:
        payload = [
            {
                **dataclasses.asdict(p),
                "port_dir": str(p.port_dir),
            }
            for p in resolved
        ]
        print(json.dumps(payload, indent=2))
    else:
        for p in resolved:
            print(
                f"{p.name}\t{p.version}-{p.release}\t{p.collection}\t"
                f"{p.source_kind}\t{p.version_source}\t{p.port_dir}"
            )
    if missing:
        print(f"ERROR: Missing packages: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


def _cmd_vercmp(args: argparse.Namespace) -> int:
    cmp_val = versions.vercmp(args.v1, args.v2)
    op = "<" if cmp_val < 0 else (">" if cmp_val > 0 else "==")
    print(f"{args.v1} {op} {args.v2} ({cmp_val})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulntool",
        description="Irradium Clearinghouse tool: CPE management, OpenVEX triage, Grype scanning, and port overrides.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. scan
    p_scan = sub.add_parser(
        "scan",
        help="Generate CycloneDX SBOM + OpenVEX and scan packages with grype",
    )
    p_scan.add_argument(
        "-o",
        "--output",
        default="table",
        choices=["table", "json", "markdown", "sarif", "cyclonedx-json"],
        help="Output format (default: table)",
    )
    p_scan.add_argument(
        "-f",
        "--fail-on",
        default="",
        help="Exit non-zero if an actionable vulnerability at/above this severity is found (negligible, low, medium, high, critical)",
    )
    p_scan.add_argument(
        "--all",
        action="store_true",
        help="Scan build.txt, upstream.txt, their '# Depends on:' closure, and repo/ packages",
    )
    p_scan.add_argument(
        "--allow-fuzzy",
        action="store_true",
        help="Fall back to wildcard vendor CPE (cpe:2.3:a:*:<name>:...) for unmapped packages instead of failing",
    )
    p_scan.add_argument(
        "--vex",
        action="append",
        default=[],
        help="Additional OpenVEX document path(s) to pass to grype --vex",
    )
    p_scan.add_argument(
        "--report-json",
        default=None,
        help="Write structured JSON scan report (actionable, suppressed, unmapped) to file",
    )
    p_scan.add_argument(
        "--summary-markdown",
        default=None,
        help="Write/append GitHub-flavored Markdown summary to file (e.g. $GITHUB_STEP_SUMMARY)",
    )
    p_scan.add_argument(
        "--sbom-out",
        default=None,
        help="Write generated CycloneDX SBOM JSON to file",
    )
    p_scan.add_argument(
        "--vex-out",
        default=None,
        help="Write generated OpenVEX JSON to file",
    )
    p_scan.add_argument(
        "--open-issues",
        action="store_true",
        help="Open deduplicated GitHub issues for actionable findings",
    )
    p_scan.add_argument(
        "--offline",
        action="store_true",
        help="Do not query remote mirror index.html when resolving versions",
    )
    p_scan.add_argument(
        "packages",
        nargs="*",
        help="Specific package(s) to scan (defaults to packages/upstream.txt + packages/build.txt)",
    )
    p_scan.set_defaults(func=scan.cmd_scan)

    # 2. cpe
    p_cpe = sub.add_parser("cpe", help="CPE dictionary mapping & maintenance")
    cpe_sub = p_cpe.add_subparsers(dest="cpe_command", required=True)

    p_cpe_lint = cpe_sub.add_parser(
        "lint",
        help="Offline structural validation of cpe-map.tsv and package coverage check",
    )
    p_cpe_lint.add_argument("--all", action="store_true", help="Require coverage of dependency closure as well")
    p_cpe_lint.add_argument("--offline", action="store_true", help="Do not query mirror index.html")
    p_cpe_lint.add_argument("--map-file", default=None, help="Path to cpe-map.tsv")
    p_cpe_lint.set_defaults(func=cpe.cmd_lint)

    p_cpe_cov = cpe_sub.add_parser(
        "coverage",
        help="List CPE coverage and any unmapped packages in build.txt, upstream.txt, and dependencies",
    )
    p_cpe_cov.add_argument("--all", action="store_true", help="Include '# Depends on:' closure and repo/ packages")
    p_cpe_cov.add_argument("--offline", action="store_true", help="Do not query mirror index.html")
    p_cpe_cov.add_argument("--map-file", default=None, help="Path to cpe-map.tsv")
    p_cpe_cov.set_defaults(func=cpe.cmd_coverage)

    p_cpe_ver = cpe_sub.add_parser(
        "verify",
        help="Verify vendor:product pairs against the NVD CPE 2.0 dictionary API",
    )
    p_cpe_ver.add_argument(
        "--diff",
        default=None,
        help="Verify only rows added/modified in cpe-map.tsv relative to this git ref (e.g. HEAD~1)",
    )
    p_cpe_ver.add_argument("--refresh", action="store_true", help="Bypass cache/nvd/ and query live API")
    p_cpe_ver.add_argument("--map-file", default=None, help="Path to cpe-map.tsv")
    p_cpe_ver.add_argument("packages", nargs="*", help="Specific package(s) to verify")
    p_cpe_ver.set_defaults(func=cpe.cmd_verify)

    p_cpe_sug = cpe_sub.add_parser(
        "suggest",
        help="Suggest cpe-map.tsv entries for package(s) using NVD CPE API and Repology",
    )
    p_cpe_sug.add_argument("--refresh", action="store_true", help="Bypass cache/nvd/ and query live API")
    p_cpe_sug.add_argument("packages", nargs="+", help="Package name(s) to suggest CPE mappings for")
    p_cpe_sug.set_defaults(func=cpe.cmd_suggest)

    # 3. vex
    p_vex = sub.add_parser("vex", help="OpenVEX triage management")
    vex_sub = p_vex.add_subparsers(dest="vex_command", required=True)

    p_vex_lint = vex_sub.add_parser("lint", help="Validate builder/vex/ statements and check for stale versions")
    p_vex_lint.add_argument("--vex-dir", default=None, help="Path to builder/vex directory")
    p_vex_lint.set_defaults(func=vex.cmd_lint)

    p_vex_list = vex_sub.add_parser("list", help="List active and stale VEX statements (manual + auto patch)")
    p_vex_list.add_argument("--active-only", action="store_true", help="Show only currently active statements")
    p_vex_list.add_argument("--vex-dir", default=None, help="Path to builder/vex directory")
    p_vex_list.set_defaults(func=vex.cmd_list)

    p_vex_add = vex_sub.add_parser("add", help="Add or update a version-bound VEX statement in builder/vex/")
    p_vex_add.add_argument("pkg", help="Package name")
    p_vex_add.add_argument("cve", help="CVE identifier (e.g. CVE-2026-1234)")
    p_vex_add.add_argument(
        "--status",
        required=True,
        choices=sorted(vex.VALID_STATUSES),
        help="OpenVEX status (not_affected or fixed)",
    )
    p_vex_add.add_argument(
        "--justification",
        default="",
        choices=["", *sorted(vex.VALID_JUSTIFICATIONS)],
        help="OpenVEX justification (required when --status=not_affected)",
    )
    p_vex_add.add_argument("--note", default="", help="Free-text note / impact statement")
    p_vex_add.add_argument("--version", default="", help="Explicit package version, or '*' for all versions (defaults to current resolved version)")
    p_vex_add.add_argument("--all-versions", action="store_true", help="Bind not_affected statement to '*' (all versions)")
    p_vex_add.add_argument("--vex-dir", default=None, help="Path to builder/vex directory")
    p_vex_add.set_defaults(func=vex.cmd_add)

    # 4. override
    p_ov = sub.add_parser("override", help="Author and manage custom port overrides")
    ov_sub = p_ov.add_subparsers(dest="override_command", required=True)

    p_ov_fork = ov_sub.add_parser("fork", help="Fork an upstream port into ports/custom/custom-<cat>/<pkg>")
    p_ov_fork.add_argument("pkg", help="Package name to fork")
    p_ov_fork.add_argument("--cve", action="append", default=[], help="CVE ID(s) motivating the override")
    p_ov_fork.add_argument("--reason", default="", help="Reason recorded in .override")
    p_ov_fork.add_argument("--retire-when", default="", help="Retire condition (e.g. upstream_version>=1.2.3|upstream_has_cve_patch)")
    p_ov_fork.add_argument("--force", action="store_true", help="Overwrite existing override if present")
    p_ov_fork.set_defaults(func=override.cmd_fork)

    p_ov_patch = ov_sub.add_parser("patch", help="Add a CVE-YYYY-NNNNN.patch to an override port")
    p_ov_patch.add_argument("pkg", help="Overridden package name")
    p_ov_patch.add_argument("patch_source", help="Patch URL or local file path")
    p_ov_patch.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2026-1234)")
    p_ov_patch.set_defaults(func=override.cmd_patch)

    p_ov_bump = ov_sub.add_parser("bump", help="Bump an override port to a new upstream version (release=1)")
    p_ov_bump.add_argument("pkg", help="Overridden package name")
    p_ov_bump.add_argument("version", help="New upstream version")
    p_ov_bump.add_argument("--cve", action="append", default=[], help="CVE ID(s) resolved by the version bump")
    p_ov_bump.set_defaults(func=override.cmd_bump)

    p_ov_refresh = ov_sub.add_parser(
        "refresh",
        help="Regenerate .md5sum and .footprint in the builder container and verify CVEs are fixed",
    )
    p_ov_refresh.add_argument("pkg", help="Overridden package name")
    p_ov_refresh.add_argument("-a", "--arch", default=None, help="Target architecture (riscv64 or aarch64)")
    p_ov_refresh.add_argument("--skip-build", action="store_true", help="Only verify signature absence and re-scan without running Docker pkgmk")
    p_ov_refresh.set_defaults(func=override.cmd_refresh)

    p_ov_retire = ov_sub.add_parser("retire", help="Remove an override and restore upstream.txt if was_prebuilt=yes")
    p_ov_retire.add_argument("pkg", help="Overridden package name")
    p_ov_retire.set_defaults(func=override.cmd_retire)

    p_ov_status = ov_sub.add_parser("status", help="Check retire / drift / stale status of all overrides")
    p_ov_status.add_argument("--stale-days", type=int, default=30, help="Days without upstream movement before flagging stale (default: 30)")
    p_ov_status.add_argument("--json", action="store_true", help="Output status in JSON format")
    p_ov_status.add_argument("--apply-github", action="store_true", help="Open deduplicated retire PRs and drift/stale GitHub issues")
    p_ov_status.add_argument("--offline", action="store_true", help="Do not query upstream binary mirrors")
    p_ov_status.set_defaults(func=override.cmd_status)

    # 5. ports (diagnostic)
    p_ports = sub.add_parser("ports", help="Resolve ports and versions across SEARCH_DIRS, repo/, and mirror")
    p_ports.add_argument("--all", action="store_true", help="Include '# Depends on:' closure and repo/ packages")
    p_ports.add_argument("--offline", action="store_true", help="Do not query remote mirror index.html")
    p_ports.add_argument("--json", action="store_true", help="Output JSON")
    p_ports.add_argument("packages", nargs="*", help="Optional package names")
    p_ports.set_defaults(func=_cmd_ports)

    # 6. vercmp (diagnostic)
    p_vc = sub.add_parser("vercmp", help="Compare two CRUX version strings")
    p_vc.add_argument("v1", help="First version")
    p_vc.add_argument("v2", help="Second version")
    p_vc.set_defaults(func=_cmd_vercmp)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
