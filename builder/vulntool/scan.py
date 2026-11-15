"""CycloneDX SBOM generation, Grype invocation with OpenVEX, bucketed classification, and Markdown/JSON reporting."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from . import cpe, ports, vex

SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]


@dataclasses.dataclass
class Finding:
    pkg: str
    version: str
    release: str
    collection: str
    source_kind: str
    cve: str
    severity: str
    fix_versions: list[str]
    description: str = ""
    url: str = ""
    bucket: str = "actionable"  # "actionable" | "suppressed"
    vex_status: str = ""
    vex_justification: str = ""
    suppression_reason: str = ""


def severity_rank(sev: str) -> int:
    s = (sev or "").strip().lower()
    if s in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(s)
    return -1


def build_cyclonedx_sbom(
    resolved_ports: list[ports.PortInfo],
    cpe_map: dict[str, list[cpe.CpeEntry]],
    allow_fuzzy: bool = False,
) -> tuple[dict, list[ports.PortInfo], list[ports.PortInfo], list[ports.PortInfo]]:
    """Build a Syft-compatible CycloneDX 1.5 SBOM from resolved ports and cpe-map.tsv.

    Returns (sbom_dict, scanned_cpe_ports, ignored_ports, unmapped_ports).
    """
    components: list[dict] = []
    scanned_cpe_ports: list[ports.PortInfo] = []
    ignored_ports: list[ports.PortInfo] = []
    unmapped_ports: list[ports.PortInfo] = []

    for port in resolved_ports:
        entries = cpe_map.get(port.name)
        if not entries:
            unmapped_ports.append(port)
            if allow_fuzzy:
                fuzzy_name = f"{port.name} [fuzzy]"
                fuzzy_cpe = cpe.format_cpe23("*", port.name, port.version, "*")
                components.append(
                    {
                        "bom-ref": f"pkg:generic/{port.name}@{port.version}#fuzzy",
                        "type": "application",
                        "name": fuzzy_name,
                        "version": port.version,
                        "purl": f"pkg:generic/{port.name}@{port.version}",
                        "cpe": fuzzy_cpe,
                        "properties": [
                            {"name": "syft:package:type", "value": "irradium-port"},
                            {"name": "irradium:fuzzy", "value": "true"},
                            {"name": "irradium:collection", "value": port.collection},
                            {"name": "irradium:source_kind", "value": port.source_kind},
                        ],
                    }
                )
            continue

        if entries[0].is_ignored:
            ignored_ports.append(port)
            continue

        scanned_cpe_ports.append(port)
        cpe_strings: list[str] = []
        primary_cpe_ver = port.version
        for idx, entry in enumerate(entries):
            cpe_str, cpe_ver, _cpe_upd = entry.format_cpe(port.version)
            if idx == 0:
                primary_cpe_ver = cpe_ver
            if cpe_str not in cpe_strings:
                cpe_strings.append(cpe_str)

        props = [
            {"name": "syft:package:type", "value": "irradium-port"},
            {"name": "irradium:collection", "value": port.collection},
            {"name": "irradium:source_kind", "value": port.source_kind},
            {"name": "irradium:version_source", "value": port.version_source},
            {"name": "irradium:pkg_version", "value": port.version},
            {"name": "irradium:pkg_release", "value": port.release},
        ]
        for extra_cpe in cpe_strings[1:]:
            props.append({"name": "syft:cpe23", "value": extra_cpe})

        components.append(
            {
                "bom-ref": f"pkg:generic/{port.name}@{port.version}",
                "type": "application",
                "name": port.name,
                "version": primary_cpe_ver,
                "purl": f"pkg:generic/{port.name}@{port.version}",
                "cpe": cpe_strings[0],
                "properties": props,
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    return sbom, scanned_cpe_ports, ignored_ports, unmapped_ports


def _extract_finding(
    match_obj: dict,
    port_by_name: dict[str, ports.PortInfo],
    bucket: str,
    vex_stmt: vex.VexStatement | None = None,
    fallback_reason: str = "",
) -> Finding:
    art = match_obj.get("artifact", {})
    vuln = match_obj.get("vulnerability", {})
    raw_name = str(art.get("name", ""))
    is_fuzzy = raw_name.endswith(" [fuzzy]")
    pkg_name = raw_name[: -len(" [fuzzy]")] if is_fuzzy else raw_name

    port = port_by_name.get(pkg_name)
    ver = port.version if port else str(art.get("version", ""))
    rel = port.release if port else "1"
    col = port.collection if port else ""
    src_kind = port.source_kind if port else ""

    fix_obj = vuln.get("fix", {})
    fix_versions = (
        [str(v) for v in fix_obj.get("versions", []) if v]
        if isinstance(fix_obj, dict)
        else []
    )
    cve_id = str(vuln.get("id", "")).strip()
    sev = str(vuln.get("severity", "Unknown")).strip()
    desc = str(vuln.get("description", "")).strip()
    data_source = str(vuln.get("dataSource", "")).strip()

    vex_status = ""
    vex_just = ""
    reason = fallback_reason
    if vex_stmt is not None:
        vex_status = vex_stmt.status
        vex_just = vex_stmt.justification
        reason = vex_stmt.note or f"{vex_stmt.status} ({vex_stmt.source})"

    return Finding(
        pkg=pkg_name,
        version=ver,
        release=rel,
        collection=col,
        source_kind=src_kind,
        cve=cve_id,
        severity=sev,
        fix_versions=fix_versions,
        description=desc,
        url=data_source,
        bucket=bucket,
        vex_status=vex_status,
        vex_justification=vex_just,
        suppression_reason=reason,
    )


def format_markdown_summary(
    resolved_ports: list[ports.PortInfo],
    scanned_cpe_ports: list[ports.PortInfo],
    ignored_ports: list[ports.PortInfo],
    unmapped_ports: list[ports.PortInfo],
    actionable: list[Finding],
    suppressed: list[Finding],
    fail_on: str = "",
) -> str:
    """Render a GitHub-flavored Markdown summary of scan findings."""
    lines: list[str] = []
    lines.append("## Irradium Vulnerability Scan Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| :--- | ---: |")
    lines.append(f"| Total resolved packages | {len(resolved_ports)} |")
    lines.append(f"| Scanned with NVD CPE | {len(scanned_cpe_ports)} |")
    lines.append(f"| Explicitly no NVD CPE (`-`) | {len(ignored_ports)} |")
    lines.append(f"| Unmapped packages | {len(unmapped_ports)} |")
    lines.append(f"| **Actionable vulnerabilities** | **{len(actionable)}** |")
    lines.append(f"| Suppressed vulnerabilities (VEX / fuzzy) | {len(suppressed)} |")
    if fail_on:
        threshold = severity_rank(fail_on)
        gated = [f for f in actionable if severity_rank(f.severity) >= threshold]
        lines.append(f"| Gate (`--fail-on {fail_on}`) findings | **{len(gated)}** |")
    lines.append("")

    if actionable:
        lines.append("### Actionable Findings")
        lines.append("")
        lines.append("| Package | Version | Collection | Source | CVE | Severity | Fixed In |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in sorted(
            actionable,
            key=lambda x: (-severity_rank(x.severity), x.pkg, x.cve),
        ):
            fix_str = ", ".join(f.fix_versions) if f.fix_versions else "-"
            cve_cell = f"[{f.cve}]({f.url})" if f.url else f.cve
            lines.append(
                f"| `{f.pkg}` | `{f.version}-{f.release}` | `{f.collection}` | {f.source_kind} | {cve_cell} | **{f.severity}** | `{fix_str}` |"
            )
        lines.append("")
    else:
        lines.append("### Actionable Findings")
        lines.append("")
        lines.append("No actionable vulnerabilities found.")
        lines.append("")

    if suppressed:
        lines.append("### Suppressed Findings (VEX)")
        lines.append("")
        lines.append("| Package | Version | CVE | Severity | Status | Justification | Reason |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in sorted(
            suppressed,
            key=lambda x: (-severity_rank(x.severity), x.pkg, x.cve),
        ):
            just = f"`{f.vex_justification}`" if f.vex_justification else "-"
            status = f"`{f.vex_status}`" if f.vex_status else "`fuzzy`"
            lines.append(
                f"| `{f.pkg}` | `{f.version}-{f.release}` | `{f.cve}` | {f.severity} | {status} | {just} | {f.suppression_reason} |"
            )
        lines.append("")

    if unmapped_ports:
        lines.append("### Unmapped Packages")
        lines.append("")
        lines.append("The following packages have no entry in `builder/cpe-map.tsv`:")
        lines.append("")
        for p in unmapped_ports:
            lines.append(f"- `{p.name}` (`{p.collection}`, `{p.version_release}`, {p.source_kind})")
        lines.append("")

    return "\n".join(lines)


def _open_github_issues_for_findings(findings: list[Finding]) -> None:
    """Open deduplicated GitHub issues for actionable findings (Section 2.5)."""
    if not findings:
        return
    # Group findings by (pkg, cve)
    seen: set[tuple[str, str]] = set()
    for f in findings:
        key = (f.pkg, f.cve)
        if key in seen:
            continue
        seen.add(key)
        title = f"[vuln] {f.pkg} {f.version}-{f.release}: {f.cve} ({f.severity})"
        check = subprocess.run(
            [
                "gh",
                "issue",
                "list",
                "--state",
                "open",
                "--search",
                f"{f.pkg} {f.cve} in:title",
                "--json",
                "number,title",
            ],
            cwd=str(ports.ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        if check.returncode == 0 and check.stdout.strip():
            try:
                existing = json.loads(check.stdout)
                if any(f.pkg in item.get("title", "") and f.cve in item.get("title", "") for item in existing):
                    print(f"==> Issue already open for {f.pkg} {f.cve}; skipping.", file=sys.stderr)
                    continue
            except Exception:
                pass

        fix_hint = ", ".join(f.fix_versions) if f.fix_versions else "<fixed-version>"
        body = (
            f"### Vulnerability Detected: `{f.pkg}` (`{f.cve}`)\n\n"
            f"- **Package:** `{f.pkg}` (`{f.collection}`)\n"
            f"- **Current Version:** `{f.version}-{f.release}` ({f.source_kind})\n"
            f"- **Severity:** **{f.severity}**\n"
            f"- **Fixed In:** `{', '.join(f.fix_versions) if f.fix_versions else 'unknown'}`\n"
            f"- **Advisory URL:** {f.url or 'n/a'}\n\n"
            f"#### Description\n\n{f.description or 'No description provided.'}\n\n"
            f"#### Clearinghouse Remediation Commands\n\n"
            f"```bash\n"
            f"# 1. Fork the port into ports/custom/\n"
            f"python3 -m vulntool override fork {f.pkg} --cve {f.cve}\n\n"
            f"# 2a. Apply an upstream patch:\n"
            f"python3 -m vulntool override patch {f.pkg} <patch-url-or-file> --cve {f.cve}\n\n"
            f"# OR 2b. Bump to the fixed upstream version:\n"
            f"python3 -m vulntool override bump {f.pkg} {fix_hint} --cve {f.cve}\n\n"
            f"# 3. Rebuild checksums/footprint and verify the CVE is resolved:\n"
            f"python3 -m vulntool override refresh {f.pkg}\n"
            f"```\n\n"
            f"If `{f.pkg}` is not affected (e.g. vulnerable code not compiled or not in execute path), "
            f"record a version-bound OpenVEX suppression:\n\n"
            f"```bash\n"
            f"python3 -m vulntool vex add {f.pkg} {f.cve} \\\n"
            f"  --status not_affected \\\n"
            f"  --justification vulnerable_code_not_in_execute_path \\\n"
            f"  --note \"<reason>\"\n"
            f"```\n"
        )
        create = subprocess.run(
            ["gh", "issue", "create", "--title", title, "--body", body],
            cwd=str(ports.ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        if create.returncode == 0:
            print(f"==> Opened issue for {f.pkg} {f.cve}: {create.stdout.strip()}", file=sys.stderr)
        else:
            print(
                f"WARN: Could not open GitHub issue for {f.pkg} {f.cve}: {create.stderr.strip()}",
                file=sys.stderr,
            )


def run_scan(
    targets: list[str] | None = None,
    include_all: bool = False,
    output_format: str = "table",
    fail_on: str = "",
    allow_fuzzy: bool = False,
    extra_vex_files: list[str] | None = None,
    report_json_path: str | None = None,
    summary_markdown_path: str | None = None,
    sbom_out_path: str | None = None,
    vex_out_path: str | None = None,
    open_issues: bool = False,
    offline: bool = False,
) -> tuple[int, list[Finding], list[Finding], list[ports.PortInfo]]:
    """Execute a full vulnerability scan and return (exit_code, actionable, suppressed, unmapped)."""
    cpe_map, lint_errors = cpe.load_cpe_map()
    if lint_errors:
        for err in lint_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1, [], [], []

    resolved_ports, missing_ports = ports.resolve_ports(
        targets=targets,
        include_all=include_all,
        use_mirror=not offline,
    )
    if missing_ports:
        print(
            f"ERROR: Package(s) not found in any configured port tree: {' '.join(missing_ports)}",
            file=sys.stderr,
        )
        return 1, [], [], []

    if not resolved_ports:
        print(
            "ERROR: No packages to scan (packages/build.txt and packages/upstream.txt are empty)",
            file=sys.stderr,
        )
        return 1, [], [], []

    active_vex_map, stale_vex, vex_errors = vex.collect_active_vex(resolved_ports)
    if vex_errors:
        for err in vex_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1, [], [], []

    if stale_vex:
        for s in stale_vex:
            print(
                f"==> [VEX:STALE] {s.pkg}@{s.version} {s.cve} ignored (current version bumped)",
                file=sys.stderr,
            )

    sbom, scanned_cpe_ports, ignored_ports, unmapped_ports = build_cyclonedx_sbom(
        resolved_ports, cpe_map, allow_fuzzy=allow_fuzzy
    )

    if unmapped_ports:
        unmapped_names = " ".join(p.name for p in unmapped_ports)
        if allow_fuzzy:
            print(
                f"==> No exact CPE on file for: {unmapped_names} (using wildcard vendor — see builder/cpe-map.tsv)",
                file=sys.stderr,
            )
        else:
            print(
                f"==> Unmapped package(s) in builder/cpe-map.tsv ({len(unmapped_ports)}): {unmapped_names}",
                file=sys.stderr,
            )

    openvex_doc = vex.build_openvex_document(
        list(active_vex_map.values()),
        resolved_ports,
        cpe_map=cpe_map,
    )

    with tempfile.TemporaryDirectory(prefix="vulntool-") as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        sbom_file = pathlib.Path(sbom_out_path) if sbom_out_path else (tmp_path / "sbom.cdx.json")
        vex_file = pathlib.Path(vex_out_path) if vex_out_path else (tmp_path / "openvex.json")
        gate_json = tmp_path / "grype-results.json"

        sbom_file.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
        vex_file.write_text(json.dumps(openvex_doc, indent=2) + "\n", encoding="utf-8")

        print(
            f"==> Scanning {len(sbom['components'])} CPE-mapped package(s) "
            f"({len(ignored_ports)} no-CPE skipped, {len(unmapped_ports)} unmapped, "
            f"{len(active_vex_map)} active VEX statement(s))",
            file=sys.stderr,
        )

        grype_cmd = ["grype", f"sbom:{sbom_file}"]
        if openvex_doc.get("statements"):
            grype_cmd.extend(["--vex", str(vex_file), "--show-suppressed"])
        for extra_vex in extra_vex_files or []:
            grype_cmd.extend(["--vex", str(extra_vex), "--show-suppressed"])

        if output_format == "markdown":
            grype_cmd.extend(["-o", f"json={gate_json}", "-q"])
        else:
            grype_cmd.extend(["-o", output_format, "-o", f"json={gate_json}"])

        res = subprocess.run(grype_cmd, check=False)
        if res.returncode != 0 or not gate_json.is_file():
            print(f"ERROR: grype exited with code {res.returncode}", file=sys.stderr)
            return res.returncode or 1, [], [], unmapped_ports

        grype_data = json.loads(gate_json.read_text(encoding="utf-8"))

    port_by_name = {p.name: p for p in resolved_ports}
    actionable: list[Finding] = []
    suppressed: list[Finding] = []
    seen_actionable: set[tuple[str, str]] = set()
    seen_suppressed: set[tuple[str, str]] = set()

    for m in grype_data.get("matches", []):
        art_name = str(m.get("artifact", {}).get("name", ""))
        vuln_id = str(m.get("vulnerability", {}).get("id", "")).upper()
        is_fuzzy = art_name.endswith(" [fuzzy]")
        clean_pkg = art_name[: -len(" [fuzzy]")] if is_fuzzy else art_name

        if is_fuzzy:
            if (clean_pkg, vuln_id) not in seen_suppressed:
                seen_suppressed.add((clean_pkg, vuln_id))
                suppressed.append(
                    _extract_finding(
                        m,
                        port_by_name,
                        bucket="suppressed",
                        fallback_reason="[fuzzy] wildcard-vendor CPE (unmapped in cpe-map.tsv)",
                    )
                )
            continue

        vex_stmt = active_vex_map.get((clean_pkg, vuln_id))
        if vex_stmt is not None:
            if (clean_pkg, vuln_id) not in seen_suppressed:
                seen_suppressed.add((clean_pkg, vuln_id))
                suppressed.append(
                    _extract_finding(
                        m,
                        port_by_name,
                        bucket="suppressed",
                        vex_stmt=vex_stmt,
                    )
                )
            continue

        if (clean_pkg, vuln_id) not in seen_actionable:
            seen_actionable.add((clean_pkg, vuln_id))
            actionable.append(_extract_finding(m, port_by_name, bucket="actionable"))

    for im in grype_data.get("ignoredMatches", []):
        art_name = str(im.get("artifact", {}).get("name", ""))
        clean_pkg = art_name[: -len(" [fuzzy]")] if art_name.endswith(" [fuzzy]") else art_name
        vuln_id = str(im.get("vulnerability", {}).get("id", "")).upper()
        if (clean_pkg, vuln_id) in seen_suppressed:
            continue
        seen_suppressed.add((clean_pkg, vuln_id))
        vex_stmt = active_vex_map.get((clean_pkg, vuln_id))
        rules = im.get("appliedIgnoreRules", [])
        rule_status = rules[0].get("vex-status", "suppressed") if rules else "suppressed"
        suppressed.append(
            _extract_finding(
                im,
                port_by_name,
                bucket="suppressed",
                vex_stmt=vex_stmt,
                fallback_reason=f"OpenVEX ({rule_status})",
            )
        )

    md_summary = format_markdown_summary(
        resolved_ports=resolved_ports,
        scanned_cpe_ports=scanned_cpe_ports,
        ignored_ports=ignored_ports,
        unmapped_ports=unmapped_ports,
        actionable=actionable,
        suppressed=suppressed,
        fail_on=fail_on,
    )

    if output_format == "markdown":
        print(md_summary)

    if summary_markdown_path:
        sm_path = pathlib.Path(summary_markdown_path)
        sm_path.parent.mkdir(parents=True, exist_ok=True)
        with sm_path.open("a", encoding="utf-8") as f:
            f.write(md_summary + "\n")

    if report_json_path:
        rj_path = pathlib.Path(report_json_path)
        rj_path.parent.mkdir(parents=True, exist_ok=True)
        report_payload = {
            "summary": {
                "total_resolved": len(resolved_ports),
                "scanned_cpe": len(scanned_cpe_ports),
                "ignored_no_cpe": len(ignored_ports),
                "unmapped": len(unmapped_ports),
                "actionable": len(actionable),
                "suppressed": len(suppressed),
                "fail_on": fail_on or None,
            },
            "actionable": [dataclasses.asdict(f) for f in actionable],
            "suppressed": [dataclasses.asdict(f) for f in suppressed],
            "unmapped": [
                {
                    "name": p.name,
                    "version": p.version,
                    "release": p.release,
                    "collection": p.collection,
                    "source_kind": p.source_kind,
                }
                for p in unmapped_ports
            ],
            "scanned_packages": [
                {
                    "name": p.name,
                    "version": p.version,
                    "release": p.release,
                    "collection": p.collection,
                    "source_kind": p.source_kind,
                    "version_source": p.version_source,
                }
                for p in resolved_ports
            ],
        }
        rj_path.write_text(json.dumps(report_payload, indent=2) + "\n", encoding="utf-8")

    # Print bucket summary to stderr
    print(
        f"==> Scan buckets: {len(actionable)} actionable, "
        f"{len(suppressed)} suppressed (VEX/fuzzy), "
        f"{len(unmapped_ports)} unmapped",
        file=sys.stderr,
    )
    if suppressed:
        for s in suppressed:
            just_str = f" [{s.vex_justification}]" if s.vex_justification else ""
            print(
                f"    [suppressed] {s.pkg} {s.version}-{s.release}: {s.cve} ({s.severity}) — "
                f"{s.vex_status or 'fuzzy'}{just_str}: {s.suppression_reason}",
                file=sys.stderr,
            )

    if open_issues and actionable:
        threshold = severity_rank(fail_on) if fail_on else 0
        to_report = [f for f in actionable if severity_rank(f.severity) >= threshold]
        _open_github_issues_for_findings(to_report)

    exit_code = 0
    if unmapped_ports and not allow_fuzzy:
        print(
            f"==> Gate FAILED: {len(unmapped_ports)} package(s) are unmapped in builder/cpe-map.tsv",
            file=sys.stderr,
        )
        exit_code = 1

    if fail_on:
        threshold = severity_rank(fail_on)
        if threshold < 0:
            print(f"ERROR: Invalid --fail-on severity: {fail_on!r}", file=sys.stderr)
            return 1, actionable, suppressed, unmapped_ports
        gated = [f for f in actionable if severity_rank(f.severity) >= threshold]
        print(
            f"==> Gate (--fail-on {fail_on}): {len(gated)} actionable at/above {fail_on}, "
            f"{len(suppressed)} suppressed",
            file=sys.stderr,
        )
        if gated:
            for f in gated:
                print(
                    f"    {f.pkg} {f.version}-{f.release}: {f.cve} ({f.severity.lower()})",
                    file=sys.stderr,
                )
            exit_code = 1

    return exit_code, actionable, suppressed, unmapped_ports


def cmd_scan(args: argparse.Namespace) -> int:
    exit_code, _, _, _ = run_scan(
        targets=args.packages if getattr(args, "packages", None) else None,
        include_all=getattr(args, "all", False),
        output_format=getattr(args, "output", "table"),
        fail_on=getattr(args, "fail_on", "") or "",
        allow_fuzzy=getattr(args, "allow_fuzzy", False),
        extra_vex_files=getattr(args, "vex", None),
        report_json_path=getattr(args, "report_json", None),
        summary_markdown_path=getattr(args, "summary_markdown", None),
        sbom_out_path=getattr(args, "sbom_out", None),
        vex_out_path=getattr(args, "vex_out", None),
        open_issues=getattr(args, "open_issues", False),
        offline=getattr(args, "offline", False),
    )
    return exit_code
