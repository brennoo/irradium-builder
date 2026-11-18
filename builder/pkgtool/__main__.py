"""CLI entrypoint for `python3 -m pkgtool` (and `./builder/build-pkg.sh`)."""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import container, docker, publish, signify

USAGE_TEXT = """Usage:
  build-pkg.sh [options] <pkg-or-port-path>...   Build, package, and sign port(s) + missing dependencies
  build-pkg.sh [options] --from-file <file>      Process packages listed in <file> (e.g. packages/build.txt)
  build-pkg.sh [options] --all                   Sync packages/upstream.txt then build packages/build.txt
  build-pkg.sh [options] publish                 Sync repo/irradium/packages/ to remote mirror storage
  build-pkg.sh [options] sign                    Sign all packages in repo/irradium/packages/<arch>/<ver>/
  build-pkg.sh [options] repgen                  Sign custom ports (.signature) and update custom-*/REPO indexes
  build-pkg.sh [options] keygen                  Generate a signify keypair in keys/
  build-pkg.sh [options] image                   Build or rebuild the irradium-<arch>:<ver> Docker image
  build-pkg.sh [options] shell                   Open an interactive shell inside the builder container

Options:
  -a, --arch <arch>        Target architecture: riscv64 (default) or aarch64
  -u, --upstream           Upstream mode: download pre-built binaries from dl.irradium.org, verify official
                           Irradium signature, and re-sign for this mirror (never compiles from source)
  -p, --publish            Automatically publish after processing
  -s, --skip-existing      Skip if the exact <name>#<ver>-<rel>.pkg.tar.gz already exists on the mirror or in repo/
  -f, --from-file <file>   Read package targets from <file>
  -h, --help               Show this help message

Examples:
  ./builder/build-pkg.sh libb2 --publish
  ./builder/build-pkg.sh --upstream --from-file packages/upstream.txt --skip-existing --publish
  ./builder/build-pkg.sh --from-file packages/build.txt --skip-existing --publish
  ./builder/build-pkg.sh --all --skip-existing --publish
  ./builder/build-pkg.sh repgen
"""

SPECIAL_COMMANDS = {"image", "keygen", "sign", "publish", "shell", "repgen"}


def _read_pkg_file(file_path: pathlib.Path, prefix: str) -> list[str]:
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    items: list[str] = []
    for raw in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            items.append(f"{prefix}{line}")
    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build-pkg.sh",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=USAGE_TEXT,
    )
    parser.add_argument("-a", "--arch", dest="arch", default=None)
    parser.add_argument("-u", "--upstream", action="store_true", default=False)
    parser.add_argument("--all", dest="run_all", action="store_true", default=False)
    parser.add_argument("-p", "--publish", dest="do_publish", action="store_true", default=False)
    parser.add_argument("-s", "--skip-existing", dest="skip_existing", action="store_true", default=False)
    parser.add_argument("-f", "--from-file", dest="from_file", default=None)
    parser.add_argument("-h", "--help", action="store_true", default=False)
    parser.add_argument("targets", nargs="*")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    # Internal in-container entrypoint
    if raw_argv and raw_argv[0] == "_container-run":
        return container.run_in_container(raw_argv[1:])

    parser = build_parser()
    args = parser.parse_intermixed_args(raw_argv)

    if args.help or (args.targets and args.targets[0] == "help"):
        print(USAGE_TEXT, end="")
        return 0

    try:
        cfg = docker.BuildConfig.from_env(arch_override=args.arch)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    mode = "upstream" if args.upstream else "build"
    resolved_targets: list[str] = []

    try:
        if args.run_all:
            up_file = docker.ROOT_DIR / "packages" / "upstream.txt"
            build_file = docker.ROOT_DIR / "packages" / "build.txt"
            if up_file.is_file():
                resolved_targets.extend(_read_pkg_file(up_file, "upstream:"))
            if build_file.is_file():
                resolved_targets.extend(_read_pkg_file(build_file, "build:"))
        elif args.from_file:
            resolved_targets.extend(_read_pkg_file(pathlib.Path(args.from_file), f"{mode}:"))
        else:
            for t in args.targets:
                if t in SPECIAL_COMMANDS or t.startswith(("upstream:", "build:")):
                    resolved_targets.append(t)
                else:
                    resolved_targets.append(f"{mode}:{t}")
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not resolved_targets:
        print(USAGE_TEXT, end="", file=sys.stderr)
        return 1

    cmd = resolved_targets[0]
    if cmd == "image":
        return docker.build_image(cfg)
    if cmd == "keygen":
        docker.ensure_image(cfg)
        docker.ensure_keys(cfg)
        return 0
    if cmd == "sign":
        return docker.sign_repo(cfg)
    if cmd == "publish":
        return publish.publish_repo(
            repo_root=cfg.repo_root,
            r2_bucket=cfg.r2_bucket,
            r2_endpoint=cfg.r2_endpoint,
            mirror_domain=cfg.mirror_domain,
        )
    if cmd == "shell":
        return docker.open_shell(cfg)
    if cmd == "repgen":
        signify.refresh_all_custom_ports(
            ports_root=cfg.ports_root,
            keys_dir=cfg.keys_dir,
            cache_root=docker.ROOT_DIR / "cache",
        )
        print("==> Signed custom ports and updated custom-*/REPO indexes", flush=True)
        return 0

    rc = docker.run_container_build(
        cfg=cfg,
        targets=resolved_targets,
        skip_existing=args.skip_existing,
    )
    if rc != 0:
        return rc

    if args.do_publish:
        return publish.publish_repo(
            repo_root=cfg.repo_root,
            r2_bucket=cfg.r2_bucket,
            r2_endpoint=cfg.r2_endpoint,
            mirror_domain=cfg.mirror_domain,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
