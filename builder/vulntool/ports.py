"""Port-tree resolution across SEARCH_DIRS, Pkgfile sourcing, and binary version resolution."""

from __future__ import annotations

import concurrent.futures
import dataclasses
import os
import pathlib
import re
import ssl
import subprocess
import urllib.parse
import urllib.request

BUILDER_DIR = pathlib.Path(__file__).resolve().parent.parent
ROOT_DIR = pathlib.Path(os.environ.get("ROOT_DIR", str(BUILDER_DIR.parent))).resolve()
PORTS_ROOT = pathlib.Path(os.environ.get("PORTS_ROOT", str(ROOT_DIR / "ports"))).resolve()
REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", str(ROOT_DIR / "repo"))).resolve()
PACKAGES_DIR = ROOT_DIR / "packages"
BUILD_TXT = PACKAGES_DIR / "build.txt"
UPSTREAM_TXT = PACKAGES_DIR / "upstream.txt"

DEFAULT_ARCH = os.environ.get("ARCH", "riscv64")
DEFAULT_DISTR_VERSION = os.environ.get("DISTR_VERSION", "3.8")
DEFAULT_MIRROR_DOMAIN = os.environ.get("MIRROR_DOMAIN", "https://irradium.blackhole.com.br").rstrip("/")

CATEGORIES = ("core", "opt", "xorg", "xfce", "contrib")

# ZeroSSL/Sectigo intermediate CA certificates for dl.irradium.org TLS verification
MISSING_INTERMEDIATES_PEM = """
-----BEGIN CERTIFICATE-----
MIIDNTCCArugAwIBAgIRAMThxbsA8CePNHvk+F1j/MowCgYIKoZIzj0EAwMwXzEL
MAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UEAxMt
U2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgRTQ2MB4X
DTI1MDkyNDAwMDAwMFoXDTM1MDkyMzIzNTk1OVowRjELMAkGA1UEBhMCQVQxFTAT
BgNVBAoTDFplcm9TU0wgR21iSDEgMB4GA1UEAxMXWmVyb1NTTCBFQ0MgRFYgU1NM
IENBIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATjn4qR1IOXAceCMsej8Qyr
4PrFw+PwjPm2vrAfijBj4u2C++Y3pZqpeLi1z05b2owKKJzQk1AtL+m1fEoFeDka
o4IBbzCCAWswHwYDVR0jBBgwFoAU0SLaTFnxS18mOKqd1u7rDcP7qWEwHQYDVR0O
BBYEFJRFn9pRR3HVc66sHasIchJtrXxiMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMB
Af8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBMGA1UdIAQMMAowCAYG
Z4EMAQIBMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9jcmwuc2VjdGlnby5jb20v
U2VjdGlnb1B1YmxpY1NlcnZlckF1dGhlbnRpY2F0aW9uUm9vdEU0Ni5jcmwwgYQG
CCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5zZWN0aWdvLmNv
bS9TZWN0aWdvUHVibGljU2VydmVyQXV0aGVudGljYXRpb25Sb290RTQ2LnA3YzAj
BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wCgYIKoZIzj0EAwMD
aAAwZQIwXKxxvuUkvPftBuaOFx73U3FxmFtKxP1Fd/+8Jq/ut2XgDrJ1vEUDdJb3
iSDXVe9AAjEA8iUwhrRHdZrIWqfgGmDMBbuXRZ4GoQbLpwxgcPhKo3OZR7SecTp4
juWAOpuawM2n
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDRjCCAsugAwIBAgIQGp6v7G3o4ZtcGTFBto2Q3TAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIy
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYGA1UEChMP
U2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIg
QXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR2
+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccCWvkEN/U0
NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+6xnOQ6Oj
ggEgMIIBHDAfBgNVHSMEGDAWgBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAdBgNVHQ4E
FgQU0SLaTFnxS18mOKqd1u7rDcP7qWEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGA1UdIAQK
MAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVz
dC5jb20vVVNFUlRydXN0RUNDQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYI
KwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu
Y29tMAoGCCqGSM49BAMDA2kAMGYCMQCMCyBit99vX2ba6xEkDe+YO7vC0twjbkv9
PKpqGGuZ61JZryjFsp+DFpEclCVy4noCMQCwvZDXD/m2Ko1HA5Bkmz7YQOFAiNDD
49IWa2wdT7R3DtODaSXH/BiXv8fwB9su4tU=
-----END CERTIFICATE-----
"""


def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cadata=MISSING_INTERMEDIATES_PEM)
    except Exception:
        pass
    return ctx


SSL_CTX = create_ssl_context()


@dataclasses.dataclass
class PortInfo:
    name: str
    version: str
    release: str
    pkgfile_version: str
    pkgfile_release: str
    collection: str
    category: str
    port_dir: pathlib.Path
    source_kind: str = "build"  # "build" | "upstream" | "dependency"
    version_source: str = "pkgfile"  # "pkgfile" | "repo" | "mirror"
    url: str = ""
    description: str = ""
    depends: list[str] = dataclasses.field(default_factory=list)

    @property
    def version_release(self) -> str:
        return f"{self.version}-{self.release}"

    @property
    def pkgfile_version_release(self) -> str:
        return f"{self.pkgfile_version}-{self.pkgfile_release}"

    @property
    def is_custom(self) -> bool:
        return self.collection.startswith("custom-")

    @property
    def has_override(self) -> bool:
        return (self.port_dir / ".override").is_file()


def get_search_dirs(
    ports_root: pathlib.Path | None = None,
    include_custom: bool = True,
) -> list[tuple[str, str, pathlib.Path]]:
    """Return (collection_name, category, directory_path) in prt-get lookup priority order."""
    root = ports_root or PORTS_ROOT
    dirs: list[tuple[str, str, pathlib.Path]] = []
    if include_custom:
        for cat in ("core", "opt", "xorg", "xfce", "contrib"):
            dirs.append((f"custom-{cat}", cat, root / "custom" / f"custom-{cat}"))
    for cat in ("core", "opt", "xorg", "xfce", "contrib"):
        dirs.append((f"irradium-{cat}", cat, root / "irradium" / f"irradium-{cat}"))
    for cat in ("core", "opt", "xorg", "contrib"):
        dirs.append((f"crux-{cat}", cat, root / f"crux-{cat}"))
    return dirs


def SearchDirs(ports_root: pathlib.Path | None = None) -> list[pathlib.Path]:
    """Return just the Path objects in SEARCH_DIRS priority order."""
    return [d for _, _, d in get_search_dirs(ports_root=ports_root, include_custom=True)]


SEARCH_DIRS = SearchDirs()


def read_package_list(file_path: pathlib.Path) -> list[str]:
    """Read package names from a package list file (build.txt or upstream.txt)."""
    if not file_path.is_file():
        return []
    pkgs: list[str] = []
    seen: set[str] = set()
    for raw_line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line and line not in seen:
            seen.add(line)
            pkgs.append(line)
    return pkgs


def parse_pkgfile_headers(pkgfile: pathlib.Path) -> tuple[str, str, list[str]]:
    """Parse # Description:, # URL:, and # Depends on: headers from a Pkgfile."""
    description = ""
    url = ""
    depends: list[str] = []
    if not pkgfile.is_file():
        return description, url, depends
    for line in pkgfile.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("#"):
            if line.strip():
                break
            continue
        m_desc = re.match(r"^#\s*Description\s*:\s*(.*)$", line, re.I)
        if m_desc:
            description = m_desc.group(1).strip()
            continue
        m_url = re.match(r"^#\s*URL\s*:\s*(.*)$", line, re.I)
        if m_url:
            url = m_url.group(1).strip()
            continue
        m_dep = re.match(r"^#\s*Depends\s+on\s*:\s*(.*)$", line, re.I)
        if m_dep:
            depends = [
                tok.strip()
                for tok in re.split(r"[, \t]+", m_dep.group(1))
                if tok.strip()
            ]
    return description, url, depends


def source_pkgfile(port_dir: pathlib.Path) -> tuple[str, str]:
    """Source a Pkgfile in a bash subshell and return (version, release)."""
    res = subprocess.run(
        ["bash", "-c", '. ./Pkgfile; printf "%s\\t%s\\n" "$version" "$release"'],
        cwd=str(port_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0 and res.stdout.strip():
        parts = res.stdout.splitlines()[-1].split("\t")
        if len(parts) >= 2 and parts[0].strip():
            return parts[0].strip(), parts[1].strip() or "1"

    # Fallback regex parsing if bash sourcing fails for any reason
    pkgfile = port_dir / "Pkgfile"
    version = ""
    release = "1"
    if pkgfile.is_file():
        for line in pkgfile.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("version="):
                version = line.split("=", 1)[1].strip().strip("\"'")
            elif line.startswith("release="):
                release = line.split("=", 1)[1].strip().strip("\"'")
    return version, release


def source_pkgfiles_batch(port_dirs: list[pathlib.Path]) -> dict[pathlib.Path, tuple[str, str]]:
    """Source multiple Pkgfiles in isolated bash subshells within a single bash process."""
    if not port_dirs:
        return {}
    script = (
        'for d in "$@"; do\n'
        '  (cd "$d" && . ./Pkgfile 2>/dev/null && printf "%s\\t%s\\t%s\\n" "$d" "$version" "$release") || true\n'
        "done\n"
    )
    res = subprocess.run(
        ["bash", "-c", script, "bash", *[str(d) for d in port_dirs]],
        capture_output=True,
        text=True,
        check=False,
    )
    out: dict[pathlib.Path, tuple[str, str]] = {}
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[1].strip():
                out[pathlib.Path(parts[0])] = (parts[1].strip(), parts[2].strip() or "1")
    for d in port_dirs:
        if d not in out:
            out[d] = source_pkgfile(d)
    return out


def find_port(
    name: str,
    ports_root: pathlib.Path | None = None,
    include_custom: bool = True,
) -> tuple[str, str, pathlib.Path] | None:
    """Resolve a package name to (collection, category, port_dir) across SEARCH_DIRS."""
    for collection, category, search_dir in get_search_dirs(
        ports_root=ports_root, include_custom=include_custom
    ):
        cand = search_dir / name
        if (cand / "Pkgfile").is_file():
            return collection, category, cand
    return None


@dataclasses.dataclass
class _IndexedPort:
    name: str
    collection: str
    category: str
    port_dir: pathlib.Path
    description: str
    url: str
    depends: list[str]


def build_port_index(
    ports_root: pathlib.Path | None = None,
    include_custom: bool = True,
) -> dict[str, _IndexedPort]:
    """Index all available ports across SEARCH_DIRS in priority order."""
    index: dict[str, _IndexedPort] = {}
    for collection, category, search_dir in get_search_dirs(
        ports_root=ports_root, include_custom=include_custom
    ):
        if not search_dir.is_dir():
            continue
        for child in sorted(search_dir.iterdir(), key=lambda p: p.name):
            if child.name in index:
                continue
            pkgfile = child / "Pkgfile"
            if pkgfile.is_file():
                desc, url, deps = parse_pkgfile_headers(pkgfile)
                index[child.name] = _IndexedPort(
                    name=child.name,
                    collection=collection,
                    category=category,
                    port_dir=child,
                    description=desc,
                    url=url,
                    depends=deps,
                )
    return index


_PKG_FILENAME_RE = re.compile(r"^([^#]+)#([^-]+)-([^.]+)\.pkg\.tar\.[a-z0-9]+$")


def parse_pkg_filename(filename: str) -> tuple[str, str, str] | None:
    """Parse '<name>#<version>-<release>.pkg.tar.<ext>' into (name, version, release)."""
    if filename.endswith(".sig"):
        return None
    unquoted = urllib.parse.unquote(filename.split("/")[-1])
    # Match name#version-release.pkg.tar.* where version itself shouldn't split on last '-'
    if "#" not in unquoted or ".pkg.tar." not in unquoted:
        return None
    name, rest = unquoted.split("#", 1)
    ver_rel = rest.split(".pkg.tar.", 1)[0]
    if "-" not in ver_rel:
        return None
    version, release = ver_rel.rsplit("-", 1)
    if not name or not version or not release:
        return None
    return name, version, release


def scan_local_repo(
    repo_root: pathlib.Path | None = None,
    arch: str = DEFAULT_ARCH,
    distr: str = DEFAULT_DISTR_VERSION,
) -> dict[str, tuple[str, str, str]]:
    """Scan local repo/irradium/packages/<arch>/<ver>/<cat>/ for binary package archives.

    Returns dict mapping pkg_name -> (version, release, category).
    """
    root = (repo_root or REPO_ROOT) / "irradium" / "packages" / arch / distr
    found: dict[str, tuple[str, str, str]] = {}
    if not root.is_dir():
        return found
    for cat in CATEGORIES:
        cat_dir = root / cat
        if not cat_dir.is_dir():
            continue
        for entry in sorted(cat_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_file() or entry.name.endswith(".sig"):
                continue
            parsed = parse_pkg_filename(entry.name)
            if parsed:
                name, ver, rel = parsed
                found[name] = (ver, rel, cat)
    return found


_MIRROR_INDEX_CACHE: dict[tuple[str, str, str], dict[str, tuple[str, str, str]]] = {}


def fetch_mirror_index(
    mirror_domain: str = DEFAULT_MIRROR_DOMAIN,
    arch: str = DEFAULT_ARCH,
    distr: str = DEFAULT_DISTR_VERSION,
    timeout: float = 10.0,
) -> dict[str, tuple[str, str, str]]:
    """Fetch binary package versions from mirror index.html across categories.

    Returns dict mapping pkg_name -> (version, release, category).
    """
    cache_key = (mirror_domain.rstrip("/"), arch, distr)
    if cache_key in _MIRROR_INDEX_CACHE:
        return _MIRROR_INDEX_CACHE[cache_key]

    base = f"{mirror_domain.rstrip('/')}/irradium/packages/{arch}/{distr}"
    found: dict[str, tuple[str, str, str]] = {}

    def _fetch_cat(cat: str) -> tuple[str, dict[str, tuple[str, str, str]]]:
        cat_items: dict[str, tuple[str, str, str]] = {}
        for suffix in ("index.html", ""):
            url = f"{base}/{cat}/{suffix}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "irradium-vulntool/1.0"})
                with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                    if resp.status != 200:
                        continue
                    html = resp.read().decode("utf-8", errors="replace")
                for m in re.finditer(r'href="([^"]+\.pkg\.tar\.[a-z0-9]+)"', html):
                    parsed = parse_pkg_filename(m.group(1))
                    if parsed:
                        name, ver, rel = parsed
                        cat_items[name] = (ver, rel, cat)
                if cat_items:
                    break
            except Exception:
                continue
        return cat, cat_items

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for _cat, items in ex.map(_fetch_cat, CATEGORIES):
            found.update(items)

    _MIRROR_INDEX_CACHE[cache_key] = found
    return found


def fetch_upstream_irradium_index(
    arch: str = DEFAULT_ARCH,
    distr: str = DEFAULT_DISTR_VERSION,
    timeout: float = 15.0,
) -> dict[str, tuple[str, str, str]]:
    """Fetch binary package versions from official upstream Irradium mirrors (dl.irradium.org etc.)."""
    mirrors = [
        f"https://mirror.accum.se/mirror/irradium.org/packages/{arch}/{distr}",
        f"https://ftp.cc.uoc.gr/mirrors/linux/irradium/packages/{arch}/{distr}",
        f"https://dl.irradium.org/irradium/packages/{arch}/{distr}",
    ]
    active_base = None
    for cand in mirrors:
        try:
            req = urllib.request.Request(f"{cand}/core/", headers={"User-Agent": "irradium-vulntool/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                if resp.status == 200:
                    active_base = cand
                    break
        except Exception:
            continue

    if not active_base:
        return {}

    found: dict[str, tuple[str, str, str]] = {}

    def _fetch_cat(cat: str) -> dict[str, tuple[str, str, str]]:
        cat_items: dict[str, tuple[str, str, str]] = {}
        url = f"{active_base}/{cat}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "irradium-vulntool/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                if resp.status != 200:
                    return cat_items
                html = resp.read().decode("utf-8", errors="replace")
            for m in re.finditer(r'href="([^"]+\.pkg\.tar\.[a-z0-9]+)"', html):
                parsed = parse_pkg_filename(m.group(1))
                if parsed:
                    name, ver, rel = parsed
                    cat_items[name] = (ver, rel, cat)
        except Exception:
            pass
        return cat_items

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for items in ex.map(_fetch_cat, CATEGORIES):
            found.update(items)

    return found


def resolve_dependency_closure(
    root_packages: list[str],
    port_index: dict[str, _IndexedPort] | None = None,
    ports_root: pathlib.Path | None = None,
) -> list[str]:
    """Compute the transitive '# Depends on:' closure for root_packages in DFS order.

    Returns the list of additional dependency package names (excluding root_packages).
    """
    idx = port_index if port_index is not None else build_port_index(ports_root=ports_root)
    root_set = set(root_packages)
    visited: set[str] = set()
    closure: list[str] = []

    def _dfs(pkg_name: str) -> None:
        if pkg_name in visited:
            return
        visited.add(pkg_name)
        entry = idx.get(pkg_name)
        if not entry:
            return
        for dep in entry.depends:
            if dep in idx and dep not in visited:
                _dfs(dep)
        if pkg_name not in root_set:
            closure.append(pkg_name)

    for pkg in root_packages:
        _dfs(pkg)
    return closure


def resolve_ports(
    targets: list[str] | None = None,
    include_all: bool = False,
    ports_root: pathlib.Path | None = None,
    repo_root: pathlib.Path | None = None,
    arch: str = DEFAULT_ARCH,
    distr: str = DEFAULT_DISTR_VERSION,
    mirror_domain: str = DEFAULT_MIRROR_DOMAIN,
    use_mirror: bool = True,
) -> tuple[list[PortInfo], list[str]]:
    """Resolve target packages (and optionally their dependency closure / repo packages).

    - Built ports (packages/build.txt or custom-* overrides): version resolved by sourcing Pkgfile in bash.
    - Prebuilt ports (packages/upstream.txt and dependencies): version resolved from local repo/
      or mirror index.html binary filenames, falling back to sourcing Pkgfile if not in repo/mirror.
    """
    build_list = read_package_list(BUILD_TXT)
    upstream_list = read_package_list(UPSTREAM_TXT)
    build_set = set(build_list)
    upstream_set = set(upstream_list)

    port_index = build_port_index(ports_root=ports_root, include_custom=True)
    local_repo = scan_local_repo(repo_root=repo_root, arch=arch, distr=distr)
    mirror_repo = (
        fetch_mirror_index(mirror_domain=mirror_domain, arch=arch, distr=distr)
        if use_mirror
        else {}
    )

    ordered_names: list[str] = []
    seen_names: set[str] = set()

    def _add(name: str) -> None:
        if name and name not in seen_names:
            seen_names.add(name)
            ordered_names.append(name)

    if targets:
        for t in targets:
            _add(t)
        if include_all:
            for dep in resolve_dependency_closure(ordered_names, port_index=port_index):
                _add(dep)
    else:
        for p in upstream_list:
            _add(p)
        for p in build_list:
            _add(p)
        if include_all:
            for dep in resolve_dependency_closure(ordered_names, port_index=port_index):
                _add(dep)
            for repo_pkg in sorted(local_repo.keys()):
                _add(repo_pkg)
            for mir_pkg in sorted(mirror_repo.keys()):
                _add(mir_pkg)

    missing: list[str] = []
    to_source: list[pathlib.Path] = []
    matched_entries: list[_IndexedPort] = []

    for name in ordered_names:
        entry = port_index.get(name)
        if entry is None:
            missing.append(name)
            continue
        matched_entries.append(entry)
        to_source.append(entry.port_dir)

    sourced_map = source_pkgfiles_batch(to_source)

    resolved: list[PortInfo] = []
    for entry in matched_entries:
        pkg_ver, pkg_rel = sourced_map.get(entry.port_dir, ("", "1"))
        if entry.name in build_set or entry.collection.startswith("custom-"):
            source_kind = "build"
        elif entry.name in upstream_set:
            source_kind = "upstream"
        else:
            source_kind = "dependency"

        # Determine authoritative version:
        # Built ports use Pkgfile sourcing; upstream/dependency ports prefer local repo/ then mirror index.html.
        if source_kind == "build":
            ver, rel, ver_src = pkg_ver, pkg_rel, "pkgfile"
        elif entry.name in local_repo:
            ver, rel, _ = local_repo[entry.name]
            ver_src = "repo"
        elif entry.name in mirror_repo:
            ver, rel, _ = mirror_repo[entry.name]
            ver_src = "mirror"
        else:
            ver, rel, ver_src = pkg_ver, pkg_rel, "pkgfile"

        resolved.append(
            PortInfo(
                name=entry.name,
                version=ver,
                release=rel,
                pkgfile_version=pkg_ver,
                pkgfile_release=pkg_rel,
                collection=entry.collection,
                category=entry.category,
                port_dir=entry.port_dir,
                source_kind=source_kind,
                version_source=ver_src,
                url=entry.url,
                description=entry.description,
                depends=list(entry.depends),
            )
        )

    return resolved, missing
