"""Pure-Python OpenBSD signify Ed25519 signing/verification and httpup REPO generation."""

from __future__ import annotations

import base64
import hashlib
import pathlib
import re
import subprocess

# Default .httpup-repgen-ignore content matching upstream ports/irradium/irradium-*/.httpup-repgen-ignore
DEFAULT_HTTPUP_REPGEN_IGNORE = """\\.svn$
\\.tar\\.gz$
\\.tgz$
\\.partial$
\\.tar\\.bz2$
\\.tar\\.xz$
\\.zip$
(^|/)CVS(/|$)
.*~$
sync.sh
\\.gif$
\\.gem$
index.html
\\.gitignore$
\\.gitkeep$
\\.htaccess$
.git
^irradium.*\\.httpup$
"""

# Ed25519 curve parameters (RFC 8032) — 100% Python stdlib
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)


def _edwards_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = t1 * 2 * _D * t2 % _Q
    dd = z1 * 2 * z2 % _Q
    e = (b - a) % _Q
    f = (dd - c) % _Q
    g = (dd + c) % _Q
    h = (b + a) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalarmult(
    pt: tuple[int, int, int, int],
    e: int,
) -> tuple[int, int, int, int]:
    q_acc = (0, 1, 1, 0)
    cur = pt
    while e > 0:
        if e & 1:
            q_acc = _edwards_add(q_acc, cur)
        cur = _edwards_add(cur, cur)
        e >>= 1
    return q_acc


def _encodepoint(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = _inv(z)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _ed25519_sign(seed: bytes, pub: bytes, msg: bytes) -> bytes:
    h = bytearray(_sha512(seed))
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h[:32], "little")
    r = int.from_bytes(_sha512(bytes(h[32:64]) + msg), "little") % _L
    r_enc = _encodepoint(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(r_enc + pub + msg), "little") % _L
    s_enc = ((r + k * a) % _L).to_bytes(32, "little")
    return r_enc + s_enc


def load_signify_seckey(sec_path: pathlib.Path) -> tuple[bytes, bytes, bytes]:
    """Load an unencrypted OpenBSD signify secret key (.sec) and return (keynum, seed, pubkey)."""
    lines = [
        line.strip()
        for line in sec_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("untrusted comment:")
    ]
    if not lines:
        raise ValueError(f"Invalid signify secret key file: {sec_path}")
    raw = base64.b64decode(lines[0])
    if len(raw) != 104 or raw[:2] != b"Ed":
        raise ValueError(f"Unsupported signify secret key format in {sec_path}")
    kdf_rounds = int.from_bytes(raw[4:8], "big")
    if kdf_rounds != 0:
        raise ValueError(f"Encrypted signify secret key is not supported without passphrase: {sec_path}")
    keynum = raw[32:40]
    seckey = raw[40:104]
    checksum = hashlib.sha512(seckey).digest()[:8]
    if checksum != raw[24:32]:
        raise ValueError(f"Signify secret key checksum mismatch in {sec_path}")
    return keynum, seckey[:32], seckey[32:64]


def sign_embedded_message(
    sec_path: pathlib.Path,
    message: str,
    verify_with_path: str,
) -> str:
    """Create an OpenBSD `signify -S -e` embedded signature document."""
    if not message.endswith("\n"):
        message += "\n"
    keynum, seed, pub = load_signify_seckey(sec_path)
    sig_bytes = b"Ed" + keynum + _ed25519_sign(seed, pub, message.encode("utf-8"))
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    return f"untrusted comment: verify with {verify_with_path}\n{sig_b64}\n{message}"


def is_upstream_signature_file(sig_path: pathlib.Path) -> bool:
    """Return True if a .signature* file was signed for an upstream (non-custom) collection."""
    if not sig_path.is_file():
        return False
    try:
        first_line = sig_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except Exception:
        return True
    return "/etc/ports/custom-" not in first_line


def _source_filenames_from_pkgfile(port_dir: pathlib.Path) -> list[str]:
    res = subprocess.run(
        ["bash", "-c", '. ./Pkgfile 2>/dev/null; for s in "${source[@]}"; do printf "%s\\n" "${s##*/}"; done'],
        cwd=str(port_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return []
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def _collect_existing_sha256_map(
    port_dir: pathlib.Path,
    upstream_port_dirs: list[pathlib.Path] | None = None,
) -> dict[str, str]:
    """Read existing SHA256 (<fname>) = <hex> entries from port_dir and upstream .signature* files."""
    sha_map: dict[str, str] = {}
    search_dirs: list[pathlib.Path] = [port_dir]
    if upstream_port_dirs:
        search_dirs.extend(upstream_port_dirs)
    pattern = re.compile(r"^SHA256 \(([^)]+)\) = ([0-9a-f]{64})$")
    for d in search_dirs:
        if not d or not d.is_dir():
            continue
        for sig_file in sorted(d.glob(".signature*")):
            try:
                for line in sig_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = pattern.match(line.strip())
                    if m:
                        fname, digest = m.group(1), m.group(2)
                        sha_map.setdefault(fname, digest)
            except OSError:
                continue
    return sha_map


def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sign_port_signatures(
    port_dir: pathlib.Path,
    sec_path: pathlib.Path,
    cache_source_dirs: list[pathlib.Path] | None = None,
    upstream_port_dirs: list[pathlib.Path] | None = None,
) -> list[pathlib.Path]:
    """Generate .signature (or .signature.<arch>) for a custom port matching CRUX/Irradium pkgmk -us.

    Also removes any legacy .md5sum file when signatures are generated or updated.
    Returns list of written .signature* paths (empty if footprint or source hashes are unavailable).
    """
    pkgfile = port_dir / "Pkgfile"
    if not pkgfile.is_file() or not sec_path.is_file():
        return []

    collection = port_dir.parent.name
    verify_with = f"/etc/ports/{collection}.pub"

    arch_footprints = sorted(port_dir.glob(".footprint.*"))
    plain_footprint = port_dir / ".footprint"
    if arch_footprints:
        footprint_targets = [
            (fp, port_dir / f".signature.{fp.name.split('.footprint.', 1)[1]}")
            for fp in arch_footprints
        ]
    elif plain_footprint.is_file():
        footprint_targets = [(plain_footprint, port_dir / ".signature")]
    else:
        return []

    source_names = _source_filenames_from_pkgfile(port_dir)
    fallback_shas = _collect_existing_sha256_map(port_dir, upstream_port_dirs=upstream_port_dirs)

    source_shas: list[tuple[str, str]] = []
    for fname in source_names:
        local_cand = port_dir / fname
        if local_cand.is_file():
            source_shas.append((fname, _sha256_file(local_cand)))
            continue

        found_cache = None
        for cdir in cache_source_dirs or []:
            cand = cdir / fname
            if cand.is_file():
                found_cache = cand
                break
        if found_cache is not None:
            source_shas.append((fname, _sha256_file(found_cache)))
            continue

        if fname in fallback_shas:
            source_shas.append((fname, fallback_shas[fname]))
            continue

        # Cannot sign yet because an external source tarball has neither been downloaded nor hashed upstream;
        # remove any stale .signature* from a previous version so pkgmk -d does not fail before downloading.
        for old_sig in port_dir.glob(".signature*"):
            old_sig.unlink(missing_ok=True)
        return []

    pkgfile_sha = _sha256_file(pkgfile)
    written: list[pathlib.Path] = []

    # Remove stale .signature variants if switching between plain and arch-specific
    expected_sig_names = {sig.name for _, sig in footprint_targets}
    for old_sig in port_dir.glob(".signature*"):
        if old_sig.name not in expected_sig_names:
            old_sig.unlink(missing_ok=True)

    for fp_path, sig_path in footprint_targets:
        fp_sha = _sha256_file(fp_path)
        lines = [
            f"SHA256 (Pkgfile) = {pkgfile_sha}",
            f"SHA256 ({fp_path.name}) = {fp_sha}",
        ]
        for fname, sha in source_shas:
            lines.append(f"SHA256 ({fname}) = {sha}")
        msg = "\n".join(lines) + "\n"
        signed_doc = sign_embedded_message(sec_path, msg, verify_with_path=verify_with)
        if not sig_path.is_file() or sig_path.read_text(encoding="utf-8", errors="replace") != signed_doc:
            sig_path.write_text(signed_doc, encoding="utf-8")
        written.append(sig_path)

    # Remove legacy .md5sum if present
    md5_file = port_dir / ".md5sum"
    if md5_file.is_file():
        md5_file.unlink()

    return written


def _md5_file(path: pathlib.Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def update_collection_repo(
    collection_dir: pathlib.Path,
    ensure_ignore_file: bool = True,
) -> bool:
    """Deterministically generate `REPO` (and `.httpup-repgen-ignore`) for a custom-* port collection.

    Also removes any obsolete `REPO.sig` file.
    Returns True if `REPO` was created, updated, or removed.
    """
    if not collection_dir.is_dir():
        return False

    repo_sig = collection_dir / "REPO.sig"
    if repo_sig.is_file():
        repo_sig.unlink()

    has_ports = any(
        (child / "Pkgfile").is_file()
        for child in collection_dir.iterdir()
        if child.is_dir() and not child.name.startswith(".")
    )
    repo_file = collection_dir / "REPO"
    ignore_file = collection_dir / ".httpup-repgen-ignore"

    if not has_ports:
        if repo_file.is_file():
            repo_file.unlink()
            return True
        return False

    if ensure_ignore_file and not ignore_file.is_file():
        ignore_file.write_text(DEFAULT_HTTPUP_REPGEN_IGNORE, encoding="utf-8")

    ignore_patterns: list[re.Pattern[str]] = []
    if ignore_file.is_file():
        for raw in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
            pat = raw.strip()
            if pat:
                ignore_patterns.append(re.compile(pat))

    def _is_ignored(rel_posix: str, name: str) -> bool:
        if name in ("REPO", "REPO.sig", ".httpup-repgen-ignore", ".gitkeep", ".DS_Store"):
            return True
        for rx in ignore_patterns:
            if rx.search(rel_posix) or rx.search(name):
                return True
        return False

    dirs: list[str] = []
    files: list[tuple[str, str]] = []  # (rel_path, md5)
    symlinks: list[tuple[str, str]] = []  # (rel_path, target)

    def _walk(cur_dir: pathlib.Path) -> None:
        for entry in sorted(cur_dir.iterdir(), key=lambda p: p.name):
            rel_posix = entry.relative_to(collection_dir).as_posix()
            if _is_ignored(rel_posix, entry.name):
                continue
            if entry.is_symlink():
                symlinks.append((rel_posix, str(entry.readlink())))
            elif entry.is_dir():
                dirs.append(rel_posix)
                _walk(entry)
            elif entry.is_file():
                files.append((rel_posix, _md5_file(entry)))

    _walk(collection_dir)

    lines: list[str] = []
    for d in dirs:
        lines.append(f"d:{d}")
    for rel_path, target in symlinks:
        lines.append(f"s:{target}:{rel_path}")
    for rel_path, digest in files:
        lines.append(f"f:{digest}:{rel_path}")

    new_content = "\n".join(lines) + "\n"
    old_content = repo_file.read_text(encoding="utf-8", errors="replace") if repo_file.is_file() else None
    if old_content != new_content:
        repo_file.write_text(new_content, encoding="utf-8")
        return True
    return False


def refresh_all_custom_ports(
    ports_root: pathlib.Path,
    keys_dir: pathlib.Path,
    cache_root: pathlib.Path | None = None,
) -> None:
    """Sign all eligible custom ports (when pkg-get.sec is available) and update custom-*/REPO indexes."""
    sec_path = keys_dir / "pkg-get.sec"
    cache_source_dirs: list[pathlib.Path] = []
    if cache_root and cache_root.is_dir():
        for arch_dir in sorted(cache_root.iterdir()):
            sdir = arch_dir / "sources"
            if sdir.is_dir():
                cache_source_dirs.append(sdir)

    custom_root = ports_root / "custom"
    if not custom_root.is_dir():
        return

    for cat in ("core", "opt", "xorg", "xfce", "contrib"):
        col_dir = custom_root / f"custom-{cat}"
        if not col_dir.is_dir():
            continue
        for child in sorted(col_dir.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or not (child / "Pkgfile").is_file():
                continue
            if sec_path.is_file():
                upstream_cands = [
                    ports_root / "irradium" / f"irradium-{cat}" / child.name,
                    ports_root / f"crux-{cat}" / child.name,
                ]
                sign_port_signatures(
                    child,
                    sec_path=sec_path,
                    cache_source_dirs=cache_source_dirs,
                    upstream_port_dirs=upstream_cands,
                )
        update_collection_repo(col_dir, ensure_ignore_file=True)
