#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.env"
fi

ARCH="${ARCH:-riscv64}"
if [[ -z "${DISTR_VERSION:-}" ]]; then
    GIT_BRANCH="$(git -C "$ROOT_DIR" branch --show-current 2>/dev/null || true)"
    if [[ "$GIT_BRANCH" =~ ^[0-9]+\.[0-9]+$ ]]; then
        DISTR_VERSION="$GIT_BRANCH"
    else
        DISTR_VERSION="3.8"
    fi
fi
PORTS_ROOT="${PORTS_ROOT:-$ROOT_DIR/ports}"
CACHE_DIR="${CACHE_DIR:-$ROOT_DIR/cache/$ARCH}"
REPO_ROOT="${REPO_ROOT:-$ROOT_DIR/repo}"
KEYS_DIR="${KEYS_DIR:-$ROOT_DIR/keys}"

R2_BUCKET="${R2_BUCKET:-irradium}"
R2_ENDPOINT="${R2_ENDPOINT:-}"
MIRROR_DOMAIN="${MIRROR_DOMAIN:-https://irradium.blackhole.com.br}"

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [options] <pkg-or-port-path>...   Build, package, and sign port(s) + missing dependencies
  $(basename "$0") [options] --from-file <file>      Process packages listed in <file> (e.g. packages/build.txt)
  $(basename "$0") [options] --all                   Sync packages/upstream.txt then build packages/build.txt
  $(basename "$0") [options] publish                 Sync repo/irradium/packages/ to remote mirror storage
  $(basename "$0") [options] sign                    Sign all packages in repo/irradium/packages/<arch>/<ver>/
  $(basename "$0") [options] keygen                  Generate a signify keypair in $KEYS_DIR
  $(basename "$0") [options] image                   Build or rebuild the irradium-<arch>:<ver> Docker image
  $(basename "$0") [options] shell                   Open an interactive shell inside the builder container

Options:
  -a, --arch <arch>        Target architecture: riscv64 (default) or aarch64
  -u, --upstream           Upstream mode: download pre-built binaries from dl.irradium.org, verify official
                           Irradium signature, and re-sign for this mirror (never compiles from source)
  -p, --publish            Automatically publish after processing
  -s, --skip-existing      Skip if the exact <name>#<ver>-<rel>.pkg.tar.gz already exists on the mirror or in repo/
  -h, --help               Show this help message

Examples:
  $(basename "$0") libb2 --publish
  $(basename "$0") --upstream --from-file packages/upstream.txt --skip-existing --publish
  $(basename "$0") --from-file packages/build.txt --skip-existing --publish
  $(basename "$0") --all --skip-existing --publish
EOF
}

DO_PUBLISH="no"
SKIP_EXISTING="no"
MODE="build"
RUN_ALL="no"
FROM_FILE=""
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch)
            ARCH="$2"
            CACHE_DIR="$ROOT_DIR/cache/$ARCH"
            shift 2
            ;;
        -u|--upstream)
            MODE="upstream"
            shift
            ;;
        --all)
            RUN_ALL="yes"
            shift
            ;;
        -p|--publish)
            DO_PUBLISH="yes"
            shift
            ;;
        -s|--skip-existing)
            SKIP_EXISTING="yes"
            shift
            ;;
        -f|--from-file)
            FROM_FILE="$2"
            shift 2
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            TARGETS+=("$1")
            shift
            ;;
    esac
done

case "$ARCH" in
    riscv64) DOCKER_PLATFORM="linux/riscv64" ;;
    aarch64) DOCKER_PLATFORM="linux/arm64" ;;
    *)
        echo "ERROR: Unsupported architecture '$ARCH' (expected riscv64 or aarch64)" >&2
        exit 1
        ;;
esac

IMAGE_NAME="irradium-${ARCH}:${DISTR_VERSION}"
REPO_DIR="$REPO_ROOT/irradium/packages/$ARCH/$DISTR_VERSION"

read_pkg_file() {
    local file="$1"
    local prefix="$2"
    if [[ ! -f "$file" ]]; then
        echo "ERROR: File not found: $file" >&2
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -n "$line" ]] && TARGETS+=("${prefix}${line}")
    done < "$file"
}

if [[ "$RUN_ALL" == "yes" ]]; then
    [[ -f "$ROOT_DIR/packages/upstream.txt" ]] && read_pkg_file "$ROOT_DIR/packages/upstream.txt" "upstream:"
    [[ -f "$ROOT_DIR/packages/build.txt" ]] && read_pkg_file "$ROOT_DIR/packages/build.txt" "build:"
elif [[ -n "$FROM_FILE" ]]; then
    read_pkg_file "$FROM_FILE" "${MODE}:"
else
    for i in "${!TARGETS[@]}"; do
        case "${TARGETS[$i]}" in
            image|keygen|sign|publish|shell) ;;
            upstream:*|build:*) ;;
            *) TARGETS[$i]="${MODE}:${TARGETS[$i]}" ;;
        esac
    done
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    usage
    exit 1
fi

ensure_binfmt() {
    if ! docker run --rm --platform "$DOCKER_PLATFORM" "$IMAGE_NAME" /bin/true >/dev/null 2>&1; then
        echo "==> Registering $ARCH binfmt_misc handler in Docker VM..."
        docker run --privileged --rm tonistiigi/binfmt --install "$ARCH"
    fi
}

ensure_image() {
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "==> Building Docker image $IMAGE_NAME ($DOCKER_PLATFORM)..."
        docker build \
            --platform "$DOCKER_PLATFORM" \
            --build-arg ARCH="$ARCH" \
            --build-arg DISTR_VERSION="$DISTR_VERSION" \
            -t "$IMAGE_NAME" \
            "$SCRIPT_DIR"
    fi
    ensure_binfmt
}

ensure_keys() {
    mkdir -p "$KEYS_DIR"
    if [[ -n "${SIGNIFY_SECRET_KEY:-}" && ! -f "$KEYS_DIR/pkg-get.sec" ]]; then
        printf "%s\n" "$SIGNIFY_SECRET_KEY" > "$KEYS_DIR/pkg-get.sec"
        chmod 600 "$KEYS_DIR/pkg-get.sec"
    fi
    if [[ ! -f "$KEYS_DIR/pkg-get.sec" || ! -f "$KEYS_DIR/pkg-get.pub" ]]; then
        echo "==> Generating signify keypair in $KEYS_DIR..."
        docker run --rm --platform "$DOCKER_PLATFORM" \
            -v "$KEYS_DIR:/keys" \
            "$IMAGE_NAME" \
            signify -G -n -p /keys/pkg-get.pub -s /keys/pkg-get.sec
        echo "==> Public key generated at $KEYS_DIR/pkg-get.pub:"
        cat "$KEYS_DIR/pkg-get.pub"
    fi
}

publish_repo() {
    if [[ -z "$R2_ENDPOINT" ]]; then
        echo "ERROR: R2_ENDPOINT is not set (configure it in .env or environment)" >&2
        exit 1
    fi
    mkdir -p "$REPO_ROOT/irradium/packages"
    echo "==> Syncing $REPO_ROOT/irradium/packages/ to s3://$R2_BUCKET/irradium/packages/..."
    local sync_status=0
    if ! aws s3 sync "$REPO_ROOT/irradium/packages/" "s3://$R2_BUCKET/irradium/packages/" \
        --endpoint-url "$R2_ENDPOINT" \
        --region auto; then
        echo "==> Retrying aws s3 sync after transient upload failure..." >&2
        aws s3 sync "$REPO_ROOT/irradium/packages/" "s3://$R2_BUCKET/irradium/packages/" \
            --endpoint-url "$R2_ENDPOINT" \
            --region auto || sync_status=$?
    fi

    echo "==> Generating HTML index listings..."
    local index_tmp
    index_tmp="$(mktemp -d)"
    aws s3 ls "s3://$R2_BUCKET/irradium/packages/" --recursive \
        --endpoint-url "$R2_ENDPOINT" \
        --region auto | python3 "$SCRIPT_DIR/gen-index.py" "$index_tmp"
    aws s3 sync "$index_tmp/" "s3://$R2_BUCKET/" \
        --endpoint-url "$R2_ENDPOINT" \
        --region auto \
        --content-type "text/html; charset=utf-8" \
        --cache-control "no-cache"
    rm -rf "$index_tmp"
    if [[ "$sync_status" -ne 0 ]]; then
        exit "$sync_status"
    fi
    echo "==> Published packages and index to $MIRROR_DOMAIN/"
}

CMD="${TARGETS[0]}"
case "$CMD" in
    image)
        docker build \
            --platform "$DOCKER_PLATFORM" \
            --build-arg ARCH="$ARCH" \
            --build-arg DISTR_VERSION="$DISTR_VERSION" \
            -t "$IMAGE_NAME" \
            "$SCRIPT_DIR"
        ensure_binfmt
        exit 0
        ;;
    keygen)
        ensure_image
        ensure_keys
        exit 0
        ;;
    sign)
        ensure_image
        ensure_keys
        mkdir -p "$REPO_DIR"
        docker run --rm --platform "$DOCKER_PLATFORM" \
            -v "$REPO_DIR:/repo" \
            -v "$KEYS_DIR:/etc/pkg-get" \
            "$IMAGE_NAME" \
            pkg-get -s /repo
        echo "==> Signed all packages under $REPO_DIR"
        exit 0
        ;;
    publish)
        publish_repo
        exit 0
        ;;
    shell)
        ensure_image
        mkdir -p "$CACHE_DIR/sources" "$CACHE_DIR/packages" "$REPO_DIR" "$KEYS_DIR"
        exec docker run --rm -it --platform "$DOCKER_PLATFORM" \
            -v "$PORTS_ROOT:/mnt/ports" \
            -v "$CACHE_DIR:/var/cache/pkgmk" \
            -v "$REPO_DIR:/repo" \
            -v "$KEYS_DIR:/etc/pkg-get" \
            "$IMAGE_NAME" /bin/bash -c '
                mkdir -p /usr/ports
                for c in core opt xorg xfce contrib; do
                    mkdir -p "/mnt/ports/custom/custom-$c"
                    ln -sfn "/mnt/ports/custom/custom-$c" "/usr/ports/custom-$c"
                    if [[ -d "/mnt/ports/irradium/irradium-$c" ]]; then
                        ln -sfn "/mnt/ports/irradium/irradium-$c" "/usr/ports/irradium-$c"
                    else
                        mkdir -p "/usr/ports/irradium-$c"
                    fi
                done
                for c in core opt xorg contrib; do
                    if [[ -d "/mnt/ports/crux-$c" ]]; then
                        ln -sfn "/mnt/ports/crux-$c" "/usr/ports/$c"
                    else
                        mkdir -p "/usr/ports/$c"
                    fi
                done
                exec /bin/bash
            '
        ;;
esac

# Process upstream and/or build targets inside the container
ensure_image
ensure_keys
mkdir -p "$CACHE_DIR/sources" "$CACHE_DIR/packages" "$REPO_DIR"

BUILD_STATUS=0
docker run -i --rm --platform "$DOCKER_PLATFORM" \
    -e SKIP_EXISTING="$SKIP_EXISTING" \
    -e MIRROR_URL="$MIRROR_DOMAIN/irradium/packages/$ARCH/$DISTR_VERSION" \
    -e ARCH="$ARCH" \
    -e DISTR_VERSION="$DISTR_VERSION" \
    -v "$PORTS_ROOT:/mnt/ports" \
    -v "$CACHE_DIR:/var/cache/pkgmk" \
    -v "$REPO_DIR:/repo" \
    -v "$KEYS_DIR:/etc/pkg-get" \
    "$IMAGE_NAME" /bin/bash -s -- "${TARGETS[@]}" <<'EOS' || BUILD_STATUS=$?
set -euo pipefail

mkdir -p /var/cache/pkgmk/sources /var/cache/pkgmk/packages /tmp/pkgmk-work /usr/ports
sed -i 's|PKGMK_WORK_DIR=.*|PKGMK_WORK_DIR="/tmp/pkgmk-work/$name"|' /etc/pkgmk.conf

# Ensure ZeroSSL/Sectigo intermediate CA certs are in system bundle for dl.irradium.org TLS verification
if [[ -f /usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt ]]; then
    if ! grep -q "MIIDNTCCArugAwIBAgIRAMThxbsA8CePNHvk" /etc/ssl/cert.pem 2>/dev/null; then
        cat /usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt >> /etc/ssl/cert.pem 2>/dev/null || true
        cat /usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
    fi
fi

# Official Irradium pkg-get public key for verifying packages downloaded from dl.irradium.org
cat > /tmp/irradium-upstream.pub <<'PUBEOF'
untrusted comment: pkg-get public key
RWTuJkODJcOmD4iSbIIUzRt+qT73ua9l6E916KuyYLp4qc5MM42EMIp0
PUBEOF

# Link port trees into /usr/ports matching /etc/prt-get.conf hierarchy
cat > /etc/prt-get.conf <<'PRTEOF'
prtdir /usr/ports/custom-core
prtdir /usr/ports/custom-opt
prtdir /usr/ports/custom-xorg
prtdir /usr/ports/custom-xfce
prtdir /usr/ports/custom-contrib
prtdir /usr/ports/irradium-core
prtdir /usr/ports/irradium-opt
prtdir /usr/ports/irradium-xorg
prtdir /usr/ports/irradium-xfce
prtdir /usr/ports/irradium-contrib
prtdir /usr/ports/core
prtdir /usr/ports/opt
prtdir /usr/ports/xorg
prtdir /usr/ports/contrib
PRTEOF

for c in core opt xorg xfce contrib; do
    mkdir -p "/mnt/ports/custom/custom-$c"
    ln -sfn "/mnt/ports/custom/custom-$c" "/usr/ports/custom-$c"
    if [[ -d "/mnt/ports/irradium/irradium-$c" ]]; then
        ln -sfn "/mnt/ports/irradium/irradium-$c" "/usr/ports/irradium-$c"
    else
        mkdir -p "/usr/ports/irradium-$c"
    fi
done
for c in core opt xorg contrib; do
    if [[ -d "/mnt/ports/crux-$c" ]]; then
        ln -sfn "/mnt/ports/crux-$c" "/usr/ports/$c"
    else
        mkdir -p "/usr/ports/$c"
    fi
done

check_existing() {
    local category="$1"
    local name="$2"
    local pkg_file="$3"
    local encoded_pkg="$4"
    local mode_label="$5"

    if [[ "${SKIP_EXISTING:-no}" == "yes" ]]; then
        if [[ -f "/repo/$category/$pkg_file" && -f "/repo/$category/${pkg_file}.sig" ]]; then
            echo "==> [$mode_label:SKIP] $category/$pkg_file already exists locally"
            if ! prt-get isinst "$name" >/dev/null 2>&1; then
                pkgadd "/repo/$category/$pkg_file"
            fi
            return 0
        fi
        if [[ "$(curl -o /dev/null --silent -Iw '%{http_code}' "${MIRROR_URL}/${category}/${encoded_pkg}")" == "200" ]]; then
            echo "==> [$mode_label:SKIP] $category/$pkg_file already published on ${MIRROR_URL}"
            if ! prt-get isinst "$name" >/dev/null 2>&1; then
                curl -fsSL "${MIRROR_URL}/${category}/${encoded_pkg}" -o "/var/cache/pkgmk/packages/$pkg_file"
                curl -fsSL "${MIRROR_URL}/${category}/${encoded_pkg}.sig" -o "/var/cache/pkgmk/packages/${pkg_file}.sig"
                signify -p /etc/pkg-get/pkg-get.pub -V -q -m "/var/cache/pkgmk/packages/$pkg_file" -x "/var/cache/pkgmk/packages/${pkg_file}.sig"
                pkgadd "/var/cache/pkgmk/packages/$pkg_file"
            fi
            return 0
        fi
    fi
    return 1
}

build_single_port() {
    local port_dir="$1"
    local collection
    collection="$(basename "$(dirname "$port_dir")")"
    local category="${collection##*-}"

    cd "$port_dir"
    # shellcheck disable=SC1091
    source Pkgfile
    local pkg_file="${name}#${version}-${release}.pkg.tar.gz"
    local encoded_pkg="${name}%23${version}-${release}.pkg.tar.gz"
    mkdir -p "/repo/$category"

    if check_existing "$category" "$name" "$pkg_file" "$encoded_pkg" "BUILD"; then
        return 0
    fi

    echo "==> [BUILD] Compiling $collection/$name (${version}-${release})..."
    if [[ -f ./pre-install ]]; then
        sh ./pre-install
    fi
    pkgmk -d -f
    if ! prt-get isinst "$name" >/dev/null 2>&1; then
        pkgadd "/var/cache/pkgmk/packages/$pkg_file"
    else
        pkgadd -u "/var/cache/pkgmk/packages/$pkg_file"
    fi

    cp -f "/var/cache/pkgmk/packages/$pkg_file" "/repo/$category/$pkg_file"
    signify -s /etc/pkg-get/pkg-get.sec -S -m "/repo/$category/$pkg_file" -x "/repo/$category/${pkg_file}.sig"
    signify -p /etc/pkg-get/pkg-get.pub -V -q -m "/repo/$category/$pkg_file" -x "/repo/$category/${pkg_file}.sig"
    echo "==> [BUILD] Built & signed: $category/$pkg_file"
}

# Fast parallel sync for all upstream:* targets (fetches mirror index once, resolves
# dependency closure, skips unavailable arch packages, and verifies + re-signs in parallel)
python3 - "$@" <<'PYEOF'
import concurrent.futures
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

targets = [t.split(":", 1)[1].rstrip("/") for t in sys.argv[1:] if t.startswith("upstream:")]
if not targets:
    sys.exit(0)

arch = os.environ.get("ARCH", "riscv64")
distr = os.environ.get("DISTR_VERSION", "3.8")
skip_existing = os.environ.get("SKIP_EXISTING", "no") == "yes"
mirror_url = os.environ["MIRROR_URL"].rstrip("/")

upstream_mirrors = [
    f"https://mirror.accum.se/mirror/irradium.org/packages/{arch}/{distr}",
    f"https://ftp.cc.uoc.gr/mirrors/linux/irradium/packages/{arch}/{distr}",
    f"https://dl.irradium.org/irradium/packages/{arch}/{distr}",
]

ssl_ctx = ssl.create_default_context()
extra_ca = pathlib.Path("/usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt")
if extra_ca.is_file():
    ssl_ctx.load_verify_locations(cafile=str(extra_ca))

active_upstream = None
for cand in upstream_mirrors:
    try:
        with urllib.request.urlopen(f"{cand}/core/", timeout=10, context=ssl_ctx) as r:
            if r.status == 200:
                active_upstream = cand
                break
    except Exception:
        continue

if not active_upstream:
    print("ERROR: All upstream Irradium mirrors are unreachable", file=sys.stderr)
    sys.exit(1)

categories = ["core", "opt", "xorg", "xfce", "contrib"]

# 1. Index packages available on upstream mirror (fail hard if any category fails or is empty)
upstream_index = {}  # pkg_name -> (upstream_cat, fname, encoded_fname)
def fetch_upstream_cat(cat):
    url = f"{active_upstream}/{cat}/"
    with urllib.request.urlopen(url, timeout=30, context=ssl_ctx) as r:
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status} fetching {url}")
        html = r.read().decode("utf-8", errors="replace")
    found = {}
    for m in re.finditer(r'href="([^"]+\.pkg\.tar\.gz)"', html):
        raw_href = m.group(1).split("/")[-1]
        fname = urllib.parse.unquote(raw_href)
        name = fname.split("#", 1)[0]
        encoded = urllib.parse.quote(fname)
        found[name] = (cat, fname, encoded)
    if not found:
        raise RuntimeError(f"Upstream category listing {url} returned 0 packages")
    return cat, found

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    for cat, found in ex.map(fetch_upstream_cat, categories):
        for name, info in found.items():
            upstream_index[name] = info

# 2. Index packages already published on MIRROR_URL (if skip_existing)
mirror_existing = set()  # "cat/fname"
if skip_existing:
    def fetch_mirror_cat(cat):
        for suffix in ("index.html", ""):
            url = f"{mirror_url}/{cat}/{suffix}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "irradium-builder/1.0"})
                with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as r:
                    html = r.read().decode("utf-8", errors="replace")
                items = set()
                for m in re.finditer(r'href="([^"]+\.pkg\.tar\.gz)"', html):
                    fname = urllib.parse.unquote(m.group(1).split("/")[-1])
                    items.add(f"{cat}/{fname}")
                return items
            except Exception as exc:
                print(f"WARN: Failed to query mirror index {url}: {exc}", file=sys.stderr, flush=True)
                continue
        return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for items in ex.map(fetch_mirror_cat, categories):
            mirror_existing |= items

# 3. Scan port trees in /usr/ports priority order for category & dependencies
prt_order = [
    ("core", "/usr/ports/custom-core"),
    ("opt", "/usr/ports/custom-opt"),
    ("xorg", "/usr/ports/custom-xorg"),
    ("xfce", "/usr/ports/custom-xfce"),
    ("contrib", "/usr/ports/custom-contrib"),
    ("core", "/usr/ports/irradium-core"),
    ("opt", "/usr/ports/irradium-opt"),
    ("xorg", "/usr/ports/irradium-xorg"),
    ("xfce", "/usr/ports/irradium-xfce"),
    ("contrib", "/usr/ports/irradium-contrib"),
    ("core", "/usr/ports/core"),
    ("opt", "/usr/ports/opt"),
    ("xorg", "/usr/ports/xorg"),
    ("contrib", "/usr/ports/contrib"),
]

port_map = {}  # pkg_name -> (target_cat, deps_list)
for cat, dpath in prt_order:
    pdir = pathlib.Path(dpath)
    if not pdir.is_dir():
        continue
    for child in pdir.iterdir():
        pkgfile = child / "Pkgfile"
        if child.name not in port_map and pkgfile.is_file():
            deps = []
            try:
                for line in pkgfile.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = re.match(r"^#\s*Depends\s+on\s*:\s*(.*)$", line, re.I)
                    if m:
                        deps = [x.strip() for x in re.split(r"[, \t]+", m.group(1)) if x.strip()]
                        break
            except Exception:
                pass
            port_map[child.name] = (cat, deps)

# Check which packages are already installed in base rootfs (/var/lib/pkg/db)
installed_base = set()
db_file = pathlib.Path("/var/lib/pkg/db")
if db_file.is_file():
    lines = db_file.read_text(encoding="utf-8", errors="replace").splitlines()
    i = 0
    while i < len(lines):
        pkgname = lines[i].strip()
        if pkgname:
            installed_base.add(pkgname)
        i += 2
        while i < len(lines) and lines[i].strip():
            i += 1
        i += 1

def resolve_dep_order(root_pkg):
    order = []
    visited = set()
    def dfs(pkg):
        if pkg in visited:
            return
        visited.add(pkg)
        if pkg in port_map:
            for dep in port_map[pkg][1]:
                if dep in port_map and dep not in installed_base:
                    dfs(dep)
        order.append(pkg)
    dfs(root_pkg)
    return order

to_sync = []
queued = set()

for t in targets:
    pkg_name = t.split("/")[-1]
    if pkg_name not in port_map:
        print(f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} not found in port trees (skipping)", flush=True)
        continue
    if pkg_name not in upstream_index:
        print(f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} has no pre-built {arch} binary on upstream mirror (skipping)", flush=True)
        continue
    dep_chain = resolve_dep_order(pkg_name)
    missing_deps = [d for d in dep_chain if d not in upstream_index]
    if missing_deps:
        print(f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} missing dependency {missing_deps[0]} on upstream {arch} mirror (skipping)", flush=True)
        continue
    for d in dep_chain:
        if d not in queued:
            queued.add(d)
            to_sync.append(d)

def sync_one(pkg_name):
    upstream_cat, pkg_file, encoded_pkg = upstream_index[pkg_name]
    # Preserve upstream category so pkg-get finds dependencies in the collection they were built in,
    # or use port_map category if matching
    category = port_map[pkg_name][0] if pkg_name in port_map else upstream_cat
    repo_cat_dir = pathlib.Path(f"/repo/{category}")
    repo_cat_dir.mkdir(parents=True, exist_ok=True)
    dest_pkg = repo_cat_dir / pkg_file
    dest_sig = repo_cat_dir / f"{pkg_file}.sig"

    if skip_existing:
        if dest_pkg.is_file() and dest_sig.is_file():
            return f"==> [UPSTREAM:SKIP] {category}/{pkg_file} already exists locally"
        if f"{category}/{pkg_file}" in mirror_existing:
            return f"==> [UPSTREAM:SKIP] {category}/{pkg_file} already published on {mirror_url}"

    cache_pkg = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}")
    cache_sig = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}.upstream.sig")

    pkg_url = f"{active_upstream}/{upstream_cat}/{encoded_pkg}"
    sig_url = f"{pkg_url}.sig"

    with urllib.request.urlopen(pkg_url, timeout=120, context=ssl_ctx) as r, open(cache_pkg, "wb") as f:
        shutil.copyfileobj(r, f)
    with urllib.request.urlopen(sig_url, timeout=30, context=ssl_ctx) as r, open(cache_sig, "wb") as f:
        shutil.copyfileobj(r, f)

    subprocess.run(
        ["signify", "-p", "/tmp/irradium-upstream.pub", "-V", "-q", "-m", str(cache_pkg), "-x", str(cache_sig)],
        check=True,
    )
    shutil.copy2(cache_pkg, dest_pkg)
    subprocess.run(
        ["signify", "-s", "/etc/pkg-get/pkg-get.sec", "-S", "-m", str(dest_pkg), "-x", str(dest_sig)],
        check=True,
    )
    subprocess.run(
        ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(dest_pkg), "-x", str(dest_sig)],
        check=True,
    )
    # Remove cached archive after copying to /repo to keep container disk usage low
    cache_pkg.unlink(missing_ok=True)
    cache_sig.unlink(missing_ok=True)
    return f"==> [UPSTREAM] Verified & re-signed: {category}/{pkg_file}"

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
    for msg in ex.map(sync_one, to_sync):
        print(msg, flush=True)
PYEOF

for item in "$@"; do
    mode="${item%%:*}"
    [[ "$mode" == "upstream" ]] && continue
    target="${item#*:}"
    target="${target%/}"

    if [[ ! "$target" =~ ^[a-zA-Z0-9._+-]+(/[a-zA-Z0-9._+-]+)?$ ]]; then
        echo "ERROR: Invalid package or port target '$target'" >&2
        exit 1
    fi

    if [[ "$target" == */* ]]; then
        if [[ -f "/usr/ports/$target/Pkgfile" ]]; then
            port_path="/usr/ports/$target"
        elif [[ -f "/mnt/ports/$target/Pkgfile" ]]; then
            port_path="/mnt/ports/$target"
        else
            echo "ERROR: Pkgfile not found for '$target'" >&2
            exit 1
        fi
        pkg_name="$(basename "$port_path")"
    else
        pkg_name="$target"
        port_path="$(prt-get path "$pkg_name" 2>/dev/null || true)"
        if [[ -z "$port_path" || ! -f "$port_path/Pkgfile" ]]; then
            echo "ERROR: Package '$pkg_name' not found in any configured port tree" >&2
            exit 1
        fi
    fi

    deps_output="$(prt-get depends "$pkg_name" 2>/dev/null || true)"
    processed_target="no"
    if [[ -n "$deps_output" && "$deps_output" != *"not found"* ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ \[\ \]\ ([^[:space:]]+) ]]; then
                dep_pkg="${BASH_REMATCH[1]}"
                dep_path="$(prt-get path "$dep_pkg")"
                build_single_port "$dep_path" </dev/null
                if [[ "$dep_pkg" == "$pkg_name" ]]; then
                    processed_target="yes"
                fi
            fi
        done <<< "$deps_output"
    fi
    if [[ "$processed_target" == "no" ]]; then
        build_single_port "$port_path" </dev/null
    fi
done

# Generate httpup REPO index and signify signature for any populated custom-* port collections
for c in core opt xorg xfce contrib; do
    custom_dir="/mnt/ports/custom/custom-$c"
    if compgen -G "$custom_dir/*/Pkgfile" >/dev/null 2>&1; then
        httpup-repgen "$custom_dir"
        signify -s /etc/pkg-get/pkg-get.sec -S -e -m "$custom_dir/REPO" -x "$custom_dir/REPO.sig"
    fi
done
EOS

if [[ "$DO_PUBLISH" == "yes" ]]; then
    publish_repo
fi

exit "$BUILD_STATUS"
