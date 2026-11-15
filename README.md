# Irradium Binary Packages

Pre-built binary packages for **[Irradium](https://irradium.org/) 3.8** - multi-arch but focused on riscv64.

## Setup on Your Device

Run the following commands as `root` on your Irradium system:

### 1. Install the Public Signing Key

Fetch the public `signify` verification key directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/brennoo/irradium-builder/3.8/keys/pkg-get.pub \
  -o /etc/pkg-get/pkg-get.pub
```

### 2. Configure the Package Mirror

Set the binary mirror in `/etc/pkg-get/mirrors` (`pkg-get` automatically replaces `ARCH` with your system's `uname -m` architecture):

```bash
sed -i 's|^https://|# https://|' /etc/pkg-get/mirrors
echo "https://irradium.blackhole.com.br/irradium/packages/ARCH/3.8" >> /etc/pkg-get/mirrors
```

### 3. Install Packages

Install binary packages and their dependencies using `pkg-get`:

```bash
# Install a package and its missing dependencies
pkg-get -di <package>

# Install a single package
pkg-get -i <package>
```

---

## Available Packages

Packages available on this mirror are tracked in two lists:

* [`packages/build.txt`](packages/build.txt): Packages compiled from source by this repository.
* [`packages/upstream.txt`](packages/upstream.txt): Pre-built upstream Irradium packages verified and mirrored here so devices only need a single mirror and signing key.

Need another package from the Irradium or CRUX port trees added to the binary mirror? Open a pull request adding it to [`packages/build.txt`](packages/build.txt) (or [`packages/upstream.txt`](packages/upstream.txt)) or open an issue.

---

## Custom Packages (`custom-opt`)

This repository also provides custom ports (such as `notqmail`) under [`ports/custom/custom-opt/`](ports/custom/custom-opt) that are not part of upstream Irradium or CRUX.

To enable custom ports on your device so `pkg-get` and `prt-get` can discover them:

```bash
# 1. Trust the public key for custom-opt ports
cp /etc/pkg-get/pkg-get.pub /etc/ports/custom-opt.pub

# 2. Configure httpup to sync custom-opt from GitHub
cat > /etc/ports/custom-opt.httpup << 'EOF'
ROOT_DIR=/usr/ports/custom-opt
URL=https://raw.githubusercontent.com/brennoo/irradium-builder/3.8/ports/custom/custom-opt/
EOF

# 3. Register /usr/ports/custom-opt in /etc/prt-get.conf and sync
sed -i '1i prtdir /usr/ports/custom-opt' /etc/prt-get.conf
ports -u custom-opt
```

Once synced, install custom binary packages just like any other package:

```bash
pkg-get -di notqmail
```

---

## Building Packages Locally

You can build and test packages locally on Linux or macOS using Docker:

```bash
# Clone the repository with upstream port submodules
git clone --recurse-submodules https://github.com/brennoo/irradium-builder.git
cd irradium-builder

# Build a package (and any missing dependencies) for riscv64
./builder/build-pkg.sh <package>

# Build for aarch64
./builder/build-pkg.sh --arch aarch64 <package>
```
