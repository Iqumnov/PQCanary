# PQCanary Distribution & Packaging Specifications

This directory contains upstream packaging specifications, package build definitions, and formulas for major operating system package managers.

---

## 1. Void Linux (`xbps-src`)

The template is located at [`void-linux/template`](void-linux/template).

### Local Compilation via `xbps-src`:
```bash
git clone https://github.com/void-linux/void-packages.git
cd void-packages
./xbps-src binary-bootstrap
mkdir -p srcpkgs/pqcanary
cp /path/to/PQCanary/packaging/void-linux/template srcpkgs/pqcanary/
./xbps-src pkg pqcanary
xi pqcanary
```

---

## 2. Arch Linux AUR (`PKGBUILD`)

The PKGBUILD is located at [`arch-linux/PKGBUILD`](arch-linux/PKGBUILD).

### Local Build & Installation:
```bash
cd packaging/arch-linux
makepkg -si
```

---

## 3. Homebrew Tap (`pqcanary.rb`)

The formula is located at [`homebrew/pqcanary.rb`](homebrew/pqcanary.rb).

### Local Tap Testing:
```bash
brew install --build-from-source packaging/homebrew/pqcanary.rb
pqcanary --version
```

---

> [!NOTE]
> **Maintainer Checksum Verification:** Once release assets are published by GitHub Actions CI for tag `v0.1.0`, maintainers can update release archive SHA-256 digests in `PKGBUILD` via `updpkgsums`, in `homebrew/pqcanary.rb` via `shasum -a 256`, and in `void-linux/template` via `xgensum -f`.

