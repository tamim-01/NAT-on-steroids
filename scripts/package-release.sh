#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release=${NAT_RELEASE_DIR:-"$root/../releases"}
version=0.7.1
cd "$root"
git rev-parse --verify HEAD >/dev/null
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  echo 'Commit all reviewed source changes before preparing a release.' >&2
  exit 1
fi
mkdir -p "$release"
NAT_RELEASE_DIR="$release" sh "$root/scripts/package-deb.sh"
git archive --format=tar.gz --prefix="nat-on-steroids-$version/" \
  --output="$release/nat-on-steroids-$version-source.tar.gz" HEAD
tar -czf "$release/nat-on-steroids-$version-linux-amd64.tar.gz" \
  -C "$root" bin/nat-on-steroids bin/n-orm-helper bin/n-orm-steroid-helper \
  bin/hev-socks5-tunnel run.sh README.md SECURITY.md CHANGELOG.md LICENSE licenses packaging
(
  cd "$release"
  sha256sum "nat-on-steroids_${version}_amd64.deb" \
    "nat-on-steroids-$version-source.tar.gz" \
    "nat-on-steroids-$version-linux-amd64.tar.gz" > SHA256SUMS
)
echo "Release files prepared in $release. Nothing was uploaded."
