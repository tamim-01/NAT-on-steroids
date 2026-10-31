#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${NORM_BUILD_DIR:-"$root/work"}
hev_commit=9b2c2320b26046b307abd6ddb5f102b2ccd1d4a4
command -v go >/dev/null || { echo 'Install Go 1.26 or newer.' >&2; exit 1; }
pkg-config --exists gtk+-3.0 webkit2gtk-4.1 || { echo 'Install GTK3 and WebKitGTK 4.1 development packages.' >&2; exit 1; }
mkdir -p "$build_dir" "$root/bin"
if [ ! -d "$build_dir/hev-socks5-tunnel/.git" ]; then
  git clone https://github.com/heiher/hev-socks5-tunnel.git "$build_dir/hev-socks5-tunnel"
fi
git -C "$build_dir/hev-socks5-tunnel" checkout --detach "$hev_commit"
git -C "$build_dir/hev-socks5-tunnel" submodule update --init --recursive
make -C "$build_dir/hev-socks5-tunnel" -j2
(cd "$root/frontend" && npm ci && npm run build)
cd "$root"
go build -buildvcs=false -trimpath -tags production,webkit2_41 -ldflags '-s -w' -o bin/nat-on-steroids .
go build -buildvcs=false -trimpath -ldflags '-s -w' -o bin/n-orm-helper ./cmd/n-orm-helper
go build -buildvcs=false -trimpath -ldflags '-s -w' -o bin/n-orm-steroid-helper ./cmd/n-orm-steroid-helper
cp "$build_dir/hev-socks5-tunnel/bin/hev-socks5-tunnel" bin/hev-socks5-tunnel
echo "Built $root/bin/nat-on-steroids"
