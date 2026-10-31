#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
staging=${NORM_PACKAGE_DIR:-"$root/work"}
release=${NAT_RELEASE_DIR:-"$root/../releases"}
for file in nat-on-steroids n-orm-helper n-orm-steroid-helper hev-socks5-tunnel; do
  test -x "$root/bin/$file" || { echo "Build bin/$file first." >&2; exit 1; }
done
mkdir -p "$staging" "$release"
package=$(mktemp -d "$staging/deb.XXXXXX")
# Only remove the temporary child created by this invocation.
trap 'rm -rf -- "$package"' EXIT
trap 'exit 1' HUP INT TERM
# Keep the installed helper directory and policy IDs compatible with existing TUN setups.
mkdir -p "$package/DEBIAN" "$package/usr/lib/n-orm-proxy" "$package/usr/share/applications" "$package/usr/share/pixmaps" "$package/usr/share/polkit-1/actions" "$package/usr/share/doc/nat-on-steroids/licenses"
cp "$root/bin/nat-on-steroids" "$root/bin/n-orm-helper" "$root/bin/n-orm-steroid-helper" "$root/bin/hev-socks5-tunnel" "$package/usr/lib/n-orm-proxy/"
cp "$root/packaging/nat-on-steroids.desktop" "$package/usr/share/applications/"
cp "$root/packaging/n-orm-proxy.png" "$package/usr/share/pixmaps/"
cp "$root/packaging/org.n-orm.proxy.policy" "$root/packaging/org.n-orm.proxy.steroid.policy" "$package/usr/share/polkit-1/actions/"
cp "$root/LICENSE" "$root/README.md" "$root/SECURITY.md" "$root/CHANGELOG.md" "$package/usr/share/doc/nat-on-steroids/"
cp -R "$root/licenses/." "$package/usr/share/doc/nat-on-steroids/licenses/"
cat > "$package/DEBIAN/control" <<'EOF'
Package: nat-on-steroids
Version: 0.7.1
Section: net
Priority: optional
Architecture: amd64
Maintainer: NAT-on-steroids contributors
Conflicts: n-orm-proxy, foxyvpn-linux
Replaces: n-orm-proxy, foxyvpn-linux
Provides: n-orm-proxy
Depends: libc6 (>= 2.34), libgtk-3-0t64 | libgtk-3-0, libwebkit2gtk-4.1-0, iproute2, pkexec
Recommends: gnome-keyring | keepassxc
Description: Unofficial Firefox proxy client for Linux
 Supports Mozilla account sign-in, HTTP/2 proxy connections, and Linux TUN.
 General UDP and IPv6 tunneling are not supported in this version.
EOF
find "$package" -type d -exec chmod 0755 {} +
find "$package" -type f -exec chmod 0644 {} +
chmod 0755 "$package/usr/lib/n-orm-proxy/nat-on-steroids" "$package/usr/lib/n-orm-proxy/n-orm-helper" "$package/usr/lib/n-orm-proxy/n-orm-steroid-helper" "$package/usr/lib/n-orm-proxy/hev-socks5-tunnel"
dpkg-deb --root-owner-group --build "$package" "$release/nat-on-steroids_0.7.1_amd64.deb"
