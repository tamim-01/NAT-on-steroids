# NAT-on-steroids

An experimental Linux desktop client for Firefox’s proxy service, built with Go, Wails, and Svelte.  The protocol implementation is based on [Vauth/FoxyVPN v1.0.7](https://github.com/Vauth/FoxyVPN/tree/v1.0.7).

**Unofficial:** this project is not affiliated with Mozilla or Fastly. Service eligibility, allowance, available locations, and destination restrictions are controlled by the provider. A Mozilla account alone does not guarantee access.

**There is no kill switch.** Disconnecting, quitting, or a tunnel failure can restore normal direct connectivity. General UDP/QUIC and remote ICMP are unsupported; TUN blocks IPv6. Read [Security and privacy](SECURITY.md) before use.

## Features

- **System-wide TUN:** the default mode for supported TCP traffic, using a separate privileged helper and hev-socks5-tunnel.
- **TUN on steroid:** a separate experimental mode with browser domain rules, explicit PAC setup, and an in-memory observed-domain list.
- **Local proxy:** loopback SOCKS5 and HTTP/HTTPS CONNECT proxies without TUN authorization.
- Multiple Mozilla accounts, service-reported remaining allowance, and manual/automatic balance refresh.
- Collapsible server list, flags, parallel server-ping checks, and sorting by the fastest responding edge in each country.
- Six themes: Midnight, Nord, Dracula, Forest, Ember, and Daylight.
- Independent speed, remaining-allowance, and received/sent visualizations, with graph, terminal-style, ring, bar, or numeric options as appropriate.
- Connected-edge latency checks with 1/15/30/45-second, 1/10/15-minute presets, or a custom interval of 1–900 seconds, including 40 seconds.

## Install a release

Experimental release **0.7.1**, Linux **x86_64**. Download the Debian package or binary archive and `SHA256SUMS` from [this repository’s Releases page](https://github.com/tamim-01/NAT-on-steroids/releases). Do not download executables from issue attachments or unknown mirrors.

The source on `main` includes an HTTP 406 sign-in fix that is not yet included in the published 0.7.1 downloads. Build from source to use it until updated release downloads are available.

Check the matching checksum before installation. For an individual download, compare its `sha256sum` result with the corresponding line in `SHA256SUMS`. If all three release files are present, run:

```sh
sha256sum -c SHA256SUMS
sudo apt install ./nat-on-steroids_0.7.1_amd64.deb
```

Checksums detect accidental differences; these artifacts are not signed and do not provide independent publisher authentication.

The Debian package targets Debian/Ubuntu-style systems with GTK3, WebKitGTK 4.1, and glibc 2.34 or newer. Debian 13 is the tested build environment; other distributions are unverified. Open **NAT-on-steroids** from the application launcher after installation.

Close earlier instances before upgrading. Existing settings and saved accounts are retained automatically.

The binary archive can be extracted and launched with `./run.sh`. It requires the same desktop libraries. Use the installed Debian package for TUN so helper ownership and authorization policies are configured. A Git source checkout has no built executables; build it first.

## Connect

1. Sign in with an eligible Mozilla account and complete any requested email verification.
2. Select a location. While disconnected, **Refresh pings** checks locations and sorts the completed results by their best responding edge. Failed checks appear last; the selected country is preserved.
3. Choose **System-wide TUN**, **TUN on steroid**, or **Local proxy**, then connect.
4. The app reports Connected after exit-IP verification. TUN modes also verify traffic through the operating-system network stack.

TUN requires administrator authorization through Polkit. The desktop UI and account credentials remain unprivileged. Do not run this app alongside another VPN. Route cleanup is attempted on disconnect and catchable termination; force-killing a privileged helper or a system failure can prevent cleanup.

### Local proxy

Default listeners are `127.0.0.1:1088` for SOCKS5 and `127.0.0.1:8088` for HTTP/HTTPS CONNECT. Configure the client application explicitly; SOCKS clients should use remote hostname resolution (`socks5h`). Ports can be changed while disconnected. Listeners close on disconnect and have no local authentication: other local users/processes can access them while active.

### TUN on steroid: domain rules

System-wide TUN remains the default; the experimental mode is explicitly selected. Its helper supervises the original TUN helper and adds a marked Direct broker. It does not replace the normal TUN routing implementation.

1. Select **TUN on steroid** and add rules, such as **Domain suffix `.ir` → Direct**. Rules start empty; unmatched hostnames use VPN.
2. Connect. Startup verifies the system route and distinct VPN/Direct exit IPs.
3. Set your browser’s automatic proxy configuration URL to the value shown in the app, normally `http://127.0.0.1:8099/proxy.pac`. Firefox exposes this in **Settings → Network Settings → Automatic proxy configuration URL**. Other browsers need a PAC-capable proxy configuration. Alternatively, set both HTTP and HTTPS proxy to the app’s HTTP listener.
4. Use **VPN** or **Direct** beside an observed hostname to save an exact-domain override. Reload affected pages after changing rules.

Browser proxy setup is required: IP-only traffic arriving through TUN stays on VPN. The PAC file routes public requests to the local proxy without a public Direct fallback; loopback access remains local. The app does not change browser profiles or system proxy settings automatically.

Exact rules override suffix rules; otherwise the longest matching suffix wins on a domain-label boundary. `.ir` matches `example.ir` and its subdomains, not `example.ir.example.com`. A page may use resources from several domains, each with its own decision. Failed routes do not silently switch between VPN and Direct.

Direct supports **public IPv4 TCP destinations on ports 80 and 443**, using the normal connection’s exit IP. Private, reserved, metadata, and IPv6 destinations are rejected. Saving rules closes existing hostname proxy streams. Up to 128 rules are saved; up to 256 observed hostnames remain in memory and can be cleared. The list shows connection attempts and last routes, not full browsing history. Direct transfer totals are separate from the VPN traffic monitor.

### Monitoring and preferences

Open **Appearance and monitoring** to select a theme, independent traffic visualizations, and the latency interval. Allowance is a service-reported snapshot, not a counter-based estimate. Unknown and exhausted allowance are distinct. Automatic balance checks run without notifications; an account can also be checked manually.

Server pings measure HTTP/2 PING round trips to the proxy edge, excluding connection setup. Scans run only while disconnected, with up to six parallel checks and a one-minute scan limit. Connected latency probes use the same edge protocol and never overlap. They are separate from traffic-health checks and token renewal. Results do not measure destination website speed or prove account eligibility.

Settings and domain rules are saved in the app’s private `settings.json` beneath your XDG configuration directory, normally `~/.config/`. Account tokens use the desktop Secret Service keyring; a locked keyring causes a warning and can limit changes to the current session. See [SECURITY.md](SECURITY.md) for sign-in behavior and external services.

## Build from a fresh source checkout

Required: Linux x86_64, Go **1.26+**, Node.js **20.19+ or 22.12+**, npm, Git, a C compiler, Make, pkg-config, and GTK3/WebKitGTK 4.1 development headers. Install a supported Go and Node.js toolchain separately if the distribution packages are older.

For Debian/Ubuntu, install native build dependencies:

```sh
sudo apt install build-essential pkg-config git libgtk-3-dev libwebkit2gtk-4.1-dev
```

Clone the repository, or extract the source archive:

```sh
git clone https://github.com/tamim-01/NAT-on-steroids.git
cd NAT-on-steroids
```

In the project directory:

```sh
./scripts/build.sh
./run.sh
```

The build downloads Go/npm dependencies and the pinned hev-socks5-tunnel source and submodules. It runs `npm ci`, validates/builds the frontend, then builds the app and helpers. The pinned hev commit is `9b2c2320b26046b307abd6ddb5f102b2ccd1d4a4`. Go/npm dependency versions are recorded in `go.sum` and `frontend/package-lock.json`. No account credentials or `.env` file are needed to build.

Generated files stay in ignored `bin/`, `frontend/dist/`, `frontend/node_modules/`, and `work/`. `NORM_BUILD_DIR` can place hev build files elsewhere. Building alone does not install a package, change routes, or start a VPN.

## Verify

Build the frontend first: Go embeds `frontend/dist`, which is absent in a clean checkout until built.

```sh
npm ci --prefix frontend
npm run build --prefix frontend
go test -race -tags webkit2_41 ./...
go vet -tags webkit2_41 ./...
desktop-file-validate packaging/nat-on-steroids.desktop
```

Tests use local fake account/proxy services and an isolated Secret Service. They open local sockets and a private D-Bus service; restricted sandboxes may require permission. They do not use saved Mozilla credentials or change host routes. The optional `FOXYVPN_LIVE_TEST=1` public-server-list check is disabled by default.

Actual kernel routing can be checked **only in disposable network and mount namespaces**, after installing the helpers, using Python 3, iproute2, OpenSSL, and util-linux:

```sh
experimental_helper=$(dpkg-query -L nat-on-steroids | sed -n '/\/[^/]*steroid-helper$/p')
test -n "$experimental_helper"
sudo unshare --mount --net --fork python3 scripts/test-steroid-netns.py \
  --helper "$experimental_helper" --uid "$(id -u)"
```

The script refuses the host namespaces. It uses fake VPN, DNS, and web endpoints and checks normal TUN capture, marked Direct bypass, rule revocation, public-address filtering, occupied-priority rejection, and EOF/SIGTERM cleanup. Controlled endpoint tests do not establish real website compatibility or an independent security audit.

See [the release checklist](RELEASE_CHECKLIST.md) for the candidate’s verification record. Authenticated Mozilla traffic, real-site split routing, long-running reliability, and normal-desktop authorization caching remain separate live checks.

## Package a release

After building, create a Debian package:

```sh
./scripts/package-deb.sh
```

Files are written to a sibling `releases/` directory. Override it with `NAT_RELEASE_DIR`; `NORM_PACKAGE_DIR` controls the parent of the temporary Debian staging directory. Packaging does not install the app or start a VPN.

From a reviewed, committed Git checkout with no tracked modifications, prepare all three downloads and checksums:

```sh
./scripts/package-release.sh
```

This creates a Debian package, source archive from the current Git commit, binary archive, and `SHA256SUMS`. Upload those files with the matching version tag and [release notes](CHANGELOG.md). Do not upload local settings, logs, node_modules, build caches, or the surrounding development workspace. Nothing is published automatically.

## License and credits

Project source and the owner-supplied logo are under [MIT](LICENSE). Keep the existing copyright notices. Third-party code retains its own licenses; notices are in [licenses/](licenses/).

- [FoxyVPN v1.0.7](https://github.com/Vauth/FoxyVPN/tree/v1.0.7): protocol reference, MIT.
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel): TUN engine, MIT, with its bundled dependency notices.
- [Wails](https://github.com/wailsapp/wails), [Svelte](https://github.com/sveltejs/svelte), and other dependencies: see the bundled notices.

The current OAuth client identity is retained from the existing implementation. Dedicated Mozilla registration is deferred; publication of this source does not imply provider approval. No additional source was copied from the separately inspected unlicensed Go reference client.
