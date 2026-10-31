# Security and privacy

NAT-on-steroids is experimental networking software. It has not received an independent security audit. Use of the service depends on Mozilla account eligibility, allowance, and provider restrictions. It is not affiliated with Mozilla or Fastly.

## Reporting a vulnerability

Do not include passwords, access or refresh tokens, keyring exports, real browsing histories, or unredacted logs in a public issue. Email the maintainer at [tamimyousefi023@gmail.com](mailto:tamimyousefi023@gmail.com) with a brief description and reproduction steps, without credentials or private browsing data. Agree on a secure channel before sending sensitive attachments. If private vulnerability reporting is enabled on the GitHub repository, its **Security → Report a vulnerability** page is another option.

## Account data

- The current sign-in form accepts the Mozilla account password inside the desktop app. The Go backend derives the protocol's authentication value and authenticates over certificate-verified HTTPS. This is not a browser redirect sign-in flow.
- Passwords are not intentionally saved to disk. Access and refresh tokens are held in the Go backend and saved through the desktop Secret Service keyring. They are not returned in UI state. A locked or unavailable keyring can leave changes limited to the current session, with a warning in the app.
- Settings, including domain rules, are stored in the app’s private `settings.json` beneath `$XDG_CONFIG_HOME`, normally `~/.config/`. This file is private to the user and does not contain account tokens. Rule domains can still reveal personal preferences; do not publish your settings.
- Account storage identifiers, helper paths, and Polkit action IDs are stable across upgrades.
- Do not attach keyring contents, authentication responses, or crash dumps to public issues.

## External connections

The app contacts Mozilla account, VPN, and public server-list services. Cloudflare HTTPS trace is used for exit-IP checks. DNS resolution uses Cloudflare DoH, with Google as fallback. Normal TUN DNS goes through the VPN; Direct-domain DNS in the experimental mode uses the marked direct route. The app does not implement a separate analytics service.

The current OAuth implementation reuses Firefox Desktop's public client ID and an inherited MozillaVPN user-agent string. A dedicated NAT-on-steroids registration is deferred. This is an unsupported dependency, not an embedded personal secret or evidence of provider approval. No OAuth identity change is included in this publication preparation.

## Privileged helpers and local access

The desktop app runs as the user. TUN requires a separate installed, root-owned helper authorized through Polkit. The installed policy uses `auth_admin_keep`, allowing temporary authorization reuse controlled by the desktop's Polkit configuration. The experimental helper supervises the original helper and brokers marked Direct sockets. Account tokens are not passed to either helper.

SOCKS, HTTP, and PAC listeners bind to loopback. They have no local proxy authentication; other users and processes on the machine can access those listeners while active. The Direct broker's Unix socket is restricted to the authorized UID and independently checks peer credentials and domain rules.

## Routing limits

- There is **no kill switch**. Disconnect, shutdown, or tunnel failure can restore normal direct connectivity. Force-killing a privileged helper or a system failure can prevent route cleanup. Do not run alongside another VPN.
- TCP is supported. General UDP, QUIC, and remote ICMP are unsupported. IPv6 is blocked while TUN is active.
- TUN on steroid requires explicit browser PAC/proxy setup for domain rules. IP-only TUN traffic remains on VPN. The hostname list is not a complete browser request history.
- Direct-domain rules support public IPv4 TCP destinations on ports 80 and 443. They reject private, reserved, metadata, and IPv6 destinations. Direct sends matching traffic through the normal connection and exposes its exit IP to those destinations.
- Up to 256 observed hostnames and connection attempts are held in memory. URLs, cookies, request bodies, and passwords are not recorded in a browsing log. Hostnames are sensitive information even without page contents.
- Exact rules override suffix rules; otherwise the longest matching suffix wins. A page can load resources from several domains with different route decisions. Saving rules closes existing hostname proxy streams; reload affected pages.

## What verification establishes

Automated tests use local fake services and an isolated Secret Service. Kernel routing tests use disposable network and mount namespaces with fake VPN, DNS, and web endpoints. These checks do not establish long-term reliability, live account eligibility, real website compatibility, or a production security audit. See the release notes for the evidence associated with a specific release.

## Known build dependency advisory

As checked on 2026-10-31, `npm audit` reports three low-severity entries from one underlying [deepmerge prototype-poisoning advisory, GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4). The affected `deepmerge@4.3.1` is used by the Svelte/Vite development plugin; the other two entries are its affected dependants. The advisory lists no patched version, and npm reports no automatic fix. No dependency override or audit suppression is applied.

This dependency belongs to the frontend build/development toolchain. Release downloads contain compiled native binaries and static frontend assets, not `node_modules` or a Vite development server. Build only reviewed source and do not expose the development server to untrusted networks. Recheck the advisory before future releases; the current candidate does not claim a clean dependency audit.
