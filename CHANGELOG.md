# Changelog

## 0.7.1 — publication candidate

- Renamed the app, native window, project, launcher, executable, and Debian package to **NAT-on-steroids**.
- Retained existing settings and account identifiers so earlier N-orm proxy installations can upgrade. The package replaces the old launcher.
- Kept the standard and experimental tunnel behavior from 0.7.0. Publication preparation changes source exclusions, documentation, and release packaging; it does not change OAuth identity or routing.
- Added GitHub-oriented build/install instructions and security/privacy documentation. Release downloads include checksums; they are not signed.

Verification for the prepared candidate is recorded in `RELEASE_CHECKLIST.md`. There is no hosted release yet. The known unpatched, low-severity frontend build-tool dependency advisory is documented in `SECURITY.md`; this release does not claim a clean dependency audit.

## 0.7.0

- Added the separate experimental **TUN on steroid** mode with configurable exact-domain and suffix rules for VPN or Direct.
- Added explicit browser PAC setup, in-memory observed hostnames, route overrides, and separate Direct transfer totals.
- Retained System-wide TUN as the default, with its original helper and routing branch.

## Earlier releases

- Multiple Mozilla accounts, account allowance checks, local proxy ports, live speed and latency monitoring.
- Server ping comparisons, a collapsible server list, responsive layouts, six themes, and configurable traffic visualizations and latency refresh intervals.
