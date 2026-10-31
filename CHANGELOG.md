# Changelog

## Unreleased

- Fixed HTTP 406 sign-in failures caused by different user agents in account and security-challenge requests.
- Refresh challenge cookies independently, require a completed cookie valid for the account API, and preserve its scope and expiry.
- Keep retries bounded and distinguish account API errors from security-challenge rejection. OAuth client ID, account storage, UI, and tunnel behavior are unchanged.
- Verified the fix with regression tests and a live empty request that reaches missing-parameter validation. Real Linux account sign-in remains a separate user check. Published 0.7.1 downloads predate this fix.

## 0.7.1 — experimental release

- Renamed the app, native window, project, launcher, executable, and Debian package to **NAT-on-steroids**.
- Retained saved settings and accounts across upgrades. The package updates the launcher automatically.
- Kept the standard and experimental tunnel behavior from 0.7.0. Publication preparation changes source exclusions, documentation, and release packaging; it does not change OAuth identity or routing.
- Added GitHub-oriented build/install instructions and security/privacy documentation. Release downloads include checksums; they are not signed.

Verification for the prepared candidate is recorded in `RELEASE_CHECKLIST.md`. The known unpatched, low-severity frontend build-tool dependency advisory is documented in `SECURITY.md`; this release does not claim a clean dependency audit.

## 0.7.0

- Added the separate experimental **TUN on steroid** mode with configurable exact-domain and suffix rules for VPN or Direct.
- Added explicit browser PAC setup, in-memory observed hostnames, route overrides, and separate Direct transfer totals.
- Retained System-wide TUN as the default, with its original helper and routing branch.

## Earlier releases

- Multiple Mozilla accounts, account allowance checks, local proxy ports, live speed and latency monitoring.
- Server ping comparisons, a collapsible server list, responsive layouts, six themes, and configurable traffic visualizations and latency refresh intervals.
