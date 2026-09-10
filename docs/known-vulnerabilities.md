# Known vulnerability findings

## Published 0.1.0 snapshot

Release 0.1.0 uses the digest-pinned official Python 3.12.14 slim-trixie ARM64 base image. Its published Grype JSON contains:

- 7 reviewed Critical entries under `ignoredMatches`;
- 61 active High entries under `matches`;
- 56 active Medium entries under `matches`.

The seven reviewed Critical entries affect Debian base packages. Debian classified the underlying issues as minor, postponed, or not requiring a stable Trixie advisory at the time of that release.

| Finding | Package and version | Debian assessment | Runtime relevance |
| --- | --- | --- | --- |
| CVE-2026-5450 | libc-bin 2.41-12+deb13u3 | no-DSA, minor | Requires a specific GNU scanf format and explicit width over 1024; no known helper path uses it. |
| CVE-2026-5450 | libc6 2.41-12+deb13u3 | no-DSA, minor | Same narrowly triggered glibc issue; no known helper path uses it. |
| CVE-2026-8376 | perl-base 5.40.1-6 | no-DSA, minor | The memory corruption applies to 32-bit Perl; the maintained image is ARM64. |
| CVE-2026-13221 | perl-base 5.40.1-6 | no-DSA, minor | Requires compiling an attacker-controlled Perl regex with more than 65,535 fixed branches; the helper does not invoke Perl. |
| CVE-2026-42496 | perl-base 5.40.1-6 | postponed, minor | Requires extracting an attacker-controlled archive through Perl Archive::Tar; the helper does not invoke Perl. |
| CVE-2026-12087 | perl-base 5.40.1-6 | no-DSA, minor | Requires attacker-controlled input to a Perl Socket function; the helper does not invoke Perl. |
| CVE-2026-57433 | perl-base 5.40.1-6 | no-DSA, minor | Requires Perl Storable to deserialize a crafted record; the helper does not invoke Perl. |

Authoritative Debian records:

- https://security-tracker.debian.org/tracker/CVE-2026-5450
- https://security-tracker.debian.org/tracker/CVE-2026-8376
- https://security-tracker.debian.org/tracker/CVE-2026-13221
- https://security-tracker.debian.org/tracker/CVE-2026-42496
- https://security-tracker.debian.org/tracker/CVE-2026-12087
- https://security-tracker.debian.org/tracker/CVE-2026-57433

These are risk acceptances, not claims that packages are fixed. The 0.1.0 JSON retains each exception with its applied rule. The active High and Medium counts were not ignored, fixed, or absent; they remained part of the operator's review burden. The phrase "seven reviewed findings" refers only to the Critical ignore set, never to the complete scan.

## Published 0.2.0 snapshot

Release 0.2.0 keeps the same digest-pinned base image and its published Grype JSON contains the same counts as 0.1.0: 7 reviewed Critical entries under `ignoredMatches`, 61 active High entries, and 56 active Medium entries under `matches`. The seven Critical exceptions are the same CVE, package, and version rows listed above; the table applies unchanged. Equal counts across two releases are a coincidence of one scan date, not a guarantee.

## 0.2.0 and later

Vulnerability counts are scan snapshots and must not be copied forward as immutable gates. Database updates, base-image rebuilds, package changes, and matching changes can alter every severity.

For each candidate, publish the complete Grype JSON and count both `matches` and `ignoredMatches` across Critical, High, Medium, Low, Negligible, and Unknown. Active Critical findings stop the release. Every ignored Critical requires an applied rule and explicit risk review. Active High/Medium findings also require review and disclosure even when they do not automatically fail the gate.

Remove exceptions when fixed packages become available. Operators remain responsible for evaluating all active and ignored findings against their environment, updating the image, restricting credentials and egress, and rebuilding when fixes are published. The MIT license provides the software without warranty.
