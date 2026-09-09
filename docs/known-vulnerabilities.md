# Known vulnerability findings

Release 0.1.0 uses the digest-pinned official Python 3.12.14 slim-trixie base image. Its ARM64
image scan contains seven reviewed critical-severity matches affecting Debian base packages.
Debian classifies the underlying issues as minor and has not issued a stable Trixie security update.

The release gate suppresses only these exact CVE, binary package, and installed-version tuples:

| Finding | Package and version | Debian assessment | Runtime relevance |
| --- | --- | --- | --- |
| CVE-2026-5450 | libc-bin 2.41-12+deb13u3 | no-DSA, minor | Requires a specific GNU scanf %mc format and explicit width over 1024; no known helper path uses it. |
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

These are risk acceptances, not claims that the packages are fixed. The published Grype JSON retains
them under ignoredMatches with the applied rules. Any new critical finding, changed package
version, missing rule attribution, or change in the expected seven-item set fails the release.
The list must be reviewed for every release and removed as soon as a fixed stable base is available.

Operators remain responsible for reviewing this residual risk against their environment, keeping
the image updated, restricting the helper to its intended local-console role, and rebuilding when
Debian publishes fixes. The MIT license provides the software without warranty.
