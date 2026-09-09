# Security model

## Capability boundary

Phase 1 is a standalone read-only MCP server. It registers no write, prepare, apply, upload, delete, restart, or configuration tools. It must run with credentials that are independently restricted to read-only access by each target platform. A future write service requires a separate binary, container, credential set, client profile, and operator-controlled activation window.

The container exposes no listening port, has no Docker socket, runs as an unprivileged user, drops all Linux capabilities, uses a read-only root filesystem, and has only tmpfs plus a persistent volume for secret-free audit metadata. Its standard bridge permits outbound traffic because diagnostics require reaching enrolled targets; container hardening does not provide egress isolation. The execution host or an externally managed container network must restrict destination addresses and ports where that boundary is required.

## Credential transport

The client-side proxy parses the local credential object, selects only the requested target record for injection, and injects it into the verified SSH stdio channel, and removes the internal authentication field from the advertised tool schema. The helper keeps credentials in process memory for one call and never writes them to its filesystem.

The public phase-1 design still accepts password-backed records. Password transport and storage are residual risks; production adaptations should use an external secret broker and platform-appropriate key or certificate authentication without broadening the target account's permissions.

## Read query policy

SSH reads use named templates with typed slots. Slot values must pass type validation and exactly match the target's enrolled inventory. HTTPS GET uses exact per-target endpoint allowlisting across path (including query strings), port, and Basic-auth choice. The agent cannot submit a raw command, introduce an unenrolled endpoint, or attach credentials where policy forbids them. Fixed query templates and endpoints remain reviewable, and device-side account authorization is the primary mutation barrier.

FortiOS uses a dedicated Netmiko subclass which skips the upstream driver's configuration-writing paging setup and restore. Enrollment requires an external assertion that console output is already `standard`; SHA-1 KEX is disabled rather than accepting Netmiko's legacy Fortinet KEX narrowing.

Content-bearing reads return explicit byte pagination metadata and a digest of the complete sanitized content. SSH continuation pages use a bounded 120-second in-memory cache and never rerun the command; expired state fails closed. Each proxy process also enforces a per-target sliding request window, defaulting to 12 calls per 60 seconds.

## Untrusted device output

All device and network output is attacker-controlled input and must be treated as evidence only, never instructions. Hostnames, banners, interface descriptions, logs, certificates, filenames, DNS data, and structured fields may contain prompt injection. Responses are marked as untrusted, and the deployment requires a dedicated read-only agent/session with no mutating or generic shell tools. These instructions are defense in depth; absence of write capabilities is the security boundary.

## Redaction and audit

Sanitization removes injected credentials and recognized private-key, token, password, community, Cisco secret, shadow-hash, and FortiOS `ENC` forms. Regex redaction cannot classify every secret. Query templates, HTTPS endpoints, file roots, remote authorization, and chroot are the primary controls; secret stores and configuration backups must never be enrolled. Network identifiers needed for correlation remain visible, so returned data is sensitive even after redaction.

Every device-touching tool writes an audit record for success, failure, or policy rejection. Records contain aliases, operation names, safe counts and options, public SSH query names, timestamps, and SHA-256 digests of paths/results; never command output, raw paths, credentials, network addresses, private material, or complete configurations. The active log and four retained segments are limited to 2 MB each.

SFTP stat, text reads, and FTP/FTPS listings must match a non-root per-target allowlisted root injected by the proxy. Missing or invalid policy denies the request. Remote permissions or chroot remain required because lexical path checks do not replace server-side authorization.
