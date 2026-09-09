# Read-only target accounts

NetOps Helper phase 1 assumes that every device account is prevented from mutating the target by authorization enforced on the target itself. Client validation and command templates are additional containment; they are not a substitute for device-side permissions.

## Required properties

- Use a dedicated identity for NetOps Helper reads; never reuse an administrator account.
- Assign the vendor's native read-only role, access profile, login class, privilege level, or command authorization policy.
- Deny configuration mode, file writes, software installation, reboot, process control, account management, secret export, interactive shell escape, and privilege escalation.
- Scope visibility to the smallest operational domain that still permits the intended troubleshooting.
- Keep phase-1 credentials separate from any future write service credentials.
- Log authentication and authorization failures on the target or its authentication service.
- Verify the effective permissions independently before enrollment and after every role or firmware change.

## Platform expectations

- FortiOS: use a dedicated administrator bound to a reviewed read-only access profile and restricted administrative domains or VDOMs where applicable. Before enrollment, an administrator must persistently configure `config system console` / `set output standard` / `end` in the applicable global context, verify the effective value, and then set `fortios_output_standard_verified: true` in target policy. NetOps Helper's FortiOS driver deliberately skips Netmiko's paging preparation and cleanup, so it never enters configuration to change or restore this value. It also disables SHA-1 Diffie-Hellman KEX algorithms; a target offering only legacy SHA-1 KEX is rejected.
- Junos: use a dedicated login class with read/view permissions and explicit denial of configuration and maintenance capabilities.
- Cisco IOS/IOS XE and Arista EOS: use a low-privilege account or external command authorization that permits only reviewed show/diagnostic commands.
- ExtremeXOS: use a dedicated read-only role and verify that configuration and save operations are denied.
- Linux: use an unprivileged account with no Docker access, no writable operational groups, and no general sudo. If privileged reads are unavoidable, expose exact root-owned read wrappers rather than a shell-capable sudo rule.

The local `account_role: "read-only"` policy field records that the operator completed this enrollment. The server rejects a target without it, but it cannot prove the remote authorization model. That proof remains an external deployment responsibility.
