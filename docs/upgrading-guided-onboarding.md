# Upgrading the guided onboarding preview

The combined feature uses host database schema28. It accepts the previous common
schema23, main's conversations schema24 and the guided feature's schemas24–27.
Both independently allocated schema24 histories are recognized before migration;
neither overwrites the other. Migration adds the missing tables in one
transaction and preserves identity, signed authority, policies and history.

## Before upgrading

1. Record the installed version, verified archive checksum, executable prefix,
   exact host state path and Peerspan person-key configuration path. Retain the
   verified old binary/archive. Explicit `--state` or service configuration can
   select a different state path from the default.
2. Stop the host. For the installed Linux user service, use
   `systemctl --user stop peerspan.service`; stop a foreground host through its
   owning terminal. Confirm it has exited and prevent another service instance
   from opening the state while the backup is made.
3. Make a private full backup of the **entire stopped host state directory** and
   **the Peerspan person-key/configuration directory**, preserving all files and
   their ownership/modes. Record a private file hash/mode manifest. Include any
   separately configured original key file in your existing private backup
   process. An SSH-agent-backed key stays in its existing original location.
   Do not export it through Peerspan or transfer it to another computer.
4. Keep this backup separate from the live state. It contains authority and
   credentials; retain it in your private backup storage. Copying only the SQLite
   file, changing its version number, or copying only the executable does not
   provide full recovery.

## Upgrade and check

Verify and extract the new archive to its lasting prefix. Start the new binary
with the same host state and signer configuration. Check public status, network
membership/provider, agent registry and retained activity before resuming work.
The database should now have schema28. If it is malformed or newer than this
binary supports, startup refuses it rather than repairing or interpreting it as
an older schema.

For the bundled Claude plugin, follow the explicit local marketplace installation
in the [quick start](quick-start.md). Reload it in the existing conversation when
Claude requests it, then open `/peerspan`. A pending exact review retains its ID
and original deadline. Restart detaches old session metadata: an attachment that
became invalid requires a fresh explicit replacement review. It does not silently
reattach or establish incoming/model readiness.

## Restore after an unsuccessful preview upgrade

An older binary **refuses schema28**. Binary-only rollback is unsupported.

Stop the new host and prevent automatic restart. Preserve the upgraded state
separately for investigation. Restore the complete stopped preupgrade state and
Peerspan key/configuration backup to their original locations and original
private modes, using empty destinations so newer files cannot be mixed into the
old backup. Restore the verified old executable/service configuration and start
that old binary against the restored state. Check the original public identity,
network authority, agents and retained history before continuing.

Never edit `PRAGMA user_version`, drop guided/conversation tables, or transplant
selected rows to simulate a downgrade. The full backup is the recovery unit.

## Verification record

The independent [installed upgrade suite](../conformance/installed_upgrade.py)
creates populated states using genuine old binaries, upgrades them with the
verified installed archive, checks history and pending-review continuity, proves
old-binary refusal without database mutation, then restores the complete backup
and reopens it with its matching old binary. The final acceptance PR records
exact source, archive and receipt hashes. Isolated test fixtures are distinguished
from separate physical machines and from authenticated model receipt.
