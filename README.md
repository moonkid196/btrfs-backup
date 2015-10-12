# btrfs-backup

A tool/service to manage local snapshots, and remote backups, of *btrfs* filesystems.

## What?

This aims to be a flexible tool for client-oriented backups of *btrfs* filesystems. Its primary design goal is to be a tool useful for laptops (like the one it's being written on), so it integrates with some **Gnome** desktop tools/utilities. It thus also would work on a desktop fairly easily.

However, I intend it to be featureful, so it should be configurable to work on servers as well.

It uses as much as I can pull out of systemd, including:
- *systemd-tmpfiles(8)*
- *systemd.service(5)* and *systemd.timer(5)* files for perdiodic activation
- *systemd-ask-password* support for unlocking the keyring, SSH keys, or decrypting disks
- *systemd-inhibit(1)* to prevent elective sleep/shutdown operations from interrupting backup

In addition, though *btrfs-backup* should support more slimmed-down environments/installs, by default, it works with the following tools to get its job done:
- *dbus-daemon(1)*
- *gnome-keyring-daemon(1)*
- *secret-tool(1)*
- *truncate(1)*
- *cryptsetup(8)*
- *sshfs(1)*

Currently, all dbus/keyring tools, keys, etc need to be set up manually, every boot, but that should change soon. Additionally, the remote backups image must be set up by hand prior to this being useful. This should all be addressed in due time.

## Features

Some of the current or future design goals for this tool:

- Keep 24 (configurable) local snapshots
- Push snapshots regularly to remote filesystem image
- Remote image encryption and compression
- Support for several remote image access mechanisms (*sshfs*, *nfs*, *USB*-attached disk)
- Snapshot-only support when not plugged in (configurable)
- Some gvfs integration for non-admin browsing
- Definable critical thresholds for skipping copying snapshots to remote
- Configurable retention of remote backups/snapshots
- Slow update of local-to-remote snapshots to keep individual job-times down
