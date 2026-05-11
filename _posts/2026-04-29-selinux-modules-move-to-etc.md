---
layout: post
author: Zdenek Kubala, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SELinux: Policy Packaging Migration to support Snapshots and Rollbacks"
date:   2026-04-29
tags:   selinux
excerpt: "The traditional SELinux policy location /var/lib/selinux is not
supported by the openSUSE snapshot and rollback mechanism. openSUSE is now
migrating the policy packaging to locations supported by this mechanism, which
will allow for proper policy snapshots and rollbacks."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

0) TL;DR
========

- The SELinux policy packaging had long-standing issues on systems using BTRFS
  snapshots: files under `/var/lib/selinux` were not covered by snapshots and
  could not be rolled back.
- These files have now been migrated to `/etc/selinux`, which allows the SELinux
  policy to be fully covered by snapshots.
- The migration applies to openSUSE Tumbleweed and MicroOS systems using
  SELinux.
- The migration is transparent to the user and automatic on default setups. If
  you have a non-standard filesystem setup, or if you observe issues, read the
  full post below.

1) Introduction
===============

SELinux has been the Mandatory Access Control mechanism on openSUSE
distributions such as MicroOS and Leap Micro since 2022, and most recently
openSUSE Tumbleweed [switched the default MAC to SELinux][news:default] in
February 2025.

The files installed on a system by the SELinux policy package have traditionally
been split between `/var/lib/selinux`, `/usr/share/selinux` and `/etc/selinux`
on most Linux distributions, including openSUSE. The separation across these
directory trees conflicts with the modern Linux concept of atomic/image-based
updates, which in openSUSE has been implemented as a [snapshot and rollback
mechanism based on BTRFS][opensuse:atomic-update]. This mechanism only snapshots
the `/usr` and `/etc` trees, intended for packages and configuration
respectively. Other directory trees are meant for user files or, as in the case
of `/var`, for mutable system state files, and as such are not covered by
snapshots.

Installing SELinux policy files under `/var` violates this requirement, and can
result in inconsistency in case of rollbacks: policy files under `/etc` and
`/usr` would be rolled back, but files under `/var` would not be touched.

To resolve this issue, we have migrated SELinux policy files under `/var` to
`/etc`. The migration is automatic and does not require any user interaction in
standard setups. This blog post explains the issue in more detail, documents the
steps taken to migrate the files, and describes known issues and how to resolve
them.

2) Issues with current SELinux policy packaging
===============================================

Atomic/image-based update systems have become increasingly relevant in recent
years. In openSUSE, this concept has been realised as both fully transactional
systems (e.g. MicroOS, Leap Micro) and as regular distributions with automatic
snapshots and the possibility to rollback broken updates (e.g. Tumbleweed). In
both of these cases, the traditional SELinux policy packaging causes some
issues.

In case of a rollback of an update containing a change to the SELinux policy, if
there is a mismatch between what was rolled back (`/usr/share/selinux` and
`/etc/selinux`) and what could not (`/var/lib/selinux`), this could lead to
policy build issues, external module installation issues, and could bring the
SELinux policy and the whole system into a state which is difficult to recover
from automatically.

In practice, these issues are very rare, since they require a particular set of
circumstances:
1. installing a policy update which contains backwards-incompatible changes
   (e.g. adding or removing SELinux types, attributes, modules ...)
2. rolling back this update
3. performing some action which requires the SELinux policy items affected by
   the rollback, such as rebuilding the policy or an affected external policy
   module (either manually or e.g. via RPM package installation).

As a matter of policy, these kinds of backwards-incompatible policy updates are
never performed on distributions such as Leap Micro (except possibly during
migration between major distribution versions), thus preventing the issue. On
Tumbleweed and MicroOS these updates can happen, albeit rarely, and when
combined with the probability of a rollback and the further triggering actions
they become exceedingly rare.

Manually reinstalling the SELinux policy package (and any affected external
policy modules) is sufficient to fix the issues, but this is still an
undesirable characteristic of this legacy packaging structure.

3) Solution: migration from /var to /etc
========================================

To permanently address the aforementioned issues, we decided to migrate SELinux
policy files under `/var/lib/selinux` to `/etc/selinux`. As mentioned, this
location was already used for other SELinux policy files, and is covered by the
snapshot and rollback mechanism.

The migration was tracked in [bsc#1221342][bug:tracker-migration]. After a long
period of automated and manual testing over several months, the migration
was performed in Tumbleweed snapshot
[20260505][opensuse:migration-release-snapshot].

Some of the challenges encountered during the implementation of the migration
process were:
- different rollback and update behaviour on classical and transactional systems
  (also transactional-update before version 5 used overlayfs for /etc)
- preserving existing local modifications to the SELinux configuration
- migrating custom modules (installed by packages or manually created by the
  user)
- packaging changes or rebuilds of some packages to properly reflect location
  changes, including RPM SELinux macros
- cleanup of `/var/lib/selinux` once no snapshot is using the old path
- installation on a fresh system, without migrating an existing system
- observability of discrepancies between migrated modules in
  `/etc/selinux` and last pre-migration state in `/var/lib/selinux`

The migration process is automatic and in most situations will not be visible
to the user, except for information printed in the `zypper` output during the
update. The process takes care not only of the migration of policy
modules provided by the system SELinux policy (e.g. `selinux-policy-targeted`),
but also of custom modules installed by other packages (see below) and local
modifications to SELinux configuration (booleans, users, ports, ...).

To allow the migration to be fully reverted, the process temporarily preserves
the "old" `/var/lib/selinux/` directory tree even after the migration. Once no
snapshots are found which still refer to `/var/lib/selinux`, the whole directory
tree is safely deleted.

Most of the steps are done during package update, except for the final cleanup
step which is performed on the system after the migration has been completed.
During package update, the migration process will:
* print information about the migration process and inform the user if the
  system satisfies the migration requirements (root BTRFS subvolume present) or
  if a non-standard setup was detected (e.g. `/etc` on different BTRFS subvolume
  or no BTRFS at all), and what to do in this case.
* check if the system has already been migrated and skip migration in this case
  (using marker files in `/etc/selinux/selinux_modules_migrated-*`)
* backup the old location (`/var/lib/selinux`) to preserve state (marker files
  `selinux_modules_pending-*` and `temp_selinux_modules_dir_created`)
* install package (modules) into the new location (`/etc/selinux`)
* copy local changes and custom modules (`*.local` files, `200`, `400` and
  `disabled` folders) from the old location to the new location, show diff in
  case of missing custom modules from `/etc/selinux` (marker file
  `selinux_modules_migrated-*`)
* install cleanup systemd service (`cleanoldsepoldir.service`) and
  script(`/usr/libexec/selinux/cleanoldsepoldir.sh`) to remove the old
  `/var/lib/selinux` location once no snapshot is using it

After package update:
* at boot, the `cleanoldsepoldir` service checks if any snapshot still requires
  `/var/lib/selinux`. If not, it removes the directory, and creates marker file
  `var_lib_selinux_deleted` to stop the `cleanoldsepoldir` service from running
  again.
* the cleanup script also allows the user to check if there are some custom
  SELinux modules missing in the new location, and has some heuristics to find
  the RPM packages of non-migrated modules to reinstall them

```sh
$ /usr/libexec/selinux/cleanoldsepoldir.sh -h
This script checks if it is safe to remove the old /var/lib/selinux directory.

Usage:
  /usr/libexec/selinux/cleanoldsepoldir.sh (Checks snapshots and deletes /var/lib/selinux if safe)
  /usr/libexec/selinux/cleanoldsepoldir.sh --check-custom-selinux-modules (Checks for unmigrated custom modules)
  /usr/libexec/selinux/cleanoldsepoldir.sh -h|--help (Displays this help message)
```

Packages involved in the migration
----------------------------------

These packages contain the SELinux policy packaging and were the main object of
the migration:

- `libsemanage-conf` (store-root set to `/etc/selinux/semanage.conf`)
- `selinux-policy` (service `cleanoldsepoldir.service` and script
  `cleanoldsepoldir.sh`)
- `selinux-policy-*` (actual migration and marker files in `/etc/selinux`)

All packages which set SELinux booleans were rebuilt:

- `selinux-policy-targeted-gaming`
- `selinux-policy-sapenablement`
- `container-selinux`
- `libvirt`

Packages which ship custom SELinux modules were also fixed and rebuilt:

- `cockpit-ws-selinux`
- `drbd-selinux`
- `google-guest-oslogin-selinux`
- `swtpm-selinux`
- `tigervnc-selinux`
- `tpm2.0-abrmd-selinux`

> We tried to identify all packages affected by this migration, but if you
> should find other packages in Tumbleweed which need to be migrated, please
> report a [bug][bugreport].

4) Troubleshooting
==================

- If you have a non-standard filesystem setup (e.g. using custom BTRFS
  subvolumes, not using BTRFS at all, ...) the migration may not work for you
  fully. You can find out if the migration was successful by checking for the
  presence of the directory `/etc/selinux/selinux_modules_migrated-*`
  corresponding to your installed policy (e.g.
  `/etc/selinux/selinux_modules_migrated-targeted`). If the directory exists,
  the migration has been successful. If not, please open a [bug][bugreport].
- If you observe any issues resembling those described in [Section
  2](#2-issues-with-current-selinux-policy-packaging), you can resolve them by
  reinstalling the `selinux-policy*` package and any affected external modules:
```sh
$ sudo zypper in -f selinux-policy selinux-policy-targeted
```
- After the migration, only the last state of `/var/lib/selinux` is preserved,
  which means that some older snapshots may still be inconsistent with it. If
  rolling back to one of these older snapshots is necessary, you can fix the
  issues after rolling back by reinstalling the policy and any affected external
  modules as detailed above.

5) Closing Remarks
==================

The openSUSE SELinux team is committed to keeping openSUSE users safe with
SELinux, and to fixing problems that SELinux may cause to the community. To
facilitate changes with SELinux we rely on users to work with us and provide
feedback, so that we understand what the current problematic areas are. If you
encounter problems with SELinux feel free to open a [bug][bugreport] or reach
out over the [mailing list][opensuse:selinux-ml].

6) References
=============

- [Tumbleweed Adopts SELinux as Default][news:default]
- [Policy migration tracker bug][bug:tracker-migration]
- [openSUSE Bugreport SELinux][bugreport]
- [openSUSE SELinux Mailing List][opensuse:selinux-ml]

Change History
==============

|2026-05-11| [Section 3](#3-solution-migration-from-var-to-etc): mentioned the specific Tumbleweed snapshot which introduced the migration ([20260505][opensuse:migration-release-snapshot]) and adjusted phrasing.|

[news:default]: https://news.opensuse.org/2025/02/13/tw-plans-to-adopt-selinux-as-default/
[opensuse:atomic-update]: https://en.opensuse.org/openSUSE:Packaging_Requirements_for_Atomic_and_Image_Update
[bug:tracker-migration]: https://bugzilla.opensuse.org/show_bug.cgi?id=1221342
[bugreport]: https://en.opensuse.org/openSUSE:Bugreport_SELinux
[opensuse:selinux-ml]: https://lists.opensuse.org/archives/list/selinux@lists.opensuse.org/
[opensuse:migration-release-snapshot]: https://lists.opensuse.org/archives/list/factory@lists.opensuse.org/message/YCAAJRIHH7TECRELF43ZIDNUAEZTF7UM/

