---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "Below: World Writable Directory in /var/log/below Allows Local Privilege Escalation (CVE-2025-27591)"
date:   2025-03-12
tags:   local tmpfiles CVE
excerpt: "Below is a tool for recording and displaying system data like
hardware utilization and cgroup information. In Below versions up to and
including version v0.8.1 a world writable log directory is created, which can
lead to a local root exploit and other security issues."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[Below][upstream:github] is a tool for recording and displaying system data
like hardware utilization and cgroup information on Linux. In January 2025,
Below was packaged and submitted to openSUSE Tumbleweed. Below runs as a
systemd service with `root` privileges. The SUSE security team monitors
additions and changes to systemd service unit files in openSUSE Tumbleweed, and
through this we noticed problematic log directory permissions applied in
Below's code.

The version we reviewed in this context was [v0.8.1][upstream:v0.8.1] and this
report is based on that version.

Upstream released a bugfix in version [v0.9.0][upstream:v0.9.0] and a
[security advisory][upstream:advisory] on GitHub.

2) Symlink Attack in `/var/log/below/error_root.log`
====================================================

Below's systemd service runs with full `root` privileges. It attempts to
create a world-writable directory in `/var/log/below`. Even if the directory
already exists, [the Rust code ensures][upstream:chmod-code] that it receives
mode 0777 permissions:

```rust
    if perm.mode() & 0o777 != 0o777 {
        perm.set_mode(0o777);
        match dir.set_permissions(perm) {
            Ok(()) => {}
            Err(e) => {
                bail!(
                    "Failed to set permissions on {}: {}",
                    path.to_string_lossy(),
                    e
                );
            }
        }
    }
```

This logic leads to different outcomes depending on the packaging on Linux
distributions:

- in openSUSE Tumbleweed the directory was packaged with
  01755 permissions ([below.spec][opensuse:spec-file] line 73), thus causing
  the `set_permissions()` call to run, resulting in a directory with mode 0777
  during runtime.
- in Gentoo Linux the directory is created with mode 01755 resulting in the
  same outcome as on openSUSE Tumbleweed ([below.ebuild][gentoo:ebuild]).
  Where the 01755 mode is exactly coming from is not fully clear, maybe the
  `cargo` build process assigns these permissions during installation.
- in Fedora Linux the directory is packaged with 01777 permissions, thus the
  `set_permissions()` code will not run, because the `if` condition masks out
  the sticky bit. The directory stays at mode 01777 ([rust-below.spec][fedora:spec-file]).
- the [Arch Linux AUR package][arch:pkgbuild] (maybe wrongly) does not
  pre-create the log directory. Thus the `set_permissions()` code will run and
  create the directory with mode 0777.

Below creates a log file in `/var/log/below/error_root.log` and assigns mode
0666 to it. This (somewhat confusingly) [happens via
a `log_dir` variable][upstream:error-log-code], which has been changed
to point to the `error_root.log` file. The 0666 permission assignment to the
logfile [happens in `logging::setup()`][upstream:devils-permissions], also
accompanied by a somewhat strange comment in the code.

A local unprivileged attacker can stage a symlink attack in this location and
cause an arbitrary file in the system to obtain 0666 permissions, likely
leading to a full local root exploit, if done right, e.g. by pointing the
symlink to `/etc/shadow`. Even if the file already exists it can be removed
and replaced by a symlink, because of the world-writable directory
permissions. The attack is thus not limited to scenarios in which the file has
not yet been created by Below.

We believe the actual intention of this code might have been to assign mode
01777 (i.e. carrying a sticky bit). The sticky bit is neither contained in
the `if` condition nor in the `set_permissions()` call, though. With the
sticky bit set the Linux kernel's `protected_symlinks` logic, which is enabled
on most Linux distributions, would protect from symlink attacks.

3) Further Issues
=================

Even on Fedora Linux, where `/var/log/below` has "safe" 01777 permissions,
there is a time window during which problems can arise. As long as
`below.service` has not been started, another local user can pre-create
`/var/log/below/error_root.log` and e.g. place a FIFO special file there. This
will pose a local DoS against the below service, since it will fail to open the
path and thus fail to start.

If `/var/log/below` were to be deleted for any reason, then Below would still
recreate it using the bad 0777 mode permissions, which can also happen on
distributions that initially package `/var/log/below` using permissions that
do not trigger the `set_permissions()` call in Below's code.

Below applies many world-writable and world-readable permissions under
`/var/log/below`. This seems a strange choice. For some reason the internal
state data of Below is also stored within the log directory in
`/var/log/below/store`. The data is fully world-readable, which could result
in information leaks, if Below stores system information there that would not
otherwise be accessible to unprivileged local users. We did not check if this
applies, though. By pre-creating this directory before `below.service` runs
for the first time, an unprivileged user can control all of its contents,
possibly violating the integrity of Below in various ways.

The world-writable logfile `error_root.log` makes no sense to us as well. Why
should arbitrary users in the system be able to modify the log data of
Below? This allows log spoofing by local users. Even making the logfile
world-readable is considered bad style by some people these days. Why
`/var/log/below` should be world-writable in the first place is also
unclear to us. Ideally only `root` or a dedicated `below` service user should
be allowed to write there.

4) Bugfix
=========

Upstream published a bugfix in [commit 10e73a21d67][upstream:bugfix] which is
part of Below [v0.9.0][upstream:v0.9.0]. The commit basically removes all
problematic permission assignments from the code, stating that these
directories are better setup by systemd. This seems to refer to an added
systemd directive `LogsDirectory=below` in the `below.service` file.

With this change no world-writable directories or files should turn up in
`/var/log/below` anymore, and the most severe issues from this report are
addressed. The possible matter of world-readable log and store files remains,
though.

We did not get any details from upstream about the design decisions in Below
that led to this issue or about any further changes that upstream intends to
perform to improve security in this area.

5) CVE Assignment
=================

Upstream assigned CVE-2025-27591 for this issue.

6) Hardening Suggestions
========================

It could be considered to apply hardening directives in Below's systemd
service unit that prevent some attack types. Most prominently, restricting
write access for the daemon to a range of well known locations comes to mind.

7) Timeline
===========

|2025-01-20|We noticed the issue and started tracking it privately in [bsc#1236109][opensuse:bsc#1236109].|
|2025-01-20|We shared the information with Meta via its [security bug report system][meta:bugbounty], offering coordinated disclosure.|
|2025-01-21|We received an initial automated reply from Meta.|
|2025-02-21|We received an update that the report would be forwarded to the appropriate engineering team.|
|2025-02-26|We were awarded a bug bounty for the report but did not receive any details about the publication, bugfix or CVE assignment. We will donate the bug bounty to open source projects and other non-profit organizations.|
|2025-02-26|Our Below packager updated the openSUSE Tumbleweed package to the newly released [version v0.9.0][upstream:v0.9.0], which happened to already contain the bugfix for the issue.|
|2025-02-27|We identified [commit 10e73a21d67][upstream:bugfix] as the likely bugfix and inquired with upstream once more about technical details and whether this is the complete bugfix they intended to apply.|
|2025-02-28|We received an automated reply about the bugfix status of the issue.|
|2025-03-03|We received a confirmation that [commit 10e73a21d67][upstream:bugfix] is the intended bugfix and that further steps (including a possible CVE assignment) are handled internally.|
|2025-03-03|We inquired whether it is okay for us to publish the full report at this time.|
|2025-03-07|We did not get a response about publication from upstream so far. Since the bugfix was public but not clearly marked as a security issue we shared this report with the [linux-distros][linux-distros] mailing list, suggesting an embargo of 5 days before general publication.|
|2025-03-08|Michel Lind, a member of the linux-distros mailing list who is also a Meta engineer, involved upstream internally about the impending disclosure.|
|2025-03-08|Upstream reached out to us stating that a GitHub security advisory on the issue is planned in the following week. They also shared the CVE assignment with us. They asked us to postpone publication on our end until that happens.|
|2025-03-10|We responded that postponing publication is okay with us. We also pointed out that the linux-distros mailing list has a maximum embargo period of 14 days, which limited the maximum postponement to 2025-03-21.|
|2025-03-12|Upstream published a [GitHub advisory][upstream:advisory]. Thus general publication could happen on the date originally proposed by us on the linux-distros mailing list.|

8) References
=============

- [Below GitHub repository][upstream:github]
- [Below v0.9.0 bugfix release][upstream:v0.9.0]
- [Bugfix commit 10e73a21d67][upstream:bugfix]
- [Below GitHub Security Advisory][upstream:advisory]

[upstream:github]: https://github.com/facebookincubator/below
[upstream:advisory]: https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w
[upstream:v0.8.1]: https://github.com/facebookincubator/below/releases/tag/v0.8.1
[upstream:v0.9.0]: https://github.com/facebookincubator/below/releases/tag/v0.9.0
[upstream:chmod-code]: https://github.com/facebookincubator/below/blob/v0.8.1/below/src/main.rs#L379
[upstream:error-log-code]: https://github.com/facebookincubator/below/blob/v0.8.1/below/src/main.rs#L552
[upstream:devils-permissions]: https://github.com/facebookincubator/below/blob/v0.8.1/below/src/open_source/logging.rs#L68
[upstream:bugfix]: https://github.com/facebookincubator/below/commit/10e73a21d67baa2cd613ee92ce999cda145e1a83
[opensuse:spec-file]: https://build.opensuse.org/projects/openSUSE:Factory/packages/below/files/below.spec?expand=1&rev=5e78e7f743f87bea8648eeee673c649b
[opensuse:bsc#1236109]: https://bugzilla.suse.com/show_bug.cgi?id=1236109
[gentoo:ebuild]: https://github.com/gentoo/gentoo/blob/master/sys-process/below/below-0.8.1-r1.ebuild#L344
[fedora:spec-file]: https://src.fedoraproject.org/rpms/rust-below/blob/6ae58353b5d12e58462425c20a2aedfbae2e769a/f/rust-below.spec#_108
[arch:pkgbuild]: https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=below#n34
[meta:bugbounty]: https://bugbounty.meta.com
[linux-distros]: https://oss-security.openwall.org/wiki/mailing-lists/distros
