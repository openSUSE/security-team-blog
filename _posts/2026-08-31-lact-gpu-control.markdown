---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "LACT: Polkit Authentication Bypass and Temporary File Handling Issues"
date:   2026-08-31
tags:   CVE local Polkit
excerpt: "LACT is a daemon and graphical UI for controlling GPUs on Linux. A
review of a UNIX domain socket API uncovered a Polkit authentication bypass
resulting in a potential local root exploit, and issues in temporary file
creation."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[LACT][upstream:repo] is a daemon and graphical user interface for controlling
GPU devices on Linux. Beyond providing access to device information,
features like GPU overclocking and cooler control are included. In a
recent update of LACT a Polkit policy appeared, which [triggered a
review][bug] for the corresponding package in openSUSE Tumbleweed.

During the review we identified a Polkit authentication bypass and a
predictable temporary file name issue, resulting in potential local root
exploits. The following sections describe the security issues in detail. This
report is based on [release v0.10.0][release:v0.10.0] of LACT.

2) The LACT Daemon
==================

LACT contains a [systemd service unit][systemd-service] which runs the `lact`
program as a daemon with full root privileges. No systemd service hardening is
in place. The daemon exposes a UNIX domain socket in `/run/lactd.sock`.
Upstream intends this socket to be accessible by members of either the `wheel`
or the `sudo` group. In openSUSE Tumbleweed a stricter opt-in model is used
instead: only members of a dedicated `lact` group are allowed to access the
socket.

The socket is used to exchange LACT-specific messages based on the Rust
[serde][serde] serialization format. In version 0.10.0 of LACT, some of the
message types supported by the daemon have been additionally protected by
Polkit authentication checks.

{: #issues}
3) Security Issues
==================

3.1) Polkit Authentication Bypass due to PID Race (CVE-2026-75037)
==================================================================

The Polkit authentication in the LACT daemon relies on function
[`check_auth()`][code:check_auth], which authenticates the client solely based
on its PID, which is a known misuse in Polkit authentication. A malicious
client can attempt to send out the request, then cycle PIDs in an attempt to
replace its own PID by a privileged process to alter the outcome of the Polkit
authentication check.

Polkit authentication in LACT is used to prevent unprivileged users from
adding so-called profile hooks to the LACT configuration. These hooks are
basically scripts that will be executed with full root privileges as soon as a
LACT profile is (de)activated. As a result, a Polkit authentication bypass in
this context allows to gain full root access. Due to the access restrictions
to the LACT UNIX domain socket, the privilege escalation is only possible for
users that already own a certain level of privilege (i.e. membership in the
`wheel`, `sudo` or `lact` group).

We assigned CVE-2026-75037 to track this issue. Upstream fixed this flaw in
[commit d0478fe4][commit:polkit-fix] by additionally passing the caller's
UID to the Polkit daemon, preventing race conditions from influencing the
outcome of the authorization.

Shortly before publication of this report the upstream author informed us
about [a more deeply rooted issue][zbus-polkit-pr] in Rust crate `zbus_polkit`
which affects various Rust applications that attempt to pass client UIDs to
Polkit. Due to a D-Bus data type mismatch the UID seems to be silently
dropped from the authentication data, resulting again in the same weakness. An
update of the `zbus_polkit` crate, which is part of Rust vendor sources of
various packages is thus strongly recommended to developers of affected
applications and distributors. For LACT a [bugfix commit][commit:zbus-fix] is
already available.

3.2) Predictable Temporary File Creation in Snapshot API (CVE-2026-75038)
=========================================================================

The [`generate_snapshot()`][code:generate_snapshot] function is accessible
without Polkit authentication. It creates a tarball in paths of the pattern
`/tmp/LACT-v{DAEMON_VERSION}-snapshot-{datetime}.tar.gz`, which are
predictable. The system calls used by the daemon to create these files are as
follows (`strace` excerpt):

```sh
openat(AT_FDCWD, "/tmp/LACT-v0.10.0-snapshot-20260819-101819.tar.gz" O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 17
[...]
fchmod(17, 0775) = 0
```

As can be seen there is no `O_NOFOLLOW` and no `O_EXCL` flag passed here. On
systems without the `protected_symlinks` and `protected_regular` sysctls
enabled this allows various attack vectors:

- local Denial-of-Service: by pointing symbolic links to vital system files,
  the target files will be overwritten, breaking the system. The content of
  the tarball is not attacker-controlled (or at best partly and indirectly),
  therefore further privilege escalation should not be possible this way.
- Denial-of-Service against the LACT daemon: by placing a special file like a
  FIFO named pipe in this location the daemon will block forever, trying to
  write data to it.
- local information leak: the tarball contains data about GPU devices and LACT
  configuration; mostly information that is available to all users in the
  system anyway. By placing a symlink to a private file, however, the target
  file will end up with world-readable permissions, due to the `fchmod()`. The
  content of the file will be lost due to the `O_TRUNC` flag during `openat()`,
  but the file might be re-populated with sensitive data by privileged processes
  at a later time, without restoring the original safe file permissions.

With the kernel hardenings `protected_symlinks` and `protected_regular`
enabled, which is the default on most systems, these issues are fortunately
not exploitable.

A side effect of how the tarball creation in LACT works at the moment is that
the snapshot tarball cannot be deleted by the client that asked for it, since
it is owned by `root`. As there is already a UNIX domain socket available, we
suggested to upstream to use file descriptor passing instead: the client
passes to the daemon an already open file where the tarball data will be
written. This way neither `open()` nor `chmod()` calls will be necessary in
the privileged daemon, resulting in a much cleaner design.

We assigned CVE-2026-75038 to track this issue. Upstream fixed this flaw in
[commit 2aae677d0][commit:snapshot-fix] by invoking `File::create_new()`
instead of plain `File::create()`. This results in the `O_EXCL` flag to be
passed to the `openat()` system call shown above, preventing both opening
already existing files and following symbolic links.

4) Coordinated Disclosure and Upstream Bugfix Release
=====================================================

We offered coordinated disclosure to upstream, who declined and quickly pushed
bugfixes to the LACT GitHub project instead. The bugfixes (including the
`zbus_polkit` fix) are included in the recently published [release
v0.10.1][release:v0.10.1].

5) Timeline
============

|2026-08-19|We reached out privately to the owner of the LACT GitHub project, offering coordinated disclosure.|
|2026-08-19|We received a reply in which upstream declined coordinated disclosure, pointing out two public bugfix commits instead.|
|2026-08-24|Due to a lost email on our end we only noticed at this time that there was an upstream reply and started acting on it.|
|2026-08-25|We assigned CVEs for the issues in this report and shared them with upstream.|
|2026-08-25|Our LACT packager backported the upstream bugfixes allowing us to progress with the openSUSE Tumbleweed LACT update to version 0.10.0.|
|2026-08-28|We received a follow-up email from upstream pointing out that an [issue in Rust's `zbus_polkit`][zbus-polkit-pr] causes the subject's UID information to be silently dropped from Polkit authentication calls.|
|2026-08-28|Publication of this report.|

6) References
==============

- [LACT GitHub repository][upstream:repo]
- [openSUSE review bug for LACT Polkit Authorization][bug]
- [Polkit Authorization Bugfix][commit:polkit-fix]
- [Snapshot Temporary File Bugfix][commit:snapshot-fix]

[upstream:repo]: https://github.com/ilya-zlobintsev/LACT
[zbus-polkit-pr]: https://github.com/z-galaxy/zbus_polkit/pull/101
[section:bugfixes]: #bugfixes
[bug]: https://bugzilla.suse.com/show_bug.cgi?id=1274863
[release:v0.10.0]: https://github.com/ilya-zlobintsev/LACT/releases/tag/v0.10.0
[release:v0.10.1]: https://github.com/ilya-zlobintsev/LACT/releases/tag/v0.10.1
[serde]: https://serde.rs/
[code:check_auth]: https://github.com/ilya-zlobintsev/LACT/blob/2aa6d0d770546fb36dd8714801c373060e4dd912/lact-daemon/src/server/handler.rs#L1273
[code:generate_snapshot]: https://github.com/ilya-zlobintsev/LACT/blob/2aa6d0d770546fb36dd8714801c373060e4dd912/lact-daemon/src/server/handler.rs#L717
[commit:polkit-fix]: https://github.com/ilya-zlobintsev/LACT/commit/d0478fe42c2219454e272f96b1cbd29ab37ee566
[commit:snapshot-fix]: https://github.com/ilya-zlobintsev/LACT/commit/2aae677d0e94bd2824cbe3dab6dc9ac795cae013
[commit:zbus-fix]: https://github.com/ilya-zlobintsev/LACT/commit/40dcf29841e9da56b787b7af0e5ba27d9ce18e0c
[systemd-service]: https://github.com/ilya-zlobintsev/LACT/blob/v0.10.0/res/lactd.service
