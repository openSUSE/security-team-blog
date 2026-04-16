---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "cosmic-greeter: Unsafe File System Operations in User Home Directories (CVE-2026-25704)"
date:   2026-04-16
tags:   CVE D-Bus
excerpt: "Cosmic is a modern Linux desktop environment implemented in Rust.
One of its components, cosmic-greeter, contains a D-Bus service which operates
in user home directories in an unsafe manner, leading to potential privilege
escalation or local Denial-of-Service."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

Introduction
============

Cosmic is [a Linux desktop environment][upstream:cosmic] written in the Rust
programming language. There is an ongoing effort to package it for openSUSE
Tumbleweed; in this context we reviewed a number of Cosmic components, among
them [a D-Bus service][bug:cosmic] found in
[cosmic-greeter][github:cosmic-greeter].  We found issues when the service
accesses home directories of unprivileged users, which will be described
further below. This report is based on cosmic-greeter version 1.0.8.

Overview
========

`cosmic-greeter-daemon` is implemented in
[daemon/src/main.rs][code:cosmic-daemon-main], runs with full root privileges
and offers a D-Bus interface "com.system76.CosmicGreeter" on the D-Bus system
bus. The interface only provides a single D-Bus method
"com.system76.CosmicGreeter.GetUserData".

This D-Bus method is only allowed to be called by members of the
`cosmic-greeter` group, not by arbitrary other unprivileged users. What the
[method does][code:cosmic-get-user-data] is basically looking up all
non-system user accounts in `/etc/passwd` and gathering Cosmic configuration
data from every user's home directory.

Security Issues
===============

The code contains [a comment][code:cosmic-security-comment], outlining that it
is important to drop privileges to the owner of the home directory
being processed, to prevent security issues. While this is a good starting
point, the actual implementation of this logic is still lacking in a number of
spots.

Following is an excerpt of an `strace` of the `cosmic-greeter-daemon` process
during invocation of the D-Bus method. The output will help illustrate some of
the issues in question:

```sh
setresuid(-1, 1000, -1) = 0
<...>
statx(AT_FDCWD, "/var/lib/AccountsService/icons/<user>", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7feb5d5f8a50) = -1 ENOENT (No such file or directory)
statx(AT_FDCWD, "/home/<user>/.local/share/cosmic/com.system76.CosmicTheme.Mode/v1", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7feb5d5f8800) = -1 ENOENT (No such file or directory)
mkdir("/home/<user>/.config/cosmic/com.system76.CosmicTheme.Mode/v1", 0777) = -1 EEXIST (File exists)
statx(AT_FDCWD, "/home/<user>/.config/cosmic/com.system76.CosmicTheme.Mode/v1", AT_STATX_SYNC_AS_STAT, STATX_ALL, {stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFDIR|0755, stx_size=4096, ...}) = 0
statx(AT_FDCWD, "/home/<user>/.config/cosmic/com.system76.CosmicTheme.Mode/v1/is_dark", AT_STATX_SYNC_AS_STAT, STATX_ALL, {stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFCHR|0666, stx_size=0, ...}) = 0
mkdir("/home/<user>/.config/cosmic/com.system76.CosmicTheme.Dark/v1", 0777) = -1 EEXIST (File exists)
openat(AT_FDCWD, "/home/<user>/.config/cosmic/com.system76.CosmicTheme.Dark/v1/palette", O_RDONLY|O_CLOEXEC) = 11
<...>
setresuid(-1, 0, -1 <unfinished ...>
```

What we are seeing here is that the privilege drop only concerns the effective
user ID of the `cosmic-greeter-daemon` process. The root group credentials are
retained. This means any potential attacks by the owner of a home directory
can still try to leverage root group credentials to their advantage.

Given this, the file operations performed in the user's home directory are
subject to a range of security issues:

- directory components within the path can be replaced by symbolic
  links. E.g. if a user places a symlink like this:

      $HOME/.config/cosmic → /root/.config/cosmic

  then the daemon would actually process root's Cosmic configuration files,
  provided that root's home directory is accessible for members of the root
  group.
- since the daemon also attempts to create directories under some conditions,
  these directories could be created in arbitrary locations where the root
  group has write permission.
- the daemon checks the type of files via `stat()` before trying to open
  configuration files, for example. This is a typical
  Time-of-Check/Time-of-Use (TOCTOU) race condition, however, because the owner
  of the home directory can attempt to replace a regular file by a symbolic link
  or special file by the time the actual `open()` call is performed by the
  daemon. This can lead to the following potential issues:
  - parsing of private files accessible to the root group.
    Whether the data parsed from such files could ever leak into the
    context of a local attacker is a matter that we did not investigate
    more closely for the purpose of this report.
  - by placing a symbolic link to e.g. `/dev/zero`, an out-of-memory situation
    can be triggered in the daemon, causing it to be killed by the kernel,
    leading to a local Denial-of-Service (DoS).
  - by placing a FIFO named pipe in the location the daemon would block
    on it forever, also leading to a local DoS.
- the daemon considers accounts with user IDs ≥ 1000 [as regular user
  accounts][code:cosmic-user-id-selection]. On many Linux distributions
  this means that also the `nobody` user account is included (UID 65534). As a
  result, the daemon also attempts to process Cosmic configuration in
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `/var/lib/nobody` on OpenSUSE. This grants processes operating
  with `nobody` privileges the opportunity to attempt to exploit the daemon's
  logic.

The severity of these issues is reduced by the fact that only members of the
`cosmic-greeter` group are allowed to invoke the `GetUserData` D-Bus method,
thus potential attackers have to wait for an authorized process to call the
function to attempt to exploit it. We don't have enough insight into the
bigger picture of the Cosmic desktop environment, but it could be possible
that local users are able to indirectly trigger the execution of this D-Bus
method by using other APIs made available by Cosmic.

Suggested Fixes
===============

We suggested the following improvements to upstream to deal with the issues:

- the privileges should be fully dropped to the target user account, including
  group ID and the supplementary group IDs.
- to prevent potential DoS attack surface, the daemon should carefully
  open target paths element by element, passing `O_NOFOLLOW|O_NONBLOCK`
  to prevent symlink attacks, then perform an `fstat()` on the open file
  to determine its type in a race-free fashion.
- the `nobody` user account should be explicitly excluded based on its name
  for distributions that set a valid shell for this account.
- as additional hardening, the systemd unit `cosmic-greeter-daemon.service` can
  be extended with directives like `ProtectSystem=full`. This needs some tuning,
  though, since the daemon still needs to be able to read files in home
  directories of other users.

Upstream Bugfix
===============

Upstream implemented [commit 63cd93bddd0][commit:cosmic-greeter-bugfix]
containing the following changes:

- the daemon properly drops its group and supplementary group IDs to the
  target user's.
- only user IDs in the range defined by `UID_MIN` and `UID_MAX` as configured
  in `/etc/login.defs` will be considered.
- icon files in `/var/lib/accountservice` will be opened with `O_NOFOLLOW`
  (actually an unrelated change / security hardening).

This bugfix is part of [upstream release 1.0.9][upstream:bugfix-release] and
newer.

What is still missing from our point of view is the prevention of local DoS
attack surface when accessing files in the user's home directory. We informed
upstream about this but have not heard back about this topic for a while.

CVE Assignment
==============

Upstream has not expressed any wishes regarding CVE assignment, or whether one
should be assigned at all. We decided to assign a single CVE-2026-25704 from
our pool to track the main aspect of this report, the incomplete privilege
drop in the daemon.

Timeline
========

|2026-03-11|We forwarded this report to security@system76.com and the main developer of cosmic-greeter, offering coordinated disclosure.|
|2026-03-11|Upstream confirmed the issue and opted out of coordinated disclosure.|
|2026-03-11|We got a follow-up response asking us to keep the information private for while longer after all.|
|2026-03-11|We received a patch from upstream corresponding to [commit 63cd93bddd0][commit:cosmic-greeter-bugfix] and have been asked to review it.|
|2026-03-12|Upstream meanwhile created a public pull request based on this bugfix and informed us that the report no longer needed to be private.|
|2026-03-13|We assigned CVE-2026-25704 to track the main aspect of the vulnerability, an incomplete privilege drop.|
|2026-03-13|We shared the CVE with upstream and provided feedback on the bugfix, mainly pointing out that local Denial-of-Service (DoS) attack service still remains.|
|2026-03-13|Upstream informed us that they are going to address these remaining issues as well.|
|2026-03-24|We asked upstream about the status of the additional fixes, but received no response so far.|
|2026-04-16|Publication of this report.|

References
==========

- [Cosmic Website][upstream:cosmic]
- [openSUSE cosmic-greeter review bug][bug:cosmic]
- [cosmic-greeter privilege drop bugfix][commit:cosmic-greeter-bugfix]
- [Upstream Release 1.0.9 containing the bugfix][upstream:bugfix-release]

[bug:cosmic]: https://bugzilla.suse.com/show_bug.cgi?id=1259401
[github:cosmic-greeter]: https://github.com/pop-os/cosmic-greeter
[upstream:cosmic]: https://system76.com/cosmic
[upstream:bugfix-release]: https://github.com/pop-os/cosmic-greeter/releases/tag/epoch-1.0.9
[code:cosmic-daemon-main]: https://github.com/pop-os/cosmic-greeter/blob/epoch-1.0.8/daemon/src/main.rs
[code:cosmic-get-user-data]: https://github.com/pop-os/cosmic-greeter/blob/epoch-1.0.8/daemon/src/main.rs#L62
[code:cosmic-security-comment]: https://github.com/pop-os/cosmic-greeter/blob/epoch-1.0.8/daemon/src/main.rs#L9
[code:cosmic-user-id-selection]: https://github.com/pop-os/cosmic-greeter/blob/epoch-1.0.8/daemon/src/main.rs#L65
[commit:cosmic-greeter-bugfix]: https://github.com/pop-os/cosmic-greeter/commit/63cd93bddd01bf714e98553966d4da12eac0ee5b
