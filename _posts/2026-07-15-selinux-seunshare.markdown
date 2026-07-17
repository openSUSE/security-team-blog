---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SELinux Userspace Utilities: Local Denial-of-Service Attack Vectors in seunshare in release 3.10"
date:   2026-07-15
tags:   setuid CVE
excerpt: "seunshare is a setuid-root utility used for sandboxing untrusted
applications based on Linux namespaces and SELinux policies. During a code
review we identified two local Denial-of-Service attack vectors in version
3.10 of the utility."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [`seunshare` program][man:seunshare] is part of the [SELinux][github]
"sandbox" feature, which is used to confine untrusted programs using Linux
mount namespaces and restrictive SELinux policies. The program is designed to
be installed with setuid-root privileges, accessible to all users in the
system.

We have been asked to [review the program's security][bug:seunshare] with the
intention of assigning the setuid bit to it on SUSE distributions
in the future. Fedora Linux already ships this program with setuid-root
enabled; other SELinux-enabled Linux distributions may do so as well.

During our review of the [utility's code][code:seunshare] in [version
3.10][release:affected] of the SELinux userspace utilities we identified two
local Denial-of-Service attack vectors, which will be described in detail in
the following sections. Upstream independently fixed these issues in [version
3.11][release:fixed], without clearly marking them as security issues, however.

The rest of this report is based on version 3.10 of the codebase of
`seunshare`.

2) Design Overview
==================

The `seunshare` program is relatively small, consisting of about 1,000 lines of
C code. The elevated `root` privileges are primarily needed to setup a custom
mount namespace for the sandbox environment.

The program accepts a range of command line arguments which, among others,
allow to request dedicated directories to be used for the following paths
inside the sandbox:

- the user's home directory.
- the `/tmp` directory.
- the `/run/user/<uid>` directory.

For the `/run` and `/tmp` directories, the source paths specified by the user
are copied into a random temporary directory in the initial mount namespace
under `/tmp/.sandbox-<label>-XXXXXX` using the `rsync` program. These
directories are then bind-mounted into the sandbox's mount namespace to appear
at the expected locations.

A lot of code in `seunshare` is concerned with securely maintaining these
temporary directories. To allow the sandbox environment to modify the directory
contents, `seunshare` assigns group write permissions for the real group ID of
the calling user, as shown in this example:

```sh
drwxrwx--T. 2 root user 80 Jul  8 16:11 /tmp/.sandbox-user-OaxmUp/
```

To safely access user-provided paths, the program flips its [filesystem
UID][man:setfsuid] to the real UID of the calling user and back to `root`, as
needed.

3) Security Issues
==================

Since `seunshare` is supposed to run on SELinux-enabled systems, it is
important to understand what kind of privilege escalation can be achieved when
vulnerabilities are exploited in a setuid-root binary like this. Many
SELinux-enabled systems, such as Fedora and openSUSE, ship with the "targeted"
SELinux policy by default. This policy is focused on confining well-known
system services, but assigns an unconfined SELinux context to interactive
users by default to achieve a balance between security and usability.

There is currently no domain transition from the unconfined domain to the more
restricted `seunshare_t` defined in the SELinux policy for `seunshare`. This
means the execution of `seunshare` continues in the unconfined domain. Thus in
the context of attacks carried out by interactive users, the impact of the
vulnerabilities below will be a root-like privilege escalation despite the
system running in SELinux enforced mode.

{: #section-issue-rmrf}
3.1) Local File Deletion Attack Vector in `rm_rf()` (CVE-2026-59676)
--------------------------------------------------------------------

The function [`rm_rf()`][code:rmrf] is called at the end of the utility's
execution to recursively remove temporary directory trees. While a comment in
the function suggests that no symbolic links would be followed by this
routine, the reality is that the [`openat()`][code:rmrf-openat] system call is
lacking the `O_NOFOLLOW` flag. This creates a race condition during the
recursion of the `rm_rf()` function:

- first an `fstatat()` is performed for directory contents obtained from
  `readdir()` to safely determine whether an entry refers to a sub-directory.
- when a directory is encountered the unsafe `openat()` happens, allowing
  the unprivileged user to replace the directory entry by a symbolic link in
  the meantime. While the `O_DIRECTORY` flag is passed to `openat()`, symbolic
  links in the target are still followed, as long as they point to a directory.

When the user calling `seunshare` is running in the unconfined SELinux domain,
arbitrary `root`-owned files can be deleted this way. The vulnerability does
not allow to delete arbitrary files of other users, however, because
`seunshare` [drops all capabilities][code:drop-caps] before calling `rm_rf()`.
This leaves the process in a somewhat strange state of privilege: it can no
longer override discretionary access control (DAC) but it is still allowed to
operate on files owned by the filesystem-uid of the privileged process, which
is 0 during the invocation of `rm_rf()`.

We developed a [reproducer][download:reproducer] for this issue, which succeeds
in executing the exploit quickly after some fine tuning of the timing for
the target system. We verified that the reproducer works on current openSUSE
Tumbleweed with policycoreutils 3.10 and the setuid-root bit enabled on
`seunshare`. It does not work on current Fedora 44, as it seems Fedora
backported a patch to fix this issue (it passes `O_NOFOLLOW` to the `openat()`
call in question).

Upstream fixed this issue in commit [38f0a4d9a][commit:rmrf-bugfix] which is
part of of the 3.11 upstream release.

{: #section-issue-killall}
3.2) Process Kill Attack Vector in `killall()` (CVE-2026-59677)
---------------------------------------------------------------

`seunshare` offers `--kill` and `-Z` switches as documented in its man page:

```man
-k --kill
       Kill all processes with matching MCS level

-Z context
       Use alternate SELinux context while running the executable
```

Both switches combined cause the [`killall()`][code:killall] function to kill
all processes running with the user-provided SELinux context. This does not
fully work for arbitrary target processes due to SELinux access control;
however, if the calling user is running in unconfined context (as explained
previously) it allows to kill e.g. `root`-owned processes running also in
unconfined context. Once the algorithm reaches its own PID (if the context
matches), it kills itself, thus it is possible that only a certain range of
PIDs can be killed this way depending on the PID selection order of the
algorithm in `killall()`.

We have been able to reproduce the issue both on openSUSE and on Fedora 44
using a command line like this:

```sh
seunshare --kill -Z unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -t ~/some-dir/ -- /usr/bin/true
```

Upstream fixed this issue by dropping the `--kill` switch and the `killall()`
function in commit [572db2fa][commit:kill-bugfix].

4) Remaining Concerns
=====================

The code of `seunshare` has seen major changes between version 3.10 and
3.11 of the SELinux userspace utilities. The new version of the program improves
on various aspects of the code; generally the code shows awareness of various
filesystem-related security concerns that are relevant for setuid-root
binaries. Still a number of concerns remain:

- Data which is modified in temporary directories within the sandbox is
  [transparently copied back][code:copy-back] into the calling user's source
  directory via `rsync`. Since the program is untrusted it can potentially
  create all kinds of dangerous files, which will now reside e.g. in the user's
  regular home directory and could lead to security issues at a later time when
  accessed without care.
- The code flips the filesystem UID a lot to temporarily drop root
  privileges for file operations. This logic is hard to follow in parts and
  leaves the process in an unusual state of privilege, as the effective UID is
  still 0; during the first stages of the program it also still has all
  capabilities. Due to the filesystem UID being set to the real user's UID, file
  operations are carried out using the calling user's lower privileges, however.
  From a design point of view it would be preferable to let the process operate
  in an unprivileged state by default (effective UID and GID set to the real
  UID and GID). Privileges could then be raised for the few operations that
  actually need `root` privileges.
- The code currently lacks some common security precautions for setuid-root
  programs:
  - while a new environment variable block is set up to execute the untrusted
    target program, the privileged parent process keeps the untrusted
    environment variables of the calling user in place. These are also
    inherited to tools like `rsync` that are invoked for the purposes of
    setting up the sandbox. While this is not an issue at the moment, it could
    turn into a security issue at a later time when the code changes.
  - the `umask()` of the process is also kept unchanged, inheriting whatever
    the unprivileged parent process configured. This can cause files to
    receive world-readable or world-writable bits leading to unexpected attack
    vectors.

{: #section-cve-assignments}
5) CVE Assignments
==================

We approached the upstream SELinux userspace utilities developers and
suggested to assign CVEs for the two issues discussed above. Upstream informed
us that they don't take care of CVE assignment themselves, however. Since Red
Hat developers are also involved with upstream development, we were waiting
for an agreement on who will assign CVEs to avoid duplicates. On 2026-07-17,
after the initial publication of this report, we received a response that
there is no intention by RedHat developers to assign CVEs. As a result we
assigned CVEs on our end as documented in the updated blog post.

6) Timeline
===========

|2026-07-03|We (mistakenly) approached the SELinux kernel code maintainer, asking for CVE assignments for these issues which have meanwhile been fixed in the 3.11 upstream release.|
|2026-07-03|The SELinux kernel code maintainer forwarded our report to the maintainers of the userspace utilities.|
|2026-07-06|An SELinux userspace developer informed us that the project is not actively assigning CVEs.|
|2026-07-07|We responded that we would be able to assign CVEs on our end, but would like to avoid a clash with any CVE assignment plans on the end of Red Hat developers working on SELinux. We thus asked for clarification of who will take care of it.|
|2026-07-15|Publication of this report.|
|2026-07-17|We received a reply from a RedHat upstream developer stating that there is no intention to assign CVEs on their end. Thus we assigned CVE-2026-59676 for [issue 3.1][section:issue-rmrf] and CVE-2026-59677 for [issue 3.2][section:issue-killall] and published the information.|

7) References
=============

- [SElinux userspace utilities bugfix release 3.11][release:fixed]
- [SELinux userspace utilities Github project][github]
- [vulnerable seunshare code in upstream release 3.10][code:seunshare]
- [Reproducer for the file delete issue][download:reproducer]

8) Change History
=================

|2026-07-17|Added information about the [CVEs][section:cve-assignments] we assigned for the issues.|


[bug:seunshare]: https://bugzilla.suse.com/show_bug.cgi?id=1268256
[code:seunshare]: https://github.com/SELinuxProject/selinux/blob/3.10/sandbox/seunshare.c
[code:rmrf]: https://github.com/SELinuxProject/selinux/blob/ca10fc4204ed60540d41d2499127c18ad0643f9e/sandbox/seunshare.c#L419
[code:rmrf-openat]: https://github.com/SELinuxProject/selinux/blob/ca10fc4204ed60540d41d2499127c18ad0643f9e/sandbox/seunshare.c#L431
[code:drop-caps]: https://github.com/SELinuxProject/selinux/blob/ca10fc4204ed60540d41d2499127c18ad0643f9e/sandbox/seunshare.c#L1069
[code:killall]: https://github.com/SELinuxProject/selinux/blob/ca10fc4204ed60540d41d2499127c18ad0643f9e/sandbox/seunshare.c#L662
[code:copy-back]: https://github.com/SELinuxProject/selinux/blob/ca10fc4204ed60540d41d2499127c18ad0643f9e/sandbox/seunshare.c#L484
[github]: https://github.com/SELinuxProject/selinux
[release:affected]: https://github.com/SELinuxProject/selinux/releases/tag/3.10
[release:fixed]: https://github.com/SELinuxProject/selinux/releases/tag/3.11
[commit:rmrf-bugfix]: https://github.com/SELinuxProject/selinux/commit/38f0a4d9a683f2cd2472d4502842df5d5b8255a8
[commit:kill-bugfix]: https://github.com/SELinuxProject/selinux/commit/572db2fae9157ae620160e0d7b2c3f8b75fe6c1a
[man:setfsuid]: https://man7.org/linux/man-pages/man2/setfsuid.2.html
[man:seunshare]: https://man7.org/linux/man-pages/man8/seunshare.8.html
[download:reproducer]: /download/seunshare-reproducer.tar.gz
[section:cve-assignments]: #section-cve-assignments
[section:issue-rmrf]: #section-issue-rmrf
[section:issue-killall]: #section-issue-killall
