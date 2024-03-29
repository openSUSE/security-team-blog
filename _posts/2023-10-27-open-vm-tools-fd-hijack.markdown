---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "File Descriptor Hijack vulnerability in open-vm-tools (CVE-2023-34059)"
date:   2023-10-27 11:12:07 +0100
tags:   CVE
excerpt: "During a routine review of the setuid-root binary vmware-user-suid-wrapper from the open-vm-tools repository, a security vulnerability was found. CVE-2023-34059 identifies the capability to hijack file descriptor in open-vm-tools."
---

Introduction
============

During a routine review of the setuid-root binary
`vmware-user-suid-wrapper` from the [open-vm-tools repository][gh-repo] I
discovered the vulnerability described in this report. The version under
review was open-vm-tools version 12.2.0. The setuid-root binary's source
code in the open-vm-tools repository did not change since version 10.3.0
(released in 2018), however, so likely most current installations of
open-vm-tools are affected by this finding.

Behaviour of vmware-user-suid-wrapper
=====================================

On first look the vmware-user-suid-wrapper seems to be small and harmless:

- it opens /dev/uinput as root, if it believes to be running on Wayland.
  The latter is determined by inspecting the value of the environment
  variable `XDG_SESSION_TYPE`, checking whether it is set to "wayland".
- it opens /var/run/vmblock-fuse/dev, if existing, as `root`.
- it permanently drops all privileges to the real (unprivileged) user
  and group ids and executes /usr/bin/vmtoolsd, inheriting to it any of
  the previously opened file descriptors.
- the new `vmtoolsd` process will inspect the environment, e.g. check
  whether the current host is running in a vmware guest environment and
  whether a graphical session is available. If one of these is not
  fulfilled then the process quickly terminates. On success the daemon
  keeps running, providing its services, keeping the privileged file
  descriptors open.

So it seems everything is in order, the program opens up to two
privileged files, drops privileges and passes the open files on to
`vmtoolsd` to use them in the calling user's context.

The Vulnerability
=================

The (somewhat surprising) problem here is the combination of dropping
privileges to the real uid / gid and the following `execve()` to execute
the non-setuid program `vmtoolsd`. During the `execve()` the process's
"dumpable" attribute is reset to the value of 1.

From the man page `prctl(5)` we can learn the following about a
process's dumpable attribute:

    Normally, the "dumpable" attribute is set to 1. However, it is reset to
    the current value contained in the file /proc/sys/fs/suid_dumpable (which by
    default has the value 0), in the following circumstances:

    [...]

    - The process executes (execve(2)) a set-user-ID or set-group-ID program,
      resulting in a change of either the effective user ID or the effective
      group ID.

    [...]

    Processes that are not dumpable can not be attached via ptrace(2)
    PTRACE_ATTACH; see ptrace(2) for further details.

On most Linux distributions the global `suid_dumpable` setting is set
either to 0 (setuid programs may not dump core at all) or 2 (setuid
programs may dump core but only in safe file system locations).
Consequently when `vmware-user-suid-wrapper` runs, its dumpable
attribute is set to 2 on openSUSE Tumbleweed, which I have been using
while researching this issue. However after the `execve()` this changes,
as is also documented in the `execve(2)` man page:

    The following Linux-specific process attributes are also not preserved
    during an execve():

    - The process's "dumpable" attribute is set to the value 1, unless a
      set-user-ID program, a set-group-ID program, or a program with
      capabilities is being executed, [...].

Consequently when `vmtoolsd` is executed with dropped privileges, the
process's "dumpable" attribute will be reset to 1.

The problem with this is that the unprivileged user that originally
invoked `vmware-user-suid-wrapper` now is allowed to `ptrace()` the
`vmtoolsd` process along with a number of other operations that have not
been allowed on the setuid-root process before.

The interesting resources that `vmtoolsd` has from a unprivileged user's
perspective are the open file descriptors for /dev/uinput and/or
/var/run/vmblock-fuse/dev. With the help of `ptrace()` malicious code
could be injected into the `vmtoolsd` process to get access to the
privileged file descriptors. An even easier approach is to use modern
Linux's pidfd API `pidfd_open()` and `pidfd_getfd()` to obtain a copy of
the privileged file descriptors. In the man page `pidfd_getfd(2)` we can
find:

    Permission to duplicate another process's file descriptor is governed by a
    ptrace access mode PTRACE_MODE_ATTACH_REALCREDS check (see ptrace(2)).

In this context this again boils down to the process's "dumpable"
attribute which is now set to 1, and thus the operation is allowed.

Exploiting the Issue
====================

`vmware-user-suid-wrapper` can be forced to open /dev/uinput even if not
running on Wayland by setting the user controlled environment variable
`XDG_SESSION_TYPE=wayland`. This means the file descriptor for this
device file will always be a valid attacker target independently of the
actual situation on a system.

There are two different scenarios to look at regarding the
exploitability of the issue. The easier case is when a valid environment
for `vmtoolsd` is available i.e. a graphical desktop session is existing
and the check for running in a VMware guest machine is succeeding
(function call `VMCheck_IsVirtualWorld()`). In this case `vmtoolsd` will
continue running permanently and there is no race condition to be won.
Exploiting the issue is straightforward, as is demonstrated in the
PoC program [vmware-get-fd.c](/download/vmware-get-fd.c).

The more difficult case is when an attacker is either not running a
graphical environment or not even running in a VMware guest environment.
In the worst case `vmtoolsd` will terminate quickly, because of the
failing `VMCheck_IsVirtualWorld()` check. Thus the time window for
actually operating on the vulnerable process is short. A variant of the
PoC program, [vmware-race-fd.c](/download/vmware-race-fd.c), starts the
`vmware-user-suid-wrapper` continuously and attempts to snatch the
privileged file descriptors from the short-lived `vmtoolsd` process. In
my tests this often succeeded quickly (even on the first attempt),
likely when the `vmtoolsd` resources have not yet been cached by the
kernel. Later attempts often take a longer time to succeed but still
succeeded after 10 to 20 seconds.

In summary the existence of the setuid-root program
`vmware-user-suid-wrapper` is enough to exploit the issue for
/dev/uinput. The attacker needs no special permissions (even the
`nobody` user can exploit it) and the operating system doesn't even need
to be running as a VMware guest. This can be relevant in situations when
open-vm-tools are distributed by default in generic Linux distributions
/ images, or in environments where unprivileged users are allowed to
install additional software from trusted sources without root
authentication (a model that is e.g. supported by the PackageKit
project).

Vulnerability Impact
====================

/dev/uinput
-----------

Getting access to a file descriptor for the /dev/uinput device allows an
attacker to create arbitrary userspace based input devices and register
them with the kernel. This includes the possibility to send synthesized
key or mouse events to the kernel. The example program
[uinput-inject.c](/download/uinput-inject.c) demonstrates how this can be used
to cause arbitrary key strokes to be injected into local user sessions both
graphical or on textual login consoles.  Thus this attack vector borders the
area of arbitrary code execution with the restriction that a local interactive
user needs to be present.

This aspect of the vulnerability could be used to increase privileges
after gaining low privilege access e.g. through a remote security hole.
On multi user machines with shared access it could be used to prepare an
attack where a background process waits for a victim user to log into
the machine and then inject malicious input into its session.

Since /dev/uinput is not VMware specific, this attack vector is
basically also available in non-VMware environments.

The following is an example exploit run using the attached programs, provided
the `vmware-user-suid-wrapper` is already installed and a compiler is
available:

    user$ gcc -O2 vmware-race-fd.c -ovmware-race-fd
    user$ gcc -O2 uinput-inject.c -ouinput-inject

    user$ ./vmware-race-fd
    vmware-user: could not open /proc/fs/vmblock/dev
    vmware-user: could not open /proc/fs/vmblock/dev
    [...]
    /usr/bin/vmtoolsd running at 12226
    Found fd 3 for /dev/uinput in /usr/bin/vmtoolsd
    Executing sub shell which will inherit the snatched file descriptor 4 (check /proc/self/fd)

    user$ ls -l /proc/self/fd/4
    l-wx------ 1 user group 64 Jul 25 13:43 /proc/self/fd/4 -> /dev/uinput

    user$ ./uinput-inject 4
    Sleeping 3 seconds for input subsystem to settle
    completed one iteration
    completed one iteration

This will continuously write the line "you have been hacked" onto
whatever session is currently selected on the system's display.

/var/run/vmblock-fuse/dev
-------------------------

As far as I understand, this file is created by the `vmware-vmblock-fuse`
daemon and represents a control file. The FUSE file system is used to
implement access to folders shared between the VMware host and VMware guests.
This file allows, according to [documentation][vmblock-fuse-design], to add, delete or list
blocks in shared folders.

As a result access to this file descriptor breaks the boundary between
different users in the guest system regarding shared folder access.  The
integrity of the shared folder content can be violated. It might also be
possible to leak information from shared folders into the unprivileged
user's context.

Depending on the actual environment it might allow to result in code
execution if e.g. malicious code is written to shared folders that could
then be executed even on the VMware host system.

The [vmware-fuse documentation][vmblock-fuse-design] mentions the outlook to
allow unprivileged users access to this control file, but this idea seems not
safe to me in its current form.

I did not look more closely into practical exploits of this.

Suggested Fix
=============

To fix this problem it must be prevented that the "dumpable" attribute
of the `vmware-user-suid-wrapper` process is reset when executing
`vmtoolsd`. One way to achieve this could be to move the privilege drop
logic into `vmtoolsd` instead. As long as the process is running in the
setuid-root context, the "dumpable" attribute will not be reset.
`vmtoolsd` can then drop privileges and also mark the privileged file
descriptors with the `O_CLOEXEC` flag to prevent them to be inherited
unintendedly to further child processes, which might result in the same
problem again.

Update: This is the route that the patch provided by upstream has taken.

As a first aid and/or hardening measure, access to the
`vmware-user-suid-wrapper` could be limited to members of a privileged
group e.g. vmware-users. This would reduce the attack surface and
prevent e.g. a compromised `nobody` user account to exploit this.

In terms of hardening, the `vmware-user-suid-wrapper` could also add
some code to sanitize the environment variables passed from the
unprivileged context, which is a frequent source of security issues in
setuid-root binaries. At least the PATH variable should be reset to a
safe value to avoid any future surprises when looking up executable for
`execve()`.

Timeline
========

|2023-07-25| I reported the findings to security@vmware.com, offering coordinated disclosure |
|2023-08-23| VMware security asked for a publication date in early November exceeding our maximum 90 days disclosure policy. We reluctantly agreed to this exception.|
|2023-10-20| VMware shared the issue and bugfixes with the distros mailing list without keeping me in the loop. In parallel an earlier publication of 2023-10-26 has now been communicated to me. My requests to get a draft patch for review before publication have not been honored.|
|2023-10-27| The general publication date has been reached.|

References
==========

- [open-vm-tools GitHub repository][gh-repo]
- [open-vm-tools vmblock-fuse design document][gh-repo]

[gh-repo]: https://github.com/vmware/open-vm-tools
[vmblock-fuse-design]: https://github.com/vmware/open-vm-tools/blob/master/open-vm-tools/vmblock-fuse/design.txt
