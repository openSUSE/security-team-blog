---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "Multiple Security Issues in Screen"
date:   2025-05-12
tags:   local CVE root-exploit
excerpt: "Screen is the traditional terminal multiplexer software used on
Linux and Unix systems. We found a local root exploit in Screen 5.0.0 affecting
Arch Linux and NetBSD, as well as a couple of other issues that partly also
affect older Screen versions, which are still found in the majority of
distributions."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

In July 2024, the upstream Screen maintainer [asked us][bugzilla:screen-audit]
if we could have a look at the current Screen code base. We treated this
request with lower priority, since we already had a cursory look at Screen
a few years earlier, without finding any problems. When we actually found time to
look into it again, we were surprised to find a local root exploit in the
Screen 5.0.0 major version update affecting distributions that ship it as
setuid-root (Arch Linux and NetBSD). We also found a number of additional,
less severe issues that partly also affect older Screen versions still found
in the majority of distributions.

We offer two sets of patches for the issues described in this report, one for
[screen-4.9.1](/download/screen-4.9.1-patches.tar.gz) and another for
[screen-5.0.0](/download/screen-5.0.0-patches.tar.gz). These patch sets apply
against the screen-4.9.1 and screen-5.0.0 release tarballs, respectively.
Due to difficulties in the communication with upstream we do not currently
have detailed information about bugfixes and releases published on their end.

The next section provides an overview of the Screen configurations and
versions found on common Linux and UNIX distributions. Section 3) discusses
each security issue we discovered in detail. Section 4) takes a look at
possible further issues in Screen's setuid-root implementation. Section 5)
gives general recommendations for the improvement of Screen's security
posture. Section 6) points out problems we encountered during the
coordinated disclosure process for these issues. Section 7) provides an
affectedness matrix which gives a quick overview of the situation on
various Linux and UNIX systems.

2) Overview of Screen Configurations and Versions
=================================================

In August 2024 a version 5.0.0 major release of Screen was published by
upstream. By now Arch Linux, Fedora 42 and NetBSD 10.1 ship this new version
of Screen. A lot of refactoring changes made their way into this Screen release
that are in some cases dating back more than ten years. Some of the issues
discussed in this report have only been introduced in the 5.0.0 release of
Screen, while others also affect Screen 4.9.1 (and older), which is still the
version found in the majority of Linux and UNIX distributions at the time of
writing.

Any source code references in this report are based on the upstream [5.0.0
release tag][git:release-tag-5-0-0], unless noted otherwise. Affectedness
information is provided for both the current 5.0.0 release and the more
widespread 4.9.1 Screen release for each vulnerability discussed below.

> NOTE: At the time of writing we often experienced HTTP 502 "Bad Gateway"
> errors trying to access Screen's Git web front end. Retrying a few seconds
> later usually resolved the error.

About the Screen Multi-User Mode
--------------------------------

Screen offers a multi-user mode which allows to attach to Screen sessions owned
by other users in the system (given the proper credentials). These multi-user
features are only available when Screen is installed with the setuid-root bit
set. This configuration of Screen results in highly increased attack surface,
because of the complex Screen code that runs with root privileges in this
case.

A Screen multi-user session is identified by its name, which needs to have a
`<user>/` prefix. The following command line would create such a session:

```sh
user1$ screen -S user1/my-multi-user-session
```

To manage access to a multi-user session, Screen maintains access control
lists (acls) that can be configured in Screen's configuration file
(`~/.screenrc`), or by sending commands to a running Screen session (see
[`screen(1)` man page][screen-man-page]). These acls are based on the account
names of other users and can optionally be protected by a password. Access can
be restricted to "read-only", a mode in which no input can be passed to the
terminal.

Of the systems we looked into, only Arch Linux, FreeBSD and NetBSD install
Screen with the setuid-root bit set. On Gentoo Linux the setuid-root bit is
optionally assigned if the "multiuser" USE flag is set. Some distributions
install Screen with a setgid bit assigned to let it run with specific group
credentials. This is the case on Gentoo Linux by default, which installs
Screen as setgid-utmp, allowing Screen to create login records in the
system-wide utmp database. Fedora Linux installs Screen as setgid-screen,
which allows Screen to place sockets into a system-wide directory in
`/run/screen`.

3) Security Issues
==================

3.a) Local Root Exploit via `logfile_reopen()` (CVE-2025-23395)
---------------------------------------------------------------

This issue affects Screen 5.0.0 when it runs with setuid-root privileges. The
function [`logfile_reopen()`][git:logfile-reopen] does not drop privileges
while operating on a user supplied path. This allows unprivileged users to
create files in arbitrary locations with `root` ownership, the invoking user's
(real) group ownership and file mode 0644. All data written to the Screen PTY
will be logged into this file. Also already existing files can be abused for
logging in this manner: the data will be appended to the file in question, but
the file mode and ownership will be left unchanged.

Screen correctly drops privileges when it initially opens the logfile. The
privilege escalation becomes possible as soon as Screen believes it is
necessary to reopen the logfile. Screen checks this by calling
[`stolen_logfile()`][git:stolen-logfile] before writing to the file. The call
to `logfile_reopen()` happens when the link count of the originally opened
logfile drops to zero, or if it unexpectedly changes in size. This condition
can be triggered at will on the end of the unprivileged user.

This is a reproducer which shows how to achieve a basic local root exploit on
an affected system:

```sh
# create a Screen session using a custom logfile path
(shell1) user$ screen -Logfile $HOME/screen.log
# enter the key combination to enable logging to the configured path
(screen) user$ <ctrl-a> H

# in another shell remove the logfile that Screen just created and
# replace it by a symlink to a privileged location
(shell2) user$ rm $HOME/screen.log; ln -s /etc/profile.d/exploit.sh \
    $HOME/screen.log

# back in the Screen session, echo an exploit command which will be logged to
# the now redirected logfile.
#
# This needs to be done via `echo` for adding a leading newline to prevent the
# bash prompt from breaking the exploit. Similarly the trailing semicolon
# is necessary to prevent following control characters from becoming part of
# the shell command.
(screen) user$ echo -e "\nchown $USER /root;"

# now perform a new login as root and watch the exploit being executed.
# you will likely see a range of shell errors during login as well.
root# ls -lhd /root
drwxr-x--- 5 user root 4.0K Dec 30  2020 .
```

This is just one naive approach to achieve a local root exploit, which is not
very well hidden (because of strange error messages) and requires the actual
`root` user to login to trigger it. There are likely many other ways to
exploit this, however, for example by writing new configuration files for
tools like `sudo`, or by appending code to privileged shell scripts found in
/usr/bin and similar locations.

### Bugfix

The problem was introduced via an [old commit
441bca708bd][git:logfile-reopen-refactoring], which has only now become part
of the 5.0.0 release. In this commit the `lf_secreopen()` function was
removed, which was considered unneeded.

[Patch 0001](/download/screen-5.0.0-patches/0001-logfile-reintroduce-lf_secreopen-to-fix-CVE-2025-233.txt)
in [screen-5.0.0-patches.tar.gz](/download/screen-5.0.0-patches.tar.gz)
addresses the issue by reintroducing the secure file handling during logfile
reopen.

### Affected Distributions

#### Arch Linux

Arch Linux is fully affected by this issue, since it ships the version 5.0.0
release and assigns the setuid-root bit. Screen is not installed by default
on Arch, however.

#### Fedora Linux

The affected 5.0.0 version is only found in the recently released Fedora 42.
Screen runs with setgid-screen credentials there, to be able to write in the
`/run/screen` directory. A private directory with mode 0700 is created in there
for each user that runs a Screen multi-user session. Due to this, the exploit
will not allow to write in other users' session directories, it will only be
possible to create files directly in `/run/screen`. The only attack vector we
can imagine here is to cause a local DoS scenario by claiming the names of
other users' session directories, should they not yet exist. Another attack
vector could be to try and fill up the free disk space of the /run file system
(a TMPFS) to break other system services.

#### Gentoo Linux

Gentoo Linux is not affected in its stable Screen ebuild, which is still based
on Screen version 4.9.1.

When using Gentoo's unstable 'app-misc/screen-9999' ebuild, then the affected
version 5.0.0 will be installed, however. If the "multiuser" USE flag is also
set, then the setuid-root bit will be applied, resulting in a fully vulnerable
Screen.

Without this USE flag, Screen runs as setgid-utmp on Gentoo Linux, which
allows to use this exploit to overwrite the `/var/log/wtmp` database. This
makes it possible to violate the integrity of the database or even to craft
login entries which could adversely influence other privileged programs in the
system that rely on this information.

#### FreeBSD

FreeBSD still uses version 4.9.1. If Screen were to be upgraded to 5.0.0 then
FreeBSD would be affected as well, since Screen is installed as setuid-root by
default.

#### NetBSD

On NetBSD the affected Screen 5.0.0 version can be installed and it will by
default run with setuid-root privileges. This makes it fully affected by the
issue.

3.b) TTY Hijacking while Attaching to a Multi-User Session (CVE-2025-46802)
---------------------------------------------------------------------------

This issue is found in the `Attach()` function when the `multiattach` flag is
set (i.e. Screen attempts to attach to a multi-user session). The function
[performs a `chmod()`][git:attach-chmod] of the current TTY to mode 0666. The
path to the current TTY is stored in the `attach_tty` string:

```c
if ((how == MSG_ATTACH || how == MSG_CONT) && multiattach) {
    /* snip */
    if (chmod(attach_tty, 0666))
        Panic(errno, "chmod %s", attach_tty);
    tty_oldmode = tty_mode;
}
```

Fortunately the TTY path which is calculated within Screen is sufficiently
probed for correctness. In particular, `isatty()` needs to be true for FD 0
(which is used for determining the TTY path) and the resulting path needs to
reside in /dev. Otherwise this `chmod()` would have led to another local root
exploit.

The original TTY mode is restored towards the end of the function [in line
284][git:attach-mode-restore]. We are not completely sure about the purpose
of this temporary permission change, maybe it is supposed to allow the Screen
daemon of the target session (which might have different credentials) to
access the client's TTY for the purposes of the attach procedure.

The issue with this temporary TTY mode change is that it introduces a race
condition allowing any other user in the system to open the caller's TTY
for reading and writing for a short period of time. We made some simple tests
based on Linux's inotify API, and we managed to open affected TTYs every
second or third attempt using a simple Python script this way.

The impact of this issue is that an attacker can intercept data typed into the
TTY and also inject data into it. An attacker could attempt to mislead the
owner of the TTY into entering a password, or gain other sensitive
information. Also, control sequences can be injected into the affected TTY
which adds further possibilities to confuse the victim or to exploit issues in
an involved terminal emulator.

There also exist return paths in the `Attach()` function where the original
mode is never restored again. This happens in [line
160][git:attach-missing-restore], for instance, where the process explicitly
exits if the target session is not found and the "quiet" command line argument
has been set. A simple reproducer of this aspect is as follows:

```sh
    # inspect the current TTY permissions, which are safe
    user$ ls -l `tty`
    crw--w---- 1 user tty 136, 1 Feb  5 12:18 /dev/pts/1
    # attempt to attach to some non-existing session of the root user.
    # note that this only works if the target user's session directory (e.g.
    # in $HOME/.screen) already exists, otherwise the logic terminates early
    # and the `chmod()` does not happen.
    user$ screen -r -S root/some-session -q
    # observe the now unsafe TTY permissions
    user$ ls -l `tty`
    crw-rw-rw- 1 user tty 136, 1 Feb  5 12:19 /dev/pts/1
```

The `Panic()` function, which is mostly used in `Attach()` to stop process
execution, [correctly restores the old TTY mode][git:panic-tty-mode-restore].
Only code paths that use `return` or `eexit()` suffer from this missing TTY
mode restore.

### Bugfix

We assume that the problematic `chmod()` calls are most likely only remnants
of past times, when this insecure approach was used to grant the target Screen
session access to the new client's PTY. These days Screen passes the PTY file
descriptor securely via the UNIX domain socket to the target session.

Thus to fix this, the temporary `chmod()` to mode 666 can be dropped. This
is what is done in
[patch 0001](/download/screen-4.9.1-patches/0001-attacher.c-prevent-temporary-0666-mode-on-PTYs-to-fi.txt)
in [screen-4.9.1.tar.gz](/download/screen-4.9.1-patches.tar.gz) and
[patch 0004](/download/screen-5.0.0-patches/0004-attacher.c-prevent-temporary-0666-mode-on-PTYs-to-fi.txt) in
[screen-5.0.0.tar.gz](/download/screen-5.0.0-patches.tar.gz).

Shortly before the publication of this report it was pointed out to us that
this patch [likely breaks some reattach use
cases][bugzilla:pty-chmod-patch-concern] in Screen. We can confirm this
problem, but at the same time found out that this specific use case was
[obviously already broken before, even in Screen
4.9.1][bugzilla:pty-reattach-broken]. For this reason we decided not to move
the publication date again or to adjust this patch in a hurry with uncertain
results. The patch still fixes the security issue and upstream can now fix
this regression, that already seems to have existed earlier, in the open.

### Affected Distributions

Unlike the previous issue, this one is not limited to the current 5.0.0
release. The observed behaviour has been present in Screen versions since at
least the year 2005. All Linux distributions and BSDs we checked suffer from
this, if they provide multi-user support in Screen by installing it setuid-root.

This issue theoretically also affects Screen if it is *not* installed
setuid-root, because the caller always has permission to modify the mode of
its own TTY. Screen refuses to continue the operation, however, if the
target session is not owned by the caller and no root privileges are
available. The problematic code still triggers when a user attempts for some
reason to join a multi-user session owned by itself. An example invocation that
leads to this would be `screen -r -S $USER/some-session -q`. Systems that are
affected by this lighter variant of the issue are marked as partly affected in
section 7).

3.c) Screen by Default Creates World Writable PTYs (CVE-2025-46803)
-------------------------------------------------------------------

In Screen version 5.0.0 the default mode of pseudo terminals (PTYs) allocated
by Screen was changed from 0620 to 0622, thereby allowing anyone to write
to any Screen PTYs in the system. Security-wise this results in some of the
issues that have been outlined in issue 3.b), without the information leak
aspects, however.

The history of the default PTY mode in Screen is rather complex. Let's have a
look at the situation in version 4.9.1 (and a lot of older versions):

- There is a 0622 default mode in the code in [process.c line
  207][git:default-pty-mode-4-9-1]. This is only a fallback that should not
  become active unless the code is compiled in unusual ways.
- A default mode of 0620 is applied in [configure.ac line 811][git:configure-pty-mode-4-9-1],
  which results in a safe default when compiling Screen using autotools.
- In [acconfig.h line 81][git:acconfig-pty-mode-comment-4-9-1] the following is stated:
  
  > define PTYMODE if you do not like the default of 0622, which allows public write to your pty.
  
  Thus in this version there is an inconsistency between the default mode on
  autoconf level and the default on source code level, but in the end the
  (safe) autoconf default wins.

Now let's look at the situation in Screen version 5.0.0:

- The configure.ac file was rewritten from scratch in [commit
  df1c012227][git:configure-rewrite]. This change drops the 0620 default mode
  on autoconf level.
- In a follow-up [commit 78a961188f7][git:pty-mode-switch-reintroduction] the
  pty-mode configure switch was reintroduced, this time with default mode 0622.
- Thus in version 5.0.0 there is no longer a mismatch between the source code
  level default and the autoconf level default, but the default is now
  unsafe.

### Bugfix

We couldn't find any Screen release notes for version 5.0.0, except for a few
ChangeLog entries. It seems it was not a deliberate decision to change the
default PTY Mode to 0622.

[Patch 0002](/download/screen-5.0.0-patches/0002-default-PTY-mode-apply-safe-default-mode-of-0620-to-.txt)
in [screen-5.0.0-patches.tar.gz](/download/screen-5.0.0-patches.tar.gz)
addresses the issue by restoring the safe default PTY mode in the configure.ac
script.  Note that you will need to run `autoreconf` to make the change
effective.

We recommend to packagers to actively pass the configure switch
`--with-pty-mode=0620` to make this choice explicit, also on older releases of
Screen.

### Affected Distributions

Gentoo Linux and Fedora Linux pass an explicit safe `--with-pty-mode` to
Screen's configure script. For distributions other than the ones listed as
affected below, we did not check if they are either doing the same, or if they
are relying on the safe default present in older Screen releases.

#### Arch Linux

On Arch Linux the package build does not pass the `--with-pty-mode` switch,
resulting in the new default being applied, thus making Screen on current Arch
Linux vulnerable to this issue.

#### NetBSD

NetBSD is affected by this issue the same way as Arch Linux is.

3.d) File Existence Tests via Socket Lookup Error Messages (CVE-2025-46804)
---------------------------------------------------------------------------

This is a minor information leak when running Screen with setuid-root
privileges that is found in older Screen versions, as well as in version 5.0.0.
The code in [screen.c starting at line 849][git:socket-error-messages]
inspects the resulting `SocketPath` with root privileges, and provides error
messages that allow unprivileged users to deduce information about the path
that would otherwise not be available.

An easy way to achieve this is by using the `SCREENDIR` environment variable.
Following is an example that works on current Arch Linux:

```sh
# this can be used to test whether /root/.lesshst exists and is a regular file
user$ SCREENDIR=/root/.lesshst screen
/root/.lesshst is not a directory.

# this allows to deduce that the directory /root/.cache exists
user$ SCREENDIR=/root/.cache screen
bind (/root/.cache/1426.pts-0.mgarch): Permission denied

# this tells us that the path /root/test does not exist
user $ SCREENDIR=/root/test screen
Cannot access /root/test: No such file or directory
```

### Bugfix

[Patch 0002](/download/screen-4.9.1-patches/0002-Avoid-file-existence-test-information-leaks-to-fix-C.txt)
in [screen-4.9.1.tar.gz](/download/screen-4.9.1-patches.tar.gz) and
[patch 0005](/download/screen-5.0.0-patches/0005-Avoid-file-existence-test-information-leaks-to-fix-C.txt)
in [screen-5.0.0.tar.gz](/download/screen-5.0.0-patches.tar.gz) address the
problem by only outputting generic error messages when Screen is installed
setuid-root and when the target path is not controlled by the real UID of the
process.

### Affected Distributions

All distributions we considered are affected.

3.e) Race Conditions when Sending Signals (CVE-2025-46805)
----------------------------------------------------------

In socket.c [lines 646][git:socket-kill-pid-1] and
[882][git:socket-kill-pid-2] time-of-check/time-of-use (TOCTOU) race
conditions exist with regards to sending signals to user supplied PIDs in
setuid-root context.

The [`CheckPid()` function][git:check-pid] drops privileges to the real user
ID and tests whether the kernel allows to send a signal to the target PID
using these credentials. The actual signal is sent later via `Kill()`,
potentially using full root privileges. By this time, the PID that was
previously checked could have been replaced by a different, privileged
process. It might also be possible to trick the (privileged) Screen daemon
process into sending signals to itself, since a process is always allowed to
send signals to itself.

Currently this should only allow to send SIGCONT and SIGHUP signals, thus the
impact is likely only in the area of a local denial of service or a minor
integrity violation.

The issue affects both Screen version 5.0.0 and older version 4 releases, when
Screen is installed setuid-root. This issue results from an [incomplete
fix][git:socket-kill-insufficient-fix] for CVE-2023-24626: before this
incomplete fix, the signals in question could be sent to arbitrary processes
even without winning a race condition.

### Bugfix

[Patch 0003](/download/screen-4.9.1-patches/0003-socket.c-don-t-send-signals-with-root-privileges-to-.txt)
in [screen-4.9.1.tar.gz](/download/screen-4.9.1-patches.tar.gz) and
[patch 0006](/download/screen-5.0.0-patches/0006-socket.c-don-t-send-signals-with-root-privileges-to-.txt)
in [screen-5.0.0.tar.gz](/download/screen-5.0.0-patches.tar.gz)
address the problem by sending the actual signal with real UID privileges,
just like `CheckPid()` does.

### Affected Distributions

All distributions we considered are affected.

3.f) Bad `strncpy()` Use Leads to Crashes when Sending Commands
---------------------------------------------------------------

We believe this is a non-security issue, but one that still should be fixed
with priority. The issue is only found in Screen version 5.0.0.

In [commit 0dc67256][git:strncpy-refactoring] a number of `strcpy()` calls
have been replaced by `strncpy()`. The author obviously was not aware of the
unfortunate semantics that `strncpy()` has. This function is not intended for
safe string handling, but to maintain zero padded buffers of fixed length. For
this reason, `strncpy()` does not stop writing data to the destination buffer
when the first `\0` byte is encountered, but it writes out zeroes until the
buffer is completely filled.

Apart from leading to bad performance, this also triggers a bug in attacher.c
line 465. The following change has been applied there:

```patch
-      strcpy(p, *av);
+      strncpy(p, *av, MAXPATHLEN);
       p += len;
```

These lines are part of the following for loop, which processes command line
parameters to send them to a running Screen session.

```c
for (; *av && n < MAXARGS - 1; ++av, ++n) {
        size_t len;
        len = strlen(*av) + 1;
        if (p + len >= m.m.command.cmd + ARRAY_SIZE(m.m.command.cmd) - 1)
                break;
        strncpy(p, *av, MAXPATHLEN);
        p += len;
}
```

The call to `strncpy()` always passes `MAXPATHLEN` bytes as destination buffer
size. This is correct for the first iteration of the `for` loop, when `p`
points to the beginning of the `struct Message.command.cmd` buffer declared in
[screen.h line 148][git:struct-message-command]. It is no longer correct for
following iterations of the `for` loop, however, when `p` is incremented by
`len`. This means future `strncpy()` calls will write an excess amount of `\0`
bytes beyond the end of the buffer.

The result of this can be observed on current Arch Linux when passing more
than one command argument to a running Screen instance:

```sh
# create a new screen session
user$ screen -S myinstance

# and detach from it again
(screen) user$ <Ctrl A> d

# now try to send a command to the running session
user$ screen -S myinstance -X blankerprg /home/$USER/blanker
*** buffer overflow detected ***: terminated
Aborted (core dumped)
```

The two command arguments lead to two iterations in the `for` loop described
above; the second iteration will trigger the buffer overflow detection. The
visible error only occurs when Screen is compiled with the `_FORTIFY_SOURCE`
feature enabled. Otherwise no errors are seen, not even when compiling with
`-fsanitize=address`, likely because after the end of the target buffer
another long buffer `char message[MAXPATHLEN * 2]` follows (thus only
application payload data is overwritten).

This issue allows the caller to overwrite `MAXPATHLEN` bytes of memory
following the `cmd` buffer with zeroes, which can cause integrity violation in
Screen, particularly when it runs setuid-root. Since an equally sized buffer
`writeback[MAXPATHLEN]` follows in memory, there should be no possibilities to
exploit this issue to the advantage of an attacker, however.

To fix this, `MAXPATHLEN` needs to be replaced by the actually remaining
amount of bytes in `p`. Furthermore ideally all `strncpy()` calls should be
replaced by `snprintf(target, target_size, "%s", source)` to avoid the
unintended effect of zero padding the target buffer.

We wondered how this issue could be present in Screen 5.0.0 for such a long
time without anybody noticing. One part of the explanation likely is that
Screen version 5.0.0 is only present in few distributions so far. Another
aspect is that perhaps only few users are using this feature to send commands
to running Screen sessions. We still found a report from not too long ago [on
the screen-users mailing list][upstream:users-mailing-list-crash] that seems
to refer to exactly this issue.

### Bugfix

[Patch 0003](/download/screen-5.0.0-patches/0003-attacher.c-fix-bad-strncpy-which-can-lead-to-a-buffe.txt)
in [screen-5.0.0.tar.gz](/download/screen-5.0.0-patches.tar.gz)
addresses this problem by changing `strncpy()` to `snprintf()` and by properly
passing the amount of remaining space in the target buffer.

### Affected Distributions

All distributions shipping screen-5.0.0 are affected.

4) Possible Further Issues in Screen's setuid-root Implementation
=================================================================

While working on the bugfix for issue 3.e), we also noticed that the original
(incomplete) bugfix for CVE-2023-24626 introduced a regression to the multi-user
mode in Screen when the target session is running as non-root. In this case
the target session drops privileges to some UID X and then attempts to
send a signal to some UID Y (of the client), which will always fail.

This shows that there are actually three different UIDs to be considered in
Screen's multi-user mode: effective UID 0 to perform privileged operations,
the real UID of the user creating the session and the real UID of the user
attaching to a session. We don't believe that the current Screen code takes
this properly into account.

This also brought to our attention that Screen multi-user sessions created by
`root` will "drop privileges" to the real UID of the creating user, which will
be UID 0, and thus effectively perform no privilege drop at all.

5) General Recommendations
==========================

From the changes in Screen 5.0.0 we can see that there have been attempts for a
longer time to refactor the code base, which was still written in K&R style C
before that. During this refactoring some of the long established security
logic has been broken, however, which led to issues 3.a) and 3.c). Before doing
further refactoring, some kind of test suite could be helpful to verify various
security properties of the implementation. Also anybody who works on this code
base obviously should have knowledge about the many dangers that linger in
setuid-root binaries.

Even after fixing the issues we identified during our review, there are still
many areas left that make us worry as outlined in the previous section. There
is also a range of file system operations where security is hanging by a
thread.

There is furthermore a broad design issue in Screen: it runs with elevated
privileges all the time, and only selectively drops privileges for operations
that are considered dangerous. For a robust setuid-root program this should be
the other way around: privileges should be dropped by default and only
raised for operations that actually require elevated privileges.

To make Screen acceptable for running setuid-root we suggest to implement a
design change in this regard and to carefully review each privileged operation
that remains for its security. We also suggest to add logic to remove any
environment variables except those that are explicitly allowed in the
setuid-root context. Other environment variables like PATH should be sanitized
to point only to trusted system directories.

Given all this, we don't recommend to install Screen setuid-root at all at the
moment (neither version 5.0.0 nor the older 4.9 versions). An
alternative could be to offer the multi-user feature only in an opt-in
fashion, e.g. by allowing only members of a trusted group to run a multi-user
version of Screen.

6) Problematic Coordinated Disclosure Process and Upstream Status
=================================================================

When we reported these issues to upstream in February 2025, we offered the
usual coordinated disclosure process based on [our
policy][opensuse:disclosure-policy]. Upstream expressed a lot of interest in
keeping the issues private to develop bugfixes before publication. A time frame
of one to two months was communicated to us for this purpose. We were not
too happy with this long embargo period, but we understand that many
upstreams are lacking resources, thus we agreed to these terms.

About a month later some activity ensued on upstream's end and discussions
about bugfixes started. These discussions were not too fruitful, but we
still believed that upstream would be able to deal with the issues - given it
was upstream itself that asked us to perform a security review for Screen.

No further communication happened, however, until about two weeks before the
maximum 90 days embargo period we offer, when we inquired upstream about the
current status and pointed out the publication date coming close. We had to
find out that upstream did not use the long time period up to this point to
work on the bugfixes. Meanwhile further distributions like NetBSD updated to
Screen 5.0.0, becoming fully affected by issue 3.a), unaware of the risk.

It was only at this point that we realized that upstream was not sufficiently
familiar with the Screen code base, not capable of fully understanding the
security issues we reported and that they did not clearly state that they
need more help than us only reviewing patches they come up with.

The communication with upstream became increasingly problematic: upstream
suddenly wanted to publish bugfixes earlier than we suggested, even though
many issues were still unaddressed. We tried to dissuade upstream and quickly
involved [the distros mailing list][distros-mailing-list] to make other
distributors aware of the issues. We exceptionally suggested a publication
date beyond our maximum 90 days embargo to the list, to accommodate for the
chaotic situation that the embargo ended up in.

After some further not very productive attempts to develop patches in
cooperation with upstream, we decided to take the matter into our own hands.
We developed the missing bugfixes and adjusted and properly documented the
patches that had already been drafted by upstream. In doing this,
we deduced that a dedicated upstream would likely have been able to complete
the coordinated disclosure process within about two weeks.

We are not satisfied with how this coordinated disclosure developed, and we
will try to be more attentive to such problematic situations early on in the
future. This experience also sheds light on the overall situation of Screen
upstream. It looks like it suffers from a lack of manpower and expertise,
which is worrying for such a widespread open source utility. We hope this
publication can help to draw attention to this and to improve this situation
in the future.

7) Affectedness Matrix
======================

|System        |Screen Version|Special Privileges|Affected by                  |Comment            |
|--------------|--------------|------------------|-----------------------------|-------------------|
|Arch Linux    |5.0.0         |setuid-root       |3.a, 3.b, 3.c, 3.d, 3.e, 3.f |                   |
|Debian 12.10  |4.9.0         |                  |3.b (partly)                 |                   |
|Ubuntu 24.04.2|4.9.1         |                  |3.b (partly)                 |                   |
|Fedora 42     |5.0.0         |setgid-screen     |3.b (partly), 3.f            |5.0.0 is only found in the recently released Fedora 42|
|Gentoo        |4.9.1         |setgid-utmp (setuid-root if multiuser USE flag is set)|3.b (partly)                             |5.0.0 is available via the unstable ebuild|
|openSUSE TW   |4.9.1         |                  |3.b (partly)                 |                   |
|FreeBSD 14.2  |4.9.1         |setuid-root       |3.b, 3.d, 3.e                |                   |
|NetBSD 10.1   |5.0.0         |setuid-root       |3.a, 3.b, 3.c, 3.d, 3.e, 3.f (without visible crash) |update to 5.0.0 was only released recently|
|OpenBSD 7.7   |4.9.1         |                  |3.b (partly)                 |                   |

8) Timeline
===========

|2024-07-01|A review request from upstream was [forwarded to us][bugzilla:screen-audit].|
|2025-01-08|We started working on the review.|
|2025-02-07|We privately reported the issues to the Screen upstream by email, offering coordinated disclosure.|
|2025-02-07|Upstream expressed that they will need 1 - 2 months of time to work on the issues, likely requiring most of the 90 days maximum embargo period we offered.|
|2025-02-11|We created [private bugs][bugzilla:savannah-links] in the GNU Savannah bug tracker to deal with each finding.|
|2025-03-11|Some discussions started in the private GNU Savannah bugs about patches for a couple of the findings.|
|2025-04-29|After nearly a month without visible activity, and the 90 days maximum embargo time approaching we asked upstream for the current status and procedures for publication of the report.|
|2025-04-30|Upstream started taking up work again, trying to come up with fixes until the end of the 90 day embargo period. We offered advice on the various patches in the private GNU Savannah bugs.|
|2025-04-30|Following some unclarity in the discussion with upstream regarding CVE assignment, we decided to assign CVEs for the security relevant issues.|
|2025-04-30|Upstream declared its intention to publish something on the weekend, while bugfixes were still missing. We urged them not to do this. In the light of this we quickly forwarded a draft of this report to the [distros mailing list][distros-mailing-list] to give other distributors the chance to react to these findings before they go public.|
|2025-05-05|Although we did not get a clear answer, upstream ended up not publishing one-sidedly. Given the chaotic situation we suggested a publication date of 2025-05-12 to the distros mailing list, which was a few days after the 90 days maximum embargo period we usually offer upstream.|
|2025-05-07|Further attempts to develop the missing bugfixes in cooperation with upstream seemed futile. We started to develop all necessary patches on our own, some of them based on patches that had already been discussed in the upstream Savannah bugs. We shared the finished and tested patches for screen 4.9.1 and screen 5.0.0 with the distros mailing list and upstream.|
|2025-05-08|Upstream complained about wrong `Author:` tags in some of the patches we distributed (we did not receive formally finished patches from upstream, only copy/paste snippets). Thus we adjusted the authorship information for these patches to accommodate for this complaint and shared the updated result with the distros mailing list again.|
|2025-05-12|Publication of the report happened as planned on our blog and on the oss-security mailing list.|

9) References
=============

- [Screen GNU Savannah Project Page][upstream:savannah]
- [openSUSE Bugzilla Screen Review Bug][bugzilla:screen-audit]
- [Links to Private GNU Savannah Bugs (it seems upstream cannot make them
  accessible even after publication)][bugzilla:savannah-links]

[upstream:savannah]: https://savannah.gnu.org/projects/screen
[upstream:users-mailing-list-crash]: https://lists.gnu.org/archive/html/screen-users/2024-12/msg00000.html
[bugzilla:screen-audit]: https://bugzilla.suse.com/show_bug.cgi?id=1227243
[bugzilla:savannah-links]: https://bugzilla.suse.com/show_bug.cgi?id=1227243#c8
[bugzilla:pty-chmod-patch-concern]: https://bugzilla.suse.com/show_bug.cgi?id=1242269#c9
[bugzilla:pty-reattach-broken]: https://bugzilla.suse.com/show_bug.cgi?id=1242269#c12
[git:logfile-reopen-refactoring]: https://git.savannah.gnu.org/cgit/screen.git/commit/?id=441bca708bd197ae15d031ccfd2b42077eeebedc
[git:configure-rewrite]: https://git.savannah.gnu.org/cgit/screen.git/commit/?id=df1c012227
[git:pty-mode-switch-reintroduction]: https://git.savannah.gnu.org/cgit/screen.git/commit/?id=78a961188f7
[git:strncpy-refactoring]: https://git.savannah.gnu.org/cgit/screen.git/commit/?id=0dc67256
[git:release-tag-5-0-0]: https://git.savannah.gnu.org/cgit/screen.git/tag/?h=v.5.0.0
[git:attach-chmod]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/attacher.c?h=v.5.0.0#n120 
[git:attach-mode-restore]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/attacher.c?h=v.5.0.0#n284
[git:attach-missing-restore]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/attacher.c?h=v.5.0.0#n160
[git:logfile-reopen]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/logfile.c?h=v.5.0.0#n81
[git:stolen-logfile]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/logfile.c?h=v.5.0.0#n101
[git:default-pty-mode-4-9-1]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/process.c?h=v.4.9.1#n207
[git:configure-pty-mode-4-9-1]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/configure.ac?h=v.4.9.1#n811
[git:acconfig-pty-mode-comment-4-9-1]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/acconfig.h?h=v.4.9.1#n81
[git:panic-tty-mode-restore]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/screen.c?h=v.5.0.0#n1554
[git:socket-error-messages]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/screen.c?h=v.5.0.0#n849
[git:socket-kill-pid-1]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/socket.c?h=v.5.0.0#n646
[git:socket-kill-pid-2]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/socket.c?h=v.5.0.0#n882
[git:check-pid]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/socket.c?h=v.5.0.0#n555
[git:struct-message-command]: https://git.savannah.gnu.org/cgit/screen.git/tree/src/screen.h?h=v.5.0.0#n148
[git:socket-kill-insufficient-fix]: https://git.savannah.gnu.org/cgit/screen.git/patch/?id=e9ad41bfedb4537a6f0de20f00b27c7739f168f7
[opensuse:disclosure-policy]: https://en.opensuse.org/openSUSE:Security_disclosure_policy
[distros-mailing-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
[screen-man-page]: https://linux.die.net/man/1/screen
