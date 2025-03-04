---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "SSSD: Weaknesses in Privilege Separation due to Issues in Privileged Helper Programs"
date:   2024-12-19
tags:   local setuid capabilities
excerpt: "SSSD (System Security Services Daemon) is a suite of daemons dealing
with user authentication based on mechanisms like LDAP, Kerberos and FreeIPA.
We found privilege escalation paths in a number of helper binaries running
with raised Linux capabilities, when privilege separation is enabled."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[SSSD][sssd-github] (System Security Services Daemon) is a suite of daemons
dealing with user authentication based on mechanisms like LDAP, Kerberos and
FreeIPA. This report is based on SSSD release 2.10.0.

SSSD supports setting up user privilege separation by specifying the build
time configure switch `--with-sssd-user=...`. The default in many Linux
distributions is still to run SSSD as `root`, though. When privilege
separation is enabled, then file based capabilities are assigned to a couple
of helper binaries shipped by SSSD:

    /usr/libexec/sssd/sssd_pam      root:sssd 0750 cap_dac_read_search=p
    /usr/libexec/sssd/selinux_child root:sssd 0750 cap_chown,cap_dac_override,cap_setuid,cap_setgid=ep
    /usr/libexec/sssd/krb5_child    root:sssd 0750 cap_chown,cap_dac_override,cap_setuid,cap_setgid=ep
    /usr/libexec/sssd/ldap_child    root:sssd 0750 cap_chown,cap_dac_override,cap_setuid,cap_setgid=ep

Only members of the group of the dedicated `sssd` account are allowed to
execute these privileged helpers. In SSSD before version 2.10.0 these helpers
(with the exception of `sssd_pam`) had setuid-root bits. With [commit
7239dd6791][sssd-caps-commit] this has been changed to using capabilities
instead.

Our openSUSE SSSD packagers enabled privilege separation for the first time in
conjunction with the update to version 2.10.0. This caused the privileged
helpers to pop up on our radar, and we reviewed them. We found that these
helper binaries do not currently provide proper privilege separation in SSSD.
Some of them offer attack vectors to escalate to `root` again, or obtain
powerful capabilities. Also the systemd service unit of SSSD has issues when
privilege separation is active. The privileged helpers are not
world-accessible, so no immediate exploitation by local users beyond the
dedicated `sssd` account is possible.

We privately reported the findings described below to the Red Hat Security
team on Nov 15. A coordinated disclosure process was in place for about a
month, until the SSSD developers decided that the issues are *not* security
issues, based on the following reasons:

- the issues are not directly exploitable, but only affect defense-in-depth.
- the `sssd` user and group are powerful by design, since these daemons
  influence the outcome of authentication.
- privilege separation has been introduced as additional hardening, not as a
  strong security layer.
- privilege separation was also introduced for some cosmetic purposes: "to
  allow running SSSD in restricted environment that do not support/allow
  running apps under uid=0/in user-ns (like restricted OCP profiles)".

In our opinion, these issues are still security relevant. Consider for example
a scenario where a system administrator or packager would allow execution of
the privileged binaries to all users in the system, either by accident or by a
false expectation of security. While it is common practice to deny world
access to privileged binaries, in our experience this is usually done as a
hardening measure only, not to protect against known weaknesses in programs.
While the permissions of the helpers are correctly applied in SSSD's
installation routine, there is no documentation found that these helpers are
security sensitive and must not be accessible to accounts other than `sssd`.

We did not press for CVE assignments, although we believe that formally they
would still be justified. We recognize that it can still be an improvement to
run SSSD processes as non-root, even if the privileged helpers allow
escalation back to `root`.

Upstream has nonetheless worked and still works on a range of fixes to address
findings from this report. The individual issues we identified are discussed
in the following sections.

2) Issues in `krb5_child` Helper
================================

Like most of the other helpers, this program accepts binary input on STDIN.
The `krb5_child` helper reads the large and complex data structures [`struct
krb5_req`][krb5-req-struct] and [`struct pam_data`][pam-data-struct].
Interesting struct fields in this context are `krb5_req.ccname` and
`krb5_req.keytab`, which specify file paths to process.

The `ccname` field is used in the code path
[`privileged_krb5_setup()`][krb5-setup] →
[`k5c_ccache_setup()`][krb5-ccache-setup] →
[`k5c_precreate_ccache()`][krb5-precreate-cache]. This ends up [in a
loop][krb5-dir-loop] that creates all the parent directories of the path
specified via STDIN, using `uid` and `gid` values also received from STDIN.

This [proof-of-concept][poc-create-dir] shows how to create arbitrary new
directories with arbitrary ownership this way. This very likely allows a full
local root exploit by skillfully creating directories under attacker control,
e.g.  directories used during lookup for trusted system binaries or libraries,
or directories in `/etc` that are used for trusted configuration files or
privileged services.

Upstream Fix
------------

This specific escalation path has been addressed in the [SSSD 2.10.1 bugfix
release][sssd-bugfix-release]. Given the extensive interface offered by this
helper program it is likely that further such escalation vectors exist. Since
upstream does not consider this a strong security barrier, we have not looked
any deeper into this component.

3) Issues in `sssd_pam` Helper
==============================

This helper starts a server instance which offers a socket-based IPC interface
for passing PAM operation requests to it. This is the only helper that has
more limited capabilities, namely only `CAP_DAC_READ_SEARCH`, which allows to
override any read-access permission checks.

In the code path [`server_setup()`][server-setup] →
[`confdb_init()`][confdb-init] the following environment variables are
interpreted in [`ldb_init()`][ldb-init] (which is part of Samba library code):

- `LDB_MODULES_PATH`
- `LDB_MODULES_ENABLE_DEEPBIND`
- `TDB_NO_FSYNC`

The `LDB_MODULES_PATH` variable allows the caller to specify a directory from
which arbitrary shared objects are loaded via `dlopen()`. This
simple [proof-of-concept][poc-load-plugin] shows how to exploit this situation
to gain access to the contents of `/etc/shadow`.

Contrary to the other helper programs, `sssd_pam` was not assigned setuid-root
bits previously. The `CAP_DAC_READ_SEARCH` has only more recently been added
via [commit 0562646cc261][sssd-pam-helper-cap-commit], to allow it to access
keytabs without having to run as `root`.

Upstream Fix
------------

There is a [pending upstream pull request][sssd-hardening-pr] to clear the
environment of this helper to prevent this specific privilege escalation path.

4) Notes on the `selinux_child` Helper
======================================

We haven't found any specific privilege escalation paths in this helper. The
nature of this helper is to allow modification of SELinux MLS mappings,
though. It accepts the new MLS range for arbitrary usernames via a binary
protocol on STDIN. In an SELinux MLS managed system this is a pretty strong
privilege for SSSD to have. Since this is likely by design, we suppose there is
little that can be done about that, except for documenting the sensitive
nature of the helper and that access to it must be well restricted.

The helper performs calls into shared SSSD library code and into libsemanage
and libselinux. Luckily we couldn't find any cases where overly problematic
environment variables are interpreted (beyond the common variables listed in
[section 7.a)][section7-a].

This helper also [changes its UID and GID to 0 early
on][selinux-child-setuid]. When transitioning to UID 0, the kernel does not
assign the full set of capabilities to the process again. This means that the
process runs under ***restricted*** root privileges, having UID and GID 0 but
only the capabilities assigned to the `selinux_child` binary. Additionally,
the SSSD processes run with the systemd hardening feature `SecureBits=noroot
noroot-locked`, thus preventing the helper from using setuid binaries like
`sudo` to regain full root privileges.

The security of restricted root privileges in Linux is lacking, though. The
Linux kernel uses capabilities for its permission checks, but userspace
utilities normally only rely on other process's UID and GID credentials. Also
some APIs lack the possibility to express restricted root privileges,
e.g. in UNIX domain sockets the `SO_PEERCRED` option is used to determine the
credentials of a peer process, which only provides a `struct ucred`,
containing the peer process's PID, UID and GID. Thus this helper runs with
privileges close to full `root`.

5) Notes on the `ldap_child` Helper
===================================

We couldn't find any bigger problems in this helper, beyond the generic
comments in [section 7)][section7] that also apply to this helper.

6) Issues in the `sssd.service` Unit
====================================

The `sssd.service` systemd unit contains the following `ExecStartPre` lines:

```sh
ExecStartPre=+-/bin/chown -f -R root:@SSSD_USER@ @sssdconfdir@
ExecStartPre=+-/bin/chmod -f -R g+r @sssdconfdir@
ExecStartPre=+-/bin/sh -c "/bin/chown -f @SSSD_USER@:@SSSD_USER@ @dbpath@/*.ldb"
ExecStartPre=+-/bin/chown -f -R @SSSD_USER@:@SSSD_USER@ @gpocachepath@
ExecStartPre=+-/bin/sh -c "/bin/chown -f @SSSD_USER@:@SSSD_USER@ @logpath@/*.log"
```

The directories `/var/log/sssd` and `/var/lib/sssd` are owned by the
unprivileged `sssd` user. The `chown` and `chmod` lines above, which are run
as `root`, allow a compromised `sssd` user to stage symlink attacks and thus
gain ownership of, or access to, privileged system files.

This is a simple proof-of-concept demonstrating the issue:

```sh
# stage a symlink attack to gain ownership of /etc/shadow
sssd$ cd /var/log/sssd
sssd$ ln -s /etc/shadow my.log
# as root trigger a sssd (re)start
# sssd needs to be configured (i.e. /etc/sssd & friends need to exist) for this to work
root# systemctl restart sssd.service
root# ls -lh /etc/shadow
-rw------- 1 sssd sssd 889 Nov 13 11:40 /etc/shadow
```

As the directories that are affected by this are not world-writable and don't
carry a sticky bit, the Linux kernel's symlink protection does not come to the
rescue here. Path arguments that are named directly on the command line of
`chown` or `chmod` will be followed, if they're symlinks, unless
`--no-dereference` is passed. Passing this option is also the recommended fix
for this.

In our opinion such automatic permission "fixes" should be treated with care.
If this is to avoid any trouble with migration from older installations
(without privilege separation) then we would rather offer an explicit utility
for system administrators to run. This would make clear that the logic only
runs once and not every time `sssd` is started. It also would prevent any
configuration errors from persisting or from being masked (e.g. other
components in the system that assign bad permissions to SSSD files, thus
fighting against the automatic permission fixes).

Upstream Fix
------------

There is a [pending upstream pull request][sssd-hardening-pr] to pass
`--no-dreference` to the `chown` invocations found in the systemd service unit.

7) Further Observations
=======================

7.a) Environment Variables
-------------------------

There are further environment variables interpreted by the helper programs:

- `TALLOC_FREE_FILL`: will cause memory `free()`'d via `talloc_free()` to be
  overwritten with the byte set in this variable.
- `_SSS_DOM`: will influence systemd journal log messages and thus allow a bit
  of log spoofing.

While these variables have only minor influence on program execution,
privileged programs should not allow arbitrary environment settings to affect
their behaviour.

7.b) Dumpable Process Attribute Setting
--------------------------------------

All of the privileged helpers support a `--dumpable` command line switch to
control whether the process will have the dumpable bit set or not. The default
for this even *is* to mark the process as dumpable (`SUID_DUMP_USER`). This
somewhat unexpectedly overrides the sysctl setting `fs.suid_dumpable`, which
is usually 0 or 2.

The dumpable setting of a process is a sensitive property that plays an
important role in the `ptrace()` system call to determine whether tracing
another process is allowed. From `man 2 ptrace`:

> These checks are performed in cases where one process can inspect sensitive
> information about, or in some cases modify the state of, another process.
> The checks are based on factors such as the credentials and capabilities of
> the two processes, whether or not the "target" process is dumpable [...]

We believe the only barrier left that prevents the unprivileged `sssd` user
from being allowed to trace the privileged binaries is this (further excerpt
from `man 2 ptrace`):

> (5.2)  Deny access if neither of the following is true:
>        - The caller and the target process are in the same user
>          namespace, and the caller’s capabilities are a superset of the target
>          process’s permitted capabilities.

Attaching via `ptrace()` is only denied because the target processes have
raised capabilities. However, this is only a kind of kernel security
extension, provided by the kernel security module
`security_ptrace_access_check()`.

Besides this, the dumpable setting allows the unprivileged user to send
e.g. a SIGSEGV signal to the privileged processes and force them to dump core.
What happens from here depends on the core dump handler installed in the
system. `systemd-coredump` safely handles such core dumps and the unprivileged
user cannot access them. If only `core` is configured as a core pattern, like
it is the case on Debian Linux by default, for example, then the unprivileged
user can cause the `core` file to be created in arbitrary directories, by
first changing into them, starting the privileged process, then killing
it. The `core` file will not be readable for the unprivileged user, but it
still allows to clutter the file system and maybe even overwrite legit files
that are named `core`.

7.c) Debugging Settings
----------------------

The privileged programs also offer rich command line settings for enabling
debugging output and redirecting it to various locations. Generally, privileged
programs should be very careful about what kind of information is leaked to
the caller. The debugging logs can contain information that weakens security
features (like stack overflow protection) or leak privileged information that
has been read in from privileged files.

8) Suggested Fixes
==================

For privileged setuid-root-like binaries the usual precautions should be
taken:

- change into a safe current working directory (CWD).
- apply a safe umask (this already happens)
- cleanse the environment from any untrusted variables, only keep a whitelist
  of vetted variables. E.g. also set a safe PATH.
- make sure none of the interfaces (command line parameters, STDIN data input)
  offers possibilities for the unprivileged caller to escalate their
  privileges beyond the scope of what the privileged program is supposed to
  do.

The last item will likely be the most difficult to realize for the programs in
question - especially in the `krb5_child` helper we expect more attack surface
to exist, for example in the handling of the `ccache` and `keytab` files.
These are dealt with in various other code paths via krb5 library routines
that are unaware of the untrusted input. We suggested upstream to carefully
think through all the possible inputs and code paths and to tighten them.

We would furthermore strip down the supported command line switches, or limit
critical switches to callers that are `root`, notably the switches that
influence debugging and logging as mentioned in [section 7.c][section7-c].

The `dumpable` setting should be left unchanged in the privilege escalation
context.

Finally we suggest to clearly document what can be expected of the privilege
separation feature and how the privileged helpers need to be packaged in order
to achieve a safe installation (especially that they must not be world
executable). This already happened in the description of the [2.10.1 bugfix
release][sssd-bugfix-release].

9) Situation on Other Distributions
===================================

We looked into a number of other Linux distributions and found that on Fedora,
Debian and Ubuntu the SSSD privilege separation is not currently used. On Arch
Linux the current 2.10.0 version is used together with privilege separation,
though, which is affected by the issues covered in this report. Upstream
informed us that there are plans for Fedora Linux to use the privilege
separation feature soon as well.

10) Timeline
============

2024-11-15|We reported the issues to the [Red Hat Security Team](mailto:secalert@redhat.com).|
2024-12-04|Red Hat Security assigned 3 CVEs for items [2)][issue-2], [3)][issue-3] and [6)][issue-6] (all later retracted). A coordinated release date (CRD) of 2024-12-18 has been suggested and agreed upon.|
2024-12-04|SSSD developer Alexey Tikhonov responded to the report explaining that he doesn't consider these findings CVE-worthy.|
2024-12-09|Red Hat Security suggested to keep the 3 CVEs but to consider the issues very high complexity to exploit.|
2024-12-10|After internal discussions Red Hat Security decided to retract the CVEs, not considering these findings to be flaws.|
2024-12-10|Upstream published a [bugfix release 2.10.1][sssd-bugfix-release] containing a fix for [issue 2)][issue-2] and a note hinting at the sensitivity of the helper's permissions used in packaging.|
2024-12-13|After some unclarity about whether the coordinated disclosure process should be continued, we agreed upon immediate publication.|
2024-12-13|Upstream created [a pull request][sssd-hardening-pr] containing further fixes addressing issues [3)][issue-3] and [6)][issue-6].|

11) References
==============

- [sssd GitHub project][sssd-github]
- [sssd 2.10.1 release containing a first batch of fixes addressing issues from this report][sssd-bugfix-release]
- [Pending hardening pull request containing further fixes][sssd-hardening-pr]

[sssd-github]: https://github.com/SSSD/sssd.git
[sssd-bugfix-release]: https://github.com/SSSD/sssd/releases/tag/2.10.1
[sssd-hardening-pr]: https://github.com/SSSD/sssd/pull/7764
[sssd-caps-commit]: https://github.com/SSSD/sssd/commit/7239dd679106748cabfd914df0344601ec5ce224
[sssd-pam-helper-cap-commit]: https://github.com/SSSD/sssd/commit/0562646cc261
[krb5-req-struct]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/krb5/krb5_child.c#L83
[pam-data-struct]: https://github.com/SSSD/sssd/blob/2.10.0/src/util/sss_pam_data.h#L48
[krb5-setup]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/krb5/krb5_child.c#L4054
[krb5-ccache-setup]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/krb5/krb5_child.c#L3870
[krb5-precreate-cache]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/krb5/krb5_child.c#L3836
[krb5-dir-loop]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/krb5/krb5_ccache.c#L247
[server-setup]: https://github.com/SSSD/sssd/blob/2.10.0/src/util/server.c#L623
[confdb-init]: https://github.com/SSSD/sssd/blob/2.10.0/src/confdb/confdb.c#L805
[ldb-init]: https://github.com/samba-team/samba/blob/master/lib/ldb/common/ldb.c#L94
[poc-create-dir]: /download/sssd-create-dir-via-krb5.py
[poc-load-plugin]: /download/sssd-pam-read-search-plugin.c
[selinux-child-setuid]: https://github.com/SSSD/sssd/blob/2.10.0/src/providers/ipa/selinux_child.c#L300
[issue-2]: #2-issues-in-krb5_child-helper
[issue-3]: #3-issues-in-sssd_pam-helper
[issue-6]: #6-issues-in-the-sssdservice-unit
[section7]: #7a-environment-variables
[section7-a]: #7-further-observations
[section7-c]: #7c-debugging-settings
