---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SUSE Security Team Spotlight Autumn 2025"
date:   2026-01-14
tags:   spotlight
excerpt: "This is the autumn 2025 edition of our spotlight series. Once again
it has been a very busy three months for us in the SUSE security team. Some of
the topics we will cover this time are the final outcome of our systemd v258
code review efforts, improvements we helped with in KDE's new plasma-setup
utility and security issues in the virtualbmc OpenStack component, which
turned out to be intended for testing purposes only."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The winter season has already begun for most of the people in our team and
with the Christmas holidays behind us, which granted us some well-earned rest,
we want to take a look back at what happened in our team during the autumn
months. During this time we already published a few dedicated review reports:

- [trivial local Denial-of-Service][blog:opensmtpd] in the `OpenSMTPD` mail
  transfer agent.
- [unauthenticated D-Bus API][blog:scx] in the `scx` scheduler project allowing
  for a major local Denial-of-Service.
- [minor privilege escalation][blog:lightdm] from `lightdm` to `root` in
  `lightdm-kde-greeter` leading to major improvements of its D-Bus code.
- [major local vulnerabilities][blog:smb4k] in the D-Bus
  interface of `smb4k`, resulting in upstream fixing a series of
  long-standing issues in the affected component.

In this post, as usual in the spotlight series, we will look into some topics
that did not justify dedicated reports. First we will discuss our [continued
efforts][section:systemd] to review privileged components found in the
`systemd` v258 release, which involved diving deep into some low-level aspects
of the Linux kernel API. [Section 3][section:plasma-setup] looks at D-Bus
issues we found in `plasma-setup`, a new component for the KDE desktop.
[Section 4][section:plocate] covers recent discussions about granting special
setgid permissions to the `plocate` package. [Section 5][section:virtualbmc]
gives insight into security issues found in the `virtualbmc` OpenStack
project, which turned out to be for testing purposes only. [Section
6][section:snapd] discusses revived efforts to bring the Snap package manager
to openSUSE.

{: #section-systemd}
2) Completion of `systemd` v258 Code Review
===========================================

We already discussed our `systemd` v258 review efforts [in the previous
spotlight edition][blog:summer-spotlight-systemd]. At the time we found a
local root exploit in the `systemd-machined` API, which could be fixed before
the final release of v258. For the addition of this new major version of
`systemd` to openSUSE Tumbleweed, we still needed to look more closely into a
number of other D-Bus and Varlink services that have been added.

During autumn we completed the review of changes in
[`systemd-mountfsd`][bug:systemd-mountfsd] and
[`systemd-nsresourced`][bug:systemd-nsresourced]. Some of the changes
introduced with these services allow unprivileged users to perform a number of
container-related operations without requiring special privileges.

The [`io.systemd.MountFileSystem.MountDirectory` API
call][code:systemd:mountwork] in `mountfsd`, for example, allows to obtain
a mount file descriptor for a directory owned by the calling user, on which a
user and group ID mapping is applied corresponding to a user namespace file
descriptor also owned by the caller. Some newer, little-known Linux system
calls like [`open_tree()`][man:open_tree] and
[`mount_setattr()`][man:mount_setattr] are used to achieve this. This niche
topic and the low-level nature of the involved APIs result in quite complex
code which needed careful reviewing. We are happy to report that we could find
no issues in this area, however.

The `nsresourced` service, among other features, allows unprivileged users to
obtain a dynamic range of user and group IDs for use with user namespaces. The
tools [`newuidmap`][man:newuidmap] and [`newgidmap`][man:newgidmap] already
allowed this for a longer time based on static configuration files. The
`nsresourced` service applies _dynamic_ limits and ID ranges to processes in
the system, however, which makes things quite more complicated. This even
includes [an EBPF program][code:systemd:nsresourced-ebpf], which keeps track
of the uses of the resulting user namespace file descriptors. Despite this
complexity we could not find any issues in this component either.

What kept us busy for a longer time was [logic
invoked][code:systemd:mountwork-load-userns] by `mountfsd` to obtain the
user and group ID mapping tied to the user namespace file descriptor passed by
the unprivileged client. To retrieve this information, the utility function
[`ns_enter_and_pin()`][code:systemd:ns-enter-and-pin] forks a short-lived
child process which joins the user namespace provided by the client.  The
parent process then reads the child's `uid_map` and `gid_map` nodes from
`/proc/<child-pid>`.

The `mountfsd` daemon runs with `root` privileges (although some sandboxing is
applied to it as well), which will be inherited by the short-lived child
process. Once the child process joins the user namespace provided by the
unprivileged client, the security domain of this process changes, however,
because the client owning the namespace is supposed to have full control over
processes associated with it.

One consequence of this is that the owner of the user namespace can send
arbitrary signals to the short-lived `systemd` process, e.g. to kill it. This
would only result in a kind of Denial-of-Service against the client itself and
should not cause any security issues.

We expected another important ramification of this to be in the area of the
[`ptrace()` system call][man:ptrace]. The following is stated in the "ptrace
access mode checking" section of the `ptrace(2)` man page:

```
(3)  Deny access if neither of the following is true:

            •  The real, effective, and saved-set user IDs of the target
               match the caller's user ID, and the real, effective, and
               saved-set group IDs of the target match the caller's group
               ID.

            •  The caller has the CAP_SYS_PTRACE capability in the user
               namespace of the target.
```

According to the second item, the unprivileged client, which owns all
capabilities in its user namespace, should be able to trace the short-lived
`systemd` process which joins the client-controlled user namespace. This
ability would have allowed for an interesting privilege escalation, because
tracing capabilities also include the ability to modify the target process,
e.g. to change its code and data. While trying to reproduce this, the kernel
always denied `ptrace()` access to this short-lived process, however, and we
were not sure why. Unclarity in such aspects is not a good thing when it
concerns security, thus we set out to get to the bottom of this.

After diving deep into the Linux kernel's `ptrace()` code, we found [the
commit][commit:kernel-ptrace] which is responsible for the rejection of
tracing access in this scenario. The background of this commit actually is
to prevent owners of unprivileged user namespaces from accessing the
executable of processes created in the initial namespace. `ptrace()` access to
the target PID is now only allowed if the target process performed an
`execve()` while being a member of the newly joined user namespace. In summary
this means the following:

- if a process only performs `fork()` and `setns()` to join a user namespace,
  then `ptrace()` access to this process is denied to the owner of the user
  namespace.
- if a process performs `fork()`, `setns()` and `execve()`, then `ptrace()`
  access to this process is granted to the owner of the user namespace.

This detail is not documented in the [`ptrace()` man page][man:ptrace] and it
took us a while to fully understand what was going on. With this well
understood we could finally move on, knowing that the logic in `mountfsd` is
robust.

{: #section-plasma-setup}
3) D-Bus Issues in Unreleased `plasma-setup` KDE Package
========================================================

This new KDE component was first named KISS (KDE initial system setup), but
meanwhile has been renamed to [`plasma-setup`][upstream:plasma-setup:repo].
Its purpose is to perform initial system configuration based on a graphical
wizard, when a Linux system has been freshly installed.

Our openSUSE KDE packagers [asked for a review][bug:plasma-setup] of this new
component, expecting it to be part of a major KDE release in autumn. It turned
out that this had not been planned by upstream after all (or plans changed).
Still the review we performed turned out to be useful, since we identified
various security problems in the existing code which could be fixed by
upstream before the new component had seen production use.

The following report is based on the `plasma-setup` source code as of upstream
[commit 08ed810e0e7][upstream:plasma-setup:reviewed-tree]. While the graphical
components of `plasma-setup` run with low privileges, there exists a D-Bus
helper service running as `root`, `kde-initial-system-setup-auth-helper`,
which allows to perform a number of operations with elevated privileges. These
operations are guarded by Polkit authorization rules. The dedicated user
account `kde-initial-system-setup` is allowed to invoke any of these actions
without authentication. Beyond this, any locally logged-in users are also
allowed to invoke the operations without authentication. The latter is quite
problematic, as will be outlined below.

The implementation of the D-Bus callbacks for these actions is found in
[`src/auth/authhelper.cpp`][code:plasma-setup:authhelper]. The following
sub-sections discuss issues in a couple of these actions.

{: #sub-section-autostarthook}
org.kde.initialsystemsetup.createnewuserautostarthook
-----------------------------------------------------

This action [receives a "username" parameter][code:plasma-setup:createnewuser]
from the unprivileged D-Bus client. The username is not verified by the
privileged helper, it only needs to be convertible to `QString`. The helper
then creates all the directory components of
`/home/<username>/.config/autostart`. After this, the file
`/home/<username>/.config/autostart/remove-autologin.desktop` is created and
fixed data is written into it.

This action allows local users to create arbitrary world-readable directories
owned by `root`. This can be achieved by passing a string like
`../../my/desired/path` as "username". Furthermore, by placing a symlink at
the expected location of `remove-autologin.desktop`, arbitrary files in the
system can be overwritten, leading to a local Denial-of-Service.

The implementation of the action also causes the created directories and files
to be owned by `root:root`, and not by the user that actually owns the home
directory, which is unclean.

### Suggested Fixes

Apart from restricting access to the helper to the `kde-initial-system-setup`
user, the implementation of this action should verify whether the
passed-in username actually exists. Furthermore, the home directory of this
account should be obtained via the [`getpwent()`][man:getpwent] API, instead
of assuming that `/home/<username>` will always be the correct home directory.

When the execution of this helper is actually limited to the initial setup
context, it could be technically acceptable to operate as `root` in the newly
created user's home directory. For reasons of prudence and giving a good
example, we still recommend to drop privileges to the target user account
before actually writing the `.desktop` file in the user's home directory.

org.kde.initialsystemsetup.setnewuserhomedirectoryownership
-----------------------------------------------------------

The method call associated with this action [also receives a "username"
parameter][code:plasma-setup:setnewuserhomedir] which is not verified. The
following command line is invoked based on the "username" parameter:

```sh
chown -R <username>:<username> /home/<username>
```

This is on the verge of a local root exploit, save for the fact that `chown`
expects a valid user and group account to give the ownership to, which at the
same time needs to result in the proper path to operate on.  A username
containing path elements will fail, because the necessary characters like `/`
are by default denied in usernames.

This action still allows to potentially change ownership of all files of
arbitrary other users' home directories. Fortunately the recursive `chown`
algorithm is not subject to symlink attacks these days. If somebody would be
able to place a symlink in place of their home directory in
`/home/<username>`, then the symlink would still be followed, however.

The username could also be interpreted as an arbitrary command line argument
to `chown`, thwarted only by the fact that the `<username>:<username>`
argument is constructed here instead of just passing `<username>`, which will
prevent proper command line arguments from being passed.

### Suggested Fixes

As for the previous action, the implementation should verify if the username
is valid and determine the proper home directory and group via `getpwent()`.
The assumption that username and group are equivalent is also problematic
here.

Why this operation would be needed at all for a newly created home directory
is questionable. When new user accounts are created, file ownership should
already be correct. If this action is supposed to fix the ownership of files
created by other `plasma-setup` actions in the home directory as `root` (as is
seen in the [`createnewuserautostarthook` action][sub-section:autostarthook]),
then this is only a hack which should be removed in favor of not creating
files as `root` in unprivileged users' home directories in the first place.

org.kde.initialsystemsetup.setnewusertempautologin
--------------------------------------------------

Again this method [receives a "username"
parameter][code:plasma-setup:setnewuserautologin] which is not verified. The
implementation writes the following content to the file
`/etc/sddm.conf.d/99-kde-initial-system-setup.conf`:

```
[Autologin]
User=<username>
Session=plasma
Relogin=true
```

This SDDM configuration snippet is supposed to automatically login the
given user account. For some reason that we did not investigate more deeply,
the configuration was not effective during our tests on openSUSE
Tumbleweed. We could verify that the configuration file created this way was
parsed and evaluated in SDDM, however, so something else must have been amiss.

The automatic login is supposed to work, though, and if it does, then any
local user account can call this action with `root` as username, which should
cause an automatic login of the `root` user the next time SDDM runs.

By passing crafted strings for "username", the content of the drop-in
configuration file can even be fully controlled by local users. The following
"username" would create a General section with a crafted "RebootCommand", for
example:

```
user\n[General]\nRebootCommand=/home/myuser/evil
```

Provided the configuration snippet is actually in effect in SDDM, this action
allows for a local root exploit.

### Suggested Fixes

As for the other actions, the implementation should verify whether the passed
"username" is valid and does not equal `root`.

Upstream Fixes
--------------

We privately approached KDE security on 2025-09-22 with a detailed report
about these findings. As a result we established contact with the
`plasma-setup` developer and discussed fixes for the issues. It was decided to
perform the bugfix in the open, since the component was not yet part of a
stable release of KDE. We reviewed an [upstream merge
request][upstream:plasma-setup:mr] during the course of two weeks and upstream
managed to arrive at a much improved version of the KAuth helper component.

As of [commit e6eb1cd9a8d][upstream:plasma-setup:fixed-helper] the privileged
helper carefully scrutinizes the input parameters received via D-Bus, and it
also drops privileges to the calling user before operating in the unprivileged
user's home directory. Also the KAuth actions provided by the helper are now
restricted to the `plasma-setup` service user and no longer accessible to
all locally logged-in users. The latter would still be problematic, since it
would allow to setup automatic login for arbitrary other users in the system,
for example.

{: #section-plocate}
4) Discussion about Granting setgid Privileges to the `plocate` Binary
======================================================================

An openSUSE community member approached us about [granting special setgid
privileges to the `plocate`][bug:plocate] binary. `plocate` is a modern and
fast replacement for the classic `locate` program. Upstream supports operation
of the `plocate` program with the `setgid` bit assigned to the `plocate`
group. This means that the program is granted `plocate` group privileges
during execution.

When `updatedb`, locate's utility for indexing files, would be invoked with
full root privileges, then the database in `/var/lib/plocate` would contain
information about all files in the file system. This way `locate` would grant
all users in the system read access to this information, resulting in an
information leak, because users can see paths that they would not normally be
allowed to list, like all the files stored in the `/root` home directory. For
this reason the `plocate-updatedb` system service on openSUSE Tumbleweed runs
as `nobody:nobody`, resulting in a system-wide `plocate` database which only
contains information about publicly accessible paths in the system. For being
able to locate their own private files, users need to create their own
user-specific databases instead.

The purpose of the setgid privilege is to address this `locate` database
access issue. `plocate` supports a mode in which `updatedb` is invoked with
full root privileges, but the ownership of the central database is changed to
`root:plocate` and file mode `0640`. When `plocate` is installed as
setgid-plocate then it is still allowed to access the central database. The
program drops the special group credentials quickly again, right after opening
the database. The program then ensures that the calling user will only be able
to retrieve information about files that it is allowed to access based on its
real credentials.

There is a minor security issue found in this approach. Since the `plocate`
database does not contain metadata about the files it indexed, the `plocate`
program needs to check the ownership of files in the file system at the time
the search query runs. This is a sort of a TOCTOU (time-of-check time-of-use)
race condition. There can be situations when the verification in `plocate`
yields wrong results:

```sh
root# mkdir --mode=1777 /shared
root# mkdir --mode=0700 /shared/secret-dir
root# touch /shared/secret-dir/secret-file
root# updatedb

# root will be able to locate any files in secret-dir
root# locate /shared/se
/shared/secret-dir
/shared/secret-dir/secret-file

# non-root cannot locate the secret-file
user$ locate /shared/se
/shared/secret-dir

# now consider root deletes the secret-dir again
root# rm -rf /shared/secret-dir

# now the unprivileged user takes ownership of this path
user$ mkdir --mode=0755 /shared/secret-dir

# this only works before `updatedb` is called again, because then it will
# notice that secret-file no longer exists and delete it from the database.
#
# when the unprivileged user calls locate this time, the secret-file will show
# up, since the "secret-dir" is now controlled by the unprivileged caller.
user$ locate /shared/se
/shared/secret-dir
/shared/secret-dir/secret-file
```

This problem likely cannot be easily fixed in the `plocate` code, since it
would require changing the database format radically, increasing database size
as a result, only to fix an unlikely problem.

The information leak is minor and should rarely be exploitable. For this
reason we left it up to the openSUSE `plocate` package maintainer whether the
setgid-plocate approach should be used, or not.

{: #section-virtualbmc}
5) Local Root Exploit in OpenStack's non-production `virtualbmc` Project
========================================================================

By way of our efforts to monitor newly introduced `systemd` services in
openSUSE Tumbleweed, the [`python-virtualbmc`][upstream:virtualbmc:repo]
package caught our attention. The program allows to emulate a board management
controller (BMC) interface for use with libvirt.

Part of the package is a daemon running with full root privileges, listening
for ZeroMQ API requests on `localhost`. A number of unauthenticated API calls
in this context raised our suspicions, which is why we scheduled a [full
review of this package][bug:virtualbmc]. A closer look showed that the
unauthenticated API calls were indeed problematic, even allowing for a full
local root exploit.

We filed a detailed private bug report on
[LaunchPad][upstream:virtualbmc:launchpad] for the OpenStack project, but had
difficulties getting a response. After some weeks we reached out to an
individual member of the OpenStack security team and learned from the reply
that the virtualbmc project was not intended for production use at all, but is
rather a utility intended for use in testing environments. This is also
documented in the repository's [README][upstream:virtualbmc:readme], which was
overlooked by us. As a result we filed a delete request for the
`python-virtualbmc` package in openSUSE Tumbleweed, and the package has
already been removed.

For completeness, a detailed report of the security issues in the virtualbmc
daemon follows below.

Lack of Authorization and Input Validation in `vbmcd`
-----------------------------------------------------

When the `virtualbmc` `systemd` service is started, then `/usr/bin/vbmcd` runs
with full root privileges. It offers a ZeroMQ-based network API, listening on
localhost port 50891 by default. Any local user in the system can talk to the
daemon this way.

A simple request which can be sent to the daemon (in JSON format) is the
following stop command, for example:

```json
{
        "command": "stop",
        "port": 1234,
        "domain_names": ["../../home/myaccount/mydomain"],
}
```

The `domain_name` passed here will be used by the daemon to lookup a
supposedly trusted per-domain configuration file, which is by default located
in `/root/.vbmc/<domain>/config`. Since the daemon does not scrutinize the
input `domain_name`, a local attacker can include directory components in the
name, to trick the daemon into accessing an attacker-controlled configuration
file.

In the context of the `stop` command used here, the daemon will try to update
the domain's configuration file in case a change of domain state is detected.
The path for writing out the updated configuration file will be constructed
using the `domain_name` found in the input configuration file. Thus the local
attacker can place data like this into `/home/myaccount/mydomain/config`:

```
[VirtualBMC]
domain_name = ../../etc/sudoers.d
port = 1234
active = true
address = some
  evil stuff
  myaccount ALL=(ALL:ALL) NOPASSWD: ALL
```

The daemon will now believe that the domain's state changed, because the input
configuration file contains `active = true`, while the daemon was asked to
stop the domain. This will trigger logic to write out an updated configuration
file with the new state of the domain configuration. The logic for this is
found in the [`_vbmc_enabled()`][code:virtualbmc:enabled-check] member
function.

Since the `domain_name` found in the crafted configuration file is set to
`../../etc/sudoers.d`, the daemon will write the new configuration file into
`/root/.vbmcd/../../etc/sudoers.d/config`. To get an advantage from this, the
attacker must get the daemon to write out at least one valid `sudoers`
configuration line into the new configuration file.

The attacker has only a limited degree of freedom at this stage, because
the daemon will write out the new configuration file via the Python
`configparser` module and will only consider the `[VirtualBMC]` section as
well as any of the configuration keys listed in the [`VBMC_OPTIONS`
list][code:virtualbmc:options] defined in the daemon's code.

To help with the exploit, the
[`configparser`](https://docs.python.org/3/library/configparser.html)
multiline syntax comes to the rescue: any lines following an assignment which
are indented will be accepted as part of the configuration value. When writing
the settings out to a new configuration file, these multiline settings will be
preserved.  This is put to use in the example above, which contains a final
line `myaccount ALL=...`. This line will now appear along with the rest of the
configuration data in `/etc/sudoers.d/config`.

As a result, when the attacker now invokes `sudo su -`, a couple of sudoers
parsing errors will appear, but in the end, access is granted and a root shell
will be obtained by the attacker.

This approach of using a sudoers drop-in configuration file is just one of the
more obvious approaches that came to mind. There's a lot of different ways
to exploit this, however, for example by overwriting shell scripts or script
snippets in `/etc` or `/usr/bin` and then waiting for a privileged process to
run them. This would be even easier, because shell scripts have less
strict syntax requirements compared to the sudoers configuration file. The
effect would not be immediate, however, like in the sudoers approach.

Reproducer
----------

We offer a [Python script for download][download:virtualbmc-reproducer], which
is a Proof-of-Concept (PoC) to reproduce the local root exploit in the context
of an arbitrary unprivileged user on the system, when `vbmcd` is running with
its default configuration.  `sudo` needs to be installed, naturally, for the
exploit to work.

Further Concerns
----------------

In general, the API offered by `vbmcd` on localhost is missing input
sanitization and authorization. Authorization seems only to be performed
indirectly via libvirt. In this context clients can also pass crafted
`libvirt_uri` parameters, for example, which seem to make it possible to let
the daemon connect to arbitrary URLs via SSH. There also is no isolation
between different users' domain configurations, e.g. the "stop" command used
above can be issued for any domain configured by another user in the system.

To make this API safe, we believe there needs to be an ownership model for
each domain's configuration, a verification of the client's credentials in
some form (a UNIX domain socket would allow this more easily) and sanitization
of all input parameters to avoid any unexpected side effects.

Since the daemon listens on an unprivileged port on localhost, other
unprivileged users can try to bind to this port first and provide a fake
`vbmcd` service. Since the API requests can also contain secret credentials,
this would pose a major local information leak. For safe operation, the API
would need to bind to a privileged port on localhost instead.

{: #section-snapd}
6) Revisit of the `snapd` Package Manager
=========================================

In 2019 we received [a request][bug:snapd:old-review] to add the [`snapd` package
manager][upstream:snapd:home] to openSUSE, which involved a [review of the
setuid-root program][bug:snapd:old-setuid] `snap-confine`. At the time we were
generally satisfied with the code quality and design of the program, but still
[found a few low to medium severity security issues][bug:snapd:setuid-findings]
and gave recommendations on how to improve the code in some spots. The
packagers have meanwhile been busy with other topics and we never saw
an updated openSUSE package containing the necessary changes, which is why we
closed the related bugs after a period of inactivity.

In August we received [a follow-up request][bug:snapd:new] for addition of an
updated `snapd` package. We revisited the privileged components and again
[provided feedback][bug:snapd:new-findings] to upstream. This time
all remaining issues could be resolved and the new package has been allowed to
become part of openSUSE Tumbleweed. We are happy to see these old efforts not
going completely to waste, and welcome the possibility to use Snap packages on
openSUSE Tumbleweed in the future.

7) Conclusion
==============

Again we hope we've been able to give you some additional insight into our
efforts to maintain the security of SUSE distributions and open source
software. We are looking forward to the next edition of the spotlight series,
which will be published in about three months from now.

[blog:lightdm]: /2025/11/13/lightdm-kde-greeter-auth-helper.html
[blog:opensmtpd]: /2025/10/31/opensmtpd-local-DoS.html
[blog:scx]: /2025/11/06/scx-unauthorized-dbus.html
[blog:smb4k]: /2025/12/10/smb4k-major-issues-in-kauth-helper.html
[blog:summer-spotlight-systemd]: /2025/10/01/summer-spotlight.html#2-systemd-v258-local-root-exploit-in-new-systemd-machined-api-found-in-release-candidates
[bug:plasma-setup]: https://bugzilla.suse.com/show_bug.cgi?id=1249520
[bug:plocate]: https://bugzilla.suse.com/show_bug.cgi?id=1254549
[bug:snapd:new-findings]: https://bugzilla.suse.com/show_bug.cgi?id=1248682#c5
[bug:snapd:new]: https://bugzilla.suse.com/show_bug.cgi?id=1248682
[bug:snapd:old-review]: https://bugzilla.suse.com/show_bug.cgi?id=1127366
[bug:snapd:old-setuid]: https://bugzilla.suse.com/show_bug.cgi?id=1127368
[bug:snapd:setuid-findings]: https://bugzilla.suse.com/show_bug.cgi?id=1127368#c3
[bug:systemd-mountfsd]: https://bugzilla.suse.com/show_bug.cgi?id=1250898
[bug:systemd-nsresourced]: https://bugzilla.suse.com/show_bug.cgi?id=1250902
[bug:virtualbmc]: https://bugzilla.suse.com/show_bug.cgi?id=1253677
[code:plasma-setup:authhelper]: https://github.com/KDE/plasma-setup/blob/08ed810e0e7ba1642d6f2bd211e0ba43e85f8496/src/auth/authhelper.cpp
[code:plasma-setup:createnewuser]: https://github.com/KDE/plasma-setup/blob/08ed810e0e7ba1642d6f2bd211e0ba43e85f8496/src/auth/authhelper.cpp#L28
[code:plasma-setup:setnewuserautologin]: https://github.com/KDE/plasma-setup/blob/08ed810e0e7ba1642d6f2bd211e0ba43e85f8496/src/auth/authhelper.cpp#L150
[code:plasma-setup:setnewuserhomedir]: https://github.com/KDE/plasma-setup/blob/08ed810e0e7ba1642d6f2bd211e0ba43e85f8496/src/auth/authhelper.cpp#L125
[code:systemd:mountwork]: https://github.com/systemd/systemd/blob/781d9d0789379d1ea1f2ecefb804d41e9c8b6c38/src/mountfsd/mountwork.c#L726
[code:systemd:mountwork-load-userns]: https://github.com/systemd/systemd/blob/781d9d0789379d1ea1f2ecefb804d41e9c8b6c38/src/mountfsd/mountwork.c#L852
[code:systemd:ns-enter-and-pin]: https://github.com/systemd/systemd/blob/781d9d0789379d1ea1f2ecefb804d41e9c8b6c38/src/basic/namespace-util.c#L600
[code:systemd:nsresourced-ebpf]: https://github.com/systemd/systemd/blob/781d9d0789379d1ea1f2ecefb804d41e9c8b6c38/src/nsresourced/bpf/userns-restrict/userns-restrict.bpf.c
[code:virtualbmc:enabled-check]: https://github.com/openstack/virtualbmc/blob/6e14e8bdb8cc022d843bfb98377bfc89d99fc9c5/virtualbmc/manager.py#L90
[code:virtualbmc:options]: https://github.com/openstack/virtualbmc/blob/6e14e8bdb8cc022d843bfb98377bfc89d99fc9c5/virtualbmc/manager.py#L40
[commit:kernel-ptrace]: https://github.com/torvalds/linux/commit/bfedb589252c01fa505ac9f6f2a3d5d68d707ef4
[download:virtualbmc-reproducer]: /download/virtualbmc-exploit.py
[man:getpwent]: https://man7.org/linux/man-pages/man3/getpwent.3.html
[man:mount_setattr]: https://manpages.debian.org/testing/manpages-dev/mount_setattr.2.en.html
[man:newgidmap]: https://man7.org/linux/man-pages/man1/newgidmap.1.html
[man:newuidmap]: https://man7.org/linux/man-pages/man1/newuidmap.1.html
[man:open_tree]: https://manpages.debian.org/testing/manpages-dev/open_tree.2.en.html
[man:ptrace]: https://man7.org/linux/man-pages/man2/ptrace.2.html
[section:plasma-setup]: #section-plasma-setup
[section:plocate]: #section-plocate
[section:snapd]: #section-snapd
[section:systemd]: #section-systemd
[section:virtualbmc]: #section-virtualbmc
[sub-section:autostarthook]: #sub-section-autostarthook
[upstream:plasma-setup:fixed-helper]: https://github.com/KDE/plasma-setup/blob/e6eb1cd9a8d4094ff2771d25ee6f761ea9f05c6c/src/auth/authhelper.cpp
[upstream:plasma-setup:mr]: https://invent.kde.org/plasma/plasma-setup/-/merge_requests/48
[upstream:plasma-setup:repo]: https://github.com/KDE/plasma-setup.git
[upstream:plasma-setup:reviewed-tree]: https://github.com/KDE/plasma-setup/tree/08ed810e0e7ba1642d6f2bd211e0ba43e85f8496
[upstream:snapd:home]: https://snapcraft.io
[upstream:virtualbmc:launchpad]: https://bugs.launchpad.net/virtualbmc/+bug/2133163
[upstream:virtualbmc:readme]: https://github.com/openstack/virtualbmc/blob/master/README.rst
[upstream:virtualbmc:repo]: https://github.com/openstack/virtualbmc
