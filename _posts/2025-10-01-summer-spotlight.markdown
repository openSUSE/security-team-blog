---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SUSE Security Team Spotlight Summer 2025"
date:   2025-10-01
tags:   spotlight
excerpt: "This is the summer 2025 edition and first anniversary of our
spotlight series. The last two months have been surprisingly busy for us
in the area of code reviews and we have quite a number of interesting
stories to share with you. Among others we will cover a local root exploit we
found in systemd v258 release candidates, issues in logrotate drop-in
configuration files, newly developed Varlink services and a symlink attack
issue in chrony."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

Autumn is already palpable for many of us these days and this means it is time
to take a look back at what happened in our team during the summer months. We
have not published any dedicated security reports during that time; instead
we have all the more to cover in this edition of the spotlight series which
discusses code review efforts that did not lead to major findings or otherwise
did not qualify for a dedicated report.

This is also the first anniversary of the spotlight series, which we started
in August 2024 with the first summer spotlight edition. We are happy to
provide our readers with interesting content about the daily work in our team
and are looking forward to more anniversaries to come.

In this issue we will cover [a local root exploit we discovered in systemd
v258-rc4][section-systemd] before it became part of a stable release, problems
found in [logrotate drop-in configuration files][section-logrotate], [changes
in D-Bus configuration files][section-gnome] related to the GNOME version 49
release, and a follow-up [code review of the Kea DHCP server
suite][section-kea]. Furthermore we found a [symlink attack issue in
`chronyc`][section-chrony], proactively reviewed [new Varlink
services][section-varlink] developed by fellow SUSE engineers and discovered a
local privilege escalation issue in [bash-git-prompt][section-bgp]. Finally we
will talk about a [problematic script used on Steam Deck
devices][section-powerbuttond].

<a name="section-systemd"/>

2) systemd v258: Local Root Exploit in new systemd-machined API found in Release Candidates
===========================================================================================

At the beginning of August one of our systemd maintainers [asked us to review
D-Bus and Polkit API changes][bugzilla:systemd] in a release candidate of
systemd 258.  This major version update of systemd contains many API additions
e.g. in `systemd-resolved`, `systemd-homed`, `systemd-machined` and
`systemd-nsresourced`.

While looking into these changes we found an issue in `systemd-machined`. This
daemon can be used to manage virtual machines and containers alike.
In upstream [commit adaff8eb35d][systemd:commit:register-action] a new Polkit
action "org.freedesktop.machine1.register-machine" has been added, which was
accessible to locally logged in users without authentication (Polkit `yes`
setting). The purpose of this new API is to allow users to register existing
containers with `systemd-machined`, that have been created by other means.

There exist two D-Bus methods which employ this Polkit action:
"RegisterMachine" and "RegisterMachineWithNetwork". Both accept [a
rather long list of parameters][systemd:code:register-method] to describe the
container which is supposed to be registered with the daemon. The following
command line performs an example registration of a fake container:

```sh
$ gdbus call -y -d org.freedesktop.machine1 -o /org/freedesktop/machine1 \
    -m org.freedesktop.machine1.Manager.RegisterMachineWithNetwork \
    mymachine '[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]' myservice container \
    $$ $PWD '[1, 2, 3]'
```

Among these parameters is the process ID (PID) of the leader process of the
container. In this example `$$`, i.e. the shell's own PID, is passed as leader
PID. The release candidate implementation of `systemd-machined` failed to
verify whether this process is owned by the caller and an actual member of an
unprivileged [user namespace][man:user_namespaces] belonging to a container.

The first problematic aspect we noticed about this was that `systemd-machined`
can send `SIGTERM` to the process group the given leader PID belongs to (e.g.
when registering a new container using the same name), allowing a trivial
local Denial-of-Service against arbitrary other processes. Far more
problematic was something else that we noticed: the unprivileged user was able
to enter a shell in such a crafted container, like this:

```sh
user$ machinectl shell mymachine
# full root privileges, this happens in the actual host's file system
container-root# touch /evil
```

Since the leader PID in this case is a process belonging to the host's initial
namespaces, the root shell for the "container" is actually a root shell in
the host itself, giving full root privileges over the system.

This problem is found in all release candidates of systemd v258. We reported
the problem privately to systemd security, and upstream developed bugfixes
right away while still in the RC phase.
The local root exploit was never present in any stable release version and
thus end users are not affected by the problem, which is also why no CVE was
assigned.

The Bugfix
----------

To address the issue, `systemd-machined` now verifies that the leader PID
specified by the client is actually owned by the caller. Furthermore the
authentication requirements for Polkit action "register-machine" have been
raised to `auth_admin_keep` even for local users.

While writing this very summary we noticed that one aspect of the issue had
been overlooked and was not fixed for the stable release: the verification of
the user namespace membership of the target process. Thus it is still possible
to gain a root shell this way, but only after authenticating as admin, which
means the caller already needs admin privileges to trigger the exploit. This
aspect [has now been addressed for future releases ][systemd:follow-up-fix] by
upstream, which is important, because upstream intends to relax the
authentication requirements for this action to `yes` again at a later time.

Increase in Complexity in systemd
---------------------------------

With this version of systemd we are seeing a noticeable increase in complexity
in the implementation of a number of systemd components. In the area of
container management the complexity is pretty much by design, given the
intricacy of the different namespace mechanisms playing together, partly
under the control of unprivileged users. There is also the addition of
[Varlink](https://varlink.org) for Inter-Process-Communication, however, which
means that two different interfaces for D-Bus and Varlink now exist in parallel
for some services. This is also the case for `systemd-machined`.

While the D-Bus and Varlink interfaces usually call into shared functions for
most of the business logic and share the same Polkit actions, there is
necessarily a certain amount of redundancy in parsing and evaluation of
input parameters. As a result this also increases the burden on code reviewers
which now need to keep track of two different entry paths to the same logic.

We are not yet completely finished with reviewing all notable changes in
systemd v258 but intend to complete the effort within the next couple of weeks.
We are happy that our review efforts already prevented a local root exploit in
software as widespread as systemd from ending up in production environments.

<a name="section-logrotate"/>

3) logrotate: Issues in drop-in Configuration Files
===================================================

Missing `su <user> <group>` Directives
--------------------------------------

Recently we noticed that there exist [a number of packages in openSUSE
Tumbleweed][bugzilla:logrotate:main] which trigger [a
"logrotate-user-writable-log-dir" rpmlint
diagnostic][rpmlint:code:logrotate-check]. This diagnostic is emitted when a
package contains a logrotate drop-in configuration file (e.g. in
`/etc/logrotate.d`) which points the logrotate daemon to a log directory which
is controlled by non-root accounts, where it will operate with full root
privileges.

Operating as `root` in locations controlled by other users is generally very
difficult to get right and can easily lead to privilege escalation from a
service user to `root` e.g. via symlink attacks. logrotate
offers a [`su <user> <group>` syntax][logrotate:code:config-syntax] to
instruct the daemon to perform a privilege drop to the user owning the
directory to avoid any security implications.

To start with, we had a look at the implementation of the logrotate daemon, to
judge what the impact would be, when a rogue service user account tries to
perform an attack against logrotate when it starts rotating logs in a
directory controlled by the compromised user. The results are as follows:

- the daemon performs [a sanity check][logrotate:code:writable-check] on the
  directory to operate on and rejects any log directories which are writable
  by world or a non-root group. This does not include the case where the
  log directory is owned by a non-root user, however.
- [the system calls used by logrotate][bugzilla:logrotate:analysis]
  always include safe flags for opening log files which will prevent trivial
  symlink attacks by service users from succeeding. There could still be more
  intricate attacks when a parent directory of the log directory is also owned
  by a non-root user account. This is not a common setup, however, and we could
  not find any package where this is the case.

In summary we believe that there are no overly dangerous situations that can
result from a missing `su <user> <group>` directive in affected logrotate
configuration files. Still we decided that it will be better to fix existing
packages and enforce that packages emitting this rpmlint diagnostic are not
allowed into openSUSE in the future. To this end we fixed a couple of
openSUSE-specific logrotate drop-in configuration files as well as an [upstream
configuration file in Munge][logrotate:munge:pr].

Problems with Scripts Embedded in Configuration
-----------------------------------------------

While looking into the credentials mismatch issue we noticed that logrotate
can end up in even more complex usage scenarios. The configuration file format
allows shell scripts to be embedded that will be executed after rotating
logfiles, for example. These scripts always run with full `root` privileges,
independently of an existing `su <user> <group>` directive. The likeliness of
security issues is higher in this case and issues are harder to detect, since
this is package-specific code possibly running as `root` in untrusted
directories.

While exploring all embedded scripts found in logrotate drop-in configuration
files in openSUSE Tumbleweed we found out that in most cases such scripts are
only used to restart a systemd service or to send a signal to a daemon running
in the background. In a few cases the scripts have been problematic, as is
described in the following sub-sections.

### python-mailman (CVE-2025-53882)

In the [python-mailman][bugzilla:logrotate:mailman] package we found two
problems in [the embedded shell script][logrotate:mailman:config], which consisted
of these two lines:

```sh
/bin/kill -HUP $(</run/mailman/master.pid) 2>/dev/null || true
@BINDIR@/mailman reopen >/dev/null 2>&1 || true
```

For one, `SIGHUP` was sent to a PID obtained from `/run/mailman/master.pid`,
which is under the control of the `mailman` service user. This would allow a
compromised `mailman` user to direct `SIGHUP` to arbitrary processes in the
system.

Furthermore the command line `/usr/bin/mailman reopen` was executed with full
root privileges, which results in output like this:

    Usage: mailman [OPTIONS] COMMAND [ARGS]...
    Try 'mailman -h' for help.
    
    Error: If you are sure you want to run as root, specify --run-as-root.

This shows that the intended reopen of logfiles doesn't work as expected.
Otherwise one might think that nothing harmful happens. This is not true,
however. This invocation of `mailman` still leads to the full initialization
of the logging system and all the logfiles in <br/>`/var/log/mailman` are
created, if not already existing, with full root privileges. Symbolic links
are followed, if necessary.

This means a compromised `mailman` user can e.g. create a symlink
`/var/log/mailman/bounce.log` → `/etc/evil-file`. After the logrotate script
runs `/etc/evil-file` will be created. The files will be created with
root-ownership, so the only impact of this should be the creation of new empty
files owned by `root` in the system. This can still have security impact when
such empty state files control sensitive settings of other programs in the
system.

To fix this issue the sending of `SIGHUP` was completely dropped and the
reopen command is invoked via `sudo` as the dedicated `mailman` service user
and group. The logrotate drop-in configuration file containing the
problematic script is specific to openSUSE, thus we assigned a CVE for this
issue to make our users aware.

### sssd

The sssd package has [a very similar issue][bugzilla:logrotate:sssd] in its
[example logrotate configuration][logrotate:sssd:config], where a `SIGHUP`
signal is sent to a PID controlled by the `sssd` service user:

```sh
/bin/kill -HUP `cat @pidpath@/sssd.pid 2>/dev/null` 2> /dev/null || true
```

We created a public [upstream GitHub issue][logrotate:sssd:issue] to make the
developers aware of the problem. There is no fix available yet for the issue.

<a name="section-icinga-cve"/>

### Icinga2 (CVE-2025-61909)

In our icinga2 package there is yet another instance of sending a signal
(`SIGUSR1`) to a PID controlled by the unprivileged `icinga` service user:

```sh
/bin/kill -USR1 $(cat /run/icinga2/icinga2.pid 2> /dev/null) 2>/dev/null || true
```

We wanted to change that into a `systemctl reload icinga2.service` instead,
only to find out that upstream's reload script is [affected by the same
issue][logrotate:icinga:issue]. We reported the problem to upstream and they
[fixed it and assigned a CVE][logrotate:icinga:announcement] by now.

### exim (CVE-2025-53881)

Our exim package contained a problematic `prerotate` shell script in its
[logrotate configuration][logrotate:exim:config] which allows [escalation from
the `mail` user/group to `root`][bugzilla:logrotate:exim], when it runs. The
shell script is rather complex and tries to generate a statistics report
creating temporary files as `root` in the log directory owned by the
unprivileged `mail` user.

To fix this, the script has been adjusted to use a private temporary directory
for the report, instead. An update containing the fix will soon be available
for openSUSE Tumbleweed.

This again is an openSUSE specific logrotate configuration file, thus we
assigned a CVE to mark the problem.

Possible Improvements in logrotate
----------------------------------

The issues we uncovered show also room for improvement in logrotate itself to
prevent such situations in the first place. For one, the daemon could refuse
to work on directories owned by non-root users, like it does for
world-writable directories. Furthermore scripts could be executed using the
same `su <user> <group>` credentials that are used for rotating the logs.

We did not reach out to upstream about these suggestions yet, but will keep
you informed about any developments in this area.

<a name="section-gnome"/>

4) GNOME 49: D-Bus and Polkit Changes in new Major Version Release
==================================================================

GNOME 49 was recently released and our GNOME maintainers asked us to look into
a number of D-Bus and Polkit changes that appeared in related packages. We
encountered nothing too exciting this time:

- [GDM][bugzilla:gnome:gdm]: Two changes appeared in GNOME's display manager:
  * Some polkit actions are now tied to the `gdm` group instead of to the `gdm`
    user. This is related to the display manager now using dynamic user
    accounts.
  * The `gdm` group is now allowed to access smart cards managed by
    `pcscd`. This is supposed to fix [a bug report][gnome:pcsc-bug] where
    smart cards could not be accessed by GDM. Why this bug never occurred
    before is not completely clear, the Polkit settings are acceptable in any
    case.
- [gnome-initial-setup][bugzilla:gnome:gis]: This package received the same
  change as GDM, Polkit actions are now tied to the `gdm` group, not the
  user.
- [gnome-remote-desktop][bugzilla:gnome:grd]: This is the same as in
  gnome-initial-setup, Polkit actions are now tied to the `gdm` group instead
  of the user.
- [mutter][bugzilla:gnome:mutter]: This part of GNOME (a Wayland compositor
  and X11 window manager) now contains a `backlight-helper`. Locally logged in
  regular users are allowed to execute this program with `root` privileges to
  control the backlight of mobile devices. We have seen this helper program
  before in the `gnome-settings-daemon` package. It is a minimal C program
  consisting of 200 lines of code and we could not find any issues in it.

<a name="section-kea"/>

5) Kea DHCP: Follow-Up Review of Network Attack Surface
=======================================================

Earlier this year we [reported a number of local security issues][blog:kea]
pertaining to the REST API in Kea DHCP. In a follow-up review we focused on
the network attack surface, which usually is the more interesting part when
dealing with a DHCP server suite. Alas, while looking at the network logic we
stumbled over [another minor local security issue][kea:umask-issue] regarding
a temporary change to the process's umask. Upstream addressed the problem in
the meantime.

Following the actual network processing logic in Kea's code base is no easy
task. The C++ coding style uses a high level of abstraction which leads to many
indirections. Untrusted data received from network peers travels far in the
code without clear logical boundaries where data is verified before further
processing takes place. The code base contains a lot of comments, which
usually is a good thing, but in this instance it felt nearly too verbose
to us, making it hard to find the relevant bits.

On the positive side of things Kea is already a matured project and there were
no easy pickings to be found. Upstream also integrated AFL fuzzing into their
testing infrastructure, which should allow them to find network security
issues proactively. Consequently we have been unable to find any security
issues in the network processing in Kea.

Kea offers advanced features like configuring custom behaviour depending on
specific DHCP header fields. This naturally comes with quite some additional
complexity. In this light we believe Kea is well suited for large
organizations, but we would recommend a simpler DHCP server implementation for
small environments where such features are not needed, to reduce attack
surface.

<a name="section-chrony"/>

6) chrony: Issues in chronyc Socket Creation
============================================

[This finding][bugzilla:chronyc] resulted from our [logrotate configuration
file][section-logrotate] investigation discussed above. chrony is the
default NTP time synchronization program used in openSUSE and a number of
other Linux distributions. It ships a logrotate drop-in configuration
file that contains this `postrotate` shell code:

```sh
postrotate
    /usr/bin/chronyc cyclelogs > /dev/null 2>&1 || true
endscript
```

`chronyc` is the client utility used to talk to the `chronyd` daemon
component. The communication mechanism used for this is a UNIX domain socket
placed in `/run/chrony/chronyd.sock`. `chronyc` is invoked as `root` in the
logrotate context above. At first we believed this should not be a problem,
since any privileged process should be allowed to talk to `chronyd`. While
looking at the `strace` output of the command line above the following system
call caught our attention, however:

```sh
chmod("/run/chrony/chronyc.6588.sock", 0666) = 0
```

The `/run/chrony` directory is owned by the `chrony` service user:

    drwxr-x--- 3 chrony chrony 100 Sep 25 09:45 .

These are the same credentials used by the `chronyd` daemon. When `root`
performs the `chmod` call above, then a compromised `chrony` service user has
an opportunity to perform a symlink attack, directing the `chmod()` operation
to arbitrary files on the system, making them world-writable, thus making
possible a `chrony` to `root` privilege escalation. A couple of years ago we
found [a somewhat similar symlink attack][chrony:pidfile-attack] in the area
of the pidfile creation performed by the daemon.

We approached upstream about the issue on July 15 by creating [a private
issue][chrony:issue] in their GitLab project. The [bugfix][chrony:bugfix]
turned out rather complex. The problem here is that the UNIX domain socket
used by chrony is datagram-oriented (`SOCK_DGRAM`). This means there is no
connection established between client and server. For the server being able to
send back data to the client, the client needs to bind its socket into the
file system as well and grant the server-side access to it. On Linux an
autobind feature exists for Unix domain sockets, which will automatically
assign an abstract address to the client socket, which is not visible in the
file system. This feature is not available on other UNIX systems, however,
that chrony also intends to support.

For these reasons the upstream approach to fix this involves the creation of
an unpredictably named sub-directory in `/run/chrony` to place the client-end
socket into. The directory is only writable for the client and the
unpredictable directory name is not known in advance, thus no symlinks can be
placed into the path anymore.

<a name="section-varlink"/>

7) pwaccessd: New Varlink Service for Reading User Account Information
======================================================================

A fellow SUSE engineer recently finished development on
[`pwaccessd`][pwaccess:github], a daemon providing user account information
via Varlink. This novel approach to providing account information allows, for
example, to grant regular users access to their own shadow entry, which would
otherwise only be accessible to `root`.

At the end of June we have been asked to [review the new
daemon][bugzilla:pwaccess] for its security. We had a couple of hardening
recommendations and found an instance of possible log spoofing, but have
otherwise been satisfied with the implementation. Bugfixes and improvements
have been incorporated and the new service is now ready to be used in
production.

8) sysextmgr: New Varlink Service for Managing systemd-sysext Images
=====================================================================

sysextmgr is [another new Varlink service][sysextmgr:github] developed by
SUSE, which this time helps with the management of systemd-sysext images on
[openSUSE MicroOS][microos]. We noticed the addition of this service to
openSUSE via our monitoring of newly added systemd services in the
distribution. While looking into the Varlink API we [discovered a number of
issues][bugzilla:sysextmgr] in the service like Denial-of-Service attack
surface and some minor symlink issues. The issues could be resolved quickly
and we are now happy with the state of the service.

<a name="section-bgp"/>

9) bash-git-prompt: Predictable Temporary File Name Offers Local Attack Surface (CVE-2025-61659)
================================================================================================

Our team is currently undertaking an effort to have a look at all kinds of
shell related drop-in code like command-specific shell completion support and
files installed into `/etc/profile.d` to manipulate the shell environment.
Any packages can install such files and they can easily lead to security
problems when things are not done right.

The amount of such files in a complete Linux distribution is huge, naturally,
thus this is a long-term task that will require time to produce a complete
list of findings. A [first finding][bugzilla:bash-git-prompt] in the
[`bash-git-prompt`][bgp:github] package already resulted from this, however.
This package installs shell code into `/etc/profile.d/bash-git-prompt.sh`
which enables an interactive Git prompt which will be displayed as soon as the
Bash shell enters a Git repository.  This prompt contains information about
the current repository, the number of modified files and other things that can
be configured by users. The prompt feature using default settings becomes
active as soon as the package is installed.

While looking into the shell code that implements all this we noticed [the use
of a predictable temporary file][bgp:code:tempfile] in
`/tmp/git-index-private$$`. `bash-git-prompt` copies the Git index file found
in the current Git repository to this location. It turns out that this copy
operation happens every time the interactive shell user enters a new command
while being located in a Git repository. The temporary file is soon deleted
again when the Git bash prompt has been fully rendered by the program.

Since an interactive bash shell session is a long-lived process it is rather
simple for other users in the system to pre-create the temporary file in
question and cause all kinds of issues:

- Denial-of-Service: by blocking the path, the Git prompt setup will fail to
  complete and the prompt will be broken. By placing a FIFO named pipe in this
  location the victim's shell will even lock up completely.
- information leak: the copy of the Git index is made using the umask of
  the shell. When the default umask `022` is used, then the copy of the Git
  index becomes world-readable in `/tmp`. If the victim's Git repository
  contains non-public data then part of that data (e.g. file names of pending
  change sets) leaks to other users in the system.
- integrity violation: when a local attacker places crafted data in the
  location of the temporary file and denies write access, then
  `bash-git-prompt` fails to write the desired Git index data to this
  location, but will not stop execution despite this error. The crafted Git
  index data will be fed to various invocations of the `git` command line
  utility, possibly leading to a crafted bash prompt or even leading to some
  forms of code execution. To determine the full extent of this, a low level
  analysis of the handling of the binary Git index format would be necessary.

The problem was discovered independently a while ago already, which is why
there exists [a public GitHub issue][bgp:github:issue] for it. An upstream
author attempted to fix the issue, but rolled back the changes due to a
regression and nothing happened since. The issue was introduced via [commit
38f7dbc0bb8][bgp:commit:introduction] in `bash-git-prompt` version 2.6.1. We
added [a simple patch][bgp:obs:patch] to our packaging of `bash-git-prompt`
which should address all issues for users of openSUSE.

At the end of September we requested a CVE from Mitre to track this issue and
they assigned CVE-2025-61659.

<a name="section-powerbuttond"/>

10) steam-powerbuttond: Insecure Operation in Home Directories
==============================================================

Our team's monitoring of newly added systemd services in openSUSE led us to
[steam-powerbuttond][powerbuttond:github]. It derives from a script found on
the SteamOS Linux distribution for use on Steam Deck gaming devices.

The main component of this package is a Python script which runs as a systemd
service with full root privileges. This script contains [various security
issues][bugzilla:powerbuttond]. During startup the script attempts to
determine who "the first user" in the system is, by parsing the output of `who
| head -1`. This user's home directory is then used for operations later on,
when a power button press event is detected. After processing the event, the
file <br/>`/home/{user}/.steam/steam.pid` is read and used for accessing
`/proc/{pid}/cmdline`.

This logic leads to various possible issues, ranging from the the wrong user
being selected initially, to denial-of-service when unexpected file content is
placed in the unprivileged user's home directory. We contacted one of the
original upstream authors about this and offered coordinated disclosure. It
turned out that the project is not supposed to be used anymore, however, and
as a result the GitHub repository has been archived by the maintainer.

The openSUSE `steam-powerbuttond` package is now waiting to be replaced by a
new script that is supposed to be found in SteamOS.

11) Conclusion
==============

This edition of the SUSE security team spotlight was quite packed with topics.
We hope this can give you an insight into all the different kind of activities
we end up in on our mission to improve the security of open source software, in
the Linux ecosystem in general and openSUSE in particular. We're looking
forward to the next issue of the spotlight series in about three months from
now.

Change History
==============

|2025-10-23|Updated the logrotate [Icinga2][section-icinga-cve] sub-section to include the upstream CVE and a link to the upstream security advisory.|

[bugzilla:bash-git-prompt]: https://bugzilla.suse.com/show_bug.cgi?id=1247489
[bugzilla:chronyc]: https://bugzilla.suse.com/show_bug.cgi?id=1246544
[bugzilla:gnome:gdm]: https://bugzilla.suse.com/show_bug.cgi?id=1248881
[bugzilla:gnome:gis]: https://bugzilla.suse.com/show_bug.cgi?id=1249067
[bugzilla:gnome:grd]: https://bugzilla.suse.com/show_bug.cgi?id=1248979
[bugzilla:gnome:mutter]: https://bugzilla.suse.com/show_bug.cgi?id=1248851
[bugzilla:kea]: https://bugzilla.suse.com/show_bug.cgi?id=1234265
[bugzilla:logrotate:analysis]: https://bugzilla.suse.com/show_bug.cgi?id=1245961#c2
[bugzilla:logrotate:exim]: https://bugzilla.suse.com/show_bug.cgi?id=1246457
[bugzilla:logrotate:mailman]: https://bugzilla.suse.com/show_bug.cgi?id=1246467
[bugzilla:logrotate:main]: https://bugzilla.suse.com/show_bug.cgi?id=1245961
[bugzilla:logrotate:sssd]: https://bugzilla.suse.com/show_bug.cgi?id=1246537
[bugzilla:powerbuttond]: https://bugzilla.suse.com/show_bug.cgi?id=1249602
[bugzilla:pwaccess]: https://bugzilla.suse.com/show_bug.cgi?id=1245261
[bugzilla:sysextmgr]: https://bugzilla.suse.com/show_bug.cgi?id=1247107
[bugzilla:systemd]: https://bugzilla.suse.com/show_bug.cgi?id=1247556
[systemd:code:register-method]: https://github.com/systemd/systemd/blob/v258-rc4/src/machine/machined-dbus.c#L969
[systemd:commit:register-action]: https://github.com/systemd/systemd/commit/adaff8eb35d
[systemd:commit:register-auth-admin]: https://github.com/systemd/systemd/commit/65badde82
[systemd:commit:register-verify-pid]: https://github.com/systemd/systemd/commit/119d332d9
[systemd:follow-up-fix]: https://github.com/systemd/systemd/pull/39102
[man:user_namespaces]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
[logrotate:code:config-syntax]: https://github.com/logrotate/logrotate/blob/4c4023aef1824c03e5be0ffee503fef6a6c2668d/logrotate.8.in#L253
[logrotate:code:writable-check]: https://github.com/logrotate/logrotate/blob/4c4023aef1824c03e5be0ffee503fef6a6c2668d/logrotate.c#L1448
[logrotate:exim:config]: https://build.opensuse.org/projects/openSUSE:Factory/packages/exim/files/exim.logrotate?expand=1
[logrotate:icinga:issue]: https://github.com/Icinga/icinga2/issues/10527
[logrotate:icinga:announcement]: https://icinga.com/blog/releasing-icinga-2-v2-15-1-2-14-7-and-2-13-13-and-icinga-db-web-v1-2-3-and-1-1-4
[logrotate:mailman:config]: https://build.opensuse.org/projects/openSUSE:Factory/packages/python-mailman/files/mailman.logrotate?expand=1&rev=f52eeb756d292f335b10d5e8a2ed822e
[logrotate:munge:pr]: https://github.com/dun/munge/pull/157
[logrotate:sssd:config]: https://github.com/SSSD/sssd/blob/2d6ef923e1309ca3bef2b6093b91f736c81d608b/src/examples/logrotate.in
[logrotate:sssd:issue]: https://github.com/SSSD/sssd/issues/8041
[rpmlint:code:logrotate-check]: https://github.com/rpm-software-management/rpmlint/blob/1bb96561b5b715ee1e32b4b3949fd8c8d94940d9/rpmlint/checks/LogrotateCheck.py#L35
[gnome:pcsc-bug]: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1061444#15
[kea:umask-issue]: https://gitlab.isc.org/isc-projects/kea/-/issues/4037
[blog:kea]: /2025/05/28/kea-dhcp-security-issues.html
[chrony:bugfix]: https://gitlab.com/chrony/chrony/-/commit/90d808ed28977ff79aaf3913ba477466c19d4695
[chrony:issue]: https://gitlab.com/chrony/chrony/-/issues/28
[chrony:pidfile-attack]: https://www.openwall.com/lists/oss-security/2020/08/21/1
[pwaccess:github]: https://github.com/thkukuk/pwaccess
[sysextmgr:github]: https://github.com/thkukuk/sysextmgr
[bgp:code:tempfile]: https://github.com/magicmonty/bash-git-prompt/blob/2.7.1/gitprompt.sh#L469
[bgp:github]: https://github.com/magicmonty/bash-git-prompt
[bgp:github:issue]: https://github.com/magicmonty/bash-git-prompt/issues/561
[bgp:obs:patch]: https://build.opensuse.org/projects/devel:tools:scm/packages/bash-git-prompt/files/use-safe-tempfile.diff?expand=1
[bgp:commit:introduction]: https://github.com/magicmonty/bash-git-prompt/commit/38f7dbc0bb891719c2773714c170fe8fea035d95
[powerbuttond:github]: https://github.com/ShadowBlip/steam-powerbuttond
[bot:github]: https://github.com/mgerstner/buffer-overflow-training
[bot:release]: https://github.com/mgerstner/buffer-overflow-training/releases/tag/v1.2
[section-bgp]: #section-bgp
[section-chrony]: #section-chrony
[section-gnome]: #section-gnome
[section-kea]: #section-kea
[section-logrotate]: #section-logrotate
[section-powerbuttond]: #section-powerbuttond
[section-systemd]: #section-systemd
[section-training]: #section-training
[section-varlink]: #section-varlink
[section-icinga-cve]: #section-icinga-cve
[microos]: https://microos.opensuse.org
