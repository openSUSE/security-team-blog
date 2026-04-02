---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SUSE Security Team Spotlight Winter 2025/2026"
date:   2026-04-20
tags:   spotlight
excerpt: "This is the winter 2025/2026 edition of our spotlight series. This
time we will discuss, among others, a review of the libpgpr signature parsing
library, the rtkit realtime scheduling service and an attempt at bringing
Deepin desktop components back to openSUSE."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The winter months have passed for us and as usual we want to give you an
overview of what topics our team covered in the area of code reviews during
this time. We did not publish any dedicated security reports for a while, after
we had to deal with a little burst of publications at the beginning of the
year. Still we haven't been idle during this time and looked into various
packages and components, which we will cover in this post.

The [next section][section:systemd] discusses continued review efforts
surrounding new systemd releases. [Section 3][section:snap] covers a follow-up
audit of changes in the Snap package manager. [Section 4][section:bootkitd]
looks at `bootkitd`, a D-Bus service for managing bootloader configuration.
[Section 5][section:libpgpr] deals with `libpgpr`, a signature parsing library
which was pulled out of the RPM package manager codebase. [Section
6][section:gdm] is about changes we reviewed in a new release of GNOME display
manager (GDM). [Section 7][section:rtkit] contains a review report about the
`rtkit` real-time scheduling D-Bus service. [Section 8][section:steamos]
provides an insight into efforts to package SteamOS components for openSUSE
Tumbleweed. [Section 9][section:deepin] looks into an attempt to get Deepin
desktop components back into openSUSE.

{: #section-systemd}
2) systemd v258 - v260 Continued Reviews of D-Bus and Varlink Changes
=====================================================================

We already gave an insight into our efforts of reviewing changes in systemd
v258 in [our previous spotlight post][blog:systemd258]. Meanwhile systemd
upstream has established a new release model leading to more frequent releases
and backports of new features into existing stable branches. This has caused an
increase of review requests in our team, as can be seen by the following list
of review bugs we received since the v258 version release:

- [bsc#1257388: follow-up review of backported code in systemd 258.3][bug:systemd258.3]
- [bsc#1257943: follow-up review of backported code in systemd 258.4][bug:systemd258.4]
- [bsc#1255368: review of changes introduced in systemd 259][bug:systemd259]
- [bsc#1259318: review of changes introduced in systemd 260][bug:systemd260]

The review of changes in systemd 260 has just been finished and the new
version is about to become available in openSUSE Tumbleweed soon. The
backports into stable 258 branches have been easy to review so far, since they
are mostly clean cherry-pick merges of changes reviewed by us earlier already.

So far we did not find any issues in the continued changes in systemd, but it
remains a challenging review target especially in the area of virtual machine
and container APIs, as we have explained in earlier posts on the topic.

{: #section-snap}
3) snapd: Follow-up Audit for Transparent Inclusion of Snap Systemd Services
============================================================================

After we [accepted snap][blog:snap] into openSUSE Tumbleweed a while ago we
received a [follow-up review request][bug:snapd], which revolves around a
feature to transparently make systemd services available which have been
installed via Snaps.

We have accepted the change, but asked the packagers to include a notice in
the package informing openSUSE users that systemd services installed via Snaps
are not covered by the security review processes of SUSE product security.

{: #section-bootkitd}
4) bootkitd: D-Bus Service for Manipulating Bootloader Configuration
====================================================================

[Bootkitd][github:bootkitd] is a D-Bus service for programmatically managing
bootloader configuration. We received [a review request][bug:bootkitd] for
its inclusion into openSUSE Tumbleweed. The service is implemented in the Rust
programming language and is a simple case regarding security, since it is only
accessible by `root`. Thus no privilege boundaries are crossed and privilege
escalation is not a concern.

{: #section-libpgpr}
5) libpgpr: RPM PGP Signature Parsing Library
=============================================

[`libpgpr`][github:libpgpr] is a library which has been recently separated from
the main RPM package manager codebase. Its purpose is the parsing and
verification of PGP signatures as they are found embedded in RPM files. Given
the sensitive nature of PGP cryptography and potentially crafted input data,
we have been asked [to check the security][bug:libpgpr] of this library.

The library consists of a legacy C codebase living up to the C90 standard.
The library API is not well documented and not very consistent at the moment.
At the same time the code is concerned with memory management and binary data
structure parsing of high complexity. These shortcomings notwithstanding, the
implementation seems to have matured over time and we believe there are
currently no major errors to be found when processing untrusted data.

In our opinion, the biggest danger regarding security in this codebase will
likely be future changes which might introduce regressions. Also users of the
library won't easily know what to expect of the API, since requirements are
not clearly marked (e.g. which parameters are optional, when memory ownership
transfers happen and so on).

We provided [comprehensive comments][github:libpgpr-review-comments] on the
codebase to upstream, suggesting various refactoring, improvements and test
coverage to bring the project up to a more modern standard.

{: #section-gdm}
6) GDM: Changes and Additions in Release 50
===========================================

In February our openSUSE Gnome Display Manager (GDM) maintainers started
preparing the upgrade for release 50, which was in Beta testing at the time,
but should be fully released by now. The new version triggered [a follow-up
review][bug:gdm] of D-Bus and Polkit related features in GDM.

GDM is tightly integrated with GNOME remote desktop (GRD) these days and the
changes we've seen here are related to this integration. The differences
compared to the previous version of GDM have been small in the area of D-Bus
and Polkit, though, and no problematic additional attack surface has been
added in this version.

{: #section-rtkit}
7) rtkit: D-Bus Service to Support Unprivileged Realtime Scheduling
===================================================================

The [rtkit daemon][upstream:rtkit] has been around on Linux distributions for
a long time. Its purpose it to allow unprivileged programs in the system to
make use of real-time scheduling features in a controlled fashion. Linux
offers [two real-time scheduling policies][man:sched7] `SCHED_RR` and
`SCHED_FIFO`, which perform Round-robin or First-in First-out scheduling
respectively. Rogue processes running under one of these policies can easily
lock up the complete system due to no other userspace threads being scheduled
by the kernel anymore. For this reason, only tasks holding the `CAP_SYS_NICE`
capability (usually only `root`) are allowed to assign these scheduling
settings.

This is where `rtkit` comes in: it offers a D-Bus interface to allow
unprivileged processes to enjoy real-time scheduling features while being
under supervision of the `rtkit` daemon to prevent any negative side effects.

In a recent update of `rtkit` to version 0.14, changes in its D-Bus
configuration triggered a [follow-up review][bug:rtkit] after over a decade
since our team last looked at it. `rtkit` is installed and running (or
activatable) by default on a number of Linux distributions like openSUSE,
Debian or Fedora. Due to this prevalence of `rtkit` in Linux systems, the
inherent danger of a local Denial-of-Service and in light of the amount of
time passed since the last full review, we thought it wise to have a fresh look
at the service's implementation.

The `rtkit` D-Bus configuration follows a bit of an unusual approach by
maintaining [a deny list][code:rtkit:dbus-config] of methods which may not be
invoked by non-root users. This is not ideal, since additional methods will
automatically be accessible to all users in the system, should a developer
forget to update the deny list. At the moment no problems exist in this area,
however.

The blacklisted D-Bus methods which are only accessible to `root` affect the
global state of the daemon. The remaining D-Bus methods are used to request
real-time scheduling for caller-owned processes. These methods are
additionally protected by Polkit authentication; the related Polkit actions
are set to `yes` for local users in an active session, meaning that local
interactive users can invoke them without authentication.

The [implementation of Polkit authentication][code:rtkit:polkit] relies on
rather complex custom code based on the "unix-process" Polkit authentication
subject. This subject is often affected by race conditions and the D-Bus
"system-bus-name" subject should rather be used. In this case the use of
"unix-process" is acceptable, since the request includes not only the client's
PID but also its process start time and UID, which is retrieved from the UNIX
domain socket D-Bus connection. Thus there should be no way that race
conditions can be exploited in a way that the client is mistaken for `root`,
for example.

The actual application of real-time scheduling to a client's target
process is highly affected by race conditions, due to the retrieval of data
from `/proc/<pid>` and the fact that processes can disappear and/or be
repurposed at any time. The developers are obviously aware of the potential
issues, since they verify the target process's properties [before and after
changing its scheduling properties][code:rtkit:set-realtime]. Such detection
of a race condition after the fact is problematic when the risk is a lockup of
the whole system.

Due to this, the daemon also maintains [a watchdog and a canary
thread][code:rtkit:watchdog] to counteract any unexpected effects of
unprivileged real-time scheduling. The watchdog runs at the highest real-time
scheduling priority and periodically monitors whether the canary thread, which
is running with low scheduling priority, is still being scheduled. If a stall
is detected, then the watchdog thread removes the real-time scheduling
settings from all registered client tasks to recover the system. Additionally
the daemon monitors the amount of requests individual users are sending,
and blocks them if a threshold is exceeded.

It is clear that the implementation of this service is confronted with various
uncertainties and it tries to make up for them. The overall result is not
ideal but should be good enough to prevent major security issues. An
improvement to the design could be to obtain a directory file descriptor for
`/proc/<pid>` of the target process, verify the process's credentials and
further on only use the directory file descriptor anymore for accessing
process data. Explicit PID file descriptors might also help in some other
spots these days (they can also be used for authentication with Polkit now,
for example).

{: #section-steamos}
8) SteamOS Package Additions
============================

There is continued effort by community packagers to bring SteamOS-related
components to openSUSE. We already covered [one of these
components][blog:steam-powerbutton] in one of last year's spotlight posts.
This winter we received three additional review requests in this area.
Packaging these components is often difficult, because the programs use
fixed non-standard paths and approaches that don't fit well into a
general-purpose Linux distribution. We will look into the individual packages
in the following sub-sections.

jupiter-fan-control
-------------------

This [review][bug:steam:fan-control] is about a fan control daemon which
regulates the speed of the Steam Deck fan. The daemon itself is acceptable, it
mostly deals with hardware information and controls found in `/sys` and
therefore it crosses no security boundaries. It also creates a world-readable
logfile in `/var/log`, which only contains fan data, however, thus not
resulting in a relevant information leak towards unprivileged users.

A Polkit action allows to start and stop the daemon by providing the
administrator password, which is also fine. A wrapper script which performs
these start/stop actions is placed into
`/usr/bin/steamos-polkit-helpers/jupiter-fan-control`, which is a non-standard
location, but according to the packager is hard-coded into SteamOS components
and cannot be changed.

gamescope-session-steam-factory-reset
-------------------------------------

[This review][bug:steam:factory-reset] is concerned with a set of scripts
which allow to perform a factory reset operation on SteamOS. On openSUSE there
is nothing sensible that can be done in terms of a factory reset, thus the
packager added scripts that are in effect no-ops. Still these scripts were
supposed to be invoked with root privileges via Polkit authentication.
After a longer discussion with the maintainer we decided to take a different
approach that does not require to run dummy scripts with root privileges, but
still allows system integrators to hook into the process and change the
behaviour.

jupiter-hw-support
------------------

[The third review][bug:steam:hw-support] is concerned with a bunch of SteamOS
scripts that automatically perform actions like mounting removable devices
without requiring authentication, expecting a single "deck" interactive user
in the system. The community packager discussed some aspects of these
privileged operations with us and how to best integrate them into openSUSE.
The effort is still ongoing.

{: #section-deepin}
9) Revisit of Deepin Desktop D-Bus Services after Removal from openSUSE
========================================================================

A year ago we announced [the removal of Deepin desktop
components][blog:deepin] from openSUSE because of policy violations and bad
security. Deepin upstream promised to improve the problematic components and
we offered to have a fresh look at things when they would have something new
to show. As a result [a follow-up review bug][bug:deepin:main] was created in
which the Deepin package maintainer claimed that all reported security issues
were fixed by upstream. The following sections discuss two of the D-Bus
components we revisited in this context.

Backlight Helper
----------------

A small D-Bus helper for [controlling laptop backlight][bug:deepin:backlight]
seemed like a promising start; the code is clean and conservative. It is
lacking Polkit authentication, however, which means that any user in the
system can meddle with the backlight. Such settings are usually restricted to
local interactive users in an active session. We informed upstream about this
shortcoming and there is supposed to be a fix available by now, but we didn't
look into it yet.

Accounts Service
----------------

The Deepin [accounts service][bug:deepin:accounts1] offers a larger D-Bus
interface for managing user accounts in the system. We looked into version
6.1.66 of the project. Unfortunately we quickly discovered new security issues
in this component:

- [the `CreateGuestUser()`][code:deepin:create-guest-user] D-Bus method, which
  requires admin authentication, creates a user account with an empty password
  and a home directory in a random location in `/tmp`. The creation of this
  directory is affected by a race condition, which could allow other users in
  the system to pre-create the directory. A home directory in `/tmp` is highly
  unusual and empty passwords, even for guest accounts, are bad practice.
- [the `SetHomeDir()`][code:deepin:set-home-dir] D-Bus method, which requires
  only user-level self-authentication, allows to move the user's home
  directory into arbitrary new locations, even `/root`. This operation is
  performed via the command line `usermod -m -d <new-home-path> <username>`. The
  only aspect that prevents a simple local root exploit is that `usermod`
  refuses to perform the operation if the calling user still has processes
  running in the system.  How this API function could ever be used meaningfully
  for self-administration, then, is puzzling. It might be possible for an
  attacker to overcome this check, however, by quickly killing all of its
  processes just in time for the `usermod` invocation to succeed.
- [the `SetPassword()`][code:deepin:set-password] D-Bus method, again
  accessible by providing the user password, is affected by multiple issues:
  * the new user password is leaked in the process command line constructed in
    [`ModifyPasswd()`][code:deepin:modify-password].
  * the function [`removeLoginKeyring()`][code:deepin:remove-login-keyring]
    which is invoked in this context operates as `root` in the user's home
    directory, offering local Denial-of-Service attack surface.
  * [an insufficient check][code:deepin:new-caller] is made by the D-Bus
    service, which tries to verify whether the client is running a trusted
    password change application. The check is affected by a race condition and
    can be circumvented by malicious clients.
  * the function [`newPwdChangerX()`][code:deepin:new-pwd-changer] performs a
    `chown()` on the client's `.XAuthority` file placed into
    `/run/user/<uid>/.XAuthority`, which is a local root exploit attack vector.

The openSUSE Deepin packager informed us that there are also fixes for these
issues available by now, but we did not get around to verify them yet.

Summary
-------

Due to the recurring number of security issues, the amount of time
required by upstream to address them and a lack of a formal security fix
workflow in the Deepin project we stopped assigning CVEs for the issues we
find in Deepin. We don't see much value in further CVEs since the security
issues are often quickly replaced by other security issues, thus resulting
mostly in noise. Overall we don't recommend to use Deepin components until
the security culture of Deepin upstream improves.

By now we are also treating Deepin review requests with lower priority, since
the efforts which went on for years still haven't yielded acceptable results
and we would rather invest our resources into other, more promising packages.

10) Conclusion
==============

One of the fundamental goals of the SUSE Security Team is to keep a high
standard regarding software available in SUSE distributions. Not blindly
accepting new software releases is necessary to uphold this commitment, which
also means often revisiting software we already looked into before.

Keeping up with the fast pace of projects like systemd can be challenging in
this regard, but the security issues we continue to find e.g. in Deepin
software show that this work is still useful. The Spotlight series is one way
to highlight this continuous and not always necessarily glamorous work.

[blog:systemd258]: /2026/01/14/autumn-spotlight.html#section-systemd
[blog:snap]: /2026/01/14/autumn-spotlight.html#section-snapd
[blog:steam-powerbutton]: /2025/10/01/summer-spotlight.html#10-steam-powerbuttond-insecure-operation-in-home-directories
[blog:deepin]: /2025/05/07/deepin-desktop-removal.html

[bug:systemd258.3]: https://bugzilla.suse.com/show_bug.cgi?id=1257388
[bug:systemd258.4]: https://bugzilla.suse.com/show_bug.cgi?id=1257943
[bug:systemd259]: https://bugzilla.suse.com/show_bug.cgi?id=1255368
[bug:systemd260]: https://bugzilla.suse.com/show_bug.cgi?id=1259318
[bug:snapd]: https://bugzilla.suse.com/show_bug.cgi?id=1256175
[bug:bootkitd]: https://bugzilla.suse.com/show_bug.cgi?id=1256421
[bug:libpgpr]: https://bugzilla.suse.com/show_bug.cgi?id=1257996
[bug:gdm]: https://bugzilla.suse.com/show_bug.cgi?id=1258025
[bug:rtkit]: https://bugzilla.suse.com/show_bug.cgi?id=1258681
[bug:steam:factory-reset]: https://bugzilla.suse.com/show_bug.cgi?id=1257125
[bug:steam:fan-control]: https://bugzilla.suse.com/show_bug.cgi?id=1256004
[bug:steam:hw-support]: https://bugzilla.suse.com/show_bug.cgi?id=1257533
[bug:deepin:main]: https://bugzilla.suse.com/show_bug.cgi?id=1254493
[bug:deepin:accounts1]: https://bugzilla.suse.com/show_bug.cgi?id=1257142
[bug:deepin:backlight]: https://bugzilla.suse.com/show_bug.cgi?id=1257149

[section:systemd]: #section-systemd
[section:snap]: #section-snap
[section:bootkitd]: #section-bootkitd
[section:libpgpr]: #section-libpgpr
[section:gdm]: #section-gdm
[section:rtkit]: #section-rtkit
[section:steamos]: #section-steamos
[section:deepin]: #section-deepin

[github:bootkitd]: https://github.com/Nykseli/bootkitd
[github:libpgpr]: https://github.com/rpm-software-management/libpgpr
[github:libpgpr-review-comments]: https://github.com/rpm-software-management/libpgpr/pull/1/changes/0310a46f661ed9059eb0fb5ab8686ee6f761b2cc

[man:sched7]: https://man7.org/linux/man-pages/man7/sched.7.html
[upstream:rtkit]: https://gitlab.freedesktop.org/pipewire/rtkit

[code:rtkit:dbus-config]: https://gitlab.freedesktop.org/pipewire/rtkit/-/blob/v0.14/org.freedesktop.RealtimeKit1.conf?ref_type=tags#L15
[code:rtkit:polkit]: https://gitlab.freedesktop.org/pipewire/rtkit/-/blob/v0.14/rtkit-daemon.c?ref_type=tags#L1261
[code:rtkit:set-realtime]: https://gitlab.freedesktop.org/pipewire/rtkit/-/blob/v0.14/rtkit-daemon.c?ref_type=tags#L763
[code:rtkit:watchdog]: https://gitlab.freedesktop.org/pipewire/rtkit/-/blob/v0.14/rtkit-daemon.c?ref_type=tags#L1973
[code:deepin:create-guest-user]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/users/guest.go#L12
[code:deepin:set-home-dir]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/user_ifc.go#L81
[code:deepin:set-password]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/user_ifc.go#L147
[code:deepin:modify-password]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/users/prop.go#L178
[code:deepin:remove-login-keyring]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/user_chpwd_union_id.go#L690
[code:deepin:new-caller]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/user_chpwd_union_id.go#L119
[code:deepin:new-pwd-changer]: https://github.com/linuxdeepin/dde-daemon/blob/6.1.66/accounts1/user_chpwd_union_id.go#L530
