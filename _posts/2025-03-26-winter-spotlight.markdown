---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "SUSE Security Team Spotlight Winter 2024/2025"
date:   2025-03-26
tags:   spotlight
excerpt: "Welcome to the winter edition of our spotlight series. A busy winter
time has come to an end, and as usual in this post we give you an insight into
some of our review efforts during that time that would otherwise not get much
attention."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

Winter time is coming to an end (at least in the northern hemisphere, where
most of the SUSE security team members are located), and with this we want to
take a look back at what happened during the last three months in our team.
We have already posted about a number of bigger topics that kept us busy over
the winter:

- [privilege separation issues in SSSD][blog:sssd-privsep]
- [problematic return values in pam-u2f][blog:pam-u2f]
- [authentication bypass in dde-api-proxy][blog:dde-api-proxy]
- [authentication bypass in pam\_pkcs11][blog:pam-pkcs11]
- [admittance of kio-admin into openSUSE][blog:kde-admin]
- [problematic log directory permissions in Below][blog:below]

As usual in the spotlight series, in this post we want to give an insight into
some of our work beyond these reports: reviews that did not lead to significant
security findings, but still kept us busy and in some cases also led to
upstream improvements. The topics again mostly involve Polkit authentication
and D-Bus APIs, but we also looked proactively into a piece of networking
software that raised our interest.

2) Synce4l Synchronous Ethernet Daemon
======================================

Our team is monitoring changes and additions to openSUSE Tumbleweed, most
notably systemd services that newly appear in packages. The
[synce4l][upstream:synce4l] package raised our interest, because it contains a
daemon which is running with full `root` privileges and is also networked. The
package implements synchronous Ethernet, a low level protocol that basically
maintains a shared clock between multiple hosts in an Ethernet subnet.

The project is implemented in the C programming language and consists of about
7.000 lines of code. The sensitivity of C programs to memory handling issues,
the fact that the `synce4l` daemon runs as `root` and the niche topic of
synchronous Ethernet is a mixture that makes it an interesting code review
target.

We [reviewed the source code][bugzilla:synce4l] in early January and
fortunately couldn't find any issues in it. The attack surface on the network
is rather small. Even though by default there is no trust established between
participants of the protocol, there is only an integer value exchanged between
nodes. Corruption of this value cannot negatively influence a system running
`synce4l` (beyond the protocol itself, naturally). The daemon also creates a
UNIX domain socket in `/tmp`, but access to it is limited to `root`. The
project employs a good coding style and we did not have any concerns left when
we were finished with the review.

3) Fwupd 2.0 D-Bus and Polkit Changes
=====================================

In January the openSUSE maintainer for [fwupd][upstream:fwupd] packaged the
major version 2.0 update, which [required a follow-up audit][bugzilla:fwupd]
by our team. `fwupd` is part of most Linux distributions and provides
mechanisms to automatically upgrade firmware on the system. The `fwupd` daemon
runs as `root` and implements a D-Bus interface with Polkit authentication. We
have already reviewed it many times when changes to these interfaces have
occurred.

Even though this time `fwupd` has received a major version update, there have
only been moderate changes to the D-Bus and Polkit aspects of the software.
Generally, the implementation of the D-Bus interface in `fwupd` is more on the
complex side. Polkit authentication is implemented properly, but it is only
applied to a subset of the D-Bus methods offered by the daemon. This means
that one has to carefully differentiate between the methods that require
Polkit authentication, and the ones that don't require any authentication at
all. This is what we did during the review; fortunately we couldn't find any
problems with the unauthenticated methods.

One notable feature that has been added in this `fwupd` release allows it to
run its own dedicated D-Bus instance, likely for lean and mean environments or
for use in early boot scenarios, when no system D-Bus is available. When this
feature is in use then no Polkit authentication will be performed, likely
because no Polkit daemon is present either in this situation. This mode will
only be active when the environment variable `FWUPD_DBUS_SOCKET` is passed to
the daemon, however, and should not be reachable in regular installations of
`fwupd`.

There was one new Polkit action `org.freedesktop.fwupd.emulation-load`,
which was allowed for users in a local session without authentication.
The corresponding D-Bus method accepts JSON data, either directly or placed in
a compressed archive which is passed to the daemon. This is used to load
"hardware emulation data" into `fwupd`. This sounded like a strong
privilege for a regular user to have, and thus we [inquired
upstream][fwupd:emulation-load-issue] if this lax authentication setting was
actually necessary. The outcome was that we could raise the authentication
requirement to `auth_admin`, thereby improving security in `fwupd`.

4) Tuned Revisited
==================

[tuned][upstream:tuned] has seen quite a number of changes recently, which
also led to a [local root exploit finding][blog:tuned] in November. We
received [yet another review request][bugzilla:tuned] in January due to
further changes in the area of D-Bus configuration and Polkit actions.

Security-wise there was not much interesting to find in these changes. A
number of Polkit actions have been renamed, and `tuned` optionally provides a
drop-in replacement for the [UPower][upstream:upower] D-Bus interface now. We
accepted the changes without further ado.

5) iio-sensor-proxy Revisited
=============================

[iio-sensor-proxy][upstream:iio-sensor-proxy] is another package that we
already reviewed in the past but that [popped up
again][bugzilla:iio-sensor-proxy] in January due to changes in its D-Bus
configuration. The package provides a D-Bus interface for different hardware
sensors like ambient light sensor, accelerometer or proximity sensor.  During
the review we found that a newly added
`net.hadess.SensorProxy.Compass.ClaimCompass` D-Bus method was
unauthenticated, while other similar methods required Polkit authentication.

We [reported the issue privately][iio-sensor-proxy:private-issue] to upstream.
The lack of authentication was confirmed and upstream [fixed the
issue][iio-sensor-proxy:bugfix-pr]. We did not request a CVE or publish a
dedicated report about this, because the impact of the issue is assumed to be
low. Such smaller findings still show the usefulness of code reviews that can
lead to improvements in upstream code and configuration before software is
shipped to openSUSE users.

6) systemd-sysupdated D-Bus Service
===================================

In February we [received a request][bugzilla:sysupdated] to review an
experimental systemd component called `sysupdated`. When reading the [program
description][sysupdated:documentation] one could be inclined to think that
systemd is now on a quest to replace package managers. The main purpose of
this daemon is only to keep container assets and other images up-to-date,
however.

`sysupdated` comes with a larger D-Bus interface protected - in parts - by
Polkit. Some read-only properties and method calls are available without
Polkit authentication. Systemd components rely on shared code to implement
D-Bus services and Polkit authentication. Compared to the last time we had a
look into these shared routines, it felt as if the complexity increased quite
a lot in this area. You can have a look at [this Bugzilla
comment][bugzilla:sysupdated-polkit-details] to get an impression of the
complexities that are involved there these days. One reason for the increased
complexity could be the addition of the [Varlink](https://varlink.org) IPC
mechanism, which can also use Polkit for authentication.

Despite the perceived complexity in the D-Bus and Polkit handling, we couldn't
find any problematic aspects in the implementation. There was one decision to
be made about the Polkit action `org.freedesktop.sysupdate1.update`. The
authentication requirements for it are by default set to
`auth_admin:auth_admin:yes`, meaning that users in a local session can update
assets managed by `sysupdated` without authentication.  This is also
documented in the [upstream Polkit policy][sysupdated:security-warning]. This
only allows to update assets to the most recent version, not to any specific
version nor to downgrade the version. It also doesn't allow to install
any new assets. For this reason we allow updates without authentication in our
[Polkit easy profile][opensuse:polkit-configuration] while the other profiles
have been hardened to require admin authentication.

7) AppArmor aa-notify Polkit Policy
===================================

In February [a request arrived][bugzilla:aa-notify] to whitelist Polkit
actions used by the `aa-notify` helper which has been added to the AppArmor
package. This utility is a graphical program similar to
[setroubleshoot][opensuse:setroubleshoot] for SELinux, and allows to
identify AppArmor violations and modify the AppArmor profile to allow
actions that have been denied.

The two Polkit actions that needed reviewing allow to execute a Python script
found in \
`/usr/lib/python3.11/site-packages/apparmor/update_profile.py` via
`pkexec` using a specific command line parameter. This script performs the
task of actually modifying the AppArmor profile according to the provided
input files. Due to the nature of the script there is no way to execute it
safely without admin authentication. This is reflected in the Polkit action
settings, which always require `auth_admin` authorization.

The implementation of the script is a bit peculiar in some ways, and some
parts also seem incomplete. The one aspect that was important to check here
was that the script must not act in dangerous ways on the file system, e.g. by
using unsafe temporary files or by writing to locations that are under control
of unprivileged users. We could not find issues of this kind at the time we
reviewed it.

As the script can only be invoked with admin credentials and since there is no
legit use case to lower this authentication requirement, we did not dig a lot
deeper here and accepted the new Polkit policy. We want to keep an eye on
this script, however, since it has some potential to be changed in ways that
could harm the local system security.

8) Conclusion
=============

Once more, we hope that with this post we have been able to give you some
additional insights into our daily review work for openSUSE and SUSE products.
Feel free to reach out to us if you have any questions about the content
discussed in this article. We expect the spring issue of the spotlight series
to be available in about three months from now.

9) References
=============

- [synce4l review bug][bugzilla:synce4l]
- [fwupd 2.0 review bug][bugzilla:fwupd]
- [tuned review bug][bugzilla:tuned]
- [iio-sensor-proxy review bug][bugzilla:iio-sensor-proxy]
- [systemd-sysupdated review bug][bugzilla:sysupdated]
- [AppArmor aa-notify review bug][bugzilla:aa-notify]

[blog:kde-admin]: /2025/02/21/kio-admin-admittance.html
[blog:pam-pkcs11]: /2025/02/06/pam-pkcs11-pam-ignore-auth-bypass.html
[blog:dde-api-proxy]: /2025/01/24/dde-api-proxy-privilege-escalation.html
[blog:pam-u2f]: /2025/01/14/pam-u2f-ignore-returns.html
[blog:sssd-privsep]: /2024/12/19/sssd-lacking-privilege-separation.html
[blog:tuned]: /2024/11/26/tuned-instance-create.html
[blog:below]: /2025/03/12/below-world-writable-log-dir.html
[bugzilla:fwupd]: https://bugzilla.suse.com/show_bug.cgi?id=1235659
[bugzilla:synce4l]: https://bugzilla.suse.com/show_bug.cgi?id=1222237
[bugzilla:tuned]: https://bugzilla.suse.com/show_bug.cgi?id=1236029
[bugzilla:iio-sensor-proxy]: https://bugzilla.suse.com/show_bug.cgi?id=1236290
[bugzilla:sysupdated]: https://bugzilla.suse.com/show_bug.cgi?id=1237106
[bugzilla:sysupdated-polkit-details]: https://bugzilla.suse.com/show_bug.cgi?id=1237106#c9
[bugzilla:aa-notify]: https://bugzilla.suse.com/show_bug.cgi?id=1237329
[upstream:synce4l]: https://github.com/intel/synce4l
[upstream:fwupd]: https://github.com/fwupd/fwupd
[upstream:tuned]: https://tuned-project.org
[upstream:upower]: https://upower.freedesktop.org
[upstream:iio-sensor-proxy]: https://gitlab.freedesktop.org/hadess/iio-sensor-proxy/
[fwupd:emulation-load-issue]: https://github.com/fwupd/fwupd/issues/8360
[iio-sensor-proxy:private-issue]: https://gitlab.freedesktop.org/hadess/iio-sensor-proxy/-/issues/405
[iio-sensor-proxy:bugfix-pr]: https://gitlab.freedesktop.org/hadess/iio-sensor-proxy/-/merge_requests/393
[sysupdated:documentation]: https://www.freedesktop.org/software/systemd/man/latest/systemd-sysupdate.html
[sysupdated:security-warning]: https://github.com/systemd/systemd/blob/cd20d48c69f9e586de914e1facf33b11122477ae/src/sysupdate/org.freedesktop.sysupdate1.policy#L22
[opensuse:polkit-configuration]: https://en.opensuse.org/openSUSE:Security_Documentation#Configuration_of_Polkit_Settings
[opensuse:setroubleshoot]: https://manpages.opensuse.org/Tumbleweed/setroubleshoot-server/setroubleshootd.8.en.html
