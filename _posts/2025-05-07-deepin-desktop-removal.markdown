---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "Removal of Deepin Desktop from openSUSE due to Packaging Policy Violation"
date:   2025-05-07
tags:   Polkit D-Bus Deepin
excerpt: "At the beginning of this year we noticed that the Deepin Desktop as
it is currently packaged in openSUSE relies on a packaging policy violation to
bypass SUSE security team review restrictions. With a long history of code
reviews for Deepin components dating back to 2017, this marks a turning point
for us that leads to the removal of the Deepin Desktop from openSUSE for the
time being."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [Deepin desktop environment][deepin:website] (DDE) is part of the Deepin
Linux distribution. It focuses on usability, a polished graphical presentation
and support for the Chinese language. It is also available on a number of
other Linux distributions, openSUSE among them.

Recently we noticed a policy violation in the packaging of the Deepin desktop
environment in openSUSE. To get around security review requirements, our
Deepin community packager implemented a workaround which bypasses the regular
RPM packaging mechanisms to install restricted assets.

As a result of this violation, and in the light of the difficult history we
have with Deepin code reviews, we will be removing the Deepin Desktop packages
from openSUSE distributions for the time being.

In this blog post we will look at the exact nature of the policy violation,
the review history of Deepin components in openSUSE and the conclusions we
draw from all of this. Finally, we will give an outlook on how this situation
could be resolved, and how users of openSUSE can continue to opt-in to use
Deepin in the future.

2) Bypass of the openSUSE Packaging Policy via a "License Agreement" Dialog
===========================================================================

<a name="section-2-policy-bypass"/>

The SUSE security team enforces a number of [packaging
restrictions][opensuse:security-guidelines] for openSUSE distributions. Among
others, the installation of D-Bus system service configuration files and Polkit
policies requires a review by us. When we are satisfied with a package's
security, then we whitelist the respective components. From there on, the
package can be submitted to the `openSUSE:Factory` project in the [Open Build
Service][opensuse:build-service], which is the base for the openSUSE
Tumbleweed rolling release distribution.

For a large software suite like Deepin, which contains a significant number of
D-Bus services, this can be a difficult initial hurdle to overcome. We have
been in contact with the openSUSE Deepin packager ever since 2017, and have
whitelisted various Deepin D-Bus components in the meantime. A number of
remaining Deepin review bugs have seen little progress in recent years,
however, because the issues we pointed out have not been addressed properly.

Perhaps tired of waiting, the packager decided to try a different avenue to
get the remaining Deepin components into openSUSE skirting the review
requirements. In January 2025, during routine reviews, we stumbled upon
the [`deepin-feature-enable`][build-service:deepin-feature-enable] package,
which was introduced [on
2021-04-27][build-service:deepin-feature-enable-intro-req] without consulting
us or even informing us. This innocently named package implements a "license
agreement dialog" which basically explains that the SUSE security team has
doubts about the security of Deepin, but to properly use Deepin, certain
components need to be installed anyway. Thus, if the user does not care about
security then "the license" should be accepted. If the user accepts, the
missing D-Bus configuration files and Polkit policies are automatically
extracted into system directories from tarballs found in the
`deepin-daemon-dbus` and `deepin-daemon-polkit` packages. The license text
also contains a hint suggesting to manually install the
`deepin-file-manager-dbus` and `deepin-file-manager-polkit` packages and run a
script to sideload further configuration files that are needed for the Deepin
file manager D-Bus component to work.

<figure>
  <img src="/assets/images/deepin-feature-enable.png" alt="The 'license agreement' dialog presented by deepin-feature-enable"/>
  <figcaption>The "license agreement" dialog presented by deepin-feature-enable.</figcaption>
</figure>

For end users, this effectively means that typing "y" once during the
installation of the Deepin pattern is enough to opt in to activating
components with questionable security which have not been accepted by the SUSE
security team.

Given the number of reviews that happened over many years, with some decline
in frequency and activity, we had wrongly assumed that by now the bulk of
Deepin D-Bus components had managed to enter `openSUSE:Factory` after being
whitelisted by us (apart from some optional utility packages). Instead we had
to find out that core components, which are found in the `deepin-daemon`
package, had never been submitted for our review, but had been smuggled into
openSUSE.

A review bug has been running for Deepin file manager since 2019 without the
package reaching a satisfying state. Offering users the ability to run a
script to activate the problematic components is less critical than
automatically doing so via a crafted "license dialog", but is still an unclean
and questionable approach.

3) Review History of Deepin Components
======================================

This section gives an overview of the long history of review requests for
Deepin components in openSUSE. This should give an insight into the effort
that already went into checking Deepin's security, and the difficulties that
we often encountered in attempting to arrive at a good solution.

2017-12-04: deepin-api: Initial Review of D-Bus Service and Polkit Actions
--------------------------------------------------------------------------

This was the [first review request][bugzilla:deepin-api] we received for
Deepin. It reached us during a time of restructuring in our team, which caused
a delay of about half a year before we found time to work on it. `deepin-api`
contained a D-Bus service which ran as `root`, offering a miscellaneous
collection of D-Bus methods on the D-Bus system bus e.g. for playing audio
files.

We found [various issues][oss-security:various-deepin-issues] in the D-Bus
method implementations. Most prominently, any user in the system was allowed to
run various commands like `rfkill` with arbitrary parameters as `root`. Polkit
authentication was only implemented in some of the D-Bus methods, while others
merely had a `TODO:` marker to add authentication. Furthermore, the Polkit
authentication that was implemented for some methods was subject to a race
condition allowing authentication bypass.

The Deepin packager involved upstream and we started a discussion in the
review bug about how to address the issues. A first attempt to fix them
produced incomplete results. We asked for a formal security contact at the
Deepin project to offer coordinated disclosure, since we found problems in
other Deepin components as well in the meantime. We did not receive an answer
to this, though.

After this initial activity there was no more progress for six months, which
is why we closed the bug due to inactivity in December 2019. In April 2021
the Deepin packager reopened this bug assigning it to an upstream developer.
In July 2021 we were finally pointed to the proper fixes for the issues, and
we granted a whitelisting for this specific Deepin component in August 2021.

2019-03-25: deepin-clone: Polkit Action com.deepin.pkexec.deepin-clone
----------------------------------------------------------------------

`deepin-clone` is a backup utility for the Deepin desktop. In March 2019 we
received a [review request for a Polkit action][bugzilla:deepin-clone]
contained in the package. We found a large number of issues in the
implementation of this Polkit action, such as problematic predictable `/tmp`
file uses, a world-readable log file in a fixed path in `/tmp` and the
possibility to prevent the unmounting of temporarily mounted block devices.

We reported these issues to the packager in April 2019. In July 2019 we
were pointed to a couple of fixes, but we found that some issues had
still not been addressed and the code in general still looked unclean. The
more severe issues had been fixed at least, thus we requested CVEs for them
and [published a report][oss-security:deepin-clone] on the oss-security
mailing list.

We never heard back about the remaining concerns we had, thus the whitelisting
for this component was never granted.

2019-05-05: deepin-file-manager: D-Bus Service and Polkit Actions
-----------------------------------------------------------------

In May 2019 we received review requests for [the D-Bus
part][bugzilla:deepin-file-manager-dbus] and [the Polkit
part][bugzilla:deepin-file-manager-polkit] of the `deepin-file-manager`
package. This application is a file manager similar to Dolphin in KDE or
Nautilus in GNOME. The D-Bus service implemented in the package offers methods
to perform actions like mounting Samba network shares or managing the UNIX
group membership for user accounts in the system. This is one of the packages
for which the Deepin packager eventually implemented a whitelisting bypass, as
explained in [section 2)][section2].

After reviewing the main D-Bus service, we could not help ourselves but call
it [a security nightmare][bugzilla:deepin-file-manager-nightmare]. The
service methods were not only unauthenticated and thus accessible to
all users in the system, but the D-Bus configuration file also allowed anybody
to own the D-Bus service path on the system bus, which could lead to
impersonation of the daemon. Among other issues, the D-Bus service allowed
anybody in the system to create arbitrary new UNIX groups, add arbitrary users
to arbitrary groups, set arbitrary users' Samba passwords or overwrite almost
any file on the system by invoking `mkfs` on them as `root`, leading to
data loss and denial-of-service. The daemon did contain some Polkit
authentication code, but it was all found in unused code paths; to top it all
off, this code used the deprecated UnixProcess Polkit subject in an unsafe
way, which would make it vulnerable to race conditions allowing authentication
bypass, if it had been used.

Other Polkit policies found in the package were at least being used. One
Polkit action allowed locally logged-in users to run
`/usr/bin/usb-device-formatter` as `root` without authentication. The program
allowed to determine the existence of arbitrary files in the system, and to
unmount or format non-busy file systems. A Deepin developer joined the
discussion in the bug and again [we tried to bring to upstream's
attention][bugzilla:deepin-file-manager-culture] the overarching security
situation in Deepin, but to no avail.

A couple of bugfixes appeared for the Polkit issues but once more they were
incomplete. By December 2019 we did not receive any further responses, thus we
closed the bug without whitelisting the Polkit policies. In March 2021 the
Deepin packager reopened the bug but only pointed us to supposed fixes later
in October 2022. We moved the discussion for the Polkit parts into the other
bug for the D-Bus service component at this time.

For the D-Bus service issues we did not receive any response at all, and thus
also closed the bug in December 2019 without whitelisting the service.
Meanwhile we [published our findings][oss-security:various-deepin-issues] on
the oss-security mailing list in August 2019. In April 2021 the Deepin
packager reopened the bug, stating that upstream would be working on the
issues. In August 2021 an upstream developer was assigned to the bug, who
pointed to a partial bugfix but at the same time [stated that Deepin
developers had "different opinions"][bugzilla:deepin-file-manager-opinion]
about the reported security issues, without providing further details,
however.

In October 2022 the Deepin packager pointed us to more fixes and a new release
packaged for openSUSE. [The D-Bus interface received major
changes][bugzilla:deepin-file-manager-bugfix1] at this point. Polkit
authentication was added to some D-Bus calls now, but it again used the
deprecated UnixProcess subject in an unsafe manner, which would allow
to bypass authentication by winning a race condition. Newly added D-Bus
methods also introduced new issues, such as lacking path validation when
unmounting Samba shares. Some other methods again were left completely
unauthenticated.

In November 2023 the Deepin packager informed us about another new release
that was supposed to contain more bugfixes. [This
time][bugzilla:deepin-file-manager-bugfix2] some of the problematic D-Bus
methods disappeared completely, but some of the original issues as well as
confusing and broken Polkit authentication attempts remained.

In April 2024 the Deepin packager informed us again about a new release
containing bugfixes. Some more D-Bus methods simply disappeared, some now
actually used proper Polkit authentication based on the D-Bus system bus name.
The D-Bus service configuration still allowed any user in the system to
impersonate the service, however. Also, once more, a bunch of newly added
D-Bus methods introduced new problems. One of them, for example, allowed any
user in the system to start the Samba system daemons `nmbd` and `smbd`. A lot
of path verification issues also lingered in the new APIs.

We did not get further responses for these reviews, and the components are still
not whitelisted for openSUSE. Due to the frequent alteration of the D-Bus
methods in the Deepin file manager daemon, which led to partial bugfixes and
new issues appearing, we also refrained from assigning further CVEs for the
issues. Formally, each incomplete bugfix would need a dedicated CVE, which
would have led to a confusingly long list of CVEs revolving around the same
topic: that the Deepin file manager daemon has major security issues, some of
them likely still unfixed.

2019-05-23: deepin-anything: D-Bus Service
------------------------------------------

In May 2019 we received [a review request][bugzilla:deepin-anything] for the
`deepin-anything` package. This component acts as the back end for a desktop
search engine. Given the number of unsolved Deepin related reviews we already
faced at this time, we refused to work on this additional review until the
others would have been resolved.

Still, just from taking a quick look at the package we noticed yet another
issue: the D-Bus service configuration allowed any user in the system to
register the deepin-anything service on the system bus.

In September 2024 the Deepin packager approached us again pointing to changes
in the upstream D-Bus configuration. We did not get around to looking more
closely into it again, as we treated Deepin with lower priority at that time.

2021-02-01: dtkcommon: FileDrag D-Bus Service
---------------------------------------------

Another [review request][bugzilla:deepin-file-drag] arrived in February 2021.
This time it was about a "com.deepin.dtk.FileDrag" D-Bus interface, but the
actual implementation of this D-Bus service remained a mystery to be found. In
the end, upstream moved this interface to the D-Bus session bus in July 2021
and no whitelisting on our end was necessary after all.

Interestingly the Deepin packager [stated in the
bug][bugzilla:deepin-file-drag-upstream] that upstream finds itself unable to
respond to security bug reports, which is rather worrying for such a big
project with such an amount of security issues uncovered.

2021-02-06: deepin-system-monitor: Polkit Policy
------------------------------------------------

[This request][bugzilla:deepin-system-monitor] also arrived in February 2021.
It is one of the few Deepin reviews that was completed quite quickly and
without any major worries. The Polkit policy only allowed execution of
programs like `kill`, `renice` and `systemctl` via the `pkexec` utility. This
was only allowed with admin authentication. We whitelisted the policy in May
2021.

2023-05-13: deepin-app-services: dde-dconfig-daemon D-Bus Service
-----------------------------------------------------------------

Here we see a gap of about two years since the last Deepin review request.
This might be due to the fact that the offending `deepin-feature-enable`
package had meanwhile been introduced in May 2021 to circumvent the
whitelisting requirements. It seems the packager was still willing to involve
us in newly added Deepin packages that contained D-Bus components, however.

Sadly the [review of `deepin-app-services`][bugzilla:deepin-app-services] was
another chaotic case, one that is actually still unfinished. Even understanding
the purpose of this D-Bus service was difficult, because there wasn't really
any design documentation or purpose description of the component. From looking
at the D-Bus service implementation, we judged that it is a kind of system
wide configuration store for Deepin. Contrary to most other Deepin D-Bus
services, this one is not running as `root` but as a dedicated unprivileged
service user.

We quickly found one class of issues in this D-Bus service, namely the
crafting of relative path names by adding `../` components to various
D-Bus input parameters that are used for looking up configuration files. It
seemed the D-Bus service should only allow the lookup JSON configuration files
from trusted paths in `/usr`. By constructing relative paths, however, the
D-Bus service could be tricked into loading untrusted JSON configuration from
arbitrary locations. We were not completely sure about the impact of this,
given the abstract nature of the configuration store, but it seemed to have
security relevance, since upstream reacted to our report of the issue.

It took three passes and a year of time, however, for upstream to fix all
combinations of input parameters that would allow construction of arbitrary
paths. Upstream did not verify and solve these on their own. Instead they only
fixed the concrete issues we reported and, when we returned to the review, we
found yet more ways to escape the `/usr` path restriction.

In December 2024 we were close to whitelisting this D-Bus service. With this
much time passed, however, we thought it would be better to have a fresh look
at the current situation in the D-Bus interface. This led to [a series of new
concerns][bugzilla:deepin-app-services-revisisted], partly again in the area
of path lookup, but also due to the fact that arbitrary users could read and
store configuration for arbitrary other users. There was a lack of Polkit
authentication and user separation in the interface.

2023-05-13: deepin-api: Follow-up Review of D-Bus and Polkit
------------------------------------------------------------

In parallel to the `deepin-app-services` review described in the previous
section, we also received a [follow-up review
request][bugzilla:deepin-api-followup] for `deepin-api`. The trigger for this
review was that upstream renamed their D-Bus interface and Polkit action names
from `com.deepin.*` to `org.deepin.*`.

Luckily, this time the implementation of the D-Bus service did not change much
compared to the last time and we could not identify any new security issues.
For this reason we quickly accepted the changes and finished the review.

2024-08-29: deepin-api-proxy: D-Bus Service
-------------------------------------------

After a longer time of standstill regarding Deepin reviews, a [request for the
addition of `deepin-api-proxy`][bugzilla:deepin-api-proxy] arrived. This package
greeted us with over two dozen D-Bus configuration files. Again, upstream's
description of what the component is supposed to do was very terse. From
looking at the implementation we deduced that the proxy component seems to be
related to the renaming of interfaces described in the previous section.

We found a design flaw in the proxy's design which allowed a local root
exploit. You can find the details in a [dedicated blog
post][blog:deepin-api-proxy] we published about this not too long ago.

It is noteworthy that the communication with upstream proved very difficult
during the coordinated disclosure process we started for this
finding. We did not get timely responses, which nearly led us to a one-sided
publication of the report, until upstream finally expressed their wish to
follow coordinated disclosure at the very last moment. The actual publication
of the upstream fix was not communicated to us and neither was the bugfix
shared or discussed with us. This resulted in a follow-up security issue,
since upstream once again relied on the unsafe use of the deprecated Polkit
`UnixProcess` subject for authentication.

The review of this component was also what led us to the discovery of the
`deepin-feature-enable` whitelisting bypass, since we installed the full
Deepin desktop environment for the first time in a long time, which triggered
the "license agreement" dialog described above. After finding out about this,
we decided that it was time to reassess the overall topic of Deepin in openSUSE
based on our long-standing experiences.

2024-09-02: deepin-system-monitor: added D-Bus service and new Polkit actions
-----------------------------------------------------------------------------

The `deepin-system-monitor` received additions in the form of [a new D-Bus
service][bugzilla:deepin-system-monitor-dbus-addition] and [additional Polkit
actions][bugzilla:deepin-system-monitor-polkit-addition]. We accepted the
D-Bus service although it contained some quirks. We did not find time
to fully complete the review of the Polkit actions until now, however. A
second look that we had at the D-Bus service showed that it was once more
using the deprecated `UnixProcess` subject for Polkit authentication in an
unsafe way. This is something that we had previously overlooked.

4) Conclusions about the Future of Deepin in openSUSE
=====================================================

The experience with Deepin software and its upstream during the code reviews
that we performed has not been the best. More than once, security issues we
reported have been replaced by new security issues. Other times, upstream
did not invest the effort to fully analyze the issues we reported and fixed
them insufficiently. Generally the communication with upstream proved
difficult, maybe also due to the language barrier. While upstream stated at
times that they don't have enough resources to deal with security reports,
which is worrying enough, the design and implementation of Deepin D-Bus
components often changed radically in unrelated ways. This makes the security
assessment of Deepin components a moving target. Building trust towards Deepin
components has thus been extremely difficult over the years.

The history of Deepin code reviews clearly shows that upstream is lacking
security culture, and the same classes of security issues keep appearing.
Although we only looked at a small fraction of the code Deepin consists of, we
found security issues nearly every time we looked at one of its components.
Based on these experiences, we expect further security issues to linger in
the rest of the Deepin code that does not stick out, as the D-Bus services do
(as they run with raised privileges). Given the experiences we have gathered
with Deepin D-Bus services, we consider it likely that they break user
isolation. These components are certainly not fit for multi-user systems; even
on single user systems they will be weakening defense-in-depth significantly.

The discovery of the bypass of the security whitelistings via the
`deepin-feature-enable` package marks a turning point in our assessment of
Deepin. We don't believe that the openSUSE Deepin packager acted with bad
intent when he implemented the "license agreement" dialog to bypass our
whitelisting restrictions. The dialog itself makes the security concerns we
have transparent, so this does not happen in a sneaky way, at least not
towards users. It was not discussed with us, however, and it violates openSUSE
packaging policies. Beyond the security aspect, this also affects general
packaging quality assurance: the D-Bus configuration files and Polkit policies
installed by the `deepin-feature-enable` package are unknown to the package
manager and won't be cleaned up upon package removal, for example. Such
bypasses are not deemed acceptable by us.

The combination of these factors led us to the decision to remove the Deepin
desktop completely from openSUSE Tumbleweed and from the future Leap 16.0
release. In openSUSE Leap 15.6 we will remove the offending
`deepin-feature-enable` package only. It is a difficult decision given that
the Deepin desktop has a considerable number of users. We firmly believe the
Deepin packaging and security assessment in openSUSE needs a reboot, however,
ideally involving new people that can help get the Deepin packages into shape,
establish a relationship with Deepin upstream and keep an eye on bugfixes,
thus avoiding fruitless follow-up reviews that just waste our time. In such a
new setup we would be willing to have a look at all the sensitive Deepin
components again one by one.

This is a process that will take time, of course, and there are limits to what
we as a security team can do. Given the size of the Deepin project we would
also like to see other Linux distributions and the (security) community join
us in trying to establish a better security culture with Deepin upstream.

After publication of this report we received an email response from Deepin
upstream and they also published [a blog post][upstream:blog-post-reaction] on
the topic which contains similar content. They outline an action plan on how
to improve the security stance of Deepin and also intend to solve any unfixed
issues we reported by the end of May 2025.

5) How to Continue Using Deepin on openSUSE
===========================================

Given the security record of Deepin and the concerns expressed in the previous
section, we don't recommend to use the Deepin desktop at this time. If you
still would like to install (or continue using) the Deepin desktop on openSUSE
Tumbleweed despite the existing security concerns, then you can add the Deepin
devel project repositories to your system as follows:

```sh
# add the devel project repository for Deepin to zypper
# for other distributions you need to adjust the URL here to point to the proper repository for your case
root# zypper ar https://download.opensuse.org/repositories/X11:/Deepin:/Factory/openSUSE_Tumbleweed deepin-factory
# refresh zypper repositories
root# zypper ref
New repository or package signing key received:

  Repository:       deepin-factory
  Key Fingerprint:  EED7 FE07 D0FC DEF0 E5B4 D4A9 C0DA 4428 1599 EA1E
  Key Name:         X11:Deepin:Factory OBS Project <X11:Deepin:Factory@build.opensuse.org>
  Key Algorithm:    RSA 2048
  Key Created:      Sat Apr 29 01:27:01 2023
  Key Expires:      Mon Jul  7 01:27:01 2025
  Rpm Name:         gpg-pubkey-1599ea1e-644c5645



    Note: Signing data enables the recipient to verify that no modifications occurred after the data
    were signed. Accepting data with no, wrong or unknown signature can lead to a corrupted system
    and in extreme cases even to a system compromise.

    Note: A GPG pubkey is clearly identified by its fingerprint. Do not rely on the key\'s name. If
    you are not sure whether the presented key is authentic, ask the repository provider or check
    their web site. Many providers maintain a web page showing the fingerprints of the GPG keys they
    are using.

Do you want to reject the key, trust temporarily, or trust always? [r/t/a/?] (r):
```

The current GPG key fingerprint for this project is `EED7 FE07 D0FC DEF0 E5B4
D4A9 C0DA 4428 1599 EA1E`. You can verify it yourself by [downloading the
public key](https://download.opensuse.org/repositories/X11:/Deepin:/Factory/openSUSE_Tumbleweed/repodata/repomd.xml.key)
, importing it via `gpg --import` and checking the output of `gpg
--fingerprint` for the newly imported key.

Note that by doing this you will trust any packages originating from this devel
project, which are neither vetted by the SUSE security team nor by the openSUSE
package submission review teams.

For openSUSE Leap you need to adjust the repository URL to point to the proper
Leap repository for your system.

6) References
=============

- [Deepin desktop website][deepin:website]
- [openSUSE packaging security guidelines][opensuse:security-guidelines]
- [deepin-feature-enable package][build-service:deepin-feature-enable] (implements whitelisting bypass)

Dedicated Security Reports
--------------------------

- [blog post about deepin-api-proxy security issues][blog:deepin-api-proxy]
- [oss-security report about various Deepin issues][oss-security:various-deepin-issues]
- [oss-security report about deepin-clone issues][oss-security:deepin-clone]

Review Bugs
-----------

- [initial deepin-api review bug][bugzilla:deepin-api] (bsc#1070943)
- [follow-up deepin-api review bug][bugzilla:deepin-api-followup] (bsc#1211376)
- [deepin-clone review bug][bugzilla:deepin-clone] (bsc#1130388)
- [deepin-file-manager Polkit policy review bug][bugzilla:deepin-file-manager-polkit] (bsc#1134131)
- [deepin-file-manager D-Bus review bug][bugzilla:deepin-file-manager-dbus] (bsc#1134132)
- [deepin-anything review bug][bugzilla:deepin-anything] (bsc#1136026)
- [dtkcommon FileDrag D-Bus review bug][bugzilla:deepin-file-drag] (bsc#1181642)
- [deepin-system-monitor review bug][bugzilla:deepin-system-monitor] (bsc#1181886)
- [deepin-app-services review bug][bugzilla:deepin-app-services] (bsc#1211374)
- [deepin-api-proxy review bug][bugzilla:deepin-api-proxy] (bsc#1229918)
- [deepin-system-monitor D-Bus additions review bug][bugzilla:deepin-system-monitor-dbus-addition] (bsc#1229918)
- [deepin-system-monitor Polkit additions review bug][bugzilla:deepin-system-monitor-polkit-addition] (bsc#1233054)

Change History
==============

|2025-05-08|Minor clarifications in [Section 3) 2019-05-05: deepin-file-manager](#2019-05-05-deepin-file-manager-d-bus-service-and-polkit-actions) and [Section 3) 2023-05-13: deepin-app-services](#2023-05-13-deepin-app-services-dde-dconfig-daemon-d-bus-service). Fixed a typo in [Section 5)](#5-how-to-continue-using-deepin-on-opensuse).|
|2025-05-14|Added a note to the end of [section 4)](#4-conclusions-about-the-future-of-deepin-in-opensuse) about upstream's response to this report.|


[deepin:website]: https://www.deepin.org/en/dde/
[opensuse:security-guidelines]: https://en.opensuse.org/openSUSE:Package_security_guidelines#Audit_Bugs_for_the_Security_Team
[opensuse:build-service]: https://build.opensuse.org
[build-service:deepin-feature-enable]: https://build.opensuse.org/package/show/X11:Deepin:Factory/deepin-feature-enable
[build-service:deepin-feature-enable-intro-req]: https://build.opensuse.org/request/show/888803
[bugzilla:deepin-api]: https://bugzilla.suse.com/show_bug.cgi?id=1070943
[bugzilla:deepin-api-followup]: https://bugzilla.suse.com/show_bug.cgi?id=1211376
[bugzilla:deepin-clone]: https://bugzilla.suse.com/show_bug.cgi?id=1130388
[bugzilla:deepin-file-manager-polkit]: https://bugzilla.suse.com/show_bug.cgi?id=1134131
[bugzilla:deepin-file-manager-dbus]: https://bugzilla.suse.com/show_bug.cgi?id=1134132
[bugzilla:deepin-file-manager-nightmare]: https://bugzilla.suse.com/show_bug.cgi?id=1134132#c2
[bugzilla:deepin-file-manager-culture]: https://bugzilla.suse.com/show_bug.cgi?id=1134131#c10
[bugzilla:deepin-file-manager-opinion]: https://bugzilla.suse.com/show_bug.cgi?id=1134132#c6
[bugzilla:deepin-file-manager-bugfix1]: https://bugzilla.suse.com/show_bug.cgi?id=1134132#c11
[bugzilla:deepin-file-manager-bugfix2]: https://bugzilla.suse.com/show_bug.cgi?id=1134132#c13
[bugzilla:deepin-file-manager-bugfix3]: https://bugzilla.suse.com/show_bug.cgi?id=1134132#c18
[bugzilla:deepin-anything]: https://bugzilla.suse.com/show_bug.cgi?id=1136026
[bugzilla:deepin-file-drag]: https://bugzilla.suse.com/show_bug.cgi?id=1181642
[bugzilla:deepin-file-drag-upstream]: https://bugzilla.suse.com/show_bug.cgi?id=1181642#c2
[bugzilla:deepin-system-monitor]: https://bugzilla.suse.com/show_bug.cgi?id=1181886
[bugzilla:deepin-app-services]: https://bugzilla.suse.com/show_bug.cgi?id=1211374
[bugzilla:deepin-app-services-revisisted]: https://bugzilla.suse.com/show_bug.cgi?id=1211374#c23
[bugzilla:deepin-api-proxy]: https://bugzilla.suse.com/show_bug.cgi?id=1229918
[bugzilla:deepin-system-monitor-dbus-addition]: https://bugzilla.suse.com/show_bug.cgi?id=1229918
[bugzilla:deepin-system-monitor-polkit-addition]: https://bugzilla.suse.com/show_bug.cgi?id=1233054
[oss-security:various-deepin-issues]: https://www.openwall.com/lists/oss-security/2019/08/05/4
[oss-security:deepin-clone]: https://www.openwall.com/lists/oss-security/2019/07/04/1
[blog:deepin-api-proxy]: /2025/01/24/dde-api-proxy-privilege-escalation.html
[section2]: #section-2-policy-bypass
[upstream:blog-post-reaction]: https://bbs.deepin.org/en/post/287017
