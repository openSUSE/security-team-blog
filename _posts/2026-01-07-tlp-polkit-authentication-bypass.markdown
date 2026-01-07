---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "TLP: Polkit Authentication Bypass in Profiles Daemon in Version 1.9.0 (CVE-2025-67859)"
date:   2026-01-07
tags:   CVE D-Bus Polkit
excerpt: "TLP is a utility for saving laptop battery power when running
Linux. In version 1.9.0 of TLP a profiles daemon has been added to the
project, which provides a D-Bus interface for controlling different power
profiles. An unsafe use of the Polkit authentication API in this daemon
allows local users to bypass authorization and gain arbitrary control over
power profiles and log level settings of TLP. While looking into the new
daemon we also found a few other security issues in the area of local
Denial-of-Service.
"
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[TLP][upstream:website] is a utility for saving laptop battery power when
running Linux (note: the TLP acronym has [no special
meaning][upstream:acronym-meaning]). In version 1.9.0 of TLP a profiles daemon
similar to [GNOME's power profiles daemon][gnome-ppd] has been added to the
project, providing a D-Bus API for controlling some of TLP's settings.

Our SUSE TLP package maintainer [asked us for a review][bugzilla:review-bug]
of the changes contained in the new TLP release, leading us to discover
issues in the Polkit authentication logic used in TLP's profiles daemon, which
allow a complete authentication bypass. While looking into the daemon we also
found some additional security problems in the area of local Denial-of-Service
(DoS).

We reported the issues to upstream in December and performed coordinated
disclosure. [TLP release 1.9.1][upstream:release-1-9-1] contains fixes
for the issues described below. This report is based on [TLP
1.9.0][upstream:release-1-9-0].

The [next section][section:overview] provides a quick overview of the TLP
power daemon. [Section 3][section:issues] discusses the security issues we
discovered in detail. [Section 4][section:cves] looks into the CVEs we
assigned. [Section 5][section:disclosure] provides a summary of the
coordinated disclosure process we followed for these findings.

{: #section-overview}
2) Overview of the TLP Daemon
=============================

The new TLP power daemon is implemented in [a Python script of moderate
size][code:daemon]. The daemon runs with full root privileges and accepts
D-Bus client connections from arbitrary users. For authorization of clients a
[Polkit policy][code:polkit-policy] defines a couple of actions which are
checked in the daemon's [`_check_polkit_auth() function`][code:polkit-check].
Some of these actions are allowed for local users in an active session without
providing further credentials, others require admin credentials.

{: #section-issues}
3) Security Issues
==================

{: #subsection-polkit-bypass}
3.1 Polkit Authorization Check can be Bypassed
----------------------------------------------

The [`check_polkit_auth()` function][code:polkit-check] relies on Polkit's
"unix-process" subject in an unsafe way. The function obtains the caller's PID
and passes this information to the Polkit daemon for authorization, which is
inherently subject to a race condition: at the time the Polkit daemon looks up
the provided PID, the process can already have been replaced by a different
one with higher privileges than the D-Bus client actually has.

As a result of this, the Polkit authorization check in the TLP power daemon
can be bypassed by local users, allowing them to arbitrarily control the power
profile in use as well as the daemon's log settings.

This is a well-known issue when using the "unix-process" Polkit subject which
was assigned [CVE-2013-4288][cve:polkit-race] in the past. For this reason the
subject has been marked as deprecated in Polkit. The "unix-process" subject
[is seeing new use][commit:polkit-pidfd-support] these days, however, when
combined with the use of Linux PID file descriptors, which are not affected by
the race condition.

### Upstream Bugfix

We suggested to upstream to switch to Polkit's D-Bus "system bus name" subject
instead, which is a robust way to authenticate D-Bus clients based on the UNIX
domain socket the client uses to connect to the bus. This is what upstream did
in commit [08aa9cd][commit:polkit-bugfix].

{: #subsection-predictable-cookies}
3.2 Predictable Cookie Values in HoldProfile Method Allow to Release Holds
--------------------------------------------------------------------------

The D-Bus methods "HoldProfile" and "ReleaseProfile" can be used by locally
logged-in users without admin authentication and allow to establish a
"profile hold", preventing the profile from being automatically switched until
it is released again.

The "HoldProfile" method returns a cookie value to the caller which needs to
be presented to the "ReleaseProfile" method again to release it. This
cookie value is a simple integer which starts counting at zero and [is
incremented][code:cookie-increment] for each call to "HoldProfile". This makes
the cookie value predictable and allows other, unrelated users or applications
to release an active profile hold by trying to guess the cookie value in use.

### Upstream Bugfix

We suggested to upstream to make the cookie value unpredictable by generating
a random number. This is what upstream did in commit
[a88002e][commit:cookie-bugfix].

3.3 Non-Integer `cookie` Parameter in "ReleaseProfile" Method Leads to Unhandled Exception
------------------------------------------------------------------------------------------

As described in the previous section, the ["ReleaseProfile" D-Bus
method][code:release-profile] expects an integer `cookie` parameter as input.
The Python D-Bus framework used to implement the method allows clients to pass
non-integer types as `cookie`, however, which causes an exception to be thrown
in the daemon. This does not lead to the daemon exiting, however, since the
framework catches the exception.

The issue can be reproduced via the following command line:

```sh
user$ dbus-send --system --dest=org.freedesktop.UPower.PowerProfiles \
      --type=method_call --print-reply /org/freedesktop/UPower/PowerProfiles \
      org.freedesktop.UPower.PowerProfiles.ReleaseProfile string:test
Error org.freedesktop.DBus.Python.ValueError: Traceback (most recent call
last):
  File "/usr/lib/python3.13/site-packages/dbus/service.py", line 712, in
_message_cb
    retval = candidate_method(self, *args, **keywords)
  File "/usr/sbin/tlp-pd", line 223, in ReleaseProfile
    cookie = int(cookie)
ValueError: invalid literal for int() with base 10: dbus.String('test')
```

### Upstream Bugfix

While this is not strictly a security issue, we still suggested to make the
daemon more robust by actively catching type mismatch issues for the `cookie`
input parameter. Upstream followed this suggestion and implemented it in the
[same commit][commit:cookie-bugfix] as above which introduces unpredictable
cookie values.

{: #subsection-unlimited-holds}
3.4 Unlimited Number of Profile Holds Provides DoS Attack Surface
-----------------------------------------------------------------

The profile hold mechanism described in [section
3.2][subsection:predictable-cookies] allows local users in an active session
to create an unlimited number of profile holds without admin authentication.
This can lead to resource exhaustion in the TLP power daemon, since an integer
is entered into a Python dictionary along with arbitrary strings `reason` and
`application_id` which are also supplied by the client. This API thus
offers Denial-of-Service attack surface.

We found a [similar issue][upstream:gnome:dos] in [GNOME's power profile
daemon][gnome-ppd] some years ago, but GNOME upstream disagreed with our
analysis at the time, which is why SUSE distributions are applying [a custom
patch][obs:gnome-ppd-patch] to limit the number parallel profile holds.

### Upstream Bugfix

We asked upstream whether there are any valid use cases for supporting a large
number of profile holds in parallel, and it turns out that the typical use
case is only to support a single profile hold at any given time. Thus upstream
agreed to restrict the number of profile holds to a maximum of 16, which is
implemented in [commit 6a637c9][commit:hold-limit].

{: #section-cves}
4) CVE Assignment
=================

We assigned CVE-2025-67859 to track [issue
3.1 (Polkit authentication bypass)][subsection:polkit-bypass]. Issues [3.2
(predictable cookie values)][subsection:predictable-cookies] and [3.4
(unlimited number of profile holds)][subsection:unlimited-holds] would
formally also justify CVE assignments; their severity is low, however, and we
agreed with upstream to focus on the main aspect of the Polkit authentication
bypass.

{: #section-disclosure}
5) Coordinated Disclosure
=========================

We reached out to the upstream author on December 16 with details about the
issues and offered coordinated disclosure. Upstream confirmed the issues and
accepted coordinated disclosure. We discussed patches and further details over
the course of the following two weeks. Due to the approaching Christmas
holiday season we decided to set the general publication date to January 7.

We want to express our thanks to the TLP upstream author for the smooth
cooperation in handling these issues.

6) Timeline
============

|2025-12-16|We reached out to the upstream developer by email providing a detailed report and offered coordinated disclosure.|
|2025-12-17|We received a reply discussing details of the report. Coordinated disclosure was established with a preliminary publication date set to 2026-01-27.|
|2025-12-20|We received a set of patches from upstream for review. 2026-01-07 was suggested as new publication date.|
|2025-12-23|We provided positive feedback on the patches and agreed to the new publication date. We also pointed out the additional problem of the unlimited number of profile holds ([issue 3.4][subsection:unlimited-holds]).|
|2025-12-25|We received a follow-up patch from upstream limiting the number of profile holds.|
|2025-12-29|We reviewed the follow-up patch and provided positive feedback to upstream.|
|2025-01-07|Upstream published [bugfix release 1.9.1][upstream:release-1-9-1] as planned.|
|2025-01-07|Publication of this report.|

7) References
==============

- [TLP Website][upstream:website]
- [TLP GitHub project][upstream:github]
- [TLP Bugfix Release 1.9.1][upstream:release-1-9-1]
- [openSUSE Bugzilla review bug for TLP 1.9.1][bugzilla:review-bug]

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1254768
[code:cookie-increment]: https://github.com/linrunner/TLP/blob/1.9.0/tlp-pd.in#L187
[code:daemon]: https://github.com/linrunner/TLP/blob/1.9.0/tlp-pd.in
[code:hold-profile]: https://github.com/linrunner/TLP/blob/1.9.0/tlp-pd.in#L164
[code:polkit-check]: https://github.com/linrunner/TLP/blob/1.9.0/tlp-pd.in#L675
[code:polkit-policy]: https://github.com/linrunner/TLP/blob/main/tlp-pd.policy
[code:release-profile]: https://github.com/linrunner/TLP/blob/1.9.0/tlp-pd.in#L223
[commit:cookie-bugfix]: https://github.com/linrunner/TLP/commit/a88002ef26f58a2caec88d09a3f70e8b5b2f8585
[commit:hold-limit]: https://github.com/linrunner/TLP/commit/6a637c9b32fbcbe5080ccd4af0d3d3ec388959c3
[commit:polkit-bugfix]: https://github.com/linrunner/TLP/commit/08aa9cdb135b3563b2fb6eb4e0ecb638df5e7c09
[commit:polkit-pidfd-support]: https://github.com/polkit-org/polkit/commit/9295e289cdb1b6cf2747ecf07054230e15edb385
[cve:polkit-race]: https://nvd.nist.gov/vuln/detail/CVE-2013-4288
[gnome-ppd]: https://gitlab.gnome.org/Infrastructure/Mirrors/lorry-mirrors/gitlab_freedesktop_org/hadess/power-profiles-daemon
[obs:gnome-ppd-patch]: https://build.opensuse.org/projects/GNOME:Next/packages/power-profiles-daemon/files/hold-profile-hardening.patch?expand=1
[section:cves]: #section-cves
[section:disclosure]: #section-disclosure
[section:issues]: #section-issues
[section:overview]: #section-overview
[subsection:predictable-cookies]: #subsection-predictable-cookies
[subsection:polkit-bypass]: #subsection-polkit-bypass
[subsection:unlimited-holds]: #subsection-unlimited-holds
[upstream:acronym-meaning]: https://linrunner.de/tlp/faq/misc.html#what-does-tlp-stand-for
[upstream:github]: https://github.com/linrunner/TLP.git
[upstream:gnome:dos]: https://gitlab.freedesktop.org/upower/power-profiles-daemon/-/issues/47#note_1088794
[upstream:release-1-9-0]: https://linrunner.de/tlp/news.html#tlp-1-9-released
[upstream:release-1-9-1]: https://github.com/linrunner/TLP/releases/tag/1.9.1
[upstream:website]: https://linrunner.de/tlp
