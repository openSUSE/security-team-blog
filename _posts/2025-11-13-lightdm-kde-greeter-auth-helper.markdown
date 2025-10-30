---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "lightdm-kde-greeter: Privilege Escalation from lightdm Service User to root in KAuth Helper Service (CVE-2025-62876)"
date:   2025-11-13
tags:   CVE KDE D-Bus
excerpt: "lightdm-kde-greeter is a KDE-themed greeter application for the
lightdm display manager. It contains a KAuth-based D-Bus helper application
for performing privileged operations, which suffers from a `lightdm` to `root`
privilege escalation and some other shortcomings in versions up to 6.0.3. In
discussions with upstream we managed to arrive at a much improved version of
the affected code."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[lightdm-kde-greeter][upstream:greeter] is a KDE-themed greeter application
for the [lightdm display manager][upstream:lightdm]. At the beginning of
September one of our community packagers [asked us][bugzilla:review-bug] to
review a D-Bus service contained in lightdm-kde-greeter for addition to
openSUSE Tumbleweed.

In the course of the review we found a potential privilege escalation from the
`lightdm` service user to `root` which is facilitated by this D-Bus service,
among some other shortcomings in its implementation.

The [next section][section:overview] provides a general overview of the D-Bus
service.  [Section 3][section:problems] discusses the security problems in the
service's implementation. [Section 4][section:bugfix] takes a look at the
bugfix upstream arrived at.

This report is based on lightdm-kde-greeter [release
6.0.3][upstream:reviewed-version].

{: #section-overview}
2) Overview of the D-Bus Helper
===============================

lightdm-kde-greeter includes a D-Bus service which enables regular users to
configure custom themes to be used by the greeter application. The D-Bus
service is implemented as a [KDE KAuth helper service][blog:kauth], running
with full root privileges.

The helper implements a [single API method][code:helper], protected by
Polkit action `org.kde.kcontrol.kcmlightdm.save`, which requires
`auth_admin_keep` by default, i.e. users need to provide root credentials to
perform this action. The method takes a map of key/value pairs which allow to
fully control the contents of `lightdm.conf` and `lightdm-kde-greeter.conf`.

From a security point of view such a generic interface is sub-optimal, since
the scope of the operation is not restricted to changing theme settings, but
also allows to change all the rest of lightdm's configuration, providing less
control over who may do what in the system. From an application's point of
view this approach is understandable, however, as this makes it easy to
support any future features.

Another Polkit action `org.kde.kcontrol.kcmlightdm.savethemedetails` is
declared in [`kcm_lightdm.actions`][code:old-action], which is unused, maybe
a remnant of former versions of the project.

{: #section-problems}
3) Problems in the D-Bus Helper
===============================

The problems in the D-Bus service start in [helper.cc line
87][code:key-comment], where we can find this comment:

```
// keys starting with "copy_" are handled in a special way, in fact,
// this is an instruction to copy the file to the greeter's home
// directory, because the greeter will not be able to read the image
// from the user's home folder
```

To start with it is rather bad API design to abuse the key/value map, which is
supposed to contain configuration file entries, for carrying "secret" copy
instructions. Even worse, in the resulting copy operation three different
security contexts are mixed:

- the helper, which runs with full root privileges.
- the unprivileged D-Bus client, which specifies a path to be opened by the
  helper.
- the `lightdm` service user; the helper will copy the user-specified file
  into a directory controlled by it.

The helper performs this copy operation with full `root` privileges without
taking precautions, reading input data from one unprivileged context and
writing it into another unprivileged context. This is done naively using
the Qt framework's `QFile::copy()` and similar APIs, leading to a range of
potential local attack vectors:

- Denial-of-Service (e.g. passing a named FIFO pipe as source file path,
  causing the D-Bus helper to block indefinitely).
- information leak (e.g. passing a path to private data as source file like
  `/etc/shadow`, which will then become public in `/var/lib/lightdm`).
- creation of directories in unexpected locations (the helper attempts to
  create `/var/lib/lightdm/.../<theme>`, thus the lightdm user can place
  symlinks there which will be followed).
- overwrite of unexpected files (similar as before, symlinks can be
  placed as destination file name, which will be followed and overwritten
  with client data).

If this action would ever be set to `yes` Polkit authentication requirements,
then this would be close to a local root exploit. Even in its existing form it
allows the `lightdm` service user to escalate privileges to `root`.

Interestingly these problems are quite similar to issues in `sddm-kcm6`, which
we covered [in a previous blog post][blog:sddm].

{: #section-bugfix}
4) Upstream Bugfix
==================

We suggested the following changes to upstream to address the problems:

- the copy operation should be implemented using D-Bus file descriptor
  passing, this way opening client-controlled paths as `root` is already avoided.
- for creating the file in the target directory of `lightdm`, a privilege drop to
  the `lightdm` service user should be performed to avoid any symlink attack
  surface.

We are happy to share that the upstream maintainer of lightdm-kde-greeter
followed our suggestions closely and coordinated the changes with us before
the publication of the bugfix. With these changes, this KAuth helper is now
kind of a model implementation which can serve as a positive example for other
KDE components. Upstream also performed some general cleanup, like the removal
of the unused `savethemedetails` Polkit action from the repository.

Upstream released [version 6.0.4][upstream:fixed-version] of
lightdm-kde-greeter which contains the fixes.

5) CVE Assignment
=================

In agreement with upstream, we assigned CVE-2025-62876 to track the `lightdm`
service user to `root` privilege escalation aspect described in this report.
The severity of the issue is low, since it only affects defense-in-depth (if
the `lightdm` service user were compromised) and the problematic logic can
only be reached and exploited if triggered interactively by a privileged user.

6) Coordinated Disclosure
=========================

We reported these issues to KDE security on 2025-09-04 offering coordinated
disclosure, but we initially had difficulties setting up the process with
them. Upstream did not clearly express the desire to practice coordinated
disclosure, no (preliminary) publication date could be set and no
confirmation of the issues was received.

Things took a turn for the better when a lightdm-kde-greeter developer
contacted us directly on 2025-10-16 and the publication date and fixes were
discussed. The ensuing review process for the bugfixes was very helpful in our
opinion, leading to a major improvement of the KAuth helper implementation in
lightdm-kde-greeter.

7) Timeline
===========

|2025-09-04|We received the [review request][bugzilla:review-bug] for the lightdm-kde-greeter D-Bus service.|
|2025-09-10|We privately reported the findings to KDE security.|
|2025-09-17|We received an initial reply from KDE security stating that they would get back to us.|
|2025-09-29|We asked for at least a confirmation of the report and a rough disclosure date, but upstream was not able to provide this.|
|2025-10-01|KDE security informed us that an upstream developer planned to release fixes by mid-November.|
|2025-10-16|An upstream developer contacted us to discuss the publication date, since the bugfixes were ready.|
|2025-10-20|We asked the developer to share the bugfixes for review.|
|2025-10-21|The developer shared a patch set with us.|
|2025-10-24|We agreed on 2025-10-31 for coordinated disclosure date.|
|2025-10-28|After a couple of email exchanges discussing the patches, upstream arrived at an improved patch set. We suggested to assign a CVE for the `ligthdm` to `root` attack surface.|
|2025-10-29|We assigned CVE-2025-62876.|
|2025-11-03|We asked when the bugfix release would be published, with the disclosure date already passed.|
|2025-11-03|Upstream agreed to publish on the same day.|
|2025-11-03|Upstream released [version 6.0.4][upstream:fixed-version] containing the bugfixes. We published our [Bugzilla bug][bugzilla:review-bug] on the topic.|
|2025-11-13|Publication of this report.|

8) References
=============

- [lightdm-kde-greeter review bug in openSUSE Bugzilla][bugzilla:review-bug]
- [lightdm-kde-greeter version 6.0.4 bugfix release][upstream:fixed-version]

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1249146
[upstream:lightdm]: https://github.com/canonical/lightdm
[upstream:greeter]: https://invent.kde.org/plasma/lightdm-kde-greeter
[upstream:reviewed-version]: https://invent.kde.org/plasma/lightdm-kde-greeter/-/tags/v6.0.3
[upstream:fixed-version]: https://invent.kde.org/plasma/lightdm-kde-greeter/-/tags/v6.0.4
[code:helper]: https://invent.kde.org/plasma/lightdm-kde-greeter/-/blob/v6.0.3/kcm/helper.cpp#L48
[code:old-action]: https://invent.kde.org/plasma/lightdm-kde-greeter/-/blob/v6.0.3/kcm/kcm_lightdm.actions?ref_type=tags#L39
[code:key-comment]: https://invent.kde.org/plasma/lightdm-kde-greeter/-/blob/v6.0.3/kcm/helper.cpp?ref_type=tags#L87
[blog:sddm]: /2024/04/02/kde6-dbus-polkit.html#problematic-file-system-operations-in-sddm-kcm6
[blog:kauth]: /2024/04/02/kde6-dbus-polkit.html#the-kde-kauth-framework
[section:overview]: #section-overview
[section:problems]: #section-problems
[section:bugfix]: #section-bugfix
