---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "malcontent: Disk Space Exhaustion via Globally Accessible D-Bus API (CVE-2026-44931)"
date:   2026-05-11
tags:   CVE D-Bus
excerpt: "malcontent is a parental control system for the GNOME desktop
environment which supports restriction of content access and screen time for
children. In version 0.14.0 of malcontent a D-Bus method has been added which
allows arbitrary users in the system to fill up the disk space in
/var/lib/malcontent-timerd."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

Introduction
============

[malcontent][gitlab:malcontent] is a parental control system for the GNOME
desktop environment which allows to restrict access to adult Internet content
and to keep track of and restrict the amount of screen time for children. As
part of the GNOME 50 version update malcontent 0.14.0 was packaged for
openSUSE, [triggering a review][bug:malcontent] of changes in the package's
D-Bus methods and Polkit actions.

During this review we identified a local disk space exhaustion attack vector
via one of the newly added D-Bus methods. There is currently no upstream
bugfix available for the issue. The full details about the issue and
communication with upstream will be provided in the following sections.

Review Summary
==============

The [complexity][bug:complexity-comment] of malcontent increased a lot
compared to [the last time][bug:malcontent-prev-review] we looked into it.
There now exist three different malcontent D-Bus daemons utilizing three
different service user accounts and some additional daemons not providing
D-Bus interfaces on top of that.

Some parts of the user tracking in malcontent suffer from race conditions. We
believe this is acceptable, given that parental controls don't need to be
strong security boundaries; it is sufficient if the target audience (children)
is not able to bypass the parental controls.

Disk Space Exhaustion Issue
===========================

The newly introduced [`RecordUsage` D-Bus method][code:record-usage-data] in
`malcontent-timerd` is problematic beyond the possibility to bypass parental
controls. It allows arbitrary users in the system to slowly fill up disk space
in `/var/lib/malcontent-timerd`. The following shell construct is a simple
reproducer of the issue:

```sh
for I in `seq 100000`; do
    gdbus call -y -d org.freedesktop.MalcontentTimer1 \
        -o /org/freedesktop/MalcontentTimer1 \
        -m org.freedesktop.MalcontentTimer1.Child.RecordUsage \
        "[(0, 1000, \"app\", \"org.gnome.MyApp$I\")]"
done
```

The daemon will create an entry for every supposed GNOME app identifier passed
to it in `/var/lib/malcontent-timerd/store/<caller-username>.gvdb`. This will
slowly use up the disk space in `/var` and therefore is a local
Denial-of-Service attack vector.

To fix the problem, the method call could be restricted to callers in local
active sessions. Furthermore an upper limit of usage entries could be placed
on every user account to prevent excess disk usage.

Upstream Report
===============

We reported this issue [privately][gitlab:private-issue] via the upstream's
GitLab bug tracker on 2026-02-18 offering coordinated disclosure. We only
received an initial reply a couple of weeks later in which upstream confirmed
the issue but also mentioned that there is a lack of developer resources for
malcontent. At this time we expressed our opinion that a non-disclosure period
would not be strictly necessary since the impact of the issue is not high. We
never received further replies from upstream, so we decided to go public with
this report to avoid wasting more time without a bugfix being developed.

CVE Assignment
==============

Due to the lack of replies we could not discuss with upstream whether a CVE
assignment is appropriate for this issue. Given that upstream at least
basically confirmed the issue and there is no bugfix available we assigned
CVE-2026-44931 to track the defect and to make others aware.

Timeline
========

|2026-02-18|We created a [private issue][gitlab:private-issue] in the upstream GitLab, offering coordinated disclosure.|
|2026-03-11|Lacking a reaction we pinged the issue asking if anybody were reading it.|
|2026-03-11|An upstream developer responded confirming the issue and pointing out that little developer time is available for malcontent.|
|2026-03-23|We asked how upstream wants to continue regarding coordinated disclosure. We explained that in our view a non-disclosure period is not strictly necessary for the issue and pointed out that the maximum non-disclosure period we can offer is 90 days until 2026-05-19.|
|2026-04-09|Still without an answer we urged upstream once more to come to a decision and a path forward regarding the publication of the issue.|
|2026-04-21|We informed upstream that we would publish the report on our end if no reaction is received by 2026-04-30.|
|2026-05-05|We published our [Bugzilla bug][bug:malcontent] describing the issue.|
|2026-05-08|We assigned CVE-2026-44931 for the issue and communicated this in the upstream issue.|
|2026-05-11|Publication of this report.|

References
==========

- [malcontent freedesktop repository][gitlab:malcontent]
- [malcontent upstream private bug about this issue][gitlab:private-issue]
- [openSUSE review bug for malcontent 0.14.0][bug:malcontent]

[bug:malcontent]: https://bugzilla.suse.com/show_bug.cgi?id=1258140
[bug:malcontent-prev-review]: https://bugzilla.suse.com/show_bug.cgi?id=1177974
[bug:complexity-comment]: https://bugzilla.suse.com/show_bug.cgi?id=1258140#c3
[gitlab:malcontent]: https://gitlab.freedesktop.org/pwithnall/malcontent
[gitlab:private-issue]: https://gitlab.freedesktop.org/pwithnall/malcontent/-/work_items/137
[code:record-usage-data]: https://gitlab.freedesktop.org/pwithnall/malcontent/-/blob/0.14.0/libmalcontent-timer/child-timer-service.c?ref_type=tags#L892
