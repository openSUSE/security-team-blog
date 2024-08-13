---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "SUSE Security Team Spotlight Summer 2024"
date:   2024-08-13
tags:   spotlight
excerpt: "Although there have been no major security findings in recent months, the SUSE security team has not been inactive. We revisited a couple of packages like Deepin desktop D-Bus services and the Croc file sharing tool, we finalized leftover KDE6 topics, checked up on our openSSH downstream patches, reviewed an age old Emacs setuid binary and looked into an OpenVPN kernel module."
---

Table of Contents
================
{:.no_toc}

* ToC
{:toc}

Introduction
============

Our blog has been silent for a few months, since we did not make any major
security findings during this time. Still our team has not been inactive. A
lot of time is spent looking into programs where no notable security issues
are found, or discussing with upstream developers about improvements in their
software. This is the first edition of the SUSE security spotlight, a post
that aims to give a quick overview of recent activities in the area of code
reviews and the proactive security efforts in our team.

Deepin File Manager D-Bus Service
=================================

Deepin is a Linux desktop environment with a focus on support for the Chinese
language. Many parts of Deepin have already been reviewed by us and have been
accepted into openSUSE distributions, often after
[various](https://www.openwall.com/lists/oss-security/2019/07/04/1) [security
findings](https://www.openwall.com/lists/oss-security/2019/08/05/4) have been
addressed. The [review for Deepin's file manager D-Bus
service](https://bugzilla.suse.com/show_bug.cgi?id=1134132) has been going on
for years without bearing fruit, though.

The review is kind of a moving target, since upstream only partly fixes the
issues we report, drops some of the problematic code, but also comes up with new
code, that sometimes even contains new issues. The file manager service was
initially missing any form of Polkit authentication, granting dangerous
operations to any actors in the system. We decided not to
request CVEs at the time, because there was no end of issues in the service
and keeping track of all of them seemed like a waste of precious time for such
a broken service.
A party unknown to us did obtain
[CVE-2023-50700](https://bugzilla.suse.com/show_bug.cgi?id=1228364) for the
missing Polkit authentication part in the meantime, though.

We revisited the service recently since the package maintainer told us that a
new version with fixes was available. Sadly there are [still too
many issues left](https://bugzilla.suse.com/show_bug.cgi?id=1134132#c18) to
accept the package into openSUSE.

Deepin App Services (Config Manager)
====================================

Another Deepin component that is waiting to be allowed into openSUSE is
the Config Manager D-Bus service, which is part of a project called Deepin App
Services. There is [a review
that has been in progress](https://bugzilla.suse.com/show_bug.cgi?id=1211374)
for a while now, and that we have revisited a couple of times. So far we found
three different ways to achieve path traversal to trick the D-Bus service into
processing untrusted files outside the intended system configuration
directory.

Upstream fixed these issues one by one as we reported them, currently we are
still waiting for cleanup in the packaging, otherwise we believe the service
can soon be added to openSUSE Tumbleweed.

KDE6 Release Final Touches and Improvements
===========================================

Since the large post we did about the [KDE6
release](/2024/04/02/kde6-dbus-polkit.html), a couple of improvements have
been achieved. The DrKonqi D-Bus component [has been
improved](https://bugzilla.suse.com/show_bug.cgi?id=1220190) by upstream and
the new release is by now included in openSUSE Tumbleweed as well. Also, after
longer discussions and tests, upstream [merged changes to
KAuth](https://invent.kde.org/frameworks/kauth/-/merge_requests/63) that allow
to pass open file descriptors to KAuth helpers. The necessary changes have
been rather small in the end, and the change should allow to implement more
robust KDE authentication helpers in the future.

Review of SUSE's OpenSSH Downstream Patches
===========================================

In the light of the discovery of the [XZ library
backdoor](https://www.openwall.com/lists/oss-security/2024/03/29/4) for
OpenSSH, we decided to have a closer look into the shape of the integration
of OpenSSH into our products. As part of this endeavor we did a detailed
review of [all the
patches](https://build.opensuse.org/package/show/openSUSE:Factory/openssh) we
currently apply to the upstream OpenSSH codebase.

Since OpenSSH is a sensitive, sometimes complex and also old component, quite
a history of patches has piled up by now. The good news is that nothing truly
problematic was found in the patches during the review. We will
attempt to upstream as many of these patches as possible to avoid having to
maintain them on our end, and to let all users of OpenSSH profit from the
changes. This is a long-term effort though, that will take its time.

Review of Croc Upstream Bugfixes
================================

[Croc](https://github.com/schollz/croc) is a file sharing utility that allows
arbitrary parties to exchange data "easily and securely". In September 2023 we
[published a series of security issues](https://www.openwall.com/lists/oss-security/2023/09/08/2)
that we identified in this utility. The cooperation with the upstream author
proved somewhat difficult, until in May 2024 bugfixes arrived. Only with
some delay have we been able to check up on the fixes. Most of them are
addressed by now, except for two:

- although escape and control sequences in filenames are now detected and
  transmission is aborted, [the problematic filenames are still output to the
  terminal](https://github.com/schollz/croc/issues/595#issuecomment-2247832387).
  This remaining issue can be fixed easily, though.
- there have been some improvements to prevent received files to end up in
  dangerous home directory locations. [Quite a number of problems
  remain](https://github.com/schollz/croc/issues/593#issuecomment-2247823935),
  though. We suggested to our Croc package maintainer [to add a sandbox wrapper
  script](https://bugzilla.suse.com/show_bug.cgi?id=1215507#c3) using
  container techniques, to make the package acceptable for openSUSE.

Revisit of Backintime D-Bus Service
===================================

Backintime is a backup software that ships a D-Bus helper service. We
reviewed it quite a long time ago in 2017. D-Bus configuration paths recently [
changed in the package](https://bugzilla.suse.com/show_bug.cgi?id=1226446),
which was an occasion to revisit the software and check that it is still sane.
Nothing relevant changed in the D-Bus component though, so we went ahead with
adapting our whitelistings for this service.

KDE Plasma Kameleonhelper Service for RGB LED Controls
======================================================

Kameleonhelper is a [KDE6 add-on D-Bus
service](https://invent.kde.org/plasma/kdeplasma-addons/-/tree/master/kdeds/kameleon)
that configures RGB LEDs (like on gaming keyboards) to match the KDE desktop's color
scheme. We [performed a review of the
service](https://bugzilla.suse.com/show_bug.cgi?id=1226306), since its addition
to openSUSE was requested. The service basically only tunes some files
in SYSFS for adjusting the RGB values of compatible devices. The single
exposed D-Bus method is accessible to locally logged-in users without further
authentication.

A typical danger in such services are path traversal attacks, i.e. that
paths outside of the desired SYSFS location can be written to. There are no
such problems found in this D-Bus service, luckily. There were [a
few quirks](https://bugzilla.suse.com/show_bug.cgi?id=1226306#c3) in the code,
though, that have been addressed [by a merge
request](https://invent.kde.org/plasma/kdeplasma-addons/-/merge_requests/598)
by now.

OpenVPN Data Channel Offload (dco) Linux Kernel Module
======================================================

An out-of-tree kernel module for OpenVPN has been added to openSUSE, which
[raised security concerns](https://bugzilla.suse.com/show_bug.cgi?id=1226150).
The purpose of the kernel module is to accelerate OpenVPN network I/O and its
encryption operations, by performing the tasks in kernel space.

The codebase of the module is of medium size. Only users with root permissions
are allowed to use the socket APIs exposed by the kernel module. The local
system security should not be weakened by this. Regarding the processing of
network packets from remote parties, the code also looks sensible. The
involved kernel frameworks provide a good base to prevent most bad things from
happening. Although packet headers for IP, TCP and UDP are touched directly in
some spots, the majority of the code is concerned with just opaque processing
of the data for encryption/decryption and forwarding it between related
parties. We could not identify any issues in the module's code.

Emacs Games setuid/setgid Highscore Sharing Helper
==================================================

Playing games in your favorite editor and sharing your highscore with other
users on the system? If that brings back good old memories to you then this
review is just for you. We have been asked [to accept a setgid-games highscore
helper program](https://bugzilla.suse.com/show_bug.cgi?id=1228058) for the
Emacs editor into the distribution. We always thought that using
setuid binaries for sharing highscores was just an academic example from UNIX
programming textbooks. But [such a program actually
exists](https://github.com/emacs-mirror/emacs/blob/master/lib-src/update-game-score.c),
and it is already over 20 years old.

The source code for this program is rather naive and [misses protection
against many of the problematic
aspects](https://bugzilla.suse.com/show_bug.cgi?id=1228058#c6) of
setuid/setgid programs: sanitization of environment variables, sanitization of
the process's umask, no proper verification of input path arguments and other
issues. Even if all these problems were fixed, the current program design does
not offer any kind of protection against arbitrary manipulation of game
scores, or against filling up the file system with insanely large highscore
files.

We don't believe that there are many users left on earth that actually
want to share highscores on a multi-user system this way. We thus rejected the
request to include this program with a setgid-games bit. Any users that want
to use this feature can manually assign the required bit e.g. by using the
[openSUSE permissions settings](https://en.opensuse.org/openSUSE:Security_Documentation#Customization_of_Profiles).

Summary and Outlook
===================

With this post we want to offer an insight into the every day business of the
proactive SUSE product security team. Even when we don't have any actual CVEs
to report, we are constantly investing resources into open source security in
various ways: by revisiting software we already reviewed in the past, by
performing code reviews that yield no major problems, by having follow-up
discussions with upstream about bugfixes or by rejecting components that
aren't considered healthy for the security stance of our products.

We are planning to make a series of blog posts of this kind in the future, to
highlight some of our efforts, that otherwise would not be well visible. Note
that this series focuses on the work of the proactive SUSE security team,
while there is also the reactive SUSE security team, which is monitoring and
managing CVEs and security issues in SUSE products, to make sure that SUSE
customers and openSUSE users always get the latest security fixes, an area
that warrants its own series of blog posts; actually we're considering to
provide something in this direction as well in the future.
