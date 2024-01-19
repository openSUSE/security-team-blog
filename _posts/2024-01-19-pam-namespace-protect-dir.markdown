---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "pam: pam_namespace misses O_DIRECTORY flag in protect_dir() (CVE-2024-22365)"
date:   2024-01-19
tags:   CVE pam
excerpt: "This is report about a local denial of service vulnerability in the <i>pam_namespace.so</i> PAM module. This module is part of the core PAM modules that are found in the linux-pam project."
---

This is report about a local denial of service vulnerability in the
`pam_namespace.so` PAM module. This module is part of the core PAM
modules that are found in the [linux-pam project][pam-gh-repo].

This report was previously shared with the [linux-distros mailing
list][distros-list] and is now published after linux-pam upstream
released a new [version 1.6.0][pam-bugfix-release] containing the bugfix on
2024-01-17.

Introduction
============

The `pam_namespace` module allows to setup "polyinstantiated directories" when
setting up a user's session during login. The typical example is setting up a
private /tmp and/or /var/tmp for every user.

To achieve this a separate mount namespace is setup during login and a
bind mount is performed in configured locations. Different methods are
offered for this like a fixed per-user directory that is bind mounted
(i.e. per-user contents are persistent and shared between sessions) or
an ephemeral temporary directory (contents are lost after a session is
closed).

The Vulnerability
=================

The PAM module explicitly supports bind mounting of polyinstantiated
directories in user controlled locations, like beneath the user's home
directory. Operating with root privileges in user controlled directories
comes with a lot of dangers. To avoid them the function `protect_dir()`
implements a special algorithm to protect the target path of a bind
mount.

The function follows the target path for the bind mount starting from
the file system root. Each path component that is under non-root control
is protected from user manipulation, by bind mounting the path upon
itself.

While this approach feels unusual, it should be effective to prevent any
shenanigans on the side of the unprivileged user for whom the directory
is mounted.

There is one bit missing though: The algorithm is not passing the
`O_DIRECTORY` flag to `openat()` and is thus subject to special files like
FIFOs being placed in user controlled directories. This can easily be
reproduced e.g. using this configuration entry in the `namespace.conf`
configuration file:

    $HOME/tmp /var/tmp/tmp-inst/ user:create root

An unprivileged user (that is not yet in a corresponding mount namespace
with ~/tmp mounted as a polyinstantiated dir) can now place a FIFO
there:

    nobody$ mkfifo $HOME/tmp

A subsequent attempt to login as this user with `pam_namespace`
configured will cause the `openat()` in `protect_dir()` to block,
causing a local denial of service.

The Bugfix
==========

The [bugfix I suggested][pam-suggested-bugfix] fixes the issue by passing the
`O_DIRECTORY` open flag to cause the open to fail if the path does not refer
to a directory. With this some existing explicit checks of the file type can
be dropped now.

Even with this patch applied the unprivileged user can still prevent the
polyinstantiated directory from being mounted by placing a FIFO in the
mount location. I don't believe that `pam_namespace` gives (or should
give) any guarantees in this regard, so I don't consider it a problem.

Timeline
========

|2023-12-27|I reported the finding to the linux-pam maintainers, offering coordinated disclosure and a suggested patch.|
|2023-12-27|An upstream maintainer quickly responded, stating that the linux-pam project does not treat security issues specially for their purposes, but suggested setting up a short embargo anyway to allow other downstream consumers to prepare.|
|2023-12-29|Since upstream intended to make a new version release in January anyway we agreed to share the issue with the distros mailing list some time before that release.|
|2024-01-05|I requested a CVE to track this issue from Mitre.|
|2024-01-09|Mitre assigned CVE-2024-22365.|
|2024-01-09|Upstream communicated to me the planned release date of 2024-01-17 which will contain the bugfix.|
|2024-01-09|I shared the issue with the linux-distro mailing list.|
|2024-01-17|linux-pam upstream released version 1.6.0 containing the bugfix as planned.|

References
==========

- [linux-pam GitHub repository][pam-gh-repo]
- [linux-pam v1.6.0 release containing the bugfix][pam-bugfix-release]
- [bugfix for the `pam_namespace` issue][pam-suggested-bugfix]

[pam-gh-repo]: https://github.com/linux-pam/linux-pam
[pam-bugfix-release]: https://github.com/linux-pam/linux-pam/releases/tag/v1.6.0
[pam-suggested-bugfix]: https://github.com/linux-pam/linux-pam/commit/031bb5a5d0d950253b68138b498dc93be69a64cb
[distros-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
