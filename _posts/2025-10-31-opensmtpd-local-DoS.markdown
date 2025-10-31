---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "OpenSMTPD: Trivial Local Denial-of-Service via UNIX Domain Socket (CVE-2025-62875)"
date:   2025-10-31
tags:   local CVE DoS
excerpt: "A world-writable `smtpd.sock` allows arbitrary local users to crash
an OpenSMTPD instance in version 7.7.0. Upstream provided a bugfix after
a longer time of silence, but there might still linger a memory
leak issue in the socket handling code, which remains unaddressed.
"
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[OpenSMTPD][upstream:website] is an implementation of the server-side SMTP
protocol offered by the OpenBSD project. A few months ago a SUSE colleague
started packaging it for openSUSE Tumbleweed, which led to [a code review of
the package][bugzilla:review-bug].

While looking into a local API offered by OpenSMTPD we discovered a trivial
local Denial-of-Service (DoS) attack vector which allows unprivileged users to
cause the shutdown of all smtpd services. The full details about the issue
follow in [section 2][section:local-dos]. Some additional remarks about
setuid-root and setgid utilities contained in OpenSMTPD are found in [section
3][section:setuid]. A quick survey of the network-facing code of OpenSMTPD is
provided in [section 4][section:network-code].

Note that two source code repositories for OpenSMTPD exist. The most
up-to-date code is found in the [OpenBSD CVS repository][upstream:cvs-repo],
while the portable version [is found on GitHub][upstream:portable-repo]. The
portable version offers cross platform support for various kinds of UNIX
systems, including Linux and the other BSDs. This report is based on the
portable [OpenSMTPD version 7.7.0p0][upstream:affected-release].

We reported the local DoS issue to upstream but [did not get a
response][section:timeline] until two days before publication, due to
communication issues. By now an [upstream bugfix][commit:upstream-bugfix] is
available which will be part of a pending 7.8.0 release, but it seems an
independent [memory leak][section:memory-leak] issue remains unaddressed.

{: #section-local-dos}
2) Local DoS Issue via UNIX Domain Socket (CVE-2025-62875)
==========================================================

OpenSMTPD contains the `smtpctl` program, which communicates with the `smtpd:
control` daemon instance via a UNIX domain socket in `/var/run/smtpd.sock`.
While looking into the protocol used for this purpose, we noticed a trivial
local Denial-of-Service attack vector affecting all of OpenSMTPD.

The UNIX domain socket `smtpd.sock` has file mode `0666` and is thus writable
for all users in the system, allowing anybody to create local connections
towards `smtpd`.

In the daemon's code in [`mproc_dispatch()`][code:mproc-dispatch-fatal] the
process exits via `fatal()` in case anything goes wrong while handling such a
UNIX domain socket connection. Two common error situations leading to this are
bad returns from `readv()` in [`ibuf_read()`][code:ibuf-read] or a bad message
length value in the message header, which is detected in
[`imsg_parse_hdr()`][code:imsg-parse-hdr].  Similar error conditions exist in
the [`msgbuf_read()`][code:msgbuf-read] call path which is used when file
descriptor passing is enabled on the connection (see
[`imsgbuf_read()`][code:imsgbuf-read]).

As a result, sending a malformed message with a bad header length is enough
for a client to provoke the invocation of `fatal()` on the daemon side.  Once
`fatal()` is called, the `smtpd: control` instance ends execution and causes
the whole smtpd instance to be shut down along with it.

We learned from upstream that the reason for the call to `fatal()` is that
`smtpd.sock` is used for two different purposes at the same time:

- connections from other, trusted `smtpd` daemon instances.
- connections from arbitrary other clients using the `smtpctl` program. 

The call to `fatal()` is made with the first kind of connections in mind.
These connections are established during startup, and if anything goes wrong
while processing data from other `smtpd` daemon instances, then a bug in
OpenSMTPD itself is assumed, and a shutdown of all daemon processes is a
viable course of action.

The second kind of connections was left unconsidered in this logic, thus
allowing unprivileged clients to trigger this code path which leads to the
local DoS. The [upstream bugfix][commit:upstream-bugfix] consequently consists
of an added `if` clause which excludes the second type of connections from the
call to `fatal()`.

{: #section-memory-leak}
Memory Leak on Regular Connection Close
---------------------------------------

While looking into a possible bugfix for the DoS issue, we noticed
[a comment in the code][code:cleanup-problem], which points to unsolved
cleanup issues, when processing a connection fails:

```c
ibuf_read_process(struct msgbuf *msgbuf, int fd)
{
    /* <<< SNIP >>> */
fail:
    /* XXX how to properly clean up is unclear */
    if (fd != -1)
        close(fd);
    return (-1);
}
```

This made us wonder, if the cleanup is unclear in error conditions, is it
maybe also unclear during regular operation? After all, proper cleanup will be
needed regardless of whether a connection ends gracefully or not. As it
happens, the cleanup logic for a regular connection close and for an erroneous
connection close indeed is equivalent in OpenSMTPD.

To this end, we tested what happens when a lot of UNIX domain socket
connections towards `smtpd` are created and closed in succession. The outcome
indeed is that the memory used by the `smtpd: control` instance
continuously grows. Thus it seems there is a memory leak present here as
well independently of the main issue described above. We did not analyze this
in more detail, but upstream is aware of the issue and is analyzing it on
their end.

This independent issue means that unprivileged clients can trigger the memory
leak in the `smtpd: control` daemon, even after applying the [upstream
bugfix][commit:upstream-bugfix] to fix the main issue in this report. The
impact will also be a local DoS, it will take a much longer time to execute
it, however, because the memory leak is small and in our tests only consumes
about 100 megabytes within half an hour. The next section describes a possible
temporary workaround to avoid this issue, as well.

{: #section-dos-workaround}
Workaround by Adjusting Socket Permissions
------------------------------------------

We initially suggested [a different patch][download:suggested-patch] to
address the local DoS issue, tightening the permissions of the
`smtpd.sock` UNIX domain socket. We wrongly assumed that there were no valid
use cases for non-root users connecting to this socket. Shortly before
publication we learned from upstream that there actually is a valid use case
for this scenario: non-root users can enqueue mail using the `sendmail`
interface, which makes use of this socket.

Even though our suggested patch causes a regression in this case, it reduces
attack surface and provides protection against the memory leak described in
the previous section. For some users of OpenSMTPD it can thus be a sensible
option to use this patch if the described use case is not needed, at least
until upstream provides a fix for the memory leak issue, as well.

Reproducer
----------

We offer a [simple Python script][download:reproducer] to reproduce the issue.
The script creates a connection towards `smtpd.sock` and sends an excessive
header length. If the reproducer works, the `smtpd` daemon processes will all
exit immediately.

Affected Versions
-----------------

In [commit 3270e23a6eb][commit:dos-introduction], which first made its way into
version 7.7.0, major changes to the message parsing code have been introduced,
including the call to `fatal()`. Triggering the issue was easily possible in
our tests for all packages based on this version.

It is unclear if older versions might be affected by some variant of this
issue as well. We only verified that the trivial reproducer does not work
against version 7.6.0 of OpenSMTPD.

Affected Systems
----------------

We verified that the issue affects the following systems, which all offer
OpenSMTPD version 7.7.0:

- Arch Linux (fully updated on 2025-09-29)
- Debian 13
- Fedora 42
- Gentoo Linux using the 7.7.0p0 ebuild
- OpenBSD 7.7
- NetBSD 10.1 (using the package available from [pkgsrc][pkgsrc])

On FreeBSD 14.2, where only the older version 7.6.0 of OpenSMTPD is available,
we could not reproduce the issue.

CVE Assignment
--------------

Without a formal confirmation from upstream we were reluctant to assign a
CVE for the issue. The case seemed clear-cut, however, and when we were
asked to provide a CVE on the [distros mailing list][distros-mailing-list], we
assigned CVE-2025-62875 and also communicated this to upstream.

When contact to upstream was established shortly before the publication of
this report, upstream picked up this CVE and used it to document their bugfix.

Upstream Bugfix
---------------

Upstream already published the [bugfix commit][commit:upstream-bugfix] for the
main issue in this report. The release of OpenSMTPD version 7.8.0 containing
this bugfix is expected soon, and [was already
announced][upstream:release-announcement] on the upstream mailing list.

{: #section-setuid}
3) Notes on setuid and setgid Binaries
======================================

The original reason for reviewing OpenSMTPD in the first place was the
[presence of setuid and setgid binaries][bugzilla:setid-comment] in the
package. The following sub-sections give a short summary of the outcome of the
review.

lockspool
---------

`/usr/libexec/opensmtpd/lockspool` is a world-accessible setuid-root binary
which is used to synchronize parallel access to a user's spool.

The [lockspool code][code:lockspool-old] found in the OpenSMTPD portable
release is quite complex and [is based on some
assumptions][bugzilla:lockspool-comment] that might not hold true. This code
can allow for a minor local DoS in multi-user scenarios. The [OpenBSD CVS
repository][code:lockspool-openbsd] already contains a simplified locking
algorithm which is not affected by this.

We reached out to upstream about this separately from the UNIX domain socket
DoS issue. In this instance we quickly got a reply and upstream [merged the
change][commit:lockspool-bugfix] from the CVS repository into the OpenBSD
portable repository. This change will be part of the OpenSMTPD 7.8.0 release.
We [backported the change][obs:lockspool-patch] into the openSUSE packaging of
OpenSMTPD as well.

smtpctl
-------

`/usr/sbin/smtpctl` is a world-accessible setgid binary operating in `_smtpq`
group context. The program uses these special group privileges to store mail
in the directory <br/>`/var/spool/smtpd/offline`, when the smtpd services are not
running.

The `_smtpq` group privileges are only used for this well defined purpose and
the extra privileges are also dropped as soon as they are no longer needed. We
found no issues in this aspect of the program.

{: #section-network-code}
4) Notes on the Network-Facing OpenSMTPD Code
=============================================

After we found the local security issues described in this report, we thought
it a good idea to also have at least [a cursory look at the actual
network-facing SMTP protocol parsing code][bugzilla:protocol-comment] found in
OpenSMTPD. We could not find any tangible security issues in these parts,
still here is a short summary of our impression of the code:

- the protocol parsing is implemented in plain C and thus error prone. The
  implementation does have this under control, however, even though there is
  some redundancy in handling the various message types.
- a lot of parsing is done manually without the help of third party libraries,
  including things like domain name end email address verification.
- transmission of plaintext passwords is rejected on unencrypted connections,
  which is a good security stance.
- the daemon processing network data is running with limited service user
  credentials and is also placed into a `chroot` jail, which reduces attack
  surface.
- the daemon logs every bad SMTP protocol message by default, including
  attacker controlled data, which is a bit peculiar. The logging systems on
  the BSDs and Linux systems we looked into are able to deal with this in safe
  ways, however (e.g. terminal escape sequences are escaped or stripped).

5) Timeline
===========

{: #section-timeline}
|2025-09-15|We reported the issue to [security@openbsd.org](mailto:security@openbsd.org), offering coordinated disclosure. We quickly got a short reply that the topic had been forwarded to the relevant people.|
|2025-09-29|After two weeks without a more detailed response, we sent a follow-up email asking for confirmation of the issue and if coordinated disclosure was desired, or not. We asked for a response until 2025-10-02, otherwise we would publish the finding on our own terms.|
|2025-10-02|Still without response, we decided to  partially publish the issue by adding [a patch][obs:socket-patch] to our packaging, which secures the UNIX domain socket permissions.|
|2025-10-23|We approached the [distros mailing list][distros-mailing-list] to give a heads-up to other distributions about the issue. We suggested an embargo until 2025-10-31.|
|2025-10-24|A member of the distros mailing list asked for a CVE, so we decided to assign CVE-2025-62875 and also informed upstream about this and the ongoing embargo on the distros mailing list.|
|2025-10-27|We shared the [suggested patch][download:suggested-patch] with the distros mailing list, which we initially had forgotten to do.|
|2025-10-29|An OpenSMTPD developer finally replied to our report, explaining that the information had been lost internally until now. Upstream confirmed the issue and informed us that a bugfix release was being prepared for 2025-11-03 at the latest.|
|2025-10-30|From further discussions with upstream we learned about the real intentions of the call to `fatal()` and about the regression caused by our [suggested patch][download:suggested-patch]. We on the other hand informed upstream about the additional [memory leak][section:memory-leak] issue we stumbled upon.|
|2025-10-31|Upstream published its [bugfix for the main issue][commit:upstream-bugfix].|
|2025-10-31|We updated our report with the latest information from upstream and published it.|

6) Links
========

- [OpenSMTPD website][upstream:website]
- [OpenSMTPD portable Git repository][upstream:portable-repo]
- [Suggested patch to work around the issue (includes a possible regression!)][download:suggested-patch]
- [Upstream bugfix of the issue (leaves a memory leak issue unaddressed)][commit:upstream-bugfix]
- [Python script to reproduce the issue][download:reproducer]
- [openSUSE Bugzilla review bug for OpenSMTPD][bugzilla:review-bug]

[upstream:website]: https://www.opensmtpd.org/
[upstream:cvs-repo]: https://cvsweb.openbsd.org/src/usr.sbin/smtpd
[upstream:portable-repo]: https://github.com/OpenSMTPD/OpenSMTPD
[upstream:affected-release]: https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/7.7.0p0
[upstream:release-announcement]: https://www.mail-archive.com/misc@opensmtpd.org/msg06634.html
[code:mproc-dispatch-fatal]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/usr.sbin/smtpd/mproc.c#L159
[code:imsg-parse-hdr]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/openbsd-compat/imsg.c#L369
[code:ibuf-read]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/openbsd-compat/imsg-buffer.c#L826
[code:msgbuf-read]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/openbsd-compat/imsg-buffer.c#L878
[code:imsgbuf-read]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/openbsd-compat/imsg.c#L74
[code:dispatch]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/usr.sbin/smtpd/control.c#L447
[code:cleanup-problem]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/openbsd-compat/imsg-buffer.c#L799
[code:lockspool-old]: https://github.com/OpenSMTPD/OpenSMTPD/blob/8c07e2a4b3d61d01483bd0f61031cb93ed46c9cf/contrib/libexec/lockspool/locking.c#L60
[code:lockspool-openbsd]: https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/libexec/mail.local/locking.c?rev=1.15&content-type=text/plain
[commit:dos-introduction]: https://github.com/OpenSMTPD/OpenSMTPD/commit/3270e23a6eb
[commit:lockspool-bugfix]: https://github.com/OpenSMTPD/OpenSMTPD/commit/91be977454d422af71700aeec247464e313320de
[commit:upstream-bugfix]: https://github.com/OpenSMTPD/OpenSMTPD/commit/653abf00f5283a2d3247eb9aabf8987d1b2f0510
[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1247781
[bugzilla:setid-comment]: https://bugzilla.suse.com/show_bug.cgi?id=1247781#c1
[bugzilla:lockspool-comment]: https://bugzilla.suse.com/show_bug.cgi?id=1247781#c3
[bugzilla:protocol-comment]: https://bugzilla.suse.com/show_bug.cgi?id=1247781#c18
[section:dos-workaround]: #section-dos-workaround
[section:setuid]: #section-setuid
[section:local-dos]: #section-local-dos
[section:network-code]: #section-network-code
[section:timeline]: #section-timeline
[section:memory-leak]: #section-memory-leak
[download:suggested-patch]: /download/0001-control_create_socket-prevent-world-access-to-UNIX-d.patch
[download:reproducer]: /download/talk_smtpd.py
[pkgsrc]: https://pkgsrc.org
[distros-mailing-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
[obs:socket-patch]: https://build.opensuse.org/projects/openSUSE:Factory/packages/OpenSMTPD/files/OpenSMTPD-reduced-permissions-on-SMTPD_SOCKET.patch?expand=1
[obs:lockspool-patch]: https://build.opensuse.org/projects/openSUSE:Factory/packages/OpenSMTPD/files/OpenSMTPD-simplified-world-writable-spoolers-handling.patch?expand=1
