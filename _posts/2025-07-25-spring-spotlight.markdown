---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SUSE Security Team Spotlight Spring 2025"
date:   2025-07-25
tags:   spotlight
excerpt: "Welcome to the spring edition of our spotlight series. Spring time
kept us busy with a couple of major security publications. With this post
we want to take some time to discuss some of our other review efforts during
the last three months that would otherwise not get much attention."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

While most of the SUSE security team members are already enjoying summer time,
we want to take a look at the notable things that happened in our team during
spring 2025. A couple of major tasks and disclosure processes that we already
covered in dedicated posts kept us busy during that time:

- [Removal of the Deepin desktop from openSUSE][blog:deepin]
- [Multiple security issues in GNU Screen][blog:screen]
- [Local privilege escalation in the Kea DHCP server][blog:kea]
- [Making Gaming work on openSUSE with SELinux enabled][blog:selinux-gaming]
- [Remote Denial-of-Service vulnerabilities in sslh][blog:sslh]

As usual in the spotlight series, we want to give an insight into some of our
work beyond these publications: reviews that did not lead to significant
security findings, but still kept us busy and in some cases also led to
upstream improvements.

This time we will discuss newly added Polkit features in [GDM][section-gdm],
[Flatpak][section-flatpak] and [ModemManager][section-modem-manager]; symlink
attack surface in [cyrus-imapd][section-cyrus] and sysctl configuration
changes for [systemd-coredump][section-systemd-coredump].

<a name="section-gdm"/>

2) GDM: Polkit Privileges to Modify system-wide Network Settings
================================================================

Our Gnome Display Manager (GDM) packagers [asked us to accept an additional
Polkit rule file][bugzilla:gdm-polkit-network], which appeared in GDM 48.0. The
newly added logic allows the `gdm` service user to fully control system-wide
network settings via the Network Manager D-Bus interface.

The reason for this is a feature in the display manager, which allows to modify
network settings from the login screen. We are not completely happy with this
change, since it is a rather powerful privilege for a rather exotic use case.
The `gdm` service user is rather powerful anyway, however, and at least it is
a well defined privilege that is granted here. Thus we accepted the change.

<a name="section-flatpak"/>

3) Flatpak: Parental Controls Polkit Action
===========================================

In version 1.16.1 of Flatpak a new [`override-parental-controls-update` Polkit
action appeared][bugzilla:flatpak-polkit]. As the action's name suggests, this
is about implementing parental controls on a Linux desktop. The implementation
of this feature in Flatpak is a bit peculiar. For example, a Flatpak
application with parental control restrictions will first be downloaded and
installed, just to be removed again, should parental control policy deny the
installation. Also the parental control restrictions are ignored in case the
application is already installed and an update is available (this is
what the newly added action is about). The reason for this is that Flatpak
developers deem it more important to apply security fixes than enforcing
parental controls.

While we found no issues with the logic behind this particular Polkit action,
we stumbled over an issue in Polkit authentication of both this and an older,
related Polkit action `override-parental-controls` (without the `-update`
suffix). These two Polkit actions are authenticated in an unsafe way based on
the Polkit UNIX process subject, in contrast to all the other Polkit actions
in Flatpak, which are authenticated based on the D-Bus sender subject. Since
this does not affect system security as such, but only application-level
policy, we decided [to report this issue in the
open][flatpak:parental-controls-issue]. We did not get a reaction from
upstream about this for a while now, however.

<a name="section-modem-manager"/>

4) ModemManager: `CellBroadcast` Polkit Action
=============================================

In ModemManager version 1.24.0 a new
[`org.freedesktop.ModemManager1.CellBroadcast` Polkit action
appeared][bugzilla:modem-manager-polkit]. Piecing together the purpose of
this action was not all that simple, because documentation and code did not
fully add up. We determined the following properties of the cell broadcast
API:

- [cell broadcast messages][wikipedia:cell-broadcast] are a feature of today's
  cellular networks to broadcast emergency messages.
- the ModemManager D-Bus API allows unauthenticated read access to any such
  messages. This is okay, since these messages are not considered sensitive
  data.
- the `CellBroadcast` Polkit action is actually used to protect the deletion
  of such messages. Only physically present users are allowed to delete them.
  This is also fine from our point of view.

After we verified the correctness of the use of the new Polkit action, we
whitelisted it, so that our packagers could continue submitting their update
to openSUSE Tumbleweed.

ModemManager in general has a very complex and continually growing API that
makes it difficult to keep track even of incremental changes. That is
precisely the reason why we deemed it important to have a deeper look to avoid
any unpleasant surprises, especially since ModemManager is running by default
in many Linux distributions.

<a name="section-cyrus"/>

5) cyrus-imapd: Privilege Escalation Attack Vectors from `cyrus` to `root`
==========================================================================

By way of our regular monitoring of newly packaged systemd unit files, we
stumbled over the [cyrus-imapd package][obs:cyrus-imapd], which offers an IMAP
mail server daemon. We found the package to have three distinct local
privilege escalation attack vectors from the `cyrus` service user to `root`,
which allow to bypass the intended user isolation.

One of the attack vectors is found in a SUSE-specific `daily-backup.sh`
script, which operates as `root` in the `/var/lib/imap` state directory
([bsc#1241536][bugzilla:cyrus-suse-script]), owned by `cyrus`. The
script performs `chown` and `chmod` operations in there, which would allow a
compromised `cyrus` user to stage symlinks attacks, leading to a local root
exploit. We assigned CVE-2025-23394 for this issue and fixed the issue by
running this script only with `cyrus:mail` credentials, instead of `root`.

The two other attack vectors are found in upstream code, thus we
approached upstream and discussed bugfixes and the coordinated release procedure
with them. Since the issues only affect defense-in-depth, and are not
directly exploitable, we left it up to upstream to decide whether to assign
CVEs or not. Upstream considered the issues to be of lower severity
and thus no CVEs have been assigned. No formal embargo has been established.
The attack vectors are described in the next two paragraphs.

When relying on cyrus-imapd's built-in privilege drop logic (instead of
starting it with lowered privileges right away, e.g. via systemd configuration
settings), then the daemon drops privileges only after unsafely operating in
`/run/cyrus-imapd` and <br/>`/var/lib/imapd/cores`
([bsc#1241543][bugzilla:cyrus-upstream-issues]). These unsafe file operations
allow a compromised `cyrus` user to create empty world-readable files in
arbitrary locations, to truncate arbitrary files, or to enter arbitrary
directories that would otherwise not be accessible. Upstream [commit
3a0db22f7][cyrus:chdir-after-privdrop] ensures that the `cores` directory is
only used after dropping privileges. Furthermore [commit
9634fc8311c][cyrus:no-follow-fix] adds the `O_NOFOLLOW` flag when creating PID
files, to prevent symlink attacks.

While reviewing these upstream bugfixes, we found [yet another symlink attack
issue][bugzilla:cyrus-chmod-socket], due to a `chmod(s->listen, 0777)`
performed as `root`, which grants world access to
<br/>`/run/cyrus-imapd/socket`, a path which is again under control of the
`cyrus` service user. When the socket is replaced by a symbolic link, then
this can be used for a full local root exploit. This `chmod()` was only in
existence for legacy UNIX systems and upstream thus removed the call in
[commit 81f342bb902][cyrus:drop-legacy-chmod].

<a name="section-systemd-coredump"/>

6) systemd-coredump: Change to sysctl Configuration File
========================================================

Our team is also restricting the packaging of [sysctl drop-in configuration
files][man:sysctl] e.g. in <br/>`/etc/sysctl.d`. sysctl configuration settings
can have security impact, and their global nature can cause conflicts between
packages that have different ideas about what some settings should look like.

We received [a change request][bugzilla:systemd-coredump-sysctl] for the
content of the `50-coredump.conf` configuration file, which is installed by
systemd-coredump. As part of the fix for
[CVE-2025-4598][oss-security:systemd-coredump-cve], the way the coredump
handler is installed in the kernel needed to be adjusted.

The change to the file was minimal and well understood, thus we quickly
whitelisted the change, to let the bugfixing process proceed.

7) Conclusion
=============

As can be seen from this edition of the SUSE security team spotlight, even
smaller and routine review work can lead to interesting insights into upstream
projects and possible vulnerabilities. We believe the consistent monitoring
of packages and interaction with packagers and upstream projects results in an
overall improvement of distribution security, and provides a net profit for
the open source community at large.

[blog:kea]: /2025/05/28/kea-dhcp-security-issues.html
[blog:screen]: /2025/05/12/screen-security-issues.html
[blog:sslh]: /2025/06/13/sslh-denial-of-service-vulnerabilities.html
[blog:deepin]: /2025/05/07/deepin-desktop-removal.html
[blog:selinux-gaming]: /2025/06/06/selinux-gaming.html
[bugzilla:gdm-polkit-network]: https://bugzilla.suse.com/show_bug.cgi?id=1239719
[bugzilla:cyrus-suse-script]: https://bugzilla.suse.com/show_bug.cgi?id=1241536
[bugzilla:cyrus-upstream-issues]: https://bugzilla.suse.com/show_bug.cgi?id=1241543
[bugzilla:cyrus-chmod-socket]: https://bugzilla.suse.com/show_bug.cgi?id=1241543#c4
[bugzilla:flatpak-polkit]: https://bugzilla.suse.com/show_bug.cgi?id=1243046
[bugzilla:modem-manager-polkit]: https://bugzilla.suse.com/show_bug.cgi?id=1243684
[bugzilla:systemd-coredump-sysctl]: https://bugzilla.suse.com/show_bug.cgi?id=1243959
[obs:cyrus-imapd]: https://build.opensuse.org/package/show/openSUSE:Factory/cyrus-imapd
[cyrus:no-follow-fix]: https://github.com/cyrusimap/cyrus-imapd/pull/5477/commits/9634fc8311c7b8096095e185591592ef40715995
[cyrus:chdir-after-privdrop]: https://github.com/cyrusimap/cyrus-imapd/pull/5477/commits/3a0db22f7b39510a3780540cbb6db87852e451c1
[cyrus:drop-legacy-chmod]: https://github.com/cyrusimap/cyrus-imapd/pull/5477/commits/81f342bb90267b15ae49f62cae9d02b443fd3d9c
[flatpak:parental-controls-issue]: https://github.com/flatpak/flatpak/issues/6212
[wikipedia:cell-broadcast]: https://en.wikipedia.org/wiki/Cell_Broadcast
[oss-security:systemd-coredump-cve]: https://www.openwall.com/lists/oss-security/2025/05/29/3
[man:sysctl]: https://man7.org/linux/man-pages/man8/sysctl.8.html
[section-gdm]: #section-gdm
[section-cyrus]: #section-cyrus
[section-flatpak]: #section-flatpak
[section-modem-manager]: #section-modem-manager
[section-systemd-coredump]: #section-systemd-coredump
