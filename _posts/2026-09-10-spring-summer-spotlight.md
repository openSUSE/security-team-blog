---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "SUSE Security Team Spotlight Spring/Summer 2026"
date:   2026-09-10
tags:   spotlight
excerpt: "This is a combined spring/summer edition of our spotlight series. This
time we will discuss various changes in D-Bus and Polkit features, a number of
Linux capability assignments, a revisit of the Apptainer starter-suid binary,
newly introduced Varlink packaging restrictions and a review of the
pam_ssh_agent PAM module."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

This edition of the spotlight series covers both spring and summer 2026, since
we did not get around to publishing a dedicated spring article due to high
workload in our team. Some of the highlights that kept us busy during that
time were:

- [Incomplete privilege drop][blog:cosmic-greeter] in cosmic-greeter when
  accessing files in user home directories.
- [Defense-in-depth issues][blog:plasma-login-manager] in a D-Bus helper in plasma-login-manager.
- [Disk space exhaustion][blog:malcontent] in the malcontent parental control system.
- [Various issues leading to privilege escalation][blog:qsnapper] in qSnapper, a GUI frontend for the `snapper` utility.
- [Local Denial-of-Service attack vectors][blog:seunshare] in `seunshare`, a
  sandboxing program from SELinux userspace utilities.
- [Escalation of Network Manager and UDisks2 Privileges][blog:port-proton] in
  PortProtonQt, a GUI application for launching Windows games on Linux.
- [Full remote system compromise][blog:openrgb] in a network protocol in
  OpenRGB.
- [Authentication bypass][blog:lact] in LACT, a GPU manager application for
  Linux.

Apart from these dedicated publications, we want to shed some light on some
less visible efforts in our team during these past months. Topics that we will
cover this time are various changes to D-Bus service configuration and Polkit
policies which we will cover in [section 2)][section:dbus-polkit]. In [section
3)][section:caps] we will look into a number of file-based Linux capability
assignments in packages. In [section 4)][section:apptainer] we will discuss a
revisit of the `starter-suid` setuid-root binary in the Apptainer container
runtime. In [section 5)][section:varlink] we will point out new whitelisting
restrictions in SUSE distributions regarding the packaging of Varlink
services. In [section 6)][section:pam-ssh-agent] we will examine the
pam-ssh-agent module which was recently packaged for openSUSE. In [section
7)][section:wireguard] we will discuss concerns about a script in `wg-quick`
for setting up DNS for Wireguard VPN interfaces.

{: #section-dbus-polkit}
2) D-Bus and Polkit Additions
=============================

As usual, many of our reviews were concerned with D-Bus services and Polkit
authentication. We look into packages containing D-Bus interfaces and Polkit
policies, both when they are first introduced and if they are later modified.
In the past months we dealt with a number of reviews of this type, discussed
in the following sub-sections.

2.1) systemd v260.2 and v261 Reviews
------------------------------------

As we pointed out [in previous][blog:systemd-prev] spotlight editions,
systemd is a heavy user of D-Bus and Polkit and also started backporting new
features from the mainline development to existing release branches, resulting
in an increased review effort on our end.

This time we looked into the [follow-up release v260.2][bug:systemd:260.2],
which introduced Polkit actions `org.freedesktop.machine1.inspect-machines` and
`org.freedesktop.machine1.inspect-images` in the context of
`systemd-machined`. Nothing problematic was found in these two additions.

The new major release of systemd v261 [also resulted in a review bug for
us][bug:systemd:261]. Various Polkit actions were added to our
systemd-experimental package, as well as a couple to `systemd-machined` and
`systemd-resolved`. In this case we also had nothing to complain about and
allowed the changes to enter openSUSE Tumbleweed.

2.2) Polkit Rules File in upower
--------------------------------

The energy management software upower [triggered a review][bug:upower] due to
a Polkit rules file which appeared in the package. Polkit rules are JavaScript
drop-in files which alter the outcome of Polkit authentication requests based
on custom logic. In this case [a strange rule][code:upower-rules] was added to
upower, allowing the `root` user to perform system power state changes
like rebooting or entering suspend. Since the `root` user is by default
allowed to perform any Polkit operation anyway, we asked our upower packager
to investigate what the supposed purpose of the rules file might be. He was
unable to find out, however, therefore we decided to simply drop this rule
file from the package to avoid unnecessary administration efforts. It could be
that the rules file is intended to be used on systems where even the `root`
user has limited capabilities.

2.3) New Polkit Action `aa-notify.from_file` in AppArmor
--------------------------------------------------------

The AppArmor utility `aa-notify`, which allows system administrators to easily
whitelist AppArmor violations, [added an additional Polkit
action][bug:apparmor-aa-notify] `net.apparmor.pkexec.aa-notify.from_file`.
This action allows to read in additional AppArmor commands from a file on
disk. All the Polkit actions related to `aa-notify` require `auth_admin`
authentication and are inherently risky, since they provide full
system access via various angles. The defense-in-depth and separation of
privileges is not ideal here, but we decided to accept the change, since there
are no better alternatives available for managing AppArmor profiles.

2.4) New Polkit Actions in `fwupd` 2.1.4
----------------------------------------

The firmware update daemon is another heavy user of D-Bus and Polkit. We
reviewed it many times in the past already as changes to the API appeared.
Security-wise we rarely found tangible issues, but the interface is vast and
only parts of it are actually authenticated, while the rest offers access to
public information and similar code paths which are assumed to be uncritical.

For the recent update of `fwupd` to 2.1.4 we [reviewed a couple of additional
Polkit actions][bug:fwupd], some of which adding authentication to previously
unrestricted D-Bus methods. We couldn't find any issues in the API changes,
and accepted the new version into openSUSE Tumbleweed.

2.5) Changes in Polkit Rules in gnome-initial-setup
---------------------------------------------------

gnome-initial-setup is a wizard intended for single-user systems to create a
user account with administrator privileges after installation of Gnome-based
systems. Its approach is to allow a special `gnome-initial-setup` user to
obtain a range of root-like privileges to perform the necessary initial setup
logic.

The security boundary between the `gnome-initial-setup` user and `root` is
very thin, but the approach is still better than running the setup wizard
with full root privileges. A somewhat worrying aspect of the component is that
the wizard automatically starts after system boot when there are "no user
accounts present" in the system, which is a condition that might be possible
to fake or force by way of other security issues in the system.

We have reviewed the package a couple of times in the past. This time a [change
to the Polkit rules][bug:grd] in the package appeared, which led us to looking
into the code once again. The change allows `gnome-initial-setup` to invoke
Polkit action `org.freedesktop.home1.passwd-home` without providing a
password, for setting up a portable home directory managed by systemd. This does
not change the general security concept of gnome-initial-setup, which is why
we accepted the change into openSUSE.

2.6) D-Bus and Varlink Services in `wall-broadcaster`
-----------------------------------------------------

A while ago [a new D-Bus and Varlink service][bug:wall-brd] called
`wall-broadcaster` was added to openSUSE Tumbleweed. This service aims to
replace the old-school `wall` setuid binary, which allows to write terminal
messages to all users in the system. Messages processed by this service are
also forwarded on D-Bus level e.g. to interested consumers in graphical
desktop environments.

We inspected the privileged components and protocols and could not find any
security issues, which is why we accepted the new services.

2.7) Transactional Update Notifier D-Bus Service
------------------------------------------------

`txnupd` is a notifier for SUSE systems based on
[transactional-update][transactional-update]. It sends out a D-Bus signal
propagating the results of a transactional update process. The corresponding
D-Bus service [was recently renamed][bug:txnupd], which triggered a follow-up
review. The privileged daemon which emits the D-Bus signal is only accessible
by `root` and does not cross privilege boundaries, thus this is a rather
worry-free case of a D-Bus service.

Still we identified an issue during the review, namely that the same script
was used in two different modes, in a privileged and an unprivileged context,
mixing two different security domains, which could potentially lead to future
issues when developers overlook this detail when making changes. We managed to
improve the service in this regard by splitting the script into two different
ones for better separation of security concerns.

2.8) Plasma Kameleon RGB LED Helper
-----------------------------------

A new D-Bus service [was added to kdeplasma6-addons][bug:plasma-kameleon]
which deals with the synchronization of RGB LED devices, like illuminated
keyboards, with the color scheme of the KDE Plasma desktop. We looked into
the privileged D-Bus helper for this feature and found the interface to be
small and offer little attack surface, thus we accepted the new component into
openSUSE.

2.9) Samba Helper in `kdenetwork-filesharing`
---------------------------------------------

A D-Bus service in the `kdenetwork-filesharing` package which interacts with
Samba network shares saw changes in [its D-Bus
configuration][bug:kdenetwork:dbus] and [Polkit
policy][bug:kdenetwork:polkit]. The name of the helper binary was changed and
additional Polkit actions for starting and stopping the Samba daemon were
added. We could not identify newly introduced security issues and thus
accepted the changes into openSUSE.

2.10) GNOME Remote Desktop Race Condition in new `pcscd` API in 51.beta
-----------------------------------------------------------------------

Our GNOME packagers [reached out to us][bug:grd-pcscd] regarding changes they
ran into in the GNOME Remote Desktop beta release for version 51. The GNOME
Remote Desktop component is constantly growing in complexity, by now amounting
to about 75,000 lines of Glib-based C code. This time a new daemon called
`grd-pcscd` was added, which offers an additional D-Bus API to deal with smart
cards by interacting with the `pcscd` smart card management daemon. The
approach of the D-Bus interface is a bit unusual:

- there is a new `org.gnome.RemoteDesktop.Pcscd.Connect` D-Bus method which is
  accessible to arbitrary users without authorization checks. The method takes
  a file descriptor as sole argument, which is supposed to refer to a `pcscd`
  connection that `grd-pcscd` should use for further smart card operations.
- the daemon runs a separate D-Bus session on this file descriptor via Glib's
  `g_dbus_connection_new()`.
- the session of the process calling `Pcscd.Connect` is looked up via the
  caller's PID. Based on the session ID obtained this way, another D-Bus
  interface is then made available in the daemon under
  `/org/gnome/RemoteDesktop/Pcscd/<session-id>`, offering the
  `org.gnome.RemoteDesktop.Pcscd.Session` interface. All methods on this
  interface are protected by Polkit `auth_admin` actions and therefore offer
  no additional attack surface.

We checked possible attack vectors resulting from crafted data sent on the
file descriptor passed to the `Pcscd.Connect()` method. The Glib functions
processing D-Bus messages on this file descriptor are pretty robust, however,
and valid D-Bus messages will not reach any additional code paths as long as
no further configuration takes place via the privileged `Pcscd.Session` API.

We found the lookup of the caller's session ID based on its PID problematic,
however. This is a race condition that allows the caller to attempt to let the
daemon see the session of another user in the system, by cycling PIDs. This
allows a local unprivileged attacker to at least block other users' smart card
usage. Even worse, it allows to potentially spoof `pcscd` replies or
intercept sensitive data like smart card PINs provided in other users'
sessions.

We created [a private upstream bug][upstream:grd-pcscd-race] describing the
problem. Since the issue only made it into the 51.beta release of GNOME, there
was no necessity for coordinated disclosure and we also did not assign CVEs.
We are happy that we helped to prevent this issue from reaching the final
release of GNOME 51.

{: #section-caps}
3) Review of File-Based Linux Capabilities
==========================================

File-based [capabilities][man:capabilities] work much the same as setuid-root
binaries: special extended attributes are set on executable binary programs
which tell the Linux kernel to automatically execute the program with
additional Linux capabilities in effect. During the past months we looked into
quite a number of Linux capability assignment requests, which we will discuss
in detail in the following sub-sections.

3.1) After-the-Fact Review of Slipped Capabilities
--------------------------------------------------

Special file-based permissions like setuid/setgid bits or Linux capabilities
have been managed in SUSE distributions via the [permissions][permissions]
package for a long time already. Packaging of such bits is restricted
and requires mandatory reviews by our team. Recently it [came to our
attention][bug:caps-tracker] that a loophole sneaked into our checkers,
resulting in a couple of packages which use file-based capabilities reaching
openSUSE Tumbleweed without us having looked into them.

Historically the RPM packaging format did not support embedding of Linux
capabilities into package metadata in the first place, thus there was no need
to reject them on this level: only a warning was emitted by our `rpmlint`
integration when capabilities appeared. With recent releases of the RPM
package manager, this restriction is no longer present. Our RPM checkers
recognized the capabilities which lacked a whitelisting but did not trigger
fatal build errors. This allowed the affected packages to reach openSUSE
Tumbleweed without going through the intended security review process.

Once we noticed this, we quickly adjusted our checkers to prevent such cases in
the future and looked into the packages that slipped into production without a
review. The following paragraphs discuss the reviews we performed in this
context.

### CAP\_NET\_ADMIN and CAP\_NET\_RAW for `ttl`

[The ttl package][bug:ttl] assigned `cap_net_admin` and `cap_net_raw` to the
`ttl` binary for tracing network routes. During our review we identified that
actually only `cap_net_raw` was necessary and we could successfully drop the
broader `cap_net_admin` privilege. Otherwise we deemed the code paths for
`cap_net_raw` safe and accepted the capability formally into our
whitelistings.

### CAP\_SYS\_RESOURCE for `noisetorch`

[The noisetorch package][bug:noisetorch] provides a virtual microphone in
Pulseaudio and assigns `cap_sys_resource` to the `noisetorch` binary for
bypassing realtime scheduling limits. We looked into this [a longer time ago
already][bug:noisetorch-old] and rejected the capability, because the use case
for the additional privilege was not very convincing.

There exists a corner case in Pulseaudio that can cause it to exceed realtime
scheduling limits when loading plugins. The noisetorch plugin seems to trigger
this corner case in some situations, which is why it temporarily bypasses
scheduling limits by modifying the Pulseaudio process based on the
`cap_sys_resource` capability. Furthermore the `noisetorch` program attempts
to modify its own executable by adding the `cap_sys_resource` capability
via a privilege escalation dialog, should it be missing. This mixture of a
capability being used to work around what looks like a bug in Pulseaudio and
the fact that the program tries to apply its own policy regarding file-based
capabilities is what led us to reject this request previously.

After looking into the matter again we decided to accept the capability this
time, provided that the package would be patched to disable the
self-modification logic, which we deem unsuitable, since it bypasses our
[permissions][permissions] profiles. A [corresponding patch][noisetorch-patch]
was implemented and we proceeded with a formal whitelisting of
`cap_sys_resource` for `noisetorch`.

### CAP\_NET\_ADMIN for `cloud-hypervisor`

[The `cloud-hypervisor` package][bug:cloud-hypervisor] is a virtual
machine manager and uses `cap_net_admin` to configure privileged virtual
machine networking. During our review we focused on the code paths that deal with
`cap_net_admin` only, because the project consists of 150,000 lines of Rust
code, not counting vendored code. We could not find issues in the
`cap_net_admin` usage and therefore formally accepted this use of capabilities
as well.

3.2) CAP\_NET\_RAW for `cacti-spine`
------------------------------------

Cacti is a system and network monitoring tool, and `cacti-spine` is a C
program used as a drop-in replacement for a PHP-based program in Cacti for
polling network services. In this context [it asks for
`cap_net_raw`][bug:cacti-spine] privileges to send out ICMP messages.
According to upstream documentation the utility is even intended to be used
with full setuid-root privileges: this is not a good idea at all, however,
since it is not very careful in parsing and processing command line arguments,
among other issues. Assigning `cap_net_raw` is acceptable, though; we could
not find any tangible security issues in this configuration.

3.3) CAP\_PERFMON for `ksystemstats6`
-------------------------------------

The [ksystemstats6 package][bug:ksystemstats6] contains the helper program
`ksystemstats_intel_helper`, for which an openSUSE user requested the
`cap_perfmon` capability. The helper utility needs it to calculate the GPU
usage in the system. The rarely seen `cap_perfmon` allows programs to open
otherwise privileged performance event counters. The utility is only 200 lines
long; for prudence we requested to apply a patch with a hardening to the
program [which also made it into the upstream
repository][upstream:ksystemstats6-pr] by now. After this patch arrived in
the openSUSE package we granted the capability in openSUSE Tumbleweed.

{: #section-apptainer}
4) Revisit of Apptainer
=======================

Apptainer is a container runtime (formerly called Singularity) which we
already reviewed a couple of times in the past, since it contains a
setuid-root binary `starter-suid`. The early reviews around the year 2019
uncovered [a number][oss-sec:singularity-1] of [security
issues][oss-sec:singularity-2] in this area. A few years ago we dropped the
`starter-suid` binary from our packaging, because upstream implemented new
features which we believed made the extra privileges unnecessary.

A SUSE customer recently ran into issues because of a specific Apptainer use
case they had, which still relied on the `starter-suid` program being
installed. For this reason [we revisited the Apptainer code
base][bug:apptainer] to check the current situation of this sensitive helper
binary.

The logic executed by the `starter-suid` program is still highly complex and
its execution paths hard to follow. We could not identify any new issues in
the code this time, however, which is why we accepted the setuid-root binary
back into SUSE distributions. Since we are still unhappy about the overall
complexity of the program we are relying on an opt-in model: users need to
become a member of the `apptainer` group to use it, which limits the attack
surface.

{: #section-varlink}
5) Restriction of Varlink Service Packaging
===========================================

With [Varlink][varlink] services becoming more widespread, we decided to
introduce whitelisting restrictions for packages wanting to submit them to SUSE
distributions. Contrary to D-Bus services, there is no central instance
managing the Inter-Process-Communication of Varlink, and there are also no
standard configuration files that every Varlink service ships. Varlink
applications simply define a path where the Varlink UNIX domain socket will be
placed and that is about all there is to it.

A kind of standard pattern in systemd socket units for Varlink daemons is that
they contain a `FileDescriptorName=varlink` directive. This is what we have
decided to rely on to restrict the packaging of Varlink services. We [looked
into all existing socket units][bug:varlink] of this kind in openSUSE and did
not find any tangible security issues in them. From now on, when packages
contain new Varlink socket units, a mandatory review by our team will be
required before they can be added to SUSE distributions.

{: #section-pam-ssh-agent}
6) pam-ssh-agent Module
=======================

Recently we [received a request][bug:pam-ssh-agent] to allow the
`pam-ssh-agent` module into openSUSE. The module performs PAM authentication
based on SSH public keys: a random payload is requested to be signed by an SSH
private key; the signature is then verified by the PAM module based on a
list of configured trusted public keys.

The PAM module is of moderate size, consisting of about 1,500 lines of Rust
(not counting vendored sources). The code and documentation generally show
security-consciousness, which is a good thing. We identified [a few
aspects][bug:pam-ssh-agent-concerns] in the PAM module that could be
problematic, mostly as a result of bad configuration:

- the PAM module can be configured to look for acceptable public keys in the
  to-be-authenticated user's home directory, which allows to basically bypass
  local `sudo` authentication, for example. This is also [documented in the
  upstream README][upstream:pam-ssh-agent-warning].
- an `authorized_keys_command` can be configured to call a program which
  produces authorized public keys. If an untrusted program is configured here
  then this would result in issues in local authentication scenarios.
- the `authorized_keys_command` is by default run with the privileges of the
  to-be-authenticated user; an option allows to change this to be run as
  `root`, however, which could easily lead to security issues further down the
  chain.
- a special authentication path in the PAM module inspects the
  `SSH_AUTH_INFO_0` environment variable, if the current PAM stack file is
  named "ssh". Public keys found in this environment variable are implicitly
  trusted by the PAM module, assuming that `sshd` already took care of the
  authentication, verifying the public key(s). This is a bit of a heuristic,
  which could break in some (highly) unexpected scenarios.

In spite of these uncertainties we are generally content with the quality and
documentation of the PAM module and accepted it into openSUSE. It is up to
system administrators to configure this PAM module carefully to avoid any
security issues.

{: #section-wireguard}
7) wireguard-tools: Update Logic for resolv.conf
================================================

An openSUSE user was concerned [about the security of
`wg-quick`][bug:wg-quick], a script which is part of the wireguard-tools
package, a collection of utilities for the Wireguard VPN solution. `wg-quick`
is supposed to bring up a WireGuard VPN interface in a worry-free manner.

A Linux-specific ["DNS hatchet"][upstream:wg-quick-dns-hatchet] is applied
during build time of wireguard-tools on openSUSE. Hatchets are overrides of
the script logic in `wg-quick`, a rather makeshift approach at customizing the
logic towards specific operating systems.

The openSUSE user approached us because he was worried about the
mount logic that this "DNS hatchet" implements for `/etc/resolv.conf`. During
the review we found the approach of the script a bit unexpected but not unsafe
at all. The script is concerned with the safe update of name server
configuration in `/etc/resolv.conf`, a resource which is difficult to manage
in Linux, because there is no central mechanism for maintaining the
consistency of the file when multiple programs want to modify it. VPN clients
are a typical use case when this results in problems: the VPN client adds
VPN-specific name servers, thereby overriding previously existing name servers
from static configuration or provided by DHCP servers. When the configuration
is blindly overwritten this results in the loss of the original DNS
configuration; once the VPN connection is terminated, DNS is no longer
working.

To prevent this situation, the "DNS hatchet" performs a bind-mount of the new
configuration file over the original one in `/etc/resolv.conf`. The resulting
file will be read-only, preventing further modifications of the configuration
until the VPN connection is terminated. When the VPN is shutdown, the
bind-mounted file will be unmounted again and the original name server
configuration reinstated.

We have no security concerns about this logic, and explained the situation to
the creator of the review bug accordingly.

8) Conclusion
==============

As can be seen from this edition of the spotlight series, maintaining the
security of a complete Linux distribution is no small feat both in terms of
volume and range of topics that have to be covered by our team. We continue
to contribute to the overall security of the Linux ecosystem by reviewing
code, publishing security reports and contributing back upstream to be able to
provide our users and customers with a robust and secure Linux distribution
that you can trust.

[varlink]: https://varlink.org
[permissions]: https://github.com/openSUSE/permissions/
[noisetorch-patch]: https://build.opensuse.org/projects/openSUSE:Factory/packages/noisetorch/files/remove-self-cap-assignment.patch?expand=1
[transactional-update]: https://github.com/openSUSE/transactional-update
[man:capabilities]: https://man7.org/linux/man-pages/man7/capabilities.7.html

[blog:plasma-login-manager]: /2026/04/27/plasma-login-manager.html
[blog:malcontent]: /2026/05/11/malcontent-disk-space-dos.html
[blog:qsnapper]: /2026/05/26/qsnapper-dbus-issues.html
[blog:seunshare]: /2026/07/15/selinux-seunshare.html
[blog:port-proton]: /2026/07/22/port-proton-qt-polkit-rules.html
[blog:openrgb]: /2026/08/25/openrgb-remote-vulnerabilities.html
[blog:lact]: /2026/08/31/lact-gpu-control.html
[blog:cosmic-greeter]: /2026/04/16/cosmic-greeter.html
[blog:systemd-prev]: https://security.opensuse.org/2026/04/20/winter-spotlight.html#section-systemd

[bug:systemd:260.2]: https://bugzilla.suse.com/show_bug.cgi?id=1266944
[bug:systemd:261]: https://bugzilla.suse.com/show_bug.cgi?id=1267504
[bug:upower]: https://bugzilla.suse.com/show_bug.cgi?id=1265867
[bug:wg-quick]: https://bugzilla.suse.com/show_bug.cgi?id=1266267
[bug:apparmor-aa-notify]: https://bugzilla.suse.com/show_bug.cgi?id=1265157
[bug:apptainer]: https://bugzilla.suse.com/show_bug.cgi?id=1265157
[bug:fwupd]: https://bugzilla.suse.com/show_bug.cgi?id=1267014
[bug:grd]: https://bugzilla.suse.com/show_bug.cgi?id=1273685
[bug:wall-brd]: https://bugzilla.suse.com/show_bug.cgi?id=1263701
[bug:txnupd]: https://bugzilla.suse.com/show_bug.cgi?id=1268577
[bug:pam-ssh-agent]: https://bugzilla.suse.com/show_bug.cgi?id=1274633
[bug:pam-ssh-agent-concerns]: https://bugzilla.suse.com/show_bug.cgi?id=1274633#c4
[bug:plasma-kameleon]: https://bugzilla.suse.com/show_bug.cgi?id=1267818
[bug:kdenetwork:dbus]: https://bugzilla.suse.com/show_bug.cgi?id=1262258
[bug:kdenetwork:polkit]: https://bugzilla.suse.com/show_bug.cgi?id=1263037
[bug:varlink]: https://bugzilla.suse.com/show_bug.cgi?id=1261919
[bug:caps-tracker]: https://bugzilla.suse.com/show_bug.cgi?id=1268674
[bug:ttl]: https://bugzilla.suse.com/show_bug.cgi?id=1270714
[bug:noisetorch]: https://bugzilla.suse.com/show_bug.cgi?id=1270715
[bug:noisetorch-old]: https://bugzilla.suse.com/show_bug.cgi?id=1184843
[bug:cloud-hypervisor]: https://bugzilla.suse.com/show_bug.cgi?id=1270717
[bug:cacti-spine]: https://bugzilla.suse.com/show_bug.cgi?id=1273300
[bug:ksystemstats6]: https://bugzilla.suse.com/show_bug.cgi?id=1262779
[bug:grd-pcscd]: https://bugzilla.suse.com/show_bug.cgi?id=1276523

[section:dbus-polkit]: #section-dbus-polkit
[section:caps]: #section-caps
[section:apptainer]: #section-apptainer
[section:varlink]: #section-varlink
[section:pam-ssh-agent]: #section-pam-ssh-agent
[section:wireguard]: #section-wireguard

[code:upower-rules]: https://gitlab.freedesktop.org/upower/upower/-/blob/v1.91.3/policy/org.freedesktop.upower.rules?ref_type=tags

[oss-sec:singularity-1]: https://www.openwall.com/lists/oss-security/2018/12/12/2
[oss-sec:singularity-2]: https://www.openwall.com/lists/oss-security/2019/05/16/1

[upstream:wg-quick-dns-hatchet]: https://github.com/WireGuard/wireguard-tools/blob/a998407747005ea7e4e0258d96f105c97241e1d3/contrib/dns-hatchet/hatchet.bash
[upstream:ksystemstats6-pr]: https://invent.kde.org/plasma/ksystemstats/-/merge_requests/141
[upstream:pam-ssh-agent-warning]: https://github.com/nresare/pam-ssh-agent/blob/f73c8609a45fec60c7fd9f02bd41bfd1bd1d835d/README.md?plain=1#L123
[upstream:grd-pcscd-race]: https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/work_items/360
