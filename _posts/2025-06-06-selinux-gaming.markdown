---
layout: post
author: Robert Frohl
title:  "SELinux: finding an elegant solution for emulated Windows gaming on Tumbleweed"
date:   2025-06-06
tags:   selinux
excerpt: "OpenSUSE Tumbleweed switched to using SELinux by default. The change was causing problems when
playing emulated Windows Games through Proton or Wine. This post looks at the requirements for a fix
and how a transparent solution was implemented."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Overview
===========
OpenSUSE Tumbleweed recently switched to using SELinux by default. While generally well received,
this change caused problems in particular when playing Windows games through Proton or Wine.
This post will provide context and introduce the solution the openSUSE SELinux team came up with.

Section 2 gives an overview of SELinux and introduce the primitives necessary to understand the
issue and solution. Section 3 takes a closer look at the root cause of the problem and the manual
steps needed to work around the issue in the past. Section 4 discusses the requirements for a
better solution and how it was implemented in the end. Section 5 closes with information on how to
report SELinux bugs and how to reach the openSUSE SELinux team.

2) Introduction to SELinux
===============

OpenSUSE Tumbleweed switched to SELinux as the default [Mandatory Access Control][wiki:mac]
mechanism for new installations in [February 2025][news:default].

The central reason for the change was that we consider SELinux the more encompassing solution:
security problems with a program do not pose a threat to the whole system, rather a compromise
can be confined to the affected program or daemon.

SELinux provides a powerful and detailed language to describe _expected_ application behaviour.
Allowing to confine a process, referred to as a SELinux domain, by limiting access to required system resources and describing the
interaction with other domains. A large catalog of domains is already available via the upstream [SELinux policy][upstream:policy].

SELinux booleans
----------------

Common behaviour of a piece of software might be allowed by default for the domain,
but very specific scenarios might be prohibited, especially when negatively impacting security.
[SELinux booleans][gentoo:Using_SELinux_booleans] provide a way for the user to enable
such optional functionality in the SELinux policy.

To give an example: the Apache _HTTP daemon_ is used to serve web pages. In
certain situations it might be needed that these webpages are stored in the user's
home directory, but as a default it is not advisable that a network facing daemon
has access to the home directories. To address these different usage scenarios
a boolean called `httpd_enable_homedirs` exists. The user can turn on the boolean
if the HTTP daemon needs to access the home directories of users to serve web pages.

3) The problem with emulating Windows games
==========

Playing Windows games on Linux with SELinux enabled did not work without manual intervention by the user.
This is related to the way Windows libraries have been developed and are used by emulation software.
To allow the software for emulating Windows games to work, for example Steam with Proton or
Lutris with Wine, a boolean called `selinuxuser_execmod` needs to be enabled:

```sh
sudo setsebool -P selinuxuser_execmod 1
```

But enabling this boolean has consequences for the general security of the system.
The [user_selinux manpage][man:user_selinux] states for `selinuxuser_execmod`:

> If you want to allow all unconfined executables to use libraries requiring text relocation that are not labeled
> textrel_shlib_t, you must turn on the selinuxuser_execmod boolean.

But why exactly is the boolean problematic and required a manual change before? Executable stack is used by hackers as a
building block in their exploitation techniques. A lot of research went into finding mitigation strategies to make it harder
for malicious actors to run successful exploits. One central measure was 
[Executable-space protection][wiki:Executable-space_protection], and [Text relocation][blog:text-relocations] touches a part of that mitigation.
If the boolean is enabled it allows modification of the executable code portions of the affected libraries,
and could result in successful exploitation of the processes using these libraries.

4) Finding an elegant solution
===========

OpenSUSE Tumbleweed is a general-purpose Linux distribution, targeting a multitude of
use cases, be it as a server, running on embedded devices, as container host or as a
desktop system. Some Tumbleweed users require their desktop system to run
emulations software for Windows games. 

In general we try to take a _Secure by Default_ approach when we take decisions affecting
security. For openSUSE Tumbleweed we decided to disable `selinuxuser_execmod` 
by default, because we think it provides a risk to the security of the system if all
unconfined executables can use libraries with text relocation.

In software security we usually want to make it as hard as possible for malicious actors
to exploit a target. Accomplishing this feat is not easy, because some attack scenarios rely
on normal system behavior that can be used or exploited by attackers. An approach to mitigate this
in defensive software security is a concept known as _Defense in Depth_, where
different protective mechanisms are used to provide a layered defense, making a
successful exploit as hard as possible.

A central requirement for a solution was not to cause a negative impact on the security of
other use cases, which do not require emulation of Windows games. Enabling `selinuxuser_execmod`
by default for all Tumbleweed installations was no option. It would take away a protection mechanism
and therefor weaken the _Defense in Depth_ approach.<br>
Manually setting the boolean was needed to get the emulation layer
for Windows to function properly. To arrive at that solution the user needed a 
certain level of familiarity with the administration of SELinux. A transparent, but selective solution,
that would need no intervention from the user would be ideal to implement.

Implementation
---

We decided to introduce a new dependency to packaged gaming software in openSUSE Tumbleweed.
If a user installs the RPM version of Lutris or Steam, then the RPM `selinux-policy-targeted-gaming`
will now be installed as well, enabling the boolean on the user system automatically.
This solution improves usability for the users who install gaming software
and does not compromise the security of other use cases of the distribution.

A user preferring the Flatpak versions of Steam or Lutris can manually install the new package:

```sh
sudo zypper in selinux-policy-targeted-gaming
```

As we do not control the Flatpak applications, we can not add any
dependencies to them. As an alternative the user can also still set the boolean manually.


5) Closing Remarks
==================

The openSUSE SELinux team is committed to keeping openSUSE users safe with SELinux,
and to fixing problems that SELinux may cause to the community. To facilitate changes with SELinux we rely on users to work with us 
and provide feedback, so that we understand what the current problematic areas are.
If you encounter problems with SELinux feel free to open a [bug][bugreport] or reach out
over the [mailing list][maillist].


6) References
=============

- [Tumbleweed Adopts SELinux as Default][news:default]
- [openSUSE Bugreport SELinux][bugreport]
- [openSUSE SELinux Mailing List][maillist]

[news:default]: https://news.opensuse.org/2025/02/13/tw-plans-to-adopt-selinux-as-default/
[wiki:mac]: https://en.wikipedia.org/wiki/Mandatory_access_control
[upstream:policy]: https://github.com/fedora-selinux/selinux-policy
[gentoo:Using_SELinux_booleans]: https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans
[wiki:Executable-space_protection]: https://en.wikipedia.org/wiki/Executable-space_protection
[blog:text-relocations]: https://flameeyes.blog/2016/01/16/textrels-text-relocations-and-their-impact-on-hardening-techniques/
[man:user_selinux]: https://manpages.opensuse.org/Tumbleweed/selinux-policy-doc/user_selinux.8.en.html
[bugreport]: https://en.opensuse.org/openSUSE:Bugreport_SELinux
[maillist]: https://lists.opensuse.org/archives/list/selinux@lists.opensuse.org/
