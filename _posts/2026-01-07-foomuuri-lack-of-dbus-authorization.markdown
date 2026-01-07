---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "Foomuuri: Lack of Client Authorization and Input Verification allow Control over Firewall Configuration (CVE-2025-67603, CVE-2025-67858)"
date:   2026-01-07
tags:   CVE D-Bus
excerpt: "Foomuuri is an nftables-based firewall manager for Linux. It
contains a privileged D-Bus service which allows to change the firewall
configuration. A lack of D-Bus client authorization and input data
verification allow arbitrary local users to completely control the system's
firewall configuration in Foomuuri before version 0.31."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[Foomuuri][upstream:project] is an nftables-based firewall manager for Linux.
The project includes a D-Bus daemon which offers an API similar to
firewalld. In early December an openSUSE community member [asked us to review
Foomuuri][bugzilla:review] for addition to openSUSE Tumbleweed.

During the review we quickly noticed a lack of client authorization and input
validation in the implementation of Foomuuri's D-Bus service. We reported the
issues to upstream and performed coordinated disclosure. Upstream published
[version 0.31][upstream:bugfix-release] of Foomuuri on 2026-01-07 which
contains bugfixes for the security issues.

The [next section][section:overview] provides an overview of the Foomuuri
D-Bus service. [Section 3)][section:issues] discusses the security issues in
detail. [Section 4)][section:bugfixes] provides an overview of the upstream
bugfixes to address the issues. [Section 5)][section:cves] looks into the CVEs
which were assigned. [Section 6)][section:disclosure] gives insight into the
coordinated disclosure process which was established for these findings.

This report is based on [Foomuuri release v0.29][upstream:review-release].

{: #section-overview}
2) Overview of the D-Bus Service
================================

Foomuuri runs with full root privileges and [registers a D-Bus
interface][code:dbus-setup] under the name"fi.foobar.Foomuuri1". Optionally a
firewalld drop-in replacement interface is also registered under
"org.fedoraproject.FirewallD1". Both interfaces hook into the same logic,
however, and there is no need to look at them separately.

There are [only a few methods][code:dbus-methods] provided by the D-Bus
interface: getting the list of available zones and managing the assignment of
network interfaces to zones.

{: #section-issues}
3) Security Issues
==================

{: #section-auth-issue}
3.1) Lack of Client Authorization
---------------------------------

There is no authentication layer like Polkit present in the Foomuuri D-Bus
service, and there are also no restrictions [on D-Bus configuration
level][code:dbus-config] as to who is allowed to connect to the D-Bus
interfaces provided.

As a result any local user, including low privilege service user accounts or
even `nobody`, can invoke the D-Bus interface and change the firewall
configuration. The only state which can be modified this way is the assignment
of interfaces to zones, but this is enough to weaken the firewall
configuration or to perform a limited Denial-of-Service.

{: #section-input-verification}
3.2 Missing Input Parameter Verification
----------------------------------------

Apart from the lack of access restrictions pointed out above, the input
parameters to the D-Bus methods are not carefully scrutinized. While the `zone`
input parameter is at least checked [against currently configured
zones][code:change-zone-check], no further checks are performed on the
`interface` parameter. This means that, e.g. via the "addInterface" D-Bus
method, arbitrary strings can be passed as interface name. There is also
intentionally no check if the specified name corresponds to an existing
network device in the system (to allow seamless coverage of network devices
even before they are added to the system).

One result from this can be log spoofing, since the `interface` name is
passed to logging functions unmodified. The string could contain control
characters or newlines, which can manipulate the log.

In [`DbusCommon.add_interface()`][code:interface-json-use] the possibly
crafted interface name is added to the to-be-generated JSON configuration via
the `out()` method. While we did not verify whether this works in practice, a
local attacker could attempt to largely control the JSON configuration passed
to `nftables`, by skillfully embedding additional JSON configuration in the
`interface` parameter.

We were worried that this could even lead to arbitrary code execution by
abusing features of `nftables` like loading external files or plugin code, but
it turned out that there are no such features available in the `nftables`
configuration format.

{: #section-umask-issue}
3.3) Unsafe `umask` used in Daemonize Code
------------------------------------------

Foomuuri contains optional support to daemonize itself. Normally this is done
by systemd and the code in question is not invoked. It [contains
logic][code:daemonize] to set the daemon's `umask` to 0, however, which is a bad
default, since applications or libraries which intend to foster user control of
the file mode of newly created files can pass modes like `0666` to `open()`,
rendering them world-writable.

Foomuuri does not contain any code paths that create new files, but the `umask`
setting is also inherited by child processes, for example. While we did not
think this was a tangible security issue in this form, we suggested to choose a
more conservative value here to prevent future issues.

{: #section-bugfixes}
4) Upstream Bugfixes
====================

We suggested the following fixes to upstream:

- restrict access to the D-Bus interfaces to `root` only, maybe also to
  members of a dedicated opt-in group. Alternatively Polkit could be used for
  authentication of callers, which is more effort and complex, however.
- the `interface` input parameter should be verified right from the
  beginning of each D-Bus method to make sure that it does not contain
  any whitespace or special characters and is not longer than `IFNAMSIZ` bytes
  (which is currently 16 bytes on Linux).
- as an additional hardening measure we also suggested to apply systemd
  directives like `ProtectSystem=full` to Foomuuri's systemd services,
  to prevent possible privilege escalation should anything go wrong at
  the first line of defense.

Upstream decided to implement Polkit authentication for Foomuuri's D-Bus
service and otherwise followed closely our suggestions:

- commit [5944a42][commit:polkit-auth] adds Polkit authentication to the D-Bus
  service. Changing firewall settings now requires admin authorization.
  The use of Polkit can be disabled in Foomuuri, in which case only clients
  with UID 0 are allowed to perform the operations.
- commit [d1961f4][commit:interface-verification] adds verification of the
  `interface` parameter to prevent manipulation of the JSON configuration
  data.
- commit [806e11d][commit:umask] sets the `umask` used in the daemonize code
  to a more conservative `0o022` setting, preventing world- or group-writable
  files from coming into existence.
- commit [5fcf125][commit:protect-system] adds the `ProtectSystem=full`
  directive to all Foomuuri systemd service units.

All of the bugfixes are contained in [version 0.31][upstream:bugfix-release]
of Foomuuri.

{: #section-cves}
5) CVE Assignment
=================

In agreement with upstream we assigned the following two CVEs corresponding to
this report:

- CVE-2025-67603: lack of client authorization allows arbitrary users to
  influence the firewall configuration ([issue 3.1][section:auth-issue]).

- CVE-2025-67858: a crafted `interface` input parameter to D-Bus methods can
  lead to integrity loss of the firewall configuration or further unspecified
  impact by manipulating the JSON configuration passed to `nft`
  ([issue 3.2][section:input-verification]).

{: #section-disclosure}
6) Coordinated Disclosure
=========================

We reported these issues to the upstream developer on 2025-12-11, offering
coordinated disclosure. We soon got a reply and discussed the details of the
non-disclosure process. Upstream quickly shared patches with us for review and
we agreed on the final patches already on 2025-12-19. In light of the
approaching Christmas season we agreed on a publication date of 2026-01-07
for general disclosure.

We want to thank the upstream author for the prompt reaction and cooperation
in fixing the issues.

7) Timeline
===========

|2025-12-11|We contacted the Foomuuri developer by email providing a detailed report about the D-Bus related findings and offered coordinated disclosure.|
|2025-12-12|The upstream author confirmed the issues, agreed to coordinated disclosure and asked us to assign CVEs the way we suggested them. 2026-01-07 was suggested for publication date.|
|2025-12-15|We discussed some additional technical details like the [umask issue][section:umask-issue] and the question of whether arbitrary code execution could result from the ability to control the JSON configuration passed to `nft`.|
|2025-12-18|Upstream shared with us a first version of patches for the issues we reported. The patches for minor issues and hardening were already published on GitHub at this point.|
|2025-12-19|We provided feedback on the patches, suggesting minor improvements.|
|2025-12-19|With the fixes ready we discussed whether earlier publication would make sense, but we agreed to stick to the date of 2026-01-07 to accommodate the Christmas holiday season.|
|2026-01-07|Upstream [release v0.31][upstream:bugfix-release] was published.|
|2026-01-07|Publication of this report.|

8) References
=============

- [Foomuuri GitHub project][upstream:project]
- [Foomuuri v0.31 Bugfix Release][upstream:bugfix-release]

[upstream:project]: https://github.com/FoobarOy/foomuuri
[upstream:review-release]: https://github.com/FoobarOy/foomuuri/releases/tag/v0.29
[upstream:bugfix-release]: https://github.com/FoobarOy/foomuuri/releases/tag/v0.31
[bugzilla:review]: https://bugzilla.suse.com/show_bug.cgi?id=1254385
[code:dbus-setup]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/src/foomuuri#L2856
[code:dbus-methods]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/src/foomuuri#L2763
[code:dbus-config]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/firewalld/fi.foobar.Foomuuri-FirewallD.conf#L20
[code:change-zone-check]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/src/foomuuri#L2698
[code:interface-json-use]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/src/foomuuri#L2692
[code:daemonize]: https://github.com/FoobarOy/foomuuri/blob/c532cc902a402bbaf88e90a972d078649425f34b/src/foomuuri#L244
[commit:umask]: https://github.com/FoobarOy/foomuuri/commit/806e11d59c1e582452668cec3b68397e4cbf71b3
[commit:protect-system]: https://github.com/FoobarOy/foomuuri/commit/5fcf1254537604b0b609047519efedeb7a2fd2cb
[commit:polkit-auth]: https://github.com/FoobarOy/foomuuri/commit/5944a428f53a132fc343ff6792b1b7539f1c990e
[commit:interface-verification]: https://github.com/FoobarOy/foomuuri/commit/d1961f420600d133e5f1d3125deb17445e7745ac
[section:overview]: #section-overview
[section:issues]: #section-issues
[section:bugfixes]: #section-bugfixes
[section:cves]: #section-cves
[section:disclosure]: #section-disclosure
[section:auth-issue]: #section-auth-issue
[section:umask-issue]: #section-umask-issue
[section:input-verification]: #section-input-verification
