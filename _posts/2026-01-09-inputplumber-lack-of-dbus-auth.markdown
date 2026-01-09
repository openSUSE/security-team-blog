---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "InputPlumber: Lack of D-Bus Authorization and Input Verification allows UI Input Injection and Denial-of-Service (CVE-2025-66005, CVE-2025-14338)"
date:   2026-01-09
tags:   CVE D-Bus Polkit
excerpt: "InputPlumber is a utility for combining Linux input devices into
virtual input devices. It includes a D-Bus daemon offering an interface to all
users in the system. A lack of D-Bus client authorization in versions before
v0.69.0 allows arbitrary local users to inject key presses into active sessions
or to perform local Denial-of-Service attacks against InputPlumber."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[InputPlumber][upstream:project] is a utility for combining Linux input
devices into virtual input devices. It is mostly used in the context of Linux
gaming and is part of [SteamOS][upstream:steamos].

An openSUSE community member packaged InputPlumber which [required a
review][bugzilla:review-bug] by the SUSE security team, as it contains a D-Bus
system service. The first version of InputPlumber we reviewed was completely
lacking client authentication, causing us to reject it. A follow-up version
contained Polkit authentication, which turned out to be lacking in multiple
regards. At this point we approached upstream with a detailed report and
established coordinated disclosure. Starting with [version
v0.69.0][upstream:bugfix-release] of InputPlumber most (but not all) of the
issues in this report have been addressed. SteamOS also [published new
images][upstream:steamos-bugfix] for version 3.7.20 containing the fixes.

This report is based on [InputPlumber release v0.67.0][upstream:review-release].
The [next section][section:overview] provides an overview of
InputPlumber's D-Bus service. [Section 3][section:issues] looks into the
security issues in detail. [Section 4][section:suggested-fixes] discusses the
fixes we suggested to upstream. [Section 5][section:bugfixes] looks into the
upstream bugfixes to address the issues and aspects that remain unfixed.
[Section 6][section:cves] covers the CVE assignments we did for the issues we
found. [Section 7][section:disclosure] provides a summary of the coordinated
disclosure process we followed for this report.

{: #section-overview}
2) Overview of the D-Bus Service
================================

InputPlumber is implemented in Rust and the size of the code base is surprisingly
high for this type of project, adding up to about 50,000 lines of code
overall (not counting vendor code) and about 3,000 lines dedicated to the
D-Bus API specifically.

The InputPlumber D-Bus service runs with full root privileges, offering the
["org.shadowblip.InputManager" interface][code:dbus-manager] on the D-Bus
system bus. Additionally various interfaces representing Linux input devices
are provided by the daemon, like a [keyboard interface][code:dbus-keyboard].
In summary the service provides around 90 different D-Bus properties and about
10 different interfaces on various objects exported by it. The [Polkit
policy][code:polkit-policy] lists over 100 different actions, controlling
every aspect of the D-Bus API including read/write access to individual
properties.

{: #section-issues}
3) Security Issues
==================

3.1) Lack of Authentication / Polkit Authentication Bypass
----------------------------------------------------------

Initially we looked into InputPlumber [version
v0.62.2][upstream:noauth-release]. In this version there is no Polkit
authorization at all for the D-Bus interfaces. There are also no
restrictions in the configuration of the D-Bus service, allowing all users in
the system to connect to it, even low privilege user accounts like `nobody`.

We thought about reaching out to upstream already at this point, when we
noticed that in InputPlumber [version v0.63.0][upstream:polkit-release] (which
was meanwhile published on GitHub) Polkit authentication had been added via
[commit 0a80f3d85][commit:initial-polkit]. Thus we asked our community
maintainer to update the package to at least that version for us to have
another look.

Due to other priorities we only got around to taking a fresh look at the
package at a later time, when the package had already been updated to [version
v0.67.0][upstream:review-release], on which this report is based.

Looking into this version we first discovered that the Polkit authentication
was still not effective in the package build provided to us. The reason for
this was that Polkit support was only a compile-time feature on Rust Cargo
configuration level - which was [disabled by
default][commit:polkit-cargo-feature]. We believe that in this version there
is also no canonical way to enable the feature when using the
[Makefile][code:makefile] found in the repository. For this reason we created
our own build of InputPlumber and applied a patch to hard-enable the Polkit
feature for testing.

In this custom package build of InputPlumber the Polkit authentication
triggered as expected. While looking into the implementation of the [Polkit
authentication wrapper][code:polkit-auth], however, we noticed that the Polkit
authentication logic uses the "unix-process" Polkit subject in an unsafe way.
It retrieves the caller's PID from the D-Bus connection and passes this
information on to the Polkit daemon. This suffers from a race condition,
because the client can attempt to have its PID replaced by a privileged
process by the time `polkitd` gets around to actually look at the credentials
of the process.

This is a well-known issue when using the "unix-process" Polkit subject which
was assigned [CVE-2013-4288][cve:polkit-race] in the past. For this reason the
subject has been marked as deprecated in Polkit. The "unix-process" subject
[is seeing new use][commit:polkit-pidfd-support] these days, however, when
combined with the use of Linux PID file descriptors, which are not affected by
the race condition.

In summary none of the versions of InputPlumber we looked into provided
sufficient authentication, even if integrators would have managed to actually
enable the Polkit layer in versions v0.63.0 and later. Thus all InputPlumber
D-Bus methods can be considered accessible by all users in the system without
authentication.

3.2) D-Bus Methods Allowing Privilege Escalation
------------------------------------------------

Considering the unprivileged access to the D-Bus methods provided by
InputPlumber, the following two methods quickly caught our attention as being
problematic:

### __`CreateCompositeDevice(in  s config_path)`__

[This method][code:create-composite] parses the provided input path as YAML to
create a CompositeDevice configuration and suffers from the following issues:

* The method allows to perform file existence tests, by passing paths usually
  not accessible to the caller.
* The method allows for a local Denial-of-Service (e.g. by passing `/dev/zero`
  as input file, leading to memory exhaustion in InputPlumber).
* The method allows for an information leak, e.g. from `/root/.bash_history`:
  ```sh
  user $ gdbus call -y -d org.shadowblip.InputPlumber -o /org/shadowblip/InputPlumber/Manager \
      -m org.shadowblip.InputManager.CreateCompositeDevice /root/.bash_history
  Error: GDBus.Error:org.freedesktop.DBus.Error.Failed: Unable to deserialize: invalid type: string "cd /etc/polkit-1/rules.d/", expected struct CompositeDeviceConfig at line 2 column 1
  ```
  The string `cd /etc/polkit-1/rules.d` is an entry from `root`'s history file
  in this case.

### __`CreateTargetDevice(in s kind)`__

[This method][code:create-target] allows to create a virtual keyboard input
device like this:

```sh
user $ gdbus call -y -d org.shadowblip.InputPlumber -o /org/shadowblip/InputPlumber/Manager \
   -m org.shadowblip.InputManager.CreateTargetDevice keyboard
```

Once the virtual keyboard has been created, key presses can be injected into
the active user session (login terminal or graphical desktop) like this:

```sh
user $ gdbus call -y -d org.shadowblip.InputPlumber -o /org/shadowblip/InputPlumber/devices/target/keyboard0 \
    -m org.shadowblip.Input.Keyboard.SendKey KEY_R true
```

All supported key symbols are found in [`keyboard.rs`][code:keyboard-symbols].
Using this ability, any user in the system can inject input to an active
desktop session or the active login terminal screen, possibly leading to
arbitrary code execution in the context of the currently logged in user, if
any.

{: #section-suggested-fixes}
4) Suggested Fixes
==================

We suggested the following action items to upstream to improve the security of
the InputPlumber D-Bus API:

- Use of the "system bus name" Polkit subject to fix the authentication code.
- Enabling of Polkit authorization by default in the build process.
- Passing of file descriptors instead of path names to D-Bus methods. This way
  the complexity of safely accessing client-provided paths is avoided and
  various attack scenarios in this area are no longer relevant.
- Addition of documentation pointing out that unauthorized access to the D-Bus
  service has security implications.
- Addition of hardening to the `inputplumber` systemd service. By using settings
  like `ProtectSystem=full` the service can be tightened to avoid any unexpected
  side effects when things go wrong at the first line of defense.

{: #section-bugfixes}
5) Upstream Bugfixes
====================

Upstream mostly followed our suggestions and fixed the issues as follows:

- in [commit 4db3b20][bugfix:system-bus-name] the Polkit subject used for
  authentication has been switched to "system bus name", therefore fixing the
  Polkit authentication bypass.
- in [commit f3854be][bugfix:polkit-default] the "Polkit" Cargo feature is
  enabled by default.
- in [commit 79f0745][bugfix:systemd-hardening] systemd hardening is applied
  to the InputPlumber service.

All of these fixes are contained in InputPlumber version
[v0.69.0][upstream:bugfix-release] and later.

Upstream initially wanted to avoid breaking the D-Bus API by switching to file
descriptors instead of path names, as we suggested. We strongly recommended to
do this, however, to avoid various issues that can occur when clients pass
malicious file paths. An upstream developer then [created a pull
request][bugfix:pending-api-break] which introduces file descriptors in the API.
We provided feedback that this is going in the right direction, but suggested to
also perform checks on the file descriptors passed by clients to make sure they
refer to regular files and have no unusual open flags like `O_PATH` set.

{: #marker-missing-fixes}
At the time of publication of this report we noticed that the improvements of
the D-Bus API to use file descriptors have not been merged yet and are not
available in a release. Thus some aspects of the issues described in this
report remain unaddressed, although they are now at least protected by proper
Polkit authentication. Sensitive methods like `CreateCompositeDevice` also
require [admin privileges to be called][code:create-composite-action], thus
these are mostly defense-in-depth issues, or only relevant when integrators
or admins relax Polkit authentication requirements.

{: #section-cves}
6) CVE Assignment
=================

In agreement with upstream we performed the following CVE assignments
corresponding to this report:

- CVE-2025-66005: lack of authorization of the InputManager D-Bus interface in
  InputPlumber versions before v0.63.0 can lead to local Denial-of-Service,
  information leak or even privilege escalation in the context of the
  currently active user session.

- CVE-2025-14338: Polkit authentication disabled by default and a race
  condition in the Polkit authorization check in versions before v0.69.0 can
  lead to the same issues as in CVE-2025-66005.

{: #section-disclosure}
7) Coordinated Disclosure
=========================

We informed upstream about the security issues on 2025-11-25 and offered
coordinated disclosure. Upstream quickly confirmed the issues and agreed to
follow coordinated disclosure. The developers discussed bugfixes with us, which
they provided in public GitHub pull requests. This way the information about
the issues was not fully private anymore, but we agreed to keep the full
report private for a longer time, until new SteamOS images would be published,
containing a fixed InputPlumber.

We found out only at the time of publication that [not all aspects of the
issues have been addressed][marker:missing-fixes] in the bugfix release.

We want to thank the InputPlumber developers for their cooperation regarding
this report.

8) Timeline
===========

|2025-11-21|We contacted one of the developers of InputPlumber, asking for the proper security contact for the project.|
|2025-11-21|We got a swift reply and learned that we reached the correct person for security reports already.|
|2025-11-25|We forwarded a detailed report outlining the issues in InputPlumber to upstream, offering coordinated disclosure.|
|2025-11-25|Upstream confirmed the issues and opted for coordinated disclosure.|
|2025-12-08|Upstream pointed us to a couple of public pull requests which should address the issues and asked us to review them.|
|2025-12-10|We provided feedback on the pull requests. The D-Bus API still used client-controlled paths at this point, and we suggested to turn them into file descriptors. We also pointed out that the issues were no longer fully private in light of the public pull requests, but suggested to keep the full report private for longer until an agreed upon date.|
|2025-12-10|We [assigned CVEs][section:cves] for the issues and communicated them to upstream.|
|2025-12-12|Upstream informed us that they wanted to keep the original D-Bus API stable, but agreed to add an additional fix to use file descriptors anyway.|
|2025-12-16|We asked upstream whether they were able to agree on a general publication date for the report by now.
|2025-12-22|Upstream pointed us to [another public GitHub pull request][bugfix:pending-api-break] introducing file descriptors in the D-Bus API.|
|2025-12-22|Upstream informed us that the publication date still needed further internal discussions and that they would get back to us.|
|2025-12-23|We provided feedback to upstream about the additional pull request. We generally agreed with the change but suggested to also check file descriptor type and flags on the service side, to avoid unexpected file descriptors being passed by clients.|
|2025-12-27|Upstream informed us that Valve was planning to publish new SteamOS images containing the InputPlumber fixes on January 9, which was agreed upon for general publication date of the full report.|
|2025-01-09|Upstream informed us about publication of the [new SteamOS images][upstream:steamos-bugfix], thanking us for our support.|
|2025-01-09|Publication of this report.|

9) References
=============

- [InputPlumber GitHub project][upstream:project]
- [InputPlumber Bugfix Release v0.69.0][upstream:bugfix-release]
- [SteamOS Images 3.7.20 Beta][upstream:steamos-bugfix] containing a fixed InputPlumber

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1249149
[code:dbus-manager]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/src/dbus/interface/manager.rs#L38
[code:dbus-keyboard]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/src/dbus/interface/target/keyboard.rs#L27
[code:create-composite]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/src/dbus/interface/manager.rs#L141
[code:create-target]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/src/dbus/interface/manager.rs#L165
[code:keyboard-symbols]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/src/dbus/interface/target/keyboard.rs#L64
[code:makefile]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/Makefile
[code:polkit-auth]: https://github.com/ShadowBlip/InputPlumber/blob/413c37c85e89d04fffcf53bd62312256e7324a86/src/dbus/polkit.rs#L31
[code:create-composite-action]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/rootfs/usr/share/polkit-1/actions/org.shadowblip.InputPlumber.policy#L206
[code:polkit-policy]: https://github.com/ShadowBlip/InputPlumber/blob/v0.67.0/rootfs/usr/share/polkit-1/actions/org.shadowblip.InputPlumber.policy
[upstream:project]: https://github.com/ShadowBlip/InputPlumber
[upstream:steamos]: https://store.steampowered.com/steamos
[upstream:steamos-bugfix]: https://steamcommunity.com/games/1675200/announcements/detail/500594947381003216
[upstream:review-release]: https://github.com/ShadowBlip/InputPlumber/releases/tag/v0.67.0
[upstream:noauth-release]: https://github.com/ShadowBlip/InputPlumber/releases/tag/v0.62.2
[upstream:bugfix-release]: https://github.com/ShadowBlip/InputPlumber/releases/tag/v0.69.0
[upstream:polkit-release]: https://github.com/ShadowBlip/InputPlumber/releases/tag/v0.63.0
[section:overview]: #section-overview
[section:issues]: #section-issues
[section:bugfixes]: #section-bugfixes
[section:suggested-fixes]: #section-suggested-fixes
[section:cves]: #section-cves
[section:disclosure]: #section-disclosure
[marker:missing-fixes]: #marker-missing-fixes
[commit:initial-polkit]: https://github.com/ShadowBlip/InputPlumber/commit/0a80f3d85741195af3d5501beacd363933c56b1b
[commit:polkit-cargo-feature]: https://github.com/ShadowBlip/InputPlumber/commit/8a201ec27e898ca07868ba9adc27191fca030969
[commit:polkit-pidfd-support]: https://github.com/polkit-org/polkit/commit/9295e289cdb1b6cf2747ecf07054230e15edb385
[cve:polkit-race]: https://nvd.nist.gov/vuln/detail/CVE-2013-4288
[bugfix:system-bus-name]: https://github.com/ShadowBlip/InputPlumber/commit/4db3b20ad9f5f21a7cbc54a9144443c9c4899249
[bugfix:polkit-default]: https://github.com/ShadowBlip/InputPlumber/commit/f3854be20099cff564aa9699632f71074f5c96ee
[bugfix:systemd-hardening]: https://github.com/ShadowBlip/InputPlumber/commit/79f0745b61b588a0ff1d29c8f45d05054ea5f138
[bugfix:pending-api-break]: https://github.com/ShadowBlip/InputPlumber/pull/477
