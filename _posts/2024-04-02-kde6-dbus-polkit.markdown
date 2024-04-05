---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi</a> (proofread)
title:  "KDE6 release: D-Bus and Polkit Galore"
date:   2024-04-02
tags:   KDE local D-Bus Polkit
excerpt: "In the context of the KDE desktop version 6 major release we looked into a series of D-Bus services using Polkit for authentication. This led to a couple of interesting findings and insights."
---

Table of Contents
================
{:.no_toc}

* ToC
{:toc}

Introduction
============

The SUSE security team restricts the installation of system wide D-Bus
services and Polkit policies in openSUSE distributions and derived SUSE
products. Any package that ships these features needs to be reviewed by us
first, before it can be added to production repositories.

In November, openSUSE KDE packagers approached us [with a long list of KDE
components][kde-tracker] for an upcoming KDE6 major release. The packages
needed adjusted D-Bus and Polkit whitelistings due to renamed interfaces or
other breaking changes. Looking into this many components at once was a unique
experience that also led to new insights, which will be discussed in this
article.

For readers that are new to D-Bus and/or Polkit, the following sections offer
a summary to get a better idea about these systems.

D-Bus Overview
--------------

The [D-Bus message bus system][dbus-home] provides a defined way to implement
remote procedure calls in applications. On Linux it is usually only used
locally, although the D-Bus specification also allows for operation over the
network.

A D-Bus service is a program that provides one or more interfaces that can be
invoked by clients to obtain information, trigger operations and so on. The
D-Bus specification defines a set of data types that can be passed to and
returned from D-Bus method calls.

D-Bus applications reach each other by connecting to a shared bus of which
there exist two predefined types: the system bus and the session bus. Services
that perform system wide tasks connect to the system bus. These services often
run as `root` or as dedicated service users. A session bus, on the other hand,
is created for each (graphical) user session, and only applications running
with the privileges of the logged-in user can connect to it. No special
privileges are involved with the session bus. Its main purpose is to provide a
defined API for session wide services, like a desktop search engine.

Polkit Overview
---------------

[Polkit][polkit-manual] is an authorization framework that allows (privileged)
applications to decide whether a user in the system is allowed to perform a
specific action. These actions allow for a more fine-grained authorization
model when compared to a plain `root` vs. non-`root` decision. Examples could be
an action to enable a Bluetooth device in the system, or to mount a removable
storage device.

A Polkit policy configuration file declares actions used by a certain
application domain and the authentication requirements for it. When an actor
in the system asks an application that uses Polkit to perform an action, then
this application in turns asks the system-wide Polkit daemon whether this
actor is privileged to do so. Depending on the context this can, for example,
lead to a password prompt being displayed in a user's graphical session to
authorize the operation.

Polkit is independent of D-Bus, but the combination of both is a very common
pattern. Other manners in which Polkit can be used is in setuid-root binaries
or via the sudo-like `pkexec` utility.

Security Relevance of D-Bus and Polkit
--------------------------------------

The typical setup of D-Bus and Polkit is as follows: a system daemon is
running with full root privileges and registers a service on the D-Bus system
bus. An unprivileged user that is logged into a graphical session asks the
daemon via D-Bus to perform an activity. This triggers the Polkit
authentication process to determine whether the caller is allowed to do this.

Security-wise, there is quite a number of things that can go wrong in this
scenario. The following sections investigate typical issues that can arise.

### Covering all Privileged Code Paths

The system daemon actually needs to implement the Polkit authorization check
properly for every sensitive D-Bus method it offers. Polkit is not something
that is magically turned on, but the privileged component needs to identify
all the code paths that need to be protected by it.

Some applications deliberately offer a mix of unauthenticated and
authenticated D-Bus methods. In these cases it can sometimes be hard to keep
all the possible side effects and outcomes in mind, which can lead to security
issues when something is overlooked.

### Acting as root on Behalf of Unprivileged Users

The privileged D-Bus service component often needs to act on behalf of an
unprivileged client. An example could be mounting a file system in the
caller's home directory, or processing a file provided by the caller. This is
a classic crossing of privilege boundaries. Developers of such services are
often not aware of the problems that can arise, especially when accessing user
controlled paths as `root`.

Similarly, if a privileged D-Bus service stores data from multiple users in a
shared system directory, then information leaks can occur by storing files with
too open permissions, or by mixing up different user contexts.

### The Integration of Polkit can be Hard

Polkit has its own nomenclature and design principles that one needs to get
into, to fully understand it. Apart from this, even if Polkit is correctly
asked for permissions, the privileged service still needs to correctly
evaluate the result. A typical mistake that can happen in this area is when a
privileged service _does_ ask Polkit correctly for authentication, but the
result is simply ignored and the privileged operation continues regardless.

### Everybody can Access the D-Bus System Bus

By default, all local users can access the D-Bus system bus and talk to most
of the privileged services. Individual D-Bus service configuration files can
limit the scope of users that are allowed to invoke a D-Bus service's methods.
This setup is the exception, however, as the majority of D-Bus services is
accessible to all users.

This increases the attack surface notably, as not only an interactive user
account that is running an authorized local session can talk to these
services, but also e.g. the `nobody` user account. These days, many system
daemons running on the network only have limited privileges or even use
dynamically allocated users provided by systemd. If one of these network
daemons with low privileges can be exploited, then weaknesses in privileged
D-Bus system services can offer the possibility to further escalate
privileges.

This is one of the reasons why, as part of a defense-in-depth strategy, the
SUSE security team looks closely also into these components that aren't
directly attached to the network.

The KDE KAuth Framework
=======================

The KDE desktop environment is a heavy user of D-Bus services both on the
system and on the session bus. It adds further abstractions on top of D-Bus
and on top of Polkit. The base component for this is the [KAuth
framework][kauth-home]. KAuth generates D-Bus configuration files and some
glue code to integrate D-Bus and Polkit into KDE applications. In KAuth, a
privileged D-Bus service running as `root` is called a KAuth helper.

We performed a [dedicated follow-up review][kauth-review] of it for the KDE6
release. A former member of the SUSE security team had found [a major security
flaw][kauth-bypass] in this glue code in 2017. Since the audit at the time was
comprehensive, we did not expect to find any major issues in the core
authorization logic anymore, and in fact we didn't.

Problematic use of QVariantMap Serialized Data
----------------------------------------------

A peculiarity of KAuth is that, instead of the native D-Bus data types, only
binary blob objects are transferred on D-Bus level, that are based on the
`QVariantMap` data type offered by the Qt framework.

During the review we noticed that the implementation of this feature in KAuth
[is a bit shaky][kauth-deser-code], since potentially attacker controlled data
is processed during Qt data type deserialization, before the actual D-Bus
function callbacks are even invoked. In 2019, the upstream authors
[had already identified this problem][kauth-deser-workaround], that can lead
to side effects like image data being deserialized, where actually only
strings and integers are expected. The KAuth code currently meddles with
internal Qt framework state to prevent such side effects.

Problems with generated D-Bus drop-in Configuration Snippets
------------------------------------------------------------

Only late in our review efforts we realized that a change introduced with the
KDE6 release of KAuth leads to [overly open D-Bus configuration files being
generated][kauth-bad-dbus-config]. Per-package configuration snippets for
D-Bus are installed in "/usr/share/dbus-1/system.d". These configuration files
serve as a kind of firewall configuration for the D-Bus system bus. They
define who is allowed to register a D-Bus service for a certain interface and
also who is allowed to talk to it.

Here is a proper example taken from systemd-network's "org.freedesktop.network1.conf":

```
<busconfig>
        <policy user="systemd-network">
                <allow own="org.freedesktop.network1"/>
        </policy>

        <policy context="default">
                <allow send_destination="org.freedesktop.network1"/>
                <allow receive_sender="org.freedesktop.network1"/>
        </policy>
</busconfig>
```

This allows only the dedicated service user "systemd-network" to register the
D-Bus interface "org.freedesktop.network1", while any other users in the
system may talk to it.

The KAuth KDE6 release candidate generated this configuration instead:

```
<policy context="default">
  <allow send_destination="*"/>
</policy>
```

The ramifications of this can easily be overlooked: this states that everybody
is allowed to talk to everything on the D-Bus system bus. It also affects
other D-Bus services that should not be influenced by the drop-in
configuration snippet shipped for individual KDE packages. While most D-Bus
services running on the system bus are "public", i.e. everybody is allowed to
talk to them, some services follow a different security model in which only
dedicated users are allowed to interact with the service. We identified 
[ratbagd][ratbag-dbus-config] as one such D-Bus service that would be
negatively affected by this defect in KAuth. This shows that the security
posture of unrelated packages is at stake. Luckily we identified this
issue in time before the KDE6 release was finished, and the issue was fixed
before it reached production systems. We also checked any non-KDE D-Bus
configuration files we ship on openSUSE Tumbleweed for the same issue, but
luckily found no further files containing this issue.

These side effects are also in some sense shortcomings of the D-Bus
configuration scheme, since developers of a specific D-Bus service don't
expect that their configuration file has a global influence. A similar issue
exists for [logrotate][logrotate-freeradius] where settings in drop-in
configuration files in "/etc/logrotate.d" can influence global settings that
affect the complete system. This can lead to hard to find bugs in both cases,
D-Bus and logrotate, because the outcome also depends on the order in which
the configuration file snippets are parsed.

Legacy fontinst D-Bus service
=============================

Most of the KDE components that we have been requested to look into for the
KDE6 release had already been reviewed by us in recent years. A few of them
are legacy packages though, since they were already in stock when we
introduced packaging restrictions for D-Bus and Polkit. At the time we didn't
have enough resources to check all of them in one go.

One such legacy component [we encountered][fontinst-review] while looking into
the KDE6 release was the "org.kde.fontinst.service" which is part of the
"plasma6-workspace" package. What we found there is a single D-Bus method
"org.kde.fontinst.manage" that actually multiplexes a whole range of
sub-methods, based on a "method" string input parameter. This is bad design
since it undermines the D-Bus protocol, and thus makes the individual method
calls less visible and less manageable. This is reinforced by the fact that
also only a single Polkit action is used to authenticate all the sub-methods.
This way there is only an all-or-nothing setting for the various code paths
that are hidden behind this single D-Bus method call.

The available sub-methods in this service nearly make up a generic file system
I/O layer, especially when we remember that this service is running with full
root privileges:

- install: this can be used to copy arbitrary file paths to arbitrary
  locations, the new files end up with mode 0644.
- uninstall: this allows to remove arbitrary file paths, as long as their
  parent directories have a writable bit set.
- move: this allows to move arbitrary paths complete with new owner uid and
  group gid to arbitrary new locations.
- toggle: this takes raw XML that also seems to specify font paths that are
  to be enabled or disabled.
- removeFile: does what is says on the label; another way to remove files.
- configure: saves modified font directories and invokes a small bash script
  `fontinst_x11` that prepares font directories and triggers a font refresh at
  the X server.

The core business logic of the fontinst service should be managing system wide
fonts provided in the system. To achieve this, ideally only the necessary high
level logical operations should be offered like: Install a font from provided
data, remove a system font by name. Copying, removing and moving arbitrary
files is way outside of the scope of what this service is supposed to do.

The single Polkit action "org.kde.fontinst.manage" requires `auth_admin_keep`
authorization by default i.e. anybody that wants to invoke this method needs
to provide admin credentials. Still, if an admin decides to lower these
requirements, because users should be able to e.g. install new fonts in the
system, then this interface does not only allow that, but also allows to gain
full root privileges by copying arbitrary files around (e.g. by creating a new
"/etc/shadow" file).

This service requires a larger redesign. KDE upstream was not able to come up
with that in time for the KDE6 release. We hope that it will still happen
though, as the API is in a rather worrying state.

Woes with "unexpected" Polkit Settings
--------------------------------------

The situation in the fontinst service regarding the `auth_admin` setting is a
common pattern that we see when reviewing D-Bus services and Polkit actions.
Developers believe that requiring `auth_admin` authentication for a Polkit
action is enough to justify overly generic APIs or unsafe file system
operations carried out as `root`. In some cases it might be justifiable to say
that an action should never have weaker authentication requirements than
`auth_admin`, since it otherwise causes uncontrollable security issues. One
should not forget that Polkit is a _configurable_ authentication framework,
though. There are default settings shipped by applications, but system
integrators and admins are allowed to change these requirements.

The (open)SUSE Linux distributions are the only ones we know of, that offer a
[defined mechanism][polkit-default-privs-wiki] for admins to override the
Polkit defaults for individual actions via profiles and overrides. This works
via the [polkit-default-privs][polkit-default-privs-gh] package. Our experience
with this shows that upstream developers mostly neither consider the security
consequences of lowering the Polkit authentication requirements, nor test what
happens when the authentication requirements are raised for hardening
purposes. Raised authentication requirements lead to additional password
prompts, and some applications implement workflows involving Polkit actions
that lead to very unfortunate behaviour in such cases.

A common example of this is a package manager like Flatpak, that attempts to
acquire Polkit authentication for a repository refresh action upon login into
a graphical session. The developers only test this with the default `yes`
Polkit authentication requirement, which makes this authentication process
invisible to users. When raising this to `auth_admin`, then suddenly a password
prompt pops up during login and users are confused and annoyed. There are ways
to deal with this: for example, services using Polkit can ask it whether an
action can be authorized without user interaction. If this is not the case,
then a package manager could choose _not_ to refresh repositories just now.
Also multiple actions can be authenticated in groups using the
"org.freedesktop.policykit.imply" annotation to avoid multiple password
prompts coming up for a single workflow.

It is understandable that the configuration management of many different
Polkit configurations is hard to test for upstream developers. Increased
awareness of the general problems in this area would help to avoid these
issues in the first place. It seems that developers just want to "cram in"
authentication into their software, though, and stop thinking about it once
they're done. Granted, Polkit and D-Bus are far from simple when you're new to
them. Still, every authentication procedure should be given careful thought.
The take home lessons for developers implementing Polkit should be:

- Polkit is a _configurable_ authentication framework and the settings
  intended by developers might not be what actually happens during runtime.
- When modelling Polkit actions, one should take advantage of the possibility
  to make them fine grained, to allow users to fine tune the requirements for
  individual activities.
- Each Polkit authorization that happens in an application should be given
  some thought in both directions: what happens if the authentication
  requirement is lowered and what happens if it is raised?
- Another aspect that hasn't been discussed yet is the topic of authentication
  messages shown to the user. They should clearly state what exactly is being
  authorized in a form that non-technical users can understand. Polkit also
  supports placeholders in messages to fill in runtime information, like a file
  that is being operated on. Sadly, this feature is used very rarely in
  practice.

Problematic File System Operations in sddm-kcm6
===============================================

This component is a KDE Configuration Module (KCM) for the SDDM display
manager. It contains a D-Bus service "org.kde.kcontrol.kcmsddm.conf". We
reviewed it already in the past and [did so again][kcmsddm-review] for the
KDE6 release. The service has two major problems, discussed in the following
sections.

Unsafe Operations on File System Paths Provided by the Unprivileged D-Bus Client
--------------------------------------------------------------------------------

Multiple of the D-Bus methods provided by the sddm-kcm6 KAuth helper expect
file system paths as input parameters. Such passing of paths to privileged
D-Bus services is another problematic pattern that is often encountered. In
the [`openConfig()`][sddm-open-config] function, the provided path to a [SDDM
theme configuration file][sddm-path-as-arg] will be created by the helper, if
necessary.  If it already exists, then a `chmod()` of the path to mode `0600`
is performed, which is also following symlinks. To see how this can be
problematic, consider what happens if "/etc/shadow" is passed as theme
configuration path.

Operating as `root`, on files that are under control of an unprivileged user, is
notoriously hard to get right, and requires careful use of lower level system
calls. Often developers aren't even aware of this problem. KDE components have
had a number of problems in this area in the past. We believe this has
deeper roots, namely in the design of the Qt framework's file system API, which
on the one hand doesn't allow full control over the lower level system calls
(owed to the fact that Qt is also a platform abstraction layer), and on the
other hand does not document exactly what can be expected of its APIs
in this regard. Furthermore the Qt framework itself isn't aware of the fact
that it runs as root, possibly operating on files owned by other users. The Qt
libraries are designed for implementing feature rich GUI applications and
don't really consider handling untrusted input, operating with raised
privileges and crossing privilege boundaries.

An elegant way to avoid the path access issue in the first place is by not
passing file paths, but already opened file descriptors over D-Bus. This is
possible since D-Bus uses UNIX domain sockets internally, and they can be used
to pass file descriptors. So instead of passing a string from client to
service suggesting "Open this file, trust me, it's fine", the client passes a
file descriptor, opened using its own low privileges, to the privileged
service. With this, many path access issues are gone in an instant. There
are cases that still require care, however, for example if recursive file
system operations need to be carried out.

Unfortunately the KAuth framework used by KDE [shows a limitation in
this area][kauth-issue-comment-fds]. Since the KAuth helper's D-Bus API only
transfers binary blobs that result from serializing `QVariantMap`, there
is currently no possibility to pass an open file descriptor.

Changes in configuration files owned by the `sddm` service user
---------------------------------------------------------------

The other problem is not found in the D-Bus API, but in the implementation of
the `sync()` and `reset()` D-Bus methods. Once any input parameters from the
client are processed, the helper operates in the home directory belonging to
the `sddm` service user. Here is some condensed code taken from the reset()
and sync() functions:

```
// from SddmAuthHelper::reset()
QString sddmHomeDirPath = KUser("sddm").homeDir();
QDir sddmConfigLocation(sddmHomeDirPath + QStringLiteral("/.config"));
QFile::remove(sddmConfigLocation.path() + QStringLiteral("/kdeglobals"));
QFile::remove(sddmConfigLocation.path() + QStringLiteral("/plasmarc"));
QDir(sddmHomeDirPath + "/.local/share/kscreen/").removeRecursively();
```

```
// from SddmAuthHelper::sync()
QString sddmHomeDirPath = KUser("sddm").homeDir();

QDir sddmCacheLocation(sddmHomeDirPath + QStringLiteral("/.cache"));
if (sddmCacheLocation.exists()) {
    sddmCacheLocation.removeRecursively();
}

QDir sddmConfigLocation(sddmHomeDirPath + QStringLiteral("/.config"));

if (!args[QStringLiteral("kscreen-config")].isNull()) {
    const QString destinationDir = sddmHomeDirPath + "/.local/share/kscreen/";
    QSet<QString> done;
    copyDirectoryRecursively(args[QStringLiteral("kscreen-config")].toString(), destinationDir, done);
}
```

A compromised `sddm` service user can exploit these operations to its advantage:

- it can cause a denial-of-service by e.g. placing directory symlinks
  to have the D-Bus service operate in completely different file system
  locations. This attack is limited though, since the final path components
  used in removal calls need to match, like `kscreen`.
- it can cause the "kscreen-config" to be copied to arbitrary locations by
  placing a symlink in "~/.local/share/kscreen".

To make these operations safe, it would be best to temporarily drop privileges
to the `sddm` user.

Going Forward from Here
-----------------------

KDE upstream was not able to come up with a redesign of this D-Bus service in
time for the KDE6 release. In this instance, the unsafe operations in the `sddm`
user's home directory would formally even justify assignment of a CVE. Since
all the D-Bus methods are guarded by `auth_admin` Polkit authentication
requirements, the issues can at least not be exploited in default installations.

KWalletManager: Pseudo-Authentication to Protect the Configuration
==================================================================

KWalletManager is KDE's password manager. It features a GUI and, as one would
expect, runs in the context of the graphical user session of a logged-in user.
It ships a "savehelper" service that offers a single D-Bus method
"org.kde.kcontrol.kcmkwallet5.save". So what does a service helper running as
`root` need to save here? Let's look [at the implementation][kwalletmanager-service-code]:

```
ActionReply SaveHelper::save(const QVariantMap &args)
{
    Q_UNUSED(args);
    const qint64 uid = QCoreApplication::applicationPid();
    qDebug() << "executing uid=" << uid;
    return ActionReply::SuccessReply();
}
```

Turning this piece of code carefully to all sides will lead to the insight
that it does _nothing_. We [asked upstream][kwalletmanager-issue] to remove
this unused helper, but we've been told that this is not a mistake, but on
purpose. They want to protect against the following attack scenario: a user
leaves their computer alone and unlocked, a random person gets by and, of all
things, wants to change KWalletManager's settings. To prevent this from
happening, the GUI is asking the service helper to authenticate the action
requiring Polkit's `auth_self` authorization, and doesn't continue if this
fails.

This cannot stop a real attacker, though, since the KWalletManager
configuration is stored in the unprivileged user's home directory and can
still be edited directly, or using a modified version of KWalletManager that
simply does not ask for this authentication. Not to talk about _all the other
things_ that an attacker could do in such a situation. So where should one
draw a line to stop? We don't even see this as a hardening, it is fake security
and confusing. If such a fake authentication is really needed then at least a
way should be found to implement it, without requiring an authentication helper
running as `root` that does nothing. Upstream seems to disagree, but we asked our
packagers to remove this logic from our packaging via patches.

Improvements in DrKonqi
=======================

DrKonqi is KDE's crash handling utility. These days, it interacts with
systemd-coredump to access core dumps of applications. Our [previous 2022
review][drkonqi-prev-review] of it led to [a finding in
systemd-coredump itself][systemd-coredump-cve]. In the meantime DrKonqi
obtained additional D-Bus service logic to copy a private core dump (e.g. from
a process that was running as `root`) into the session of an unprivileged user
for analysis.

The [implementation of this][drkonqi-dbus-impl] is unusual for a KDE component
in so far as it doesn't rely on KAuth: it directly uses the Qt framework's D-Bus
and Polkit facilities. The likely reason for this is the shortcoming of KAuth
with regard to passing file descriptors, as discussed above. The single
`excavateFromToDirFd()` D-Bus method actually accepts a file descriptor.
It is supposed to be a file descriptor referring to a directory under control
of the unprivileged caller, where the selected core dump is to be copied to.
Even though this means that DrKonqi cannot benefit from the common framework
features of KAuth, it is security-wise a good example of how to improve the
robustness of a D-Bus service running as `root` and operating in the file
system.

Unfortunately, even with file descriptors issues can arise, as this example
also shows. The permission handling for directories is different from regular
files. Directories generally can only be opened in read-only mode
(`O_RDONLY`). Write permissions are only checked at the time a write attempt
is made, like when calling `renameat()` in the case of the DrKonqi helper.
This is too late. The unprivileged caller can open just any directory it has
read access for and pass it to the D-Bus service. The D-Bus service running as
`root` will now happily create new files in the directory even if the caller
doesn't have any write permissions for it.

There is a [constructive discussion][drkonqi-discussion] discussion going on
with upstream that led to various improvements in detail in this D-Bus service
[that are about to be merged][drkonqi-mr]. The issue with the dir file
descriptor was only found late in the process, but hopefully a solution for
the problem will be found soon.

Conclusion
==========

D-Bus and Polkit have their share of complexities that need to be understood
and managed well. This is important as a defense in depth measure even beyond
the local security of a Linux system. Putting additional layers on top, like in
the KAuth framework, can cause long-term problems, as can be seen from the lack
of support for passing file descriptors with the current KAuth API.

It was helpful that our KDE packagers and upstream approached us early about
the KDE6 release candidate and the changes it introduces. In some areas, like
the badly generated D-Bus KAuth configuration files, upstream quickly reacted
and applied fixes, thus avoiding that the problematic code was ever released
in a production version of KDE6. In other areas, like the legacy fontinst
D-Bus service or the sddm-kcm D-Bus service, the complexity of fixing API
issues has obviously been too high for upstream to come up with something
better in time. We decided not to ask for CVE assignments for the findings in
these services, since the attack vectors are not reachable to regular users in
the default Polkit configuration.

By now most KDE6 packages should have reached openSUSE Tumbleweed and can be
used in production.

References
==========

- [D-Bus Project Page][dbus-home]
- [Polkit Manual][polkit-manual]
- [KDE KAuth Framework Documentation][kauth-home]

Change History
==============

|2024-04-05|Minor spelling fixes; inserted an introductory paragraph to [Unsafe Operations in sddm-kcm6](#unsafe-operations-on-file-system-paths-provided-by-the-unprivileged-d-bus-client).|

[dbus-home]: https://www.freedesktop.org/wiki/Software/dbus/
[drkonqi-dbus-impl]: https://invent.kde.org/plasma/drkonqi/-/blob/Plasma/6.0/src/coredump/polkit/main.cpp?ref_type=heads#L34
[drkonqi-discussion]: https://bugzilla.suse.com/show_bug.cgi?id=1220190#c6
[drkonqi-mr]: https://invent.kde.org/plasma/drkonqi/-/merge_requests/217
[drkonqi-prev-review]: https://bugzilla.suse.com/show_bug.cgi?id=1203493
[fontinst-review]: https://bugzilla.suse.com/show_bug.cgi?id=1217186
[kauth-bad-dbus-config]: https://bugzilla.suse.com/show_bug.cgi?id=1220215
[kauth-bypass]: https://bugzilla.suse.com/show_bug.cgi?id=1036244
[kauth-deser-code]: https://invent.kde.org/frameworks/kauth/-/blob/4e94f01d3a191861c8095f673d70291dc225f23e/src/backends/dbus/DBusHelperProxy.cpp#L218
[kauth-deser-workaround]: https://invent.kde.org/frameworks/kauth/-/commit/fc70fb0161c1b9144d26389434d34dd135cd3f4a
[kauth-home]: https://api.kde.org/frameworks/kauth/html/
[kauth-issue-comment-fds]: https://invent.kde.org/frameworks/kauth/-/issues/3#note_826581
[kauth-review]: https://bugzilla.suse.com/show_bug.cgi?id=1217178
[kcmsddm-review]: https://bugzilla.suse.com/show_bug.cgi?id=1217188
[kde-tracker]: https://bugzilla.suse.com/show_bug.cgi?id=1217076
[kwalletmanager-issue]: https://invent.kde.org/utilities/kwalletmanager/-/issues/4
[kwalletmanager-service-code]: https://invent.kde.org/utilities/kwalletmanager/-/blob/master/src/konfigurator/savehelper.cpp
[logrotate-freeradius]: https://bugzilla.suse.com/show_bug.cgi?id=1180525
[polkit-default-privs-gh]: https://github.com/openSUSE/polkit-default-privs
[polkit-default-privs-wiki]: https://en.opensuse.org/openSUSE:Security_Documentation#Configuration_of_Polkit_Settings
[polkit-manual]: https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html
[ratbag-dbus-config]: https://github.com/libratbag/libratbag/blob/v0.17/ratbagd/org.freedesktop.ratbag1.conf
[systemd-coredump-cve]: https://www.openwall.com/lists/oss-security/2022/12/21/3
[sddm-path-as-arg]: https://invent.kde.org/plasma/sddm-kcm/-/blob/Plasma/6.0/sddmauthhelper.cpp?ref_type=heads#L280
[sddm-open-config]: https://invent.kde.org/plasma/sddm-kcm/-/blob/Plasma/6.0/sddmauthhelper.cpp?ref_type=heads#L30
