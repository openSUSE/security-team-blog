---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)"
date:   2025-01-24
tags:   local D-Bus deepin CVE
excerpt: "dde-api-proxy is a component of the Deepin desktop environment
that provides backward compatibility for legacy D-Bus service and interface
names. We discovered a major authentication flaw in the design of this D-Bus
proxy component."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

We received a [review request][deepin-proxy-bugzilla] for the
[Deepin api-proxy D-Bus service][deepin-proxy-github] which is part of the
[Deepin desktop environment][deepin-website]. During the review we discovered
a major authentication flaw in the design of this D-Bus service which allows
local users to escalate privileges in various ways.

We reported this issue privately to Deepin security in December and did not
receive a reply for a month. As we were preparing for publication, upstream
became alive and quickly released a bugfix which is, sadly, still incomplete.

This report is based on [dde-api-proxy version
1.0.17][deepin-proxy-reviewed-version]. The findings still apply to release
1.0.18. Upstream has attempted to fix these findings in release 1.0.19, but
the bugfix is insufficient as outlined in section 6).

2) Authentication Bypass Issue
==============================

Dde-api-proxy runs as `root` and provides various D-Bus services on the
D-Bus system bus. It sticks out since it ships a lot of D-Bus configuration
files but only little code. The reason for this is that the service only
forwards D-Bus requests between its clients and the actual Deepin D-Bus
services. We believe this is for backward compatibility due to changes in
Deepin D-Bus interface names, alas the [component's GitHub
repository][deepin-proxy-github] provides little insight into its
purpose.

During startup the proxy service proactively registers the requested legacy
D-Bus interface and creates a connection to the actual Deepin D-Bus service,
to which messages will be forwarded to. When a client sends a message to one
of the legacy service names, the proxy synchronously forwards the message
(see [`handleMessage()`][deepin-proxy-handle-msg]) via its existing connection
and returns the reply to the client.

This rather straightforward approach of proxying D-Bus messages has a major
security flaw, however:

- the proxy runs as `root`.
- the proxy forwards messages from arbitrary local users to the actual D-Bus
  services without any authentication requirements.
- the actual D-Bus services don't know about the proxy situation, they believe
  that `root` is asking them to perform operations.

Consequently with the help of dde-api-proxy, legacy D-Bus methods that
normally wouldn't be accessible to non-root users will become accessible
without authentication.

3) Reproducers
==============

D-Bus Method without Polkit
---------------------------

Following is a simple demonstration of the issue based on the Deepin Grub2
service. This service simply checks the UID of the D-Bus client for
authentication of privileged operations. In the first command shown below the
actual D-Bus service name is used, and the service rejects the operation,
because the caller is not privileged:

```sh
user$ gdbus call -y -d org.deepin.dde.Grub2 \
    -o /org/deepin/dde/Grub2 -m org.deepin.dde.Grub2.SetTimeout 100
Error: GDBus.Error:org.deepin.dde.DBus.Error.Unnamed: not allow :1.167 call this method
```

In the next command the legacy D-Bus service name is used, and this time the
target service performs the operation, because it believes the request
originates from a privileged UID 0 client (dde-api-proxy):

```sh
user$ gdbus call -y  -d com.deepin.daemon.Grub2 \
    -o /com/deepin/daemon/Grub2 -m com.deepin.daemon.Grub2.SetTimeout 10
()
```

D-Bus method using Polkit
-------------------------

In the previous example Polkit authentication was not involved. When it is
involved then the caller is treated as "admin", resulting in a similar
escalation of privileges. We found a suitable example using Polkit in the
Deepin accounts service. This service offers a large range of system
operations, among them the possibility to add users to groups. It checks the
authorization of the "org.deepin.dde.accounts.user-administration" Polkit
action, which is by default only allowed for users in a local session if they
provide admin credentials.

The following `gdbus` call attempts to add the unprivileged user with UID 1000
to the `root` group. The call only works this way when it runs from within a
(Deepin) graphical session. The actual accounts service interface is invoked
here, thus the operation fails (it would require entering a root password).

```sh
user$ gdbus call -y -d org.deepin.dde.Accounts1 -o /org/deepin/dde/Accounts1/User1000 \
    -m org.deepin.dde.Accounts1.User.AddGroup root
Error: GDBus.Error:org.deepin.dde.DBus.Error.Unnamed: Policykit authentication failed
```

When switching to the legacy accounts service interface offered by
dde-api-proxy, the operation succeeds without any authentication request,
because the accounts service again believes root with UID 0 is the client
asking for this:

```sh
user$ gdbus call -y -d com.deepin.daemon.Accounts -o /com/deepin/daemon/Accounts/User1000 \
    -m com.deepin.daemon.Accounts.User.AddGroup root
()
```

4) Affected D-Bus Interfaces
============================

We did not look into all the privileged D-Bus methods that become available to
unauthenticated local users via dde-api-proxy. On some of the proxied
interfaces only a certain set of "filtered methods" is allowed to be invoked.
The rest of the interfaces don't put restrictions on the methods invoked,
though. On first look, interesting attack surface seems to be found in the
following D-Bus interfaces offered by dde-api-proxy:

- Accounts services (no method filter list)
- network proxy settings (no method filter list)
- PasswdConf1 WriteConfig method
- Lastore service (Apt backend, no method filter list)
- Lastore manager install package method

5) Suggested Bugfix
===================

The authentication bypass is deeply rooted in the design of dde-api-proxy,
thus fixing it is difficult. Possible approaches to addressing it are
presented in the following sub-sections.

a) Dropping Privileges
----------------------

The proxy could temporarily drop privileges to the unprivileged caller's
credentials, create a new D-Bus connection and forward the message to the
proper service. This still won't work properly if the D-Bus service in
question is using Polkit for authentication, because Polkit differentiates
whether the caller is in an active session or not. The D-Bus proxy service
will never be in a session, though. This means that authentication
requirements could be stronger than necessary. At least this approach would be
safer than what currently happens.

b) Reimplementing Authentication Checks
---------------------------------------

The proxy could implement all necessary authentication checks on its own. This
would result in the proper authentication being performed, but would lead to
duplication of a lot of code. It would also add the danger that the
authentication requirements of the proxy service and the actual service get
out of sync.

c) Implementing Legacy Interfaces in the Affected Services
----------------------------------------------------------

Finally dde-api-proxy could be dropped completely and the backward
compatibility could be implemented in every one of the affected services. This
is a less generic approach than what dde-api-proxy attempts to achieve, of
course.

6) Upstream Bugfix
==================

After a longer period of silence, upstream unexpectedly replied to our report
and a short embargo period was established until a bugfix was published
on January 17. The bugfix is found in upstream [commit
95b50dd][deepin-bugfix-commit] which made its way into [release
1.0.19][deepin-bugfix-release].

For the bugfix upstream went in the direction of our suggestion outlined in
section 5.b), by implementing redundant Polkit authorization checks in the
proxy service. A list of sensitive D-Bus methods offered by the proxy is now
maintained in the source code. All of these methods are protected by a single,
newly introduced Polkit action "org.deepin.dde.api.proxy" which requires admin
authentication.

The bugfix introduces a new problem, though. The Polkit authorization check is
implemented as follows:

```cpp
bool checkAuthorization(const QString &actionId, const QString &service,const QDBusConnection &connection) const
{
    auto pid = connection.interface()->servicePid(service).value();
    auto authority = PolkitQt1::Authority::instance();
    auto result = authority->checkAuthorizationSync(actionId,
                                                    PolkitQt1::UnixProcessSubject(pid),
                                                    PolkitQt1::Authority::AllowUserInteraction);
    /* snip */
}
```

This code forwards the client's process ID (PID) to the Polkit service for
authentication. This way of using the Polkit UnixProcessSubject has been
deprecated for a long time, because it is subject to a race condition that
allows to bypass such authorization checks. This issue was
[discovered][oss-security-polkit-cve] in 2013 by former SUSE security engineer
Sebastian Krahmer, and was assigned CVE-2013-4288.

Upstream did not share the bugfix with us before publication, thus we were not
able to prevent this incomplete bugfix. It should be possible to amend the
incomplete bugfix by switching to the SystemBusName subject for
authentication.

Even with an improved fix we believe this approach is not ideal, since it
requires proper maintenance of all the proxied methods by upstream. If new
methods are added at a later time, security issues could sneak in again. Also
the newly introduced Polkit action makes the proxy service less transparent
and could hamper the user experience.  There is no more fine-grained control
over the authentication requirements of individual D-Bus methods, and the
authentication message for all of these proxied D-Bus methods is generic and
unhelpful for end users.

7) Possible Workarounds
=======================

We don't see any viable ways to work around this issue, except for removing
dde-api-proxy from the system.

8) CVE Assignment
=================

This finding is a bigger design issue in dde-api-proxy that allows for a local
root (group) exploit and likely more similar attack vectors. We decided to
request a CVE from Mitre to make the community aware of the issue. Mitre
assigned CVE-2025-23222 to track this issue.

Formally another CVE would need to be assigned for the new security issue
introduced by the incomplete bugfix described in section 6), but we refrained
from doing so at this time.

9) Timeline
===========

|2024-12-18|We reported the issues by email to security@deepin.com, which is documented on the project's [contact page][deepin-contact-page]. The email was rejected by the mail server.|
|2024-12-18|We reached out to support@deepin.org asking what the proper way to report Deepin security issues is. We quickly got a reply that pointed us to their (public) bug tracker or security@deepin.org.|
|2024-12-19|We reported the issues by email to security@deepin.org, offering coordinated disclosure. This time the email was not rejected.|
|2025-01-07|Since we did not receive a reply yet from Deepin security yet we sent another email asking for an initial reply until 2025-01-12, otherwise we would publish the information.|
|2025-01-13|Since we still did not receive a reply we started working on publishing the full report. We requested a CVE from Mitre.|
|2025-01-14|Mitre assigned CVE-2025-23222.|
|2025-01-16|An upstream contact unexpectedly replied and confirmed the issue, stating they are working on a bugfix. We asked once more whether coordinated disclosure is desired, and also forwarded the assigned CVE.|
|2025-01-17|Upstream replied that they want to maintain an embargo until 2025-01-20.|
|2025-01-23|Since no activity at the publication date was visible upstream and we did not get a notification, we asked upstream whether publication will happen as planned.|
|2025-01-24|Upstream pointed us [to the bugfix][deepin-bugfix-commit], which had already been published with no further communication on 2025-01-17.|
|2025-01-24|Since the bugfix was published, we decided to publish all information. While reviewing the bugfix, we realised it was incomplete and notified upstream by email.|

10) References
==============

- [Deepin Website][deepin-website]
- [dde-api-proxy GitHub repository][deepin-proxy-github]
- [Incomplete bugfix commit][deepin-bugfix-commit]
- [Release 1.0.19 containing incomplete bugfix][deepin-bugfix-release]

[deepin-website]: https://www.deepin.org/en/dde/
[deepin-proxy-github]: https://github.com/linuxdeepin/dde-api-proxy
[deepin-proxy-reviewed-version]: https://github.com/linuxdeepin/dde-api-proxy/releases/tag/1.0.17
[deepin-proxy-bugzilla]: https://bugzilla.suse.com/show_bug.cgi?id=1229918
[deepin-proxy-handle-msg]: https://github.com/linuxdeepin/dde-api-proxy/blob/1.0.17/src/dbus-proxy/common/dbusproxybase.hpp#L92
[deepin-contact-page]: https://www.deepin.org/index/en/docs/wiki/en/About_Deepin/Contact-the-deepin-Officials
[deepin-bugfix-commit]: https://github.com/linuxdeepin/dde-api-proxy/commit/95b50ddead0c86fa2cbaaa7c130088fda8315c01
[deepin-bugfix-release]: https://github.com/linuxdeepin/dde-api-proxy/releases/tag/1.0.19
[oss-security-polkit-cve]: https://www.openwall.com/lists/oss-security/2014/03/24/2
