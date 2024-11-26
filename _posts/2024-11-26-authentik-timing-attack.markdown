---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "authentik: remote timing attack in MetricsView HTTP Basic Auth (CVE-2024-52307)"
date:   2024-11-26
tags:   CVE remote timing-attack 
excerpt: "Authentik is a popular open source identity provider that can be
self-hosted. While investigating the overall security of the project we
discovered a remote timing attack weakness in the code. We also looked at the
big picture of security in Authentik."
---

Table of Contents
================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[Authentik][authentik-github] is a popular open source identity provider that
can be self-hosted. SUSE IT is considering to use this software internally in
the future and thus we have been asked to have a look at its security.

The Authentik version we examined was 2024.8.3. Beyond the finding in this
report, we also discovered the possibility to access SSL private keys without
authentication, but this was [independently discovered and fixed in
parallel][ghsa-privkey-access] by upstream before we had a chance to report
it. The only CVE-worthy finding that was left is discussed in the next
section. Some general insights into the security of Authentik are given in
section 3).

2) Vulnerability Details
========================

The MetricsView, reachable via URL "/-/metrics/", implements HTTP basic auth
in [authentik/root/monitoring.py:27][auth-comparison-code]. The expected
username is hard-coded to be `monitor`. The expected password is the constant
`settings.SECRET_KEY`, which is the same as the `AUTHENTIK_SECRET_KEY`,
generated when setting up Authentik. According to documentation it is used for
cookie signing and in older versions also for "unique user IDs".

To verify the password, the implementation uses the regular Python "=="
string comparison operator. This operator will optimize the string comparison,
making it likely possible to employ timing attacks to guess the correct
`SECRET_KEY`. Security research has repeatedly shown that timing attacks
are a realistic danger, even over the network.

Exploiting this vulnerability is likely complex, but a determined
attacker might be able to develop a successful approach. We did not look in
more detail into how to exploit the issue.

Upstream published a [security advisory][ghsa-timing-attack] and provides
fixes for this issue in versions 2024.10.3 and 2024.8.5. It is also possible
to employ a workaround by making the affected API endpoint inaccessible for
remote users.

3) Review Summary
=================

Authentik is a big project consisting of about 10,000 lines of Golang code and
nearly 100,000 lines of Python code. It uses various web frameworks and a
rather complex set of abstractions. Reviewing this in full with our limited
resources is impossible. Thus we concentrated on inspecting the accessible
REST API endpoints and tried to get a general feel for the robustness of the
software.

The web frameworks and development style used in Authentik result in pretty
robust REST API endpoints. Even when issues are found, the upstream project
shows that it is well organized and manages to fix them quickly and
transparently.

The sheer amount of features supported by Authentik in terms of network
protocols, authentication mechanisms etc. is big and results in a level of
complexity that is hard to manage. Keeping track of the interactions of all
these features with client and third party systems is a challenge. Authentik
also implements a complex permission framework of over 500 different
privileges for controlling access to the system. We suggest to train
administrators of such systems well to avoid that issues are introduced
through bad configuration of the system.

A bit of a problematic area that we identified in Authentik is its
deployment. It only offers Docker-Compose or Kubernetes based installation.
No official bare-metal installation support exists. The minimum setup requires
four containers that are connected via an isolated network. One container is
running the Postgres database, one is running the Redis in-memory key/value
store, another one is running the actual Authentik server components and an
"Authentik Worker" container is running the celeryd task scheduler. We looked
into the containers and noted the following aspects:

* Two of the containers (Postgres and Redis) are based on Alpine Linux and the
  other two (Authentik Server and Worker) are based on Debian Linux.
* The local security within some of these containers is not fully maintained,
  e.g. in the Authentik Server container there exist globally accessible
  IPC sockets and unsafe temporary file permissions in /dev/shm. This means
  that the local security is only based on the container isolation. As soon as
  an attacker is able to run code in this container, there is little
  defense-in-depth.
* The file system hierarchy standard is violated in some of the containers,
  the / directory is cluttered with proprietary Authentik directories. A
  custom Python installation is placed there, for example.

Consequently, one must not only consider the security of Authentik itself, but
also the security of at least four different Linux containers running two
different Linux distributions and the customized Python stacks involved etc.
Users have to rely on Authentik upstream to properly maintain the security of
these components.

Offering a bare-metal installation could address the concerns in this area.
Individual services on modern Linux can still benefit from isolation features
(e.g. via [protection settings in systemd service
units][suse-secure-systemd]), while the system packages and distribution
security are transparent and under full control of the Admin. Of course this
likely makes things more complex for the upstream developers, when they no
longer have full control of the Linux environment that Authentik is running
in.

4) Timeline
===========

2024-10-25|We reported the finding to <security@goauthentik.io>, offering coordinated disclosure.|
2024-10-28|Upstream replied and confirmed the issue.|
2024-11-13|Upstream obtained a CVE and informed us they would publish the issue within a week.|
2024-11-21|Upstream published fixes and [a security advisory][ghsa-timing-attack].|

5) References
=============

- [Authentik GitHub project][authentik-github]
- [Advisory about insufficient authorization of API endpoints][ghsa-privkey-access]
- [Advisory about the remote timing attack][ghsa-timing-attack]

[authentik-github]: https://github.com/goauthentik/authentik
[ghsa-privkey-access]: https://github.com/goauthentik/authentik/security/advisories/GHSA-qxqc-27pr-wgc8
[ghsa-timing-attack]: https://github.com/goauthentik/authentik/security/advisories/GHSA-2xrw-5f2x-m56j
[auth-comparison-code]: https://github.com/goauthentik/authentik/blob/fd1d252d44a010fad558bed2d315577a9d8d1f2b/authentik/root/monitoring.py#L27
[suse-secure-systemd]: https://documentation.suse.com/smart/security/html/systemd-securing/index.html
