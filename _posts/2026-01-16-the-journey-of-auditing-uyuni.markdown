---
layout: post
author: <a href='mailto:paolo.perego@suse.de'>Paolo Perego</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "The Journey of auditing UYUNI"
date:   2026-01-16
tags:   UYUNI audit pentest cve web-pentest
excerpt: "UYUNI is software designed to help system administrators manage a heterogeneous data center full of Linux servers. Auditing such a large piece of software is a long-running journey with ups and downs. Let's explore the process that led us to discover a number of CVEs."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[UYUNI](https://github.com/uyuni-project/uyuni) is an open source system management solution, forked from [Spacewalk](https://spacewalkproject.github.io/) and upstream community project from which [SUSE Multi-Linux Manager](https://www.suse.com/products/multi-linux-manager/) is derived.

The audit started in January 2024 with the perimeter definition. Since it's not feasible to audit everything, a list of packages was chosen and submitted to UYUNI product owner.
The criteria for including a package in the perimeter were:
* the package implementing UYUNI web UI
* the package implementing API or websocket layer
* the package implementing UYUNI backend
* the `salt` package (fundamental for UYUNI server and minions interaction)
* packages not included in previous UYUNI audits

In March 2024 the code scanning activities effectively started.

<a name="section-methodology"/>

2) The methodology
===============

Auditing a complex codebase like UYUNI is not just running a static analysis tool and waiting for it to complete. It is a
complex and long-running journey that took one year and a half to complete.

## Some numbers about the codebase

The codebase is big with a lot of sub-packages. Each sub-package was treated as a standalone audit with its own Bugzilla bug, its own list of affected vulnerabilities and its own report. 
The final report was produced by combining the reports of all sub-packages.

The audited codebase is more than 4.5 millions lines of code, with at least 7 different programming languages.

| Language | Files | Lines of code |
|----------|------:|--------------:|
| JavaScript | 2547 | 3805282 |
| Java | 4052 | 369100 |
| Go | 795 | 250684 |
| Python | 407 | 103965|
| JSP | 641| 36861 |
| Shell | 86| 6744|
| Perl | 65| 6070 |


As you may wonder, using a single catch-all tool to analyze such a heterogeneous codebase is not possible.  

Every package in the scanning perimeter was audited looking at the source both using tools and by manual inspection. The running server was continuously inspected dynamically looking for low-hanging fruit like cross-site-scripting (XSS), SQL injection and similar, and for business logic flaws.

Each security issue was then triaged and if necessary a CVE identifier was assigned and the vulnerability put under EMBARGO. Using the
[openSUSE coordinated disclosure policy](https://en.opensuse.org/openSUSE:Security_disclosure_policy)
as a framework, we coordinate with upstream and disclose the issue when solved.

## The activity tracking

We use Bugzilla as tracking authority for audits and vulnerabilities found during the activity. A master bug ([boo#1218619](https://bugzilla.opensuse.org/show_bug.cgi?id=1218619)) was created with the purpose of acting as a main container for all sub-packages audit bugs.

Each audit bug contains all affecting vulnerabilities and, of course, a vulnerability bug can be set as blocker to more sub-packages.

## The setup

For the activity, a set of
[KVM](https://en.wikipedia.org/wiki/Kernel-based_Virtual_Machine)-powered machines were created:

- a UYUNI server instance
- a UYUNI proxy instance
- a couple of minions, Linux workstations attached and managed centrally by the master.

The server is the main UYUNI component orchestrating minions attestation and enabling system administrators to launch commands and interact with minions using the web interface.

A minion, in the UYUNI slang, is a Linux-powered machine (ideally it is a client in a local network), connected to the server. 

A UYUNI proxy is a particular kind of server, used to fetch packages from software distribution channels and centrally store software packages for an efficient distribution to minions. Distribution channels are software repositories and a system administrator subscribes his own UYUNI instance to different repositories.

Each server was running [openSUSE MicroOS](https://microos.opensuse.org/) as
underlying operating system and minions were running either
[openSUSE Tumbleweed](https://get.opensuse.org/tumbleweed/) or
[Ubuntu](https://ubuntu.com/) Linux distributions.

## The attacker's corner

For the testing activities we used two different machines. A virtual machine running openSUSE Tumbleweed, used for source code inspection and a virtual machine running [Kali Linux](https://www.kali.org) installed to help in penetration testing activities.

### The tools

[Burp Suite community](https://portswigger.net/burp/communitydownload) was the
main tool used trying to spot security issues in the running application.

To help, during the UYUNI application browsing, a custom tool was developed. While browsing the web UI trying to find business logic flaws, I felt the need for something running in the background spotting low-hanging fruit in web pages form, cookies and more.
The tool eventually became an OSS project named [nightcrawler-mitm](https://github.com/thesp0nge/nightcrawler-mitm). It's a [mitmproxy](https://www.mitmproxy.org/) extension implementing both an active and a passive scanner running several security controls in the background.

Also for auditing the source code, opensource tools were used.
Some of the tools used are famous OSS projects, like:

- [bandit](https://github.com/PyCQA/bandit)
- [semgrep](https://semgrep.dev/)
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)

To help me during the activities, I also used some SAST tools previously written by myself, like:

- [dr_source](https://github.com/thesp0nge/dr_source)
- [dawnscanner](https://github.com/thesp0nge/dawnscanner)

## The reporting method

As discussed before, every finding was tracked on a separate bugzilla bug. Each bug was linked, marking as a blocking bug, to any sub-package audit bug affected by the associated vulnerability.

Of course, every vulnerability was confirmed by a successful exploitation, before being added to our Bugzilla tracking system. Vulnerabilities were assigned to UYUNI developers and tracked until a fix was released. 
A CVE was also assigned if required by the issue severity.

The standard [CVSS version 4](https://www.first.org/cvss/v4.0/) was used as a scoring system and to assign a severity. The rationale is that if a CVSS is lower than 5, then the severity is low, it is medium if CVSS is between 5 and 7 and high otherwise. 
The same approach was used to assign a triage score to each sub-package. The triage score will be used in the future to decide if the sub-package must be in future audit perimeter or not. 

At the end of the audit, the list of issues and the triage score created a technical report sent to UYUNI developers.

<a name="section-results"/>

3) Audit results
================

During the audit, seven CVEs were found and fixed, and numerous minor issues were addressed, improving the product’s reliability and overall security posture.

## CVE-2024-49502: spacewalk-web: Reflected XSS in Setup Wizard, HTTP Proxy credentials pane

A reflected cross-site scripting has been found in the HTTP proxy pane of the setup wizard UI element. Tracked in
[boo#1231852](https://bugzilla.opensuse.org/show_bug.cgi?id=1231852)

## CVE-2024-49503: spacewalk-web: Reflected XSS in Setup Wizard, Organization Credentials

A reflected cross-site scripting has been found in the Organization Credentials pane of the setup wizard UI element. Tracked in
[boo#1231922](https://bugzilla.opensuse.org/show_bug.cgi?id=1231922)

## CVE-2025-23392: spacewalk-java: reflected XSS in SystemsController.java

Some URLs, served by the `SystemsController.java` class are vulnerable to a reflected XSS vulnerability. Some example of vulnerable URLs are listed in the Github advisory as well. The
[advisory](https://github.com/uyuni-project/uyuni/security/advisories/GHSA-v588-pf3f-jfp9)
was filed by an external independent researcher following
[our coordinated disclosure policy](https://en.opensuse.org/openSUSE:Security_disclosure_policy).
Tracked in [boo#1239826](https://bugzilla.opensuse.org/show_bug.cgi?id=1239826)

## CVE-2025-46809: Plain text HTTP Proxy user:password in repolog accessible from the UYUNI 5.x webUI

Credentials to be used in UYUNI HTTP proxy are disclosed in the error log in case of wrong port number or misspelled
hostname. Tracked in
[boo#1245005](https://bugzilla.opensuse.org/show_bug.cgi?id=1245005)

## CVE-2025-46811: Unprotected websocket endpoint

During an internal assessment, a customer found an issue with the remote-commands websocket endpoint (`/rhn/websocket/minion/remote-commands`).
Using websockets, anyone with the ability to connect to port 443 of SUSE Manager is able to run any command as root on any client with no authentication. The customer using our coordinated disclosure policy as a reference, reported the issue which was then fixed and publicly disclosed. Tracked in
[boo#1246119](https://bugzilla.opensuse.org/show_bug.cgi?id=1246119)

## CVE-2025-53883: spacewalk-java: various XSS found on search page

During an internal assessment, a customer found that some reflected cross-site scriptings were possible due to improper input validation. The issue was tracked in the private SUSE bugzilla instance, since some customer sensitive information was included. However the issue is described in the public
[CVE-2025-53883 page.](https://www.suse.com/security/cve/CVE-2025-53883.html)

## CVE-2025-53880: susemanager-tftpsync-recv: arbitrary file creation and deletion due to path traversal

A Path Traversal vulnerability in the `tftpsync/add` and `tftpsync/delete` scripts allows a remote attacker on an adjacent network to write or delete files on the filesystem with the privileges of the unprivileged `wwwrun` user. Although the endpoint is unauthenticated, access is restricted to a list of allowed IP addresses. The unprivileged user has write access to a directory that controls the provisioning of other systems, leading to a full compromise of those subsequent systems. Tracked in
[boo#1246277](https://bugzilla.opensuse.org/show_bug.cgi?id=1246277)

## Other minor findings

Additional vulnerabilities were identified that, while valid, did not meet the criteria for CVE assignment:

- [boo#1231900](https://bugzilla.opensuse.org/show_bug.cgi?id=1231900): VUL-0: arbitrary log messages in API can lead to a disk space exhaustion (and so to a denial of service)
- [boo#1245740](https://bugzilla.opensuse.org/show_bug.cgi?id=1245740): VUL-0: Default venv-salt-minion environment is activated on the different user accounts
- [boo#1243679](https://bugzilla.opensuse.org/show_bug.cgi?id=1243679): VUL-0: Insecure communication in TFTP proxy sync.
- [boo#1243768](https://bugzilla.opensuse.org/show_bug.cgi?id=1243768): VUL-0: Potential Command InjectionPattern in check_push Function. No activity: a follow-up was requested.
- [boo#1239636](https://bugzilla.opensuse.org/show_bug.cgi?id=1239636): VUL-0: log pollution in class TraceBackEvent
- [boo#1237368](https://bugzilla.opensuse.org/show_bug.cgi?id=1237368): VUL-0: unhandled exception when dealing with numeric request parameters
- [boo#1243087](https://bugzilla.opensuse.org/show_bug.cgi?id=1243087): VUL-0: spacewalk-search: unexploitable XSS in XML RPC Server.
- [boo#1227577](https://bugzilla.opensuse.org/show_bug.cgi?id=1227577): VUL-0: spacecmd and spacewalk-backend: usage of unsafe third party library for XML.

Last but not least, during the audit also some codebase improvements were suggested to raise the security posture even further:

- [boo#1228945](https://bugzilla.opensuse.org/show_bug.cgi?id=1228945):
  AUDIT-FIND: spacewalk-utils: Sensitive information disclosure in backup file
- [boo#1223313](https://bugzilla.opensuse.org/show_bug.cgi?id=1223313):
  AUDIT-FIND: Possible deserialization issue in spacewalk-client-tools
  (affecting only SUMA 4.x)
- [boo#1228116](https://bugzilla.opensuse.org/show_bug.cgi?id=1228116):
  AUDIT-FIND: spacewalk-admin: mgr-monitoring-ctl doesn’t sanitize PILLAR
  parameter
- [boo#1231983](https://bugzilla.opensuse.org/show_bug.cgi?id=1231983):
  AUDIT-FIND: spacewalk-web: generatePassword() improve namespace entropy
- [boo#1246941](https://bugzilla.opensuse.org/show_bug.cgi?id=1246941):
  AUDIT-FIND: saline: Hardening Against Insecure Deserialization
- [boo#1247015](https://bugzilla.opensuse.org/show_bug.cgi?id=1247015):
  AUDIT-FIND: saline: Race Condition in Service Startup Allows for IPC Hijacking
  on Systems with a Permissive umask
- [boo#1227579](https://bugzilla.opensuse.org/show_bug.cgi?id=1227579):
  AUDIT-FIND: spacecmd: get rid of pickle to read and parse configuration files.

<a name="section-conclusions"/>

4) Conclusions
===============

The UYUNI audit was an intense and rewarding run. The good results in term of number of found vulnerabilities and the fast reaction to release the fixes, confirmed UYUNI as a solid and reliable product for the community.

As all software, of course it can be improved in terms of code quality by applying safe coding patterns, using secure and reliable third-party libraries and consolidating the usage of one or two programming languages. This is an important step, because it creates a common ground for engineers and a solid codebase for the community to entice contributions and pull requests.

A vibrant codebase, using a balanced mix between standard and cutting edge technologies can increase adoption of the product and it can attract developers and contributors.

It also helps in adopting safe coding best practices that are widely updated and developed for newer technologies rather than ancient and not actively used programming languages.

The low number of vulnerabilities found, and the reaction time in fixing the serious ones, indicate that the project is well-curated and actively maintained. The  security posture is good and it can be safely deployed in production.

<a name="section-next"/>

5) What's next?
===============

Like every journey, the final destination is not the reward itself. The UYUNI project is actively under development with a monthly (more or less) release cycle.

The next audit will start in the first quarter of 2026 and it will be another one year and a half rollercoaster ride, with rabbit holes, false positives, suspected CVEs turning out to be not exploitable and real _root dance_ issues.

The fun part is to audit code written in multiple languages, with different stacks and libraries.

It's not rewarding only from a security perspective, it's
a real learning experience.

<a name="section-links"/>

6) Links
========

- The [master Bugzilla bug](https://bugzilla.opensuse.org/show_bug.cgi?id=1218619).
- The [latest stable version 2025.10 of UYUNI](https://www.uyuni-project.org/pages/stable-version.html) containing all the relevant fixes.
- The [nightcrawler-mitm](https://github.com/thesp0nge/nightcrawler-mitm) tool, written to actively and passively scan the web application in the background.
- The [dr_source](https://github.com/thesp0nge/dr_source) tool, written as a SAST companion tool mainly for Java but improved with support for other programming languages.
- [The UYUNI source code on Github](https://github.com/uyuni-project/uyuni)
- [The openSUSE coordinated disclosure policy](https://en.opensuse.org/openSUSE:Security_disclosure_policy)


