---
###############################################################################
# NOTE : Copy this template to _posts/ to be able to see it rendered.
layout: post
author: <a href='mailto:name.surname@suse.de'>Name Surname</a>, <a href='mailto:name.surname@suse.com'>Name H. Surname (editor)</a>
title:  "Software: Vulnerabilities and Issues in Linux and BSD Distributions"
# The post title generally follows this convention:
# Component: Short Nominal Description of Issues (CVE-XXXX if applicable)
# If the blog references only one CVE, it can be mentioned in the title. If
# there are multiple CVE references, it becomes unwieldy.
# Post and section titles should be nominal sentences (names only, with no
# verbs), and follow a common capitalisation convention (names and adjectives
# should be uppercase; prepositions, conjunctions etc. should be lowercase).
date:   2025-05-30
tags:   add your tags such as local CVE root-exploit PAM
excerpt: "Software is a thing used for putting things on top of other things.
During a routine review we found a remote arbitrary code execution and a local
root exploit, affecting all Linux and BSD distributions."
# The excerpt should be a 1-3 sentence paragraph explaining the context and
# purpose of the blog post.
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [Software][upstream:website] is the foremost open source software used for
putting things on top of other things. It replaces the traditional Older
Software [which has reached its end of life][upstream:old-software-eol].

Our openSUSE packager for Software recently updated the version in openSUSE
Factory, which contained a privileged systemd service. The openSUSE Security
Team [monitors](https://en.opensuse.org/openSUSE:Package_security_guidelines)
all privileged systemd services added to openSUSE Factory, and during this
review we noticed significant security issues in this new component.

This report is based on [Software release 3.1.4][upstream:review-version-tag].
Any source code references in this report refer to this version. The issues have
been introduced in version 3.1.4, and all previous versions are unaffected.

<a href="#section-overview">Section 2)</a> gives an overview of the Software
design, as far as it is relevant for the issues in this report.
<a href="#section-issues">Section 3)</a> describes the security issues we found
in detail. <a href="#section-hardening">Section 4)</a> provides further
hardening suggestions. <a href="#section-bugfixes">Section
5)</a> discusses the upstream bugfixes for the issues. <a
href="#section-affectedness">Section 6)</a> documents the affectedness of
Software in widespread Linux and UNIX systems. Finally <a href="#section-cves">
Section 7)</a> gives an overview of the CVE assignments.

{: #section-overview}
2) Overview of Software Design
==============================

This section provides a short overview of the involved components, to allow
readers that are unfamiliar with Software to better understand the rest of this
report.

Software offers three separate services for putting things on top of A, B and C.
A `software-daemon.service` systemd service is active by default in most
Software installations and allows users to put things on top of privileged
locations. This service runs the privileged `software-daemon` binary as root.
The service reads files from unprivileged folders X and Y, and writes to
unprivileged folder Z.

> NOTE: You can use this format to add a banner-like note to your posts. These
> can be used for warnings, quotes from manpages, ...

{: #section-issues}
3) Security Issues
==================

3.1) Remote Arbitrary Code Execution in `software-daemon` (CVE-2025-12345)
--------------------------------------------------------------------------

The `software-daemon` executable runs as root and listens on port 123 by
default. Remote code execution can trivially be achieved by sending a payload
to the server:

{: #code-snippet1}
```sh
someuser$ cat exploit | nc host 123
```

You can use normal code blocks delimited by triple backticks, with optional
(recommended) syntax highlighting by specifying the language.
You can then reference <a href="#code-snippet1">the code</a> later on, but it's
not ideal without reference text (e.g. "Code 1"). We'll see how to do that in
the next section.


3.2) Local Root Exploit via Something Else (CVE-2025-12346)
-----------------------------------------------------------

Software does the thing in [horriblefunction()][code:horrible-function]:

{: #code-snippet2}
<figure>
{% highlight python %}
def horriblefunction():
    stuff = 0
    other_stuff = compromise_everything()
{% endhighlight %}
  <figcaption>Code 2: horriblefunction() as present in Software version 3.1.4</figcaption>
</figure>

You can also use this format for code blocks, which can be wrapped into a
`<figure>` environment containing a `<caption>` (useful e.g. to attribute code).
You can then reference <a href="#code-snippet2">Code 2</a> later on.

You can also host resources (reproducers, log files, text files, ...) directly
on the blog (under `/download`), offering them for download directly. For
example, a [Python script](/download/kea-hook-lib-exploit.py) will be offered
for download, while a [text
file](/download/screen-5.0.0-patches/0001-logfile-reintroduce-lf_secreopen-to-fix-CVE-2025-233.txt)
  will be directly displayed in the browser.

3.3) Other Issues Shown with a Picture
--------------------------------------

You can also show pictures, with optional (recommended) captions:

{: #figure-image1}
<figure>
  <img src="/assets/images/deepin-feature-enable.png" alt="An alternate text for
  the image"/>
  <figcaption>Figure 1: An image hosted in assets/images, with a caption</figcaption>
</figure>

You can then reference <a href="#figure-image1">Figure 1</a> later on.

{: #section-hardening}
4) Hardening Suggestions
========================

This section contains further hardening suggestions about issues that we don't
consider high severity at the moment.

This is also an opportunity to show multiple nested subsections.

4.1) Hardening Suggestion 1
---------------------------

This is the first suggestion.

### 4.1.1) Something else about the first suggestion

You can say more.

#### 4.1.1.a) Something even more specific

Section nesting is supported up to the 4th layer (this one).
Only the 1st and 2nd level sections will be displayed in the table of contents.

4.2) Hardening Suggestion 2
---------------------------

This is the second suggestion.

{: #section-bugfixes}
5) Bugfixes
===========

To fix the issues described in this report, upstream published bugfix release
[3.1.5][upstream:bugfix-release-3.1.5].

We reviewed the fixes and they seem to be thorough. As is also documented in the
[upstream release notes][upstream:release-notes-3.1.5], the following changes
have been introduced:

- Fix A
- Fix B
  - This was more tricky than expected and took a larger rework.
- Fix C

The hardenings for the issues described in <a href="#section-hardening">Section
4)</a> have not yet been applied, but upstream intends to address them in the
near future.

{: #section-affectedness}
6) Affectedness of Software Configurations on Common Linux and UNIX Systems
===========================================================================

Software is a cross-platform project that allows to put things on top of other
things on both modern Linux and traditional UNIX systems. Every distribution
integrates Software in its own way, leading to a complex variety of outcomes
with regards to affectedness. The defaults and the resulting affectedness on a
range of current well-known Linux and BSD systems are documented in detail in
this section.

All systems we looked at have been updated to the most recent package versions
on 2025-05-30.

6.1) Arch Linux
---------------

|                   |                                    |
| ----------------- | ---------------------------------- |
|**System Release** | rolling release (as of 2025-05-30) |
|**Software Version**    | 3.1.4                              |
|**Software Credentials**| `root:root`                        |
|**Software Socket Dir** | /tmp                               |
|**Software Log Dir**    | /var/log/software-\*.log, mode 0644     |
|**Software State Dir**  | /var/lib/software, mode 0755            |
|**Affected By**    | 3.1 through 3.3                    |

Arch Linux is affected by all the issues.

6.9) OpenBSD
------------

|                   |                                              |                     |
| ----------------- | -------------------------------------------- | ------------------- |
|**System Release** | 7.6                                          |       7.7           |
|**Software Version**    | 3.1.4                                        |        "            |
|**Software Credentials**| `root:root`                                  |        "            |
|**Software Socket Dir** | /var/run/software, owned by `root:_software` mode 0775 |        "            |
|**Software Log Dir**    | redirected to syslog (world-readable)        |        "            |
|**Software State Dir**  | /var/lib/software, owned by `root:_software` mode 0775 |    mode 0750        |
|**Affected By**    | 3.1, 3.2, 3.3                      | 3.1, 3.3  |

When we first discovered these issues we looked into OpenBSD 7.6.  Meanwhile
OpenBSD 7.7 has been released. As far as we can see only the mode of the
`/var/lib/software` directory changed in this release.

OpenBSD is affected by issues 3.1, 3.2 and 3.3.

{: #section-cves}
7) CVE Assignments
==================

Software upstream assigned the following CVEs. Some of them are cumulative and
cover multiple of the issues found in this report.

|   CVE          | Corresponding Issues | Description                                                               |
| -------------- | -------------------- | ------------------------------------------------------------------------- |
| CVE-2025-12345 | 3.1                  | Remote Arbitrary Code Execution in software-daemon.  |
| CVE-2025-12346 | 3.2, 3.3   | Local Root Exploit via Something Else.            |

Timeline
========

|2025-04-01|We reported the findings via [a private issue][upstream:private-issue] in the Software GitLab.|
|2025-04-02|After some initial controversial discussions, Software upstream decided to accept the offer for coordinated disclosure and to work on bugfixes.|
|2025-04-10|Upstream assigned CVEs for the issues.|
|2025-04-29|Upstream communicated a coordinated release date of 2025-05-28 and their intention to involve the [distros mailing list][distros-mailing-list] 5 days earlier. Given the range of affected distributions and the severity of the issues, we suggested to involve the distros mailing list already 10 days before publication.|
|2025-05-15|Software upstream pre-disclosed the vulnerabilities to the [distros mailing list][distros-mailing-list].|
|2025-05-22|Software upstream shared links to private bugfix release 3.1.5, containing fixes for the issues, both with the distros mailing list and in the private GitLab issue.|
|2025-05-26|We inspected the differences between version 3.1.4 and version 3.1.5 and found the bugfixes to be thorough.|
|2025-05-28|Publication happened as planned.|

References
==========

- [SUSE Bugzilla review bug for Software][bugzilla:review-bug]
- [Software project page][upstream:website]
- [Software GitLab private issue detailing the issues from this report][upstream:private-issue]

A note about references: this section should contain the few fundamental
resources that the reader would want to find at the end of the post. These can
be the corresponding bugs (in our Bugzilla or in upstream bug trackers), or
significant material that the reader would want to reserve for further reading.

Other links throughout the post can be provided as named links (see list at the
end of the file) or inline links. Named links should be used if a resource is
referred to more than once in the document (for example, if a resource is linked
again in this References section).

Footnotes [^footnote-link] are also available, although they should be used
sparingly. They can be used e.g. to explain some tangential detail that would
otherwise derail the flow of the text.

Change History
==============

|2025-05-31|Changes added to the blog post after publication should be individually mentioned in a change history section like this one.|
|2025-05-32|Each source line creates a new table row.|

[^footnote-link]: For an example usage of a footnote, see the
    [Screen](/2025/05/12/screen-security-issues.html#fn:netbsd-info)
    post.

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1234567
[upstream:private-issue]: https://gitlab.software.com/projects/software/-/issues/1234
[upstream:website]: https://www.software.com
[upstream:old-software-eol]: https://www.software.com/old-software-eol
[upstream:review-version-tag]: https://gitlab.software.com/projects/software/tree/software-3.1.4
[code:horrible-function]: https://gitlab.software.com/projects/software/-/blob/Software-3.1.4/src/horrible.py?ref_type=tags#L342
[upstream:bugfix-release-3.1.5]: https://downloads.software.com/software/3.1.5
[upstream:release-notes-3.1.5]: https://downloads.software.com/software/3.1.5/Software-3.1.5-ReleaseNotes.txt

[distros-mailing-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
