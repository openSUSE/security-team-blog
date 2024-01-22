---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "darkhttpd: timing attack and local leak of HTTP basic auth credentials"
date:   2024-01-22
tags:   CVE remote
excerpt: "This report deals with HTTP basic auth issues in the <i>darkhttpd</i> project. Darkhttpd is a minimal HTTP web server implemented in the C programming language, for serving static files."
---

This report deals with HTTP basic auth issues in the [darkhttpd
project][darkhttpd-gh-repo]. Darkhttpd is a minimal HTTP web server
implemented in the C programming language, for serving static files. The
version under review was [1.14][darkhttpd-reviewed-version].

A [version 1.15 bugfix release][darkhttpd-fixed-version] containing a bugfix
and an additional warning message is available. I requested CVEs from Mitre
for the two issues found during this review. They have not been assigned yet,
though. I will give an update once I know them.

Basic Auth Timing Attack
========================

The issue is found in [darkhttpd.c line 2272][timing-src-loc]. Here the HTTP
basic authentication string supplied by a client is compared against the
secret configured via the `--auth` command line parameter. For this comparison
a regular `strcmp()` function call is used.

Since `strcmp()` performs an efficient linear comparison, it will terminate
earlier if the first bytes of the supplied authentication string don't match
compared to if they do match. This difference in runtime can be used for
timing attacks to try and find out the correct authentication credentials to
access the web server.

To fix this, a constant-time string comparison function needs to be used
that always takes the same amount of computation time for the comparison
independently of how many bytes of the provided data match the actual
authentication secret. An example for such a function is the
[`CRYPTO_memcmp()`][openssl-memcmp] function provided by the openSSL library.

Darkhttp does not support SSL encrypted traffic by itself. When darkhttpd
is used for unencrypted http:// over the Internet then it could be argued that
the authentication data will be sent unencrypted over an untrusted channel
anyway. If darkhttpd is used behind a reverse proxy that uses SSL and thus
uses a secure channel, then a major security property will be violated by this
issue though.

Bugfix
------

After discussing the available options with him, the upstream author decided
to implement a [custom constant-time string comparison
algorithm][constant-time-change] to address the issue. This algorithm is a
rather simple xor operation over the complete range of bytes.

Local Leak of Authentication Parameter in Process List
======================================================

The only way to configure the HTTP basic auth string in darkhttpd is to pass
it via the `--auth` command line parameter. On Linux all local users can view
the parameters of other programs running on the system. This means if there
are other users or programs running in different security domains, then these
can obtain the authentication credentials for the web server.

To fix this an alternative mechanism needs to be provided to pass the
authentication credentials in a safe way. Typically this can be solved by
using an environment variable or a protected configuration file. If the
existing `--auth` command line switch is kept around, then the fact that this
leaks the authentication credentials on Linux systems should be documented.

Bugfix
------

The upstream author decided to only [document the security
implications][leak-documentation-change] by adding a warning to the command
line usage output.

Review Summary
==============

Apart from these HTTP basic authentication related issues, I have not found
any problematic spots in the code base of darkhttpd. I focused on the
potential for log file spoofing, escaping the web root via crafted URLs and
memory corruption, e.g. through specifying bad byte ranges in HTTP headers.
The code is robust in these areas.

Timeline
========

| 2024-01-12 | I reported the findings to the upstream author <emikulic@gmail.com>, offering coordinated disclosure. |
| 2024-01-13 | The author confirmed the security issues but declined a formal embargo period. |
| 2024-01-18 | After some discussions about the bugfixes, the author published the new version 1.15 containing the changes. |

References
==========

- [darkhttpd GitHub Repository][darkhttpd-gh-repo]
- [darkhttpd v1.14 version tag (version that was reviewed)][darkhttpd-reviewed-version]
- [darkhttpd v1.15 release (fixed version)][darkhttpd-fixed-version]

[darkhttpd-gh-repo]: https://github.com/emikulic/darkhttpd
[darkhttpd-reviewed-version]: https://github.com/emikulic/darkhttpd/releases/tag/v1.14
[darkhttpd-fixed-version]: https://github.com/emikulic/darkhttpd/releases/tag/v1.15
[timing-src-loc]: https://github.com/emikulic/darkhttpd/blob/v1.14/darkhttpd.c#L2272
[openssl-memcmp]: https://www.openssl.org/docs/man1.1.1/man3/CRYPTO_memcmp.html
[constant-time-change]: https://github.com/emikulic/darkhttpd/commit/f477619d49f3c4de9ad59bd194265a48ddc03f04
[leak-documentation-change]: https://github.com/emikulic/darkhttpd/commit/2b339828b2a42a5fda105ea84934957a7d23e35d
