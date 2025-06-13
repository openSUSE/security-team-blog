---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "sslh: Remote Denial-of-Service Vulnerabilities"
date:   2025-06-13
tags:   remote CVE DoS
excerpt: "sslh is a protocol demultiplexer that allows to provide different
types of services on the same network port. During a routine review we
identified two remote Denial-of-Service vulnerabilities and a number of
non-security issues."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[`sslh`][upstream:github] is a protocol demultiplexer that allows to provide
different types of services on the same network port. To achieve this, `sslh`
performs heuristic analysis of the initial network data arriving on a
connection, and forwards all further traffic to a matching service on the
local system. A typical use case is to serve both SSL and SSH connections
(hence the name) on port 443, to accommodate corporate firewall restrictions.

In April 2025 we conducted a review of `sslh`, mostly due to the fact that
it processes all kinds of network protocols and is implemented in the C
programming language, which is known to be prone to memory handling errors.
For this review we looked into release [v2.2.1][upstream:release:review] of
`sslh`. Bugfixes for the issues described in this report can be found in
release [v2.2.4][upstream:release:bugfix].

The <a href="#section-overview">next section</a> provides an overview of
the `sslh` implementation. <a href="#section-issues">Section 3)</a>
describes two security relevant Denial-of-Service issues we discovered during
our review. <a href="#section-other">Section 4)</a> discusses some
non-security relevant findings and remarks we gathered during our review.
<a href="#section-resilience">Section 5)</a> looks into the general resilience
of `sslh` against high network load attacks. <a
href="#section-summary">Section 6)</a> provides a summary of our assessment of
`sslh`.

{: #section-overview}
2) Overview of sslh
===================

`sslh` implements so-called [probes][code:probes] to determine the type of
service when a new TCP or UDP session is initiated. These probes inspect the
first few bytes of incoming data until a positive or a negative decision can
be made. Once a specific service type has been determined, all following
traffic will be forwarded to a dedicated service running on localhost, without
interpreting further data. `sslh` will only probe for those protocols that are
[actively configured][upstream:example-config], no other probes will be
invoked without need.

`sslh` supports three different I/O models for handling network input. The
choice of what model to use is made at compile time, which is why there
can exist multiple `sslh` binaries, one for each I/O flavor. The following
models exist:

- a fork model implemented in [`sslh-fork.c`][code:sslh-fork]. In this model,
  a separate process is forked for each newly incoming TCP connection. The
  forked process obtains ownership of the TCP connection, handles related I/O,
  and exits when the connection ends. UDP protocols are not supported in this
  model.
- a select model implemented in [`sslh-select.c`][code:sslh-select]. In this
  model, file descriptors are monitored in a single process using the
  `select()` system call. This model also supports UDP protocols: for this
  purpose, all data originating from the same source address are considered to
  be part of the same session. A dedicated socket is created for each new
  session `sslh` detects.
- an implementation based on [libev][libev] implemented in
  [`sslh-ev.c`][code:sslh-libev]. This variant outsources the I/O management
  details to the third party library. This also supports UDP protocols in a
  similar way to the select model described earlier.

The different probes implemented in `sslh` were one of the focus areas during
our review. `sslh` runs with lowered privileges and systemd hardenings
enabled, thus privilege escalation attack vectors will only have limited
impact. An area that is still important in spite of these protections is
Denial-of-Service, which we looked into as well.

{: #section-issues}
3) Security Issues
==================

{: #issue-segfault}
3.1) File Descriptor Exhaustion Triggers Segmentation Fault (CVE-2025-46807)
----------------------------------------------------------------------------

As part of our investigation of Denial-of-Service attack vectors, we looked
into what happens when a lot of connections are created towards `sslh` and, as
a result, file descriptors are exhausted. While the `sslh-fork` variant
manages file descriptor exhaustion quite well, the other two variants have
issues in this area. This especially affects UDP connections that need to be
tracked on application level, since there is no concept of a connection on
protocol level.

For each connection, `sslh` maintains a timeout after which the connection is
terminated if the type of service could not be determined. The `sslh-select`
implementation only checks UDP timeouts when there is network activity,
otherwise the file descriptors that are created for each UDP session stay
open. Due to this, an attacker can create enough sessions to exhaust the
1024 file descriptors supported by default by `sslh`, thereby making it
impossible for genuine clients to connect anymore.

Even worse, when the file descriptor limit is encountered, `sslh` crashes with
a segmentation fault, as it [attempts to dereference
`new_cnx`][code:null-deref], which is a `NULL` pointer in this case. Therefore,
this issue represents a simple remote Denial-of-Service attack vector. The
segmentation fault also happens when the admin configures the
`udp_max_connections` setting (or command line switch), as the `NULL` pointer
dereference is reached in this context as well.

To reproduce this, we tested the `openvpn` probe configured for UDP. On the
client side we created many connections where each connection only sends a
single `0x08` byte.

We did not check the `sslh-ev` implementation very thoroughly, because it
depends on the third party `libev` library. The behaviour is similar to the
`sshl-select` variant, though. UDP sockets are seemingly never closed again.

### Bugfix

Upstream fixed this issue in [commit ff8206f7c][bugfix:segfault] which is part
of the [v2.2.4][upstream:release:bugfix] release. While the segmentation fault
is fixed with this change, UDP sockets potentially still stay open for a
longer time until further traffic is processed by `sslh`, which triggers the
socket timeout logic.

{: #issue-sigbus}
3.2) Misaligned Memory Accesses in OpenVPN Protocol Probe (CVE-2025-46806)
--------------------------------------------------------------------------

In the [UDP code path of `is_openvpn_protocol()`][code:openvpn-udp-path], `if`
clauses like this can be found:

```c
    if (ntohl(*(uint32_t*)(p + OVPN_HARD_RESET_PACKET_ID_OFFSET(OVPN_HMAC_128))) <= 5u)
```

This dereferences a `uint32_t*` that points to memory located 25 bytes after
the start of the heap allocated network buffer. On CPU architectures like ARM
this will cause a SIGBUS error, and thus represents a remote DoS attack vector.

We reproduced this issue on a `x86_64` machine by compiling `sslh` with <br/>
`-fsanitize=alignment`. By sending a sequence of at least 29 `0x08` bytes, the
following diagnostic is triggered:

```
probe.c:179:13: runtime error: load of misaligned address 0x7ffef1a5a499 for type 'uint32_t', which requires 4 byte alignment
0x7ffef1a5a499: note: pointer points here
 08 08 08  08 08 08 08 08 08 08 08  08 08 08 08 08 08 08 08  08 08 08 08 08 08 08 08  08 08 08 08 08
              ^
probe.c:185:13: runtime error: load of misaligned address 0x7ffef1a5a49d for type 'uint32_t', which requires 4 byte alignment
0x7ffef1a5a49d: note: pointer points here
 08 08 08 08 08 08 08  08 08 08 08 08 08 08 08  08 08 08 08 08 08 08 08  08 08 08 08 08 08 08 08  08
```

### Bugfix

The usual fix for this problem in protocol parsing is to `memcpy()` the
integer data into a local stack variable instead of dereferencing the pointer
into the raw network data. This is what upstream did in [commit
204305a88fb3][bugfix:sigbus] which is part of the
[v2.2.4][upstream:release:bugfix] release.

{: #section-other}
4) Other Findings and Remarks
=============================

{: #other-short-reads}
4.1) Missing Consideration of Short Reads on TCP Streams
--------------------------------------------------------

A couple of probes don't consider short reads when dealing with the TCP
protocol. For example in [`is_openvpn_protocol()`][code:probe:openvpn] the
following code is found in the TCP code path:

```c
    if (len < 2)
        return PROBE_AGAIN;

    packet_len = ntohs(*(uint16_t*)p);
    return packet_len == len - 2;
```

If less than two bytes have been received, then the function indicates
`PROBE_AGAIN`, which is fine. After the supposed message length has been
parsed into `packet_len`, the probe only succeeds if the complete message has
been received by now, otherwise the function returns `0` which equals
`PROBE_NEXT`.

Similar situations are found in
[`is_teamspeak_protocol()`][code:probe:teamspeak] and
[`is_msrdp_protocol()`][code:probe:msrdp]. While it may be unlikely that such
short reads occur often with TCP, it is still formally incorrect and could
lead to false negative protocol detection in a number of cases.

### Bugfix

Based on experience upstream believes that this is not an issue in practice
currently, since no bug reports in this area have appeared. For this reason
this is not a priority for upstream at the moment.

{: #other-false-positive}
4.2) Likelihood of False Positive Probe Results
-----------------------------------------------

A couple of probe functions rely on very little protocol data to come to a
positive decision. For example [`is_tinc_protocol()`][code:probe:tinc]
indicates a match if the packet starts with the string <br/>`" 0"`. In
[`is_openvpn_protocol()`][code:probe:openvpn] any packet that stores the
packet length in the first two bytes in network byte order is considered a
match, which is probably the case for quite a few network protocols.

Security-wise this is not relevant, because the services these packets are
being forwarded to have to be able to deal with whatever data is sent to them,
even if it is destined for a different type of service. From a perspective of
correct probe implementation it could lead to unexpected behaviour in some
situations, however (especially when a lot of protocols are multiplexed over
the same `sslh` port). We suggested upstream to try and base probe decisions
on more reliable heuristics to avoid false positives.

### Bugfix

Similar to section 4.1) upstream does not believe that this is a major issue
for users at the moment, hence there are no immediate changes to the code base
to address this.

4.3) Parsing of Potentially Undefined Data in `is_syslog_protocol()`
--------------------------------------------------------------------

The following code is found in [`is_syslog_protocol()`][code:probe:syslog]:

```c
    res = sscanf(p, "<%d>", &i);
    if (res == 1) return 1;

    res = sscanf(p, "%d <%d>", &i, &j);
    if (res == 2) return 1;
```

The `sscanf()` function does not know about the boundaries of the incoming
network data here. Very short reads like a 1 byte input will cause `sscanf()`
to operate on undefined data, found in the buffer allocated on the heap in
[`defer_write()`][code:defer-write-alloc].

### Bugfix

For a quick bugfix we suggested to explicitly zero terminate the buffer by
allocating an extra byte after the end of the payload. Running `sscanf()` to
parse integers found in untrusted data could be considered a bit on the
dangerous side, however, thus we suggested to generally try and change this
into more careful code.

Upstream fixed this in [commit ad1f5d68e96][bugfix:undefined], which is part
of the [v2.2.4][upstream:release:bugfix] release. The bugfix is along the
lines of our suggestion and also adds an additional sanity check for the
integer which is parsed from the network data.

{: #section-resilience}
5) Resilience of `sslh` Against High Network Load Attacks
=========================================================

A general-purpose network service like `sslh` can be sensitive to resource
depletion attacks, such as the aforementioned <a href="#issue-segfault">file
descriptor exhaustion issue</a>. The `sslh-fork` implementation spawns a
new process for each incoming TCP connection, which brings to mind the
possibility to consume excessive resources not only on a per-process scope,
but also on a system-wide scope. By creating a large amount of connections
towards `sslh`, a ["fork bomb" effect][wikipedia:fork-bomb] could be
achieved. When a "fork bomb" is executed locally on Linux then this often
still causes an inaccessible system even today, when there are no strict
resource limits in place.  Achieving something like this remotely would be a
major DoS attack vector.

`sslh-fork` implements a timeout for each connection, which is based on the
`select()` system call. If the probing phase does not come to a decision
before the timeout occurs, then the connection is closed again. By default
this timeout is set to five seconds. Since `sslh-fork` creates a new process
for each newly incoming connection, there is no limit of 1024 file descriptors
being opened by `sslh`. In theory an attacker could attempt to exceed the
system-wide file descriptor and/or process limit by creating an excessive
amount of connections.

The default timeout enforcement of five seconds means that the attack is quite
limited, however. During our tests we were not able to create more than about
5,000 concurrent `sslh-fork` processes. This creates quite a bit of system
load, but does not expose any critical system behaviour on an average machine.

Even though the current situation is acceptable, it could be considered to offer
an application level limit for the amount of parallel connections. For UDP
there exists a `udp_max_connections` setting already, but not for TCP.

{: #section-summary}
### Bugfix

In discussions with upstream it was agreed that proper protection from
such Denial-of-Service attacks is best achieved on the end of the
administrator, who can for example configure Linux cgroup constraints.
Upstream is still considering to add a `tcp_max_connections` setting to limit
the maximum amount of parallel TCP connections in the future.

6) Summary
==========

Overall we believe `sslh` is in good shape. There is little attack surface, and
hardenings are in place by default. With the two remote DoS vectors <a
href="#issue-segfault">3.1)<a/> and
<a href="#issue-sigbus">3.2)</a> fixed, it should be safe to use `sslh` in
production. Users that are worried about more complex DoS attacks should
additionally consider customizing their setup to enforce resource consumption
limits on operating system level.

There is some danger of false positive or false negative probe outcomes as
outlined in sections <a href="#other-short-reads">4.1)</a> and <a
href="#other-false-positive">4.2)</a>. These seem not to have occurred a lot
in practice yet, and it is a trade-off towards simplicity and efficiency in
the current implementation of `sslh`.

7) Timeline
===========

|2025-04-25|We privately reported the findings to the author of `sslh` by email, offering coordinated disclosure.|
|2025-05-06|We discussed details about the reported issues and possible CVE assignments. The issues were kept private for the time being.|
|2025-05-08|We assigned two CVEs from our pool for the issues and shared them with upstream.|
|2025-05-25|The upstream author informed us about bugfixes that have already been published in the `sslh` GitHub repository and about an upcoming release containing the fixes.|
|2025-05-28|Release [v2.2.4][upstream:release:bugfix] containing the fixes was published.|
|2025-06-13|We published this report.|

8) References
=============

- [sslh GitHub project][upstream:github]
- [SUSE Bugzilla review bug for sslh][bugzilla:review-bug]
- [`sslh` release v2.2.1][upstream:release:review] (reviewed version)
- [`sslh` release v2.2.4][upstream:release:bugfix] (fixed version)

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1224800
[upstream:github]: https://github.com/yrutschle/sslh
[upstream:release:review]: https://github.com/yrutschle/sslh/releases/tag/v2.2.1
[upstream:release:bugfix]: https://github.com/yrutschle/sslh/releases/tag/v2.2.4
[upstream:example-config]: https://github.com/yrutschle/sslh/blob/v2.2.1/example.cfg#L116
[libev]: https://github.com/enki/libev
[code:probes]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L34
[code:probe:openvpn]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L162
[code:probe:teamspeak]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L383
[code:probe:msrdp]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L396
[code:probe:tinc]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L217
[code:probe:syslog]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L365
[code:sslh-fork]: https://github.com/yrutschle/sslh/blob/v2.2.1/sslh-fork.c
[code:sslh-select]: https://github.com/yrutschle/sslh/blob/v2.2.1/sslh-select.c
[code:sslh-libev]: https://github.com/yrutschle/sslh/blob/v2.2.1/sslh-ev.c
[code:null-deref]: https://github.com/yrutschle/sslh/blob/v2.2.1/sslh-select.c#L161
[code:openvpn-udp-path]: https://github.com/yrutschle/sslh/blob/v2.2.1/probe.c#L179
[code:defer-write-alloc]: https://github.com/yrutschle/sslh/blob/v2.2.1/common.c#L516
[bugfix:segfault]: https://github.com/yrutschle/sslh/commit/ff8206f7c8a47f901b78a1b78db5a4c788f6aa6f
[bugfix:sigbus]: https://github.com/yrutschle/sslh/commit/204305a88fb32cffaf1349253a2b052186ca8d39
[bugfix:undefined]: https://github.com/yrutschle/sslh/commit/ad1f5d68e96eec389668d1139cb281b1f3f13725
[wikipedia:fork-bomb]: https://en.wikipedia.org/wiki/Fork_bomb
