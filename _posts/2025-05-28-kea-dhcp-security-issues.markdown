---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "Kea DHCP: Local Vulnerabilities in many Linux and BSD Distributions"
date:   2025-05-28
tags:   local CVE root-exploit
excerpt: "Kea is the next generation DHCP server suite offered by the Internet
Systems Consortium (ISC). During a routine review we found a local root
exploit and a number of further local vulnerabilities in its REST API,
affecting Kea packages found in many Linux and BSD distributions."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [Kea DHCP distribution][upstream:website] is the next generation DHCP
server suite offered by the Internet Systems Consortium (ISC). It replaces the
traditional ISC DHCP software [which has reached its end of
life][upstream:dhcp-eol].

Since SUSE is also going to ship Kea DHCP in its products, we performed a
routine review of its code base. Even before checking the network security of
Kea, we stumbled over a range of local security issues, among them a local
root exploit which is possible in many default installations of Kea on Linux
and BSD distributions. This, as well as some other issues and security
recommendations for Kea follow below in a detailed report.

This report is based on [Kea release 2.6.1][upstream:review-version-tag]. Any
source code references in this report relate to this version. Many systems
still ship older releases of Kea, but we believe they are all affected as well
by the issues described in this report.

In the <a href="#section-overview">next section</a> an overview of the Kea
design, as far as it is relevant for the issues in this report, is provided.
In <a href="#section-issues">section 3)</a> the security issues we found will
be discussed in detail. In <a href="#section-hardening">section 4)</a> further
hardening suggestions are provided. In <a href="#section-bugfixes">section
5)</a> the upstream bugfixes for the issues are discussed. In <a
href="#section-affectedness">section 6)</a> the packaging properties and
affectedness of Kea in widespread Linux and UNIX systems are documented.
Finally in <a href="#section-cves">section 7)</a> an overview of the CVE
assignments is given.

{: #section-overview}
2) Overview of Kea Design
=========================

This section provides a short overview of the involved components, to allow
readers that are unfamiliar with Kea to better understand the rest of this
report.

Kea offers three separate services for dhcp4, dhcp6 and dhcp-ddns. A
`kea-ctrl-agent` is active by default in most Kea installations and offers an
HTTP REST API listening on localhost:8000. This REST API is based on JSON
requests that are either processed by `kea-ctrl-agent` itself or forwarded to
one of the Kea services it controls. To allow forwarding, each Kea service
listens on a UNIX domain socket that is only accessible to `kea-ctrl-agent`.

In most installations, the REST API is by default accessible to all users in
the system without authentication. Many installations run the Kea
services with full root privileges. On Linux systems that use a dedicated
service user account instead, the Linux capability `CAP_NET_BIND_SERVICE` is
assigned to all of the Kea services. The dhcp4 service additionally needs
`CAP_NET_RAW` to function.

The default configuration and the packaging of Kea are important aspects to
judge the exploitability of the issues described in this report. In some
sense, the issues could be considered vendor-specific problems and not
upstream issues (some ISC engineers argued in this direction when we first
reported these issues). The number of affected Kea packages and the fact that
the default configuration installed by the Kea build system also enables an
unauthenticated REST API make these seem like overarching upstream issues to
us, however.

{: #section-issues}
3) Security Issues
==================

3.1) Local Privilege Escalation by Injecting a Hook Library via the `set-config` Command (CVE-2025-32801)
---------------------------------------------------------------------------------------------------------

The `set-config` REST API command allows to completely control the
configuration of `kea-ctrl-agent` itself, as well as of the individual Kea
services. A trivial local privilege escalation is possible by configuring a
hook library under control of an unprivileged user. The following example uses
the `curl` utility to perform the exploit.

```sh
someuser$ curl -X POST -H "Content-Type: application/json" \
    -d '{ "command": "config-set", "arguments":
          { "Control-agent": {"hooks-libraries": [{"library": "/home/someuser/libexploit.so"}] }}}' \
    localhost:8000
```

By placing a constructor function into `libexploit.so`, attacker controlled
code will be executed by `kea-ctrl-agent` upon `dlopen()` of the library. The
impact is arbitrary code execution with full root privileges on installations
that run Kea services as `root`. On systems that use a dedicated service user
for Kea, the impact will be full control over the Kea processes and also
escalated networking privileges.

Hook libraries can be configured for any of the other Kea services as well,
thus code execution can be achieved in the context of each of the Kea daemons
this way.

We offer a simple Python script
[`kea-hook-lib-exploit.py`](/download/kea-hook-lib-exploit.py) for download
which can be used to reproduce the issue.

3.2) Arbitrary File Overwrite via `config-write` Command (CVE-2025-32802)
-------------------------------------------------------------------------

The `config-write` REST API command instructs a Kea service to write out its
configuration to an arbitrary file path:

```sh
curl -X POST -H "Content-Type: application/json" \
    -d '{ "command": "config-write", "arguments": { "filename": "/etc/evil.conf" } }' \
    localhost:8000
```

The file write happens via a regular C++ `std::ofstream` with `trunc` setting,
i.e. the target file will be truncated and overwritten if it already exists.
The configuration content that is written to disk can as well be controlled by
the attacker, but the JSON format and configuration sanity checks that are
enforced by Kea restrict the degree of freedom of what will eventually be
written out.

If the Kea services run with full root privileges, then this is a local
denial-of-service bordering on a local root exploit. By embedding shell code,
a crafted JSON configuration written e.g. to a file in `/etc/profile.d` could
trigger a local root exploit upon `root` logging in, for example.

If the Kea services are running as dedicated service users, then this attack
vector can be used to corrupt Kea-owned configuration, log and state files,
thus resulting in integrity violation and denial-of-service limited to the
scope of the Kea services.

3.3) Redirection of Log Files to Arbitrary Paths (shared CVE with 3.2)
----------------------------------------------------------------------

This is similar to issue 3.2): an arbitrary new logfile path can be configured
to be used by Kea services. This is an example JSON configuration that
demonstrates the problem:

```json
{
    "command": "config-set",
        "arguments": {
             "Control-agent": {
                 "loggers": [{
                     "name": "kea-ctrl-agent",
                     "output-options": [{
                         "output": "/root/bad.log"
                     }],
                     "severity": "DEBUG"
                 }]
             }
         }
     }
}
```

This configuration causes `kea-ctrl-agent` to create the file `/root/bad.log`
and also to change logging severity to DEBUG, potentially exposing sensitive
internal program state. Also a lock file will be created in
`/root/bad.log.lock`.

This attack vector poses another local denial-of-service vulnerability
bordering on a local root exploit, similar to what is outlined in section
3.2).

3.4) Service Spoofing with Sockets in `/tmp` (shared CVE with 3.2)
------------------------------------------------------------------

For the purposes of forwarding a REST API request to one of the Kea services,
`kea-ctrl-agent` attempts to connect to the service's UNIX domain socket. If
a legit Kea admin tries to send a command to a Kea service that is not
currently running, like the `kea-dhcp-ddns` service (which isn't configured by
default on most distributions), then the admin can fall victim to a local
service spoofing attack.

Whether this is possible depends upon the directory into which the UNIX domain
sockets are placed. Many distributions use the public `/tmp` directory for
this. In this case an unprivileged local user can create the UNIX domain
socket in question on its own, for example in `/tmp/kea-ddns-ctrl-socket`. If
this succeeds, then API requests will be forwarded to a spoofed service that
can respond with a crafted reply. With this a local attacker can attempt to
trick the admin into performing dangerous actions, or might be able to
intercept sensitive data contained in the request forwarded to the spoofed
service.

We reproduced this attack vector for example on Fedora 41 as follows:

```sh
curl -X POST -H "Content-Type: application/json" \
    -d '{ "command": "config-get", "service": [ "d2" ], "arguments": { "secret": "data" } }' \
    localhost:8000
```

The `d2` service socket is configured by default in `kea-ctrl-agent` and
refers to the `kea-dhcp-ddns` service. When running `strace` on
`kea-ctrl-agent` then the following `connect()` attempt is observed during
this request:

```
connect(18, {sa_family=AF_UNIX, sun_path="/tmp/kea-ddns-ctrl-socket"}, 27) = -1 ENOENT (No such file or directory)
```

A local unprivileged user can bind a UNIX domain socket in
`/tmp/kea-ddns-ctrl-socket` to intercept any such requests.

This attack type also affects Kea services that _are_ configured but not yet
running, e.g. before the Kea service unit or init script is started, or when
Kea services are restarted. Upon startup each service will attempt to
`unlink()` the UNIX domain socket path before binding to it, but this is
subject to a race condition that unprivileged users can win by rebinding a
socket in this location before the legit service has a chance to do so. The
legit service will then fail to start, while the unprivileged user will be
able to intercept REST API requests that are forwarded to the spoofed service
by `kea-ctrl-agent`.

3.5) Denial-of-Service issues with Sockets in `/tmp` (shared CVE with 3.2)
--------------------------------------------------------------------------

The use of the `/tmp` directory for the Kea service sockets is generally
problematic. The Kea services create lock files in the socket directory that
are derived from the socket names. Any local user can pre-create either the
UNIX domain sockets or the associated lock files to prevent Kea services from
starting.

3.6) World-Readable DHCP Lease Files in `/var/lib/kea/*.cvs` (CVE-2025-32803)
----------------------------------------------------------------------------

Many of the distributions we checked grant read access to the state data of
the default Kea in-memory database, which is in most cases found in `/var/lib/kea`.
This means all local users will be able to access this information and thereby
this poses a local information leak. Whether DHCP leases are private data is
debatable. More sensitive data might be stored in these files (in a future
implementation), however.

We don't recommend to allow general read access to this data. We originally
only reported this as a hardening recommendation, but upstream decided to
assign a CVE for it anyway.

3.7) World-Readable Kea Log Files (shared CVE with 3.6)
-------------------------------------------------------

On most systems we checked, the Kea log files found in `/var/log/kea` or
`/var/log/kea*.log` are world-readable. As a hardening measure we
recommend to restrict access to this data.

We originally only reported this as a hardening recommendation, but upstream
decided to assign a CVE for it anyway.

{: #section-hardening}
4) Hardening Suggestions
========================

This section contains further hardening suggestions about issues that we don't
consider high severity at the moment.

4.1) Possible Timing Attack against the HTTP Basic Auth Implementation
----------------------------------------------------------------------

`kea-ctrl-agent` uses the HTTP Basic Auth mechanism to implement
authentication on the REST API interface. In this scheme the string
`"<username>:<password>"` is base64 encoded and placed into an
`"Authorization:"` HTTP header.

The verification of these credentials happens in
[`BasicHttpAuthConfig::checkAuth()`][code:check-auth]. The code maintains a
`std::unordered_map<std::string, std::string>`, where the keys consist of the
base64 encoded `"<username>:<password>"` combinations found in the Kea
configuration. The values are the cleartext usernames that can be
authenticated with the credentials found in the key.

In [`basic_auth_config.cc:365`][code:check-auth-lookup] the credentials
provided by the REST API client are looked up directly in this map data
structure to verify them. The verification of cleartext passwords can suffer
from timing attack weaknesses when the passwords are compared using optimized
string comparison routines. Attackers can perform statistical analysis of the
time required by a service to report an authentication failure to construct,
little by little, a valid user/password combination.

In the case of `kea-ctrl-agent` it isn't plaintext passwords that are compared,
but the base64 encoded `"<username>:<password>"` strings. This adds a bit of
complexity but does not prevent a timing attack from succeeding. A bigger
hurdle is the use of the `std::unordered_map`, however, which uses a hash
function to lookup elements in the map. When using the `gcc` compiler suite
and the `libstdc++` standard library, then the default hash function used for
`std::string` is [MurmurHash2][code:libstdpp-murmur-hash] with a [static
seed][code:libstdpp-murmur-seed]. While the hash lookup complicates a
possible timing attack, it is still a deterministic algorithm and an attacker
might be able to choose input values in a way that causes `kea-ctrl-agent` to
produce hash values for the hash map lookup that are suitable for a timing
attack.

To be on the safe side we suggest to supply a custom `KeyEqual` template
parameter to the `std::unordered_map`. This key comparison function should
implement a constant-time comparison of the input data to avoid any observable
timing differences.

Since the complexity of such a timing attack, given the circumstances, will be
very high, we don't see this as a relevant security issue at the moment. A
dedicated attacker might be willing to make an attempt at this and succeed,
however.

4.2) API Credentials Leak via 'get-config' Command
--------------------------------------------------

When API authorization is enabled in the REST API, then the configuration
potentially contains cleartext user names and passwords that can be used for
authentication. A user that already has a valid set of credentials can discover
the credentials of other users by retrieving the configuration via the API,
even if the configuration file would otherwise not be world-readable in the
system.

This means that any user with valid credentials can impersonate any other user.
This can also be problematic when the credentials of a user are revoked at
some point. By storing the credentials of other users, such a user could still
access the API even after being denied access to Kea. Another issue could be
that users might be reusing the same credentials for other, unrelated services.

Cleartext credentials should never be exposed on the API level, except maybe
if the client is `root` anyway. Even then it could be a source of information
leaks, for example if an admin shares a Kea configuration dump (e.g. for
debugging purposes), unaware of the fact that cleartext credentials are
contained in the data.

Users of Kea can circumvent this problem by avoiding storing cleartext
credentials in the Kea configuration and instead referring to credential files
on disk that are only accessible to privileged users.

{: #section-bugfixes}
5) Bugfixes
===========

In our initial report we suggested to upstream to restrict paths from where
hook libraries are loaded (issue 3.1) and also paths where configuration and
log files are written to (issues 3.2, 3.3). It is obvious, however,
that the unauthenticated REST API is problematic beyond the concrete exploit
scenarios we explored. Arbitrary users in the system should not be able to
fully control Kea's configuration, for example. Thus we advised to
enforce authentication on REST API level by default.

To fix the issues described in this report, upstream published bugfix releases
for all currently supported versions of Kea:

- [Release 2.4.2][upstream:bugfix-release-2.4.2]
- [Release 2.6.3][upstream:bugfix-release-2.6.3]
- [Release 2.7.9][upstream:bugfix-release-2.7.9]

We looked into release 2.6.3 and believe the bugfixes are thorough. As is
also documented in the [upstream release notes][upstream:release-notes-2.6.3],
the following changes have been introduced:

- For many operations only safe directories are allowed for reading from or
  writing to. Among others this covers the following aspects:
  - Hook libraries can only be loaded from a trusted system directory
    (addresses issue 3.1).
  - Configuration files can only be written to the trusted system configuration
    directory (addresses issue 3.2).
  - Logfiles can only be written to the log directory determined during build
    time (addresses issue 3.3).
- The default configuration files installed by Kea now enforce authentication
  of the REST API.
- The log, state and socket directories are now installed without the world
  readable / world writable bits set (addresses issues 3.5, 3.6, 3.7).
- Sockets are now placed under `/var/run/kea` by default. This
  directory must not be world-writable (addresses issue 3.5).
- The documentation and example files have been updated to avoid issues like
  discussed in this report.

The hardenings for the issues described in <a
href="#section-hardening">section 4)</a> are not yet available, but upstream
intends to address them in the near future.

{: #section-affectedness}
6) Affectedness of Kea Configurations on Common Linux and UNIX Systems
======================================================================

Kea is a cross-platform project that also targets traditional UNIX systems,
which might be the reason why there are no well established standards for
the packaging of Kea. Every distribution integrates Kea in its own
way, leading to a complex variety of outcomes with regards to affectedness.
The defaults and the resulting affectedness on a range of current well-known
Linux and BSD systems are documented in detail in this section.

All systems we looked at have been updated to the most recent package versions
on 2025-05-23.

6.1) Arch Linux
---------------

|                   |                                    |
| ----------------- | ---------------------------------- |
|**System Release** | rolling release (as of 2025-05-23) |
|**Kea Version**    | 2.6.1                              |
|**Kea Credentials**| `root:root`                        |
|**Kea Socket Dir** | /tmp                               |
|**Kea Log Dir**    | /var/log/kea-\*.log, mode 0644     |
|**Kea State Dir**  | /var/lib/kea, mode 0755            |
|**Affected By**    | 3.1 through 3.7                    |

Arch Linux is affected by all the issues.

6.2) Debian Linux
-----------------

|                   |                                              |
| ----------------- | -------------------------------------------- |
|**System Release** | 12.10, 12.11 (Bookworm)                      |
|**Kea Version**    | 2.2.0                                        |
|**Kea Credentials**| `_kea:_kea`                                  |
|**Kea Socket Dir** | /run/kea, owned by `_kea:_kea` mode 0755     |
|**Kea Log Dir**    | /var/log/kea, owned by `_kea:_kea` mode 0750 |
|**Kea State Dir**  | /var/lib/kea, mode 0755                      |
|**Affected By**    | 3.1 (partially), 3.2 (partially), 3.3 (partially), 3.6 |

When we first discovered these issues we looked into Debian 12.10. Meanwhile
Debian 12.11 has been released. The situation seems to be the same in both
versions, however.

No local root exploit is possible here, because the services run as non-root.
Debian also applies an AppArmor profile to Kea services. This makes the hook
library injection (3.1) difficult. For the injection to succeed, a directory
would be needed that can be written to by the attacker and from where the Kea
service is allowed to read and map a library. This seems not possible in
the current AppArmor profile used for Kea. Due to this, Debian is not affected
by 3.1) at all.

3.2) and 3.3) only affect files owned by `_kea` and that are allowed to
be written to according to AppArmor configuration. This still allows to
corrupt the log, lock and state files owned by `_kea`.

The only information leak is found in the state directory (3.6); logs are
protected.

### AppArmor Security

We checked more closely if there is a loophole in the Kea AppArmor profiles to
make arbitrary code execution (3.1) possible after all. The profiles for the
dhcp4, dhcp6 and ddns Kea services allow reading and mapping of files found in
`/home/*/.Private/**`, with the restriction that the files must be owned by
`_kea`. An attacker with a home directory can place an injection library in
its `$HOME/.Private/libexploit.so`. Only the ownership of the file is
preventing the exploit from succeeding.

By leveraging issue 3.2), the Kea services can be instructed to create `_kea`
owned files in the attacker's `$HOME/.Private`. The content of the created
files is not fully attacker controlled, however, so it will not be possible to
craft a valid ELF object for loading via `dlopen()` this way. By placing a
setgid-directory in `$HOME/.Private/evil-dir`, any files created in this
directory will even have the group-ownership of the attacker. The file mode
will be 0644, however, so the attacker is still not able to write to the file.
Our research shows that there is only a very thin line of defense left against
this arbitrary code execution in `_kea:_kea` context on Debian, but it seems
to hold.

#### Update

Jakub Wilk [shared a working attack vector][oss-sec:acl-attack-vector] on the
oss-security mailing list which makes it possible to overcome the AppArmor
restrictions after all. To allow code execution, a default ACL (access control
list) entry can be assigned to `$HOME/.Private`:

```sh
$ setfacl -d -m u:$LOGNAME:rwx ~/.Private/
```

The mode of newly created files in this directory will be the bitwise AND
between the default ACL setting and the `mode` parameter used by the program
that creates the file (the process's `umask` is not used in this case). When
observed with `strace`, the creation of configuration files by Kea looks like
this:

    openat(AT_FDCWD, "/home/<user>/.Private/libexploit.so", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 14

As a result, the `libexploit.so` created by Kea will end up with a mode of
`0666`. The executable bits will be missing, but Linux allows to `mmap()`
executable code from the file even if it doesn't have executable bits assigned.
This is enough for the `dlopen()` within Kea to succeed and for arbitrary code
to be executed. Actual library code can simply be redirected into a
`libexploit.so` that was previously created by Kea:

```sh
$ cat /path/to/librealexploit.so >~/.Private/libexploit.so
```

The exploit code will still be restricted by the AppArmor profiles applied to
the Kea processes. This means that e.g. only files allowed to be written to by
the AppArmor profiles can be modified. This still makes it possible to control
all Kea state on disk.

6.3) Ubuntu Linux
-----------------

|                   |                                              |
| ----------------- | -------------------------------------------- |
|**System Release** | 24.04.02 LTS                                 |
|**Kea version**    | 2.4.1                                        |
|**Kea Credentials**| `_kea:_kea`                                  |
|**Kea Socket Dir** | /run/kea, owned by `_kea:_kea` mode 0755     |
|**Kea Log Dir**    | /var/log/kea, owned by `_kea:_kea` mode 0750 |
|**Kea State Dir**  | /var/lib/kea, mode 0755                      |
|**Affected By**    | 3.6                                          |

Ubuntu is mostly equivalent to the situation on Debian Linux with one major
difference: REST API access authentication is enforced either by configuring a
custom "user:password" pair, or by generating a random password. If no
password is configured, `kea-ctrl-agent` will not start.

Due to this, Ubuntu is not affected by 3.1 and 3.2 at all. Only the
information leak in the state directory (3.6) exists.

6.4) Fedora Linux
-----------------

|                   |    Fedora 41            |   Fedora 42            |
| ----------------- | ----------------------- | ---------------------- |
|**Kea Version**    |     2.6.1               |      2.6.2             |
|**Kea Credentials**| `kea:kea`               |        "               |
|**Kea Socket Dir** |     /tmp                |        "               |
|**Kea Log Dir**    | /var/log/kea, mode 0755 | /var/log/kea mode 0750 |
|**Kea State Dir**  | /var/lib/kea, mode 0750 |        "
|**Affected By**    | (all limited to the `kea:kea` credentials) 3.1, 3.2, 3.3, 3.4, 3.5, 3.7 | (all limited to the `kea:kea` credentials) 3.1, 3.2, 3.3, 3.4, 3.5 |

When we first discovered these issues we looked into Fedora 41. Meanwhile
Fedora 42 has been released. There are some changes found in Fedora 42, most
notably a safer mode for `/var/log/kea`.

No local root exploit is possible on Fedora, because the services run as
non-root.

Items 3.1 and 3.2 only affect Kea integrity and escalation of the
`CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` capabilities. There is no SELinux
policy in effect for Kea, thus there are no additional protection layers
present that would prevent arbitrary code execution in the context of
`kea:kea` (3.1).

Fedora is affected by 3.3, 3.4 and 3.5 within the constraints of the
`kea:kea` credentials. On Fedora 41 there exists an information leak in the
log directory (3.7). The state directory is safe on both Fedora versions.

6.5) Gentoo Linux
-----------------

|                   |                                              |
| ----------------- | -------------------------------------------- |
|**System Release** | rolling release (as of 2025-05-23)           |
|**Kea Version**    | 2.4.1                                        |
|**Kea Credentials**| `root:root`                                  |
|**Kea Socket Dir** | /run/kea owned by `dhcp:dhcp` mode 0750      |
|**Kea Log Dir**    | /var/log/kea, owned by `root:dhcp` mode 0750 |
|**Kea State Dir**  | /var/lib/kea, owned by `root:dhcp` mode 0750 |
|**Affected By**    | if `kea-ctrl-agent` is manually enabled: 3.1, 3.2, 3.3|

On Gentoo Linux Kea is only available as an unstable `~amd64` ebuild. It
seems still incomplete, because the default configuration is broken (wrong
paths) and the services won't start. Also the `kea-ctrl-agent` is not part of
the default configuration.

The directory permissions are inconsistent with the `root:root` credentials
the Kea services are running with. This creates opportunities for a
compromised `dhcp` user/group to stage symlink attacks in `/run/kea`, for
example.

There are no information leaks and the `/tmp` directory is not used for
sockets. Since the agent is not configured by default at all, we consider that
Gentoo is not affected by any of the issues.

When `kea-ctrl-agent` is actively added to the mix and authorization is not
enabled on the REST API, then Gentoo would be affected by issues 3.1,
3.2 and 3.3.

6.6) openSUSE Tumbleweed
------------------------

|**System Release** | rolling release (as of 2025-04-01)                 | rolling release (as of 2025-05-23)                           |
| ----------------- | -------------------------------------------------- | ------------------------------------------------------------ |
|**Kea Version**    | 2.6.1                                              | 2.6.2                                                        |
|**Kea Credentials**| `root:root`                                        | `keadhcp:keadhcp`                                            |
|**Kea Socket Dir** | /tmp                                               | /tmp                                                         |
|**Kea Log Dir**    | /var/log/kea, owned by `keadhcp:keadhcp` mode 0755 | mode changed to 0750                                         |
|**Kea State Dir**  | /var/lib/kea, owned by `root:root` mode 0755       | /var/lib/kea, owned by `keadhcp:keadhcp` mode 0750           |
|**Affected By**    | 3.1 through 3.7                                    | (all limited to keadhcp credentials) 3.1, 3.2, 3.3, 3.4, 3.5 |

When we first discovered these issues, openSUSE Tumbleweed was fully affected
by all of them. We asked our Kea maintainer to harden the packaging already
before the publication of these issues, which was possible without disclosing
any information about the vulnerabilities. In the current packaging on openSUSE
Tumbleweed Kea no longer runs as `root` and the systemd unit has
`ProtectSystem=full` enabled, which adds another layer of defense. The
information leaks in `/var/log/kea` and `/var/lib/kea` have been fixed as
well.

The more disruptive changes have been delayed until the general publication of
these issues and will soon be addressed as well.

6.7) FreeBSD
------------

|                   |                                                    |
| ----------------- | -------------------------------------------------- |
|**System Release** | 14.2                                               |
|**Kea Version**    | 2.6.1                                              |
|**Kea Credentials**| `root:root`                                        |
|**Kea Socket Dir** | /tmp                                               |
|**Kea Log Dir**    | /var/log/kea-\*.log, owned by `root:root` mode 0644|
|**Kea State Dir**  | /var/db/kea, owned by `root:wheel` mode 0755       |
|**Affected By**    | 3.1 through 3.7                                    |

FreeBSD is affected by all the issues.

6.8) NetBSD (pkgsrc binary)
---------------------------

|                   |                                                      |
| ----------------- | ---------------------------------------------------- |
|**System Release** | 10.1                                                 |
|**Kea Version**    | 2.6.1                                                |
|**Kea Credentials**| `root:root`                                          |
|**Kea Socket Dir** | /tmp                                                 |
|**Kea Log Dir**    | /var/log/kea-\*.log, owned by `root:wheel` mode 0644 |
|**Kea State Dir**  | /var/lib/kea, owned by `root:wheel` mode 0755        |
|**Affected By**    | if example configuration is used unmodified: 3.1 through 3.7 |

NetBSD supports the installation of a [pkgsrc][pkgsrc] binary distribution of
Kea, which is also available on some other systems like MacOS. This
distribution of Kea is affected by all the issues.

By default no configuration is active, however. Admins have to copy over the
configuration from example files found in `/usr/pkg/share/examples/kea`. Thus
it is debatable whether NetBSD is affected in default installations of Kea.

6.9) OpenBSD
------------

|                   |                                              |                     |
| ----------------- | -------------------------------------------- | ------------------- |
|**System Release** | 7.6                                          |       7.7           |
|**Kea Version**    | 2.4.1                                        |        "            |
|**Kea Credentials**| `root:root`                                  |        "            |
|**Kea Socket Dir** | /var/run/kea, owned by `root:_kea` mode 0775 |        "            |
|**Kea Log Dir**    | redirected to syslog (world-readable)        |        "            |
|**Kea State Dir**  | /var/lib/kea, owned by `root:_kea` mode 0775 |    mode 0750        |
|**Affected By**    | 3.1, 3.2, 3.3, 3.6, 3.7                      | 3.1, 3.2, 3.3, 3.7  |

When we first discovered these issues we looked into OpenBSD 7.6.  Meanwhile
OpenBSD 7.7 has been released. As far as we can see only the mode of the
`/var/lib/kea` directory changed in this release.

OpenBSD is affected by issues 3.1, 3.2 and 3.3. Sockets are placed
in a dedicated directory, thus 3.4 and 3.5 do not apply here. There exist
information leaks for log and state data (the latter only in release 7.6).

The `_kea` group ownership for the socket and state dir is inconsistent with
the actual daemon credentials. A compromised `_kea` group could stage symlink
attacks in these directories.

{: #section-cves}
7) CVE Assignments
==================

Kea upstream assigned the following CVEs. Some of them are cumulative and
cover multiple of the issues found in this report.

|   CVE          | Corresponding Issues | Description                                                               |
| -------------- | -------------------- | ------------------------------------------------------------------------- |
| CVE-2025-32801 | 3.1                  | Loading a malicious hook library can lead to local privilege escalation.  |
| CVE-2025-32802 | 3.2, 3.3, 3.4, 3.5   | Insecure handling of file paths allows multiple local attacks.            |
| CVE-2025-32803 | 3.6, 3.7             | Insecure file permissions can result in confidential information leakage. |

Timeline
========

|2025-04-01|We reported the findings via [a private issue][upstream:private-issue] in the ISC GitLab.|
|2025-04-02|After some initial controversial discussions, Kea upstream decided to accept the offer for coordinated disclosure and to work on bugfixes.|
|2025-04-10|Upstream assigned CVEs for the issues.|
|2025-04-29|Upstream communicated a coordinated release date of 2025-05-28 and their intention to involve the [distros mailing list][distros-mailing-list] 5 days earlier. Given the range of affected distributions and the severity of the issues, we suggested to involve the distros mailing list already 10 days before publication.|
|2025-05-15|Kea upstream pre-disclosed the vulnerabilities to the [distros mailing list][distros-mailing-list].|
|2025-05-22|Kea upstream shared links to private bugfix releases 2.4.2, 2.6.3, and 2.7.9, containing fixes for the issues, both with the distros mailing list and in the private GitLab issue.|
|2025-05-26|We inspected the differences between version 2.6.2 and version 2.6.3 and found the bugfixes to be thorough.|
|2025-05-28|Publication happened as planned.|

Change History
==============

|2025-05-30|Added additional attack vector to <a href="#section-affectedness">section 6.2)</a> to overcome AppArmor on Debian Linux. Fixed missing entry for issue 3.3 in <a href="#section-cves">section 7)</a>.|

References
==========

- [SUSE Bugzilla review bug for Kea][bugzilla:review-bug]
- [ISC Kea project page][upstream:website]
- [ISC GitLab private issue detailing the issues from this report][upstream:private-issue]

[bugzilla:review-bug]: https://bugzilla.suse.com/show_bug.cgi?id=1234265
[upstream:website]: https://www.isc.org/kea
[upstream:dhcp-eol]: https://www.isc.org/blogs/isc-dhcp-eol
[upstream:private-issue]: https://gitlab.isc.org/isc-projects/kea/-/issues/3825
[upstream:review-version-tag]: https://github.com/isc-projects/kea/tree/Kea-2.6.1
[upstream:bugfix-release-2.4.2]: https://downloads.isc.org/isc/kea/2.4.2
[upstream:bugfix-release-2.6.3]: https://downloads.isc.org/isc/kea/2.6.3
[upstream:bugfix-release-2.7.9]: https://downloads.isc.org/isc/kea/2.7.9
[upstream:release-notes-2.6.3]: https://downloads.isc.org/isc/kea/2.6.3/Kea-2.6.3-ReleaseNotes.txt
[distros-mailing-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
[code:check-auth]: https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-2.6.2/src/lib/http/basic_auth_config.cc?ref_type=tags#L342
[code:check-auth-lookup]: https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-2.6.2/src/lib/http/basic_auth_config.cc?ref_type=tags#L365
[code:libstdpp-murmur-hash]: https://github.com/gcc-mirror/gcc/blob/97a36b466ba1420210294f0a1dd7002054ba3b7e/libstdc%2B%2B-v3/libsupc%2B%2B/hash_bytes.cc#L74
[code:libstdpp-murmur-seed]: https://github.com/gcc-mirror/gcc/blob/97a36b466ba1420210294f0a1dd7002054ba3b7e/libstdc%2B%2B-v3/include/bits/functional_hash.h#L205
[pkgsrc]: https://pkgsrc.org
[oss-sec:acl-attack-vector]: https://www.openwall.com/lists/oss-security/2025/05/28/11
