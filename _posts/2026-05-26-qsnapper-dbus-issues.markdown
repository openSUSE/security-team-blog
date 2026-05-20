---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "qSnapper: Various Security Issues in Privileged D-Bus Service (CVE-2026-41045 through CVE-2026-41048)"
date:   2026-05-26
tags:   CVE D-Bus
excerpt: "qSnapper is a GUI frontend for the Snapper utility for managing
Btrfs file system snapshots. In versions up to qSnapper 1.3.2 various
security issues are found in a privileged D-Bus service component, allowing
for Denial-of-Service, authentication bypass, information leaks or even a
local root exploit."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[qSnapper][github:qsnapper] is a GUI frontend for the
[snapper][snapper:overview] utility for managing Btrfs filesystem snapshots.
In April we received [a review request][bug:qsnapper] for qSnapper, because it
contains a privileged D-Bus service and Polkit policies.

Normally, Btrfs snapshots can only be managed with root privileges. qSnapper aims to
provide more user-friendly and fine-grained access to snapshot management
features, based on a privileged daemon which utilizes D-Bus and Polkit. Our
review of the service uncovered various security issues, which led to
a longer coordinated disclosure to allow upstream to develop bugfixes, which
are part of upstream [release 1.3.3][github:bugfix-release].

The full details of the security issues will be covered in the sections
below. The original review was performed on [qSnapper release
1.1.3][github:review-tag]. Since bigger upstream changes appeared in the
meantime this report is based on [qSnapper release 1.3.2][github:report-tag],
however.

2) Overview of the qSnapper D-Bus Service
=========================================

The qSnapper project contains a daemon named `qsnapper-dbus-service`, which
runs with full root privileges. The daemon provides the D-Bus interface
"com.presire.qsnapper.Operations" on the system bus; some of its methods
are provided to arbitrary users in the system without authentication, while the
majority of them is protected by Polkit authentication checks. The
implementation of the various D-Bus methods offered by the service is found in
[`snapshotoperations.cpp`][code:dbus-impl]. All of the security issues
outlined below are located in this compilation unit.

3) Security Issues
==================

{: #issue-polkit-bypass}
3.1) Weak Polkit Authentication Check is Subject to Race Condition (CVE-2026-41045)
-----------------------------------------------------------------------------------

The [`SnapshotOperations::checkAuthorization()`][code:check-authorization]
function uses Polkit's `UnixProcess` subject in an unsafe way to authenticate
clients. The code obtains the client's PID from the active D-Bus connection,
which leads to a race condition. At the time the Polkit daemon (`polkitd`)
checks the provided PID, the process in question can already have been
replaced by another, privileged process. This is a well-known class of Polkit
authentication bypasses which was assigned [CVE-2013-4288][polkit-race].

In effect this means that clients may be able to bypass all Polkit
authentication checks performed by qSnapper, although the attack is somewhat
complex and might need multiple attempts to succeed. There is nothing stopping
a local attacker from doing that, however. In combination with the [configuration
path traversal in D-Bus methods][section:issue-path-traversal] like
`WriteSnapperConfig()` described below, this can be used to achieve a full
local root exploit.

To fix this, we suggested to use Polkit's `SystemBusName` subject instead. With
this subject, the D-Bus daemon obtains the client's UID in a race-free fashion
from the UNIX domain socket the client used to connect, and `polkitd` cannot be
fooled by recycled PIDs.

{: #issue-path-traversal}
3.2) Path Traversal via `configName` Parameter (CVE-2026-41046)
---------------------------------------------------------------

All the D-Bus methods accepting [a `configName` parameter][code:config-name]
(that is nearly all of them) suffer from a path traversal vulnerability. This
string parameter is directly passed to `snapper::Snapper()`, which is part of
the libsnapper API, without checking its safety. libsnapper expects a basename
here to look up a configuration file in `/etc/snapper/configs`. In the context
of qSnapper this string can contain additional path components like
`../../path/to/crafted.cfg`. This allows clients to use arbitrary
configuration files as input to libsnapper.

When looking at the [writeSnapperConfig()][code:write-snapper-config] D-Bus
method, which requires admin authentication, this path traversal allows to
write largely attacker-controlled data to arbitrary locations. Combined with
the Polkit authentication bypass described earlier in [section
3.1][section:issue-polkit-bypass], this would allow for a full local root
exploit.

In case of other D-Bus methods which use the ["list-snapshots" Polkit
action][code:list-snapshots-action], the path traversal is also accessible to
locally logged-in users without any authentication. Luckily the libsnapper
[configuration file format][snapper:config-man-page] offers no features that
lead to a trivial local root exploit in this context. The impact of the
vulnerability can be any of the following, however:

- local Denial-of-Service (DoS): by pointing libsnapper to a special file like
  `/dev/zero`, the daemon will consume the maximum amount of memory and be
  killed by the kernel. By pointing libsnapper to a named FIFO special file,
  the daemon will block indefinitely.
- information leak from parsing of private files: by pointing libsnapper to a
  private file like `/etc/shadow`, libsnapper will parse the sensitive data
  from the file as configuration data. If any logging features are active and
  the logs can be accessed by unprivileged users, then private data from such a
  file might leak into the unprivileged context. We are not aware of such an
  information leak in default installations, however.
- by providing crafted configuration data further attacks can be carried out:
  - `SUBVOLUME` can be pointed to arbitrary mounts in the system. Luckily
    libsnapper is conservative in its file operations here, and quite strictly
    verifies the validity of this path; it verifies if it is really a mount
    point and is backed by the expected block device and file system etc.
  - `ALLOW_USERS` and `ALLOW_GROUPS` can be set to arbitrary users and groups,
    allowing them officially to control the Snapper configuration.
  - The `SYNC_ACL` setting causes libsnapper to apply ACL entries to the
    `.snapshots` directory of the volume path, granting the users and groups
    from `ALLOW_USERS` and `ALLOW_GROUPS` to access the snapshot data. Thus
    this is a major local information leak.

libsnapper is using different backends depending on the file system type.
Different code is used for each backend, which means that the exploitability
of some aspects of the vulnerability depends on which backend is used. On
openSUSE only the Btrfs and LVM thin volume backends are compiled-in by
default, which only offer little additional attack surface.

To fix the issue, we suggested to upstream to verify the `configName`
parameter in all cases and reject it if any `/` or `..` components are
found in it.

{: #issue-info-leak}
3.3) Information Leak via "diff" Methods (CVE-2026-41047)
---------------------------------------------------------

The Polkit action ["list-snapshots"][code:list-snapshots-action] is allowed for
locally logged-in users without authentication, and is used by multiple
qSnapper D-Bus methods which are likely considered "read-only" operations not
harmful to the system. In version 1.1.3 of qSnapper the following methods are
relying on this Polkit action:

- `ListSnapshots()`
- `GetFileChanges()`
- `GetFileDiffAndDetails()`

In version 1.3.2 of qSnapper these additional methods are using the action:

- `GetFileChangesBetween()`
- `GetFileDiffBetween()`

These methods allow to obtain information about metadata changes of arbitrary
files between snapshots or between snapshots and the live filesystem. The
newer `GetFileDiffBetween()` method even offers full file content diff output.
These are major local information leaks, since unprivileged users can get a
diff e.g. of the `/etc/shadow` file between different system states, or
changes from root's home directory which could leak sensitive data like
passwords or private keys.

To fix this, we suggested to upstream that all methods providing non-public
information get restricted by `auth_admin` Polkit checks. Alternatively, a check
could be implemented whether the files to be diffed are normally accessible to
the caller by using checks similar to the `access()` system call; such an
approach would likely be rather complex and error-prone, however.

{: #issue-auth-caching}
3.4) Caching of Authentication allows Authentication Bypass (CVE-2026-41048, CVE-2026-41049)
-------------------------------------------------------------------------------------

In version 1.2.1 of qSnapper an `m_authenticated` flag was introduced to the
daemon's code, which caches authentication once a client has passed certain Polkit
action authentication checks. This cached authentication is shared between the
methods [`DeleteSnapshot()`][code:delete-snapshot],
[`RestoreFiles()`][code:restore-files] and
[`RestoreFilesDirect()`][code:restore-files-direct]. There are two issues
with this approach:

- `DeleteSnapshot()` uses the "delete-snapshot" action, while the
  other methods use the "rollback-snapshot" action. If a caller can
  authenticate for "delete-snapshot" then it is also implicitly authenticated
  for "rollback-snapshot" and vice versa. This is not how Polkit is intended
  to be used. If a system administrator decides to relax the authentication
  requirement for "delete-snapshot", then this automatically implies the
  "rollback-snapshot" action now, which are two very different impacts to the
  system. We assigned CVE-2026-41048 for this aspect of the issue.
- The implementation of the caching logic assumes that a single interactive
  client is talking to the daemon. In fact, arbitrary users can invoke
  these methods. If a legitimate client is authenticated for one of the affected
  actions once, then arbitrary other users like `nobody` are now
  also considered authenticated and Polkit will not be invoked anymore. This
  authentication bypass allows for a full local root exploit in the context of
  the `RestoreFiles()` methods, as outlined below in [section
  3.6][section:issue-other]. We assigned CVE-2026-41049 for this aspect of the
  issue.

We suggested to upstream to drop this form of authentication caching, or
alternatively implement an authentication cache tied to each user and each
Polkit action in question to avoid the issues.

{: #issue-defense-in-depth}
3.5) Defense-in-Depth Issues when Restoring Arbitrary Files
-----------------------------------------------------------

This section discusses Defense-in-Depth issues which remain once all the
more tangible issues discussed above are fixed. The
[restoreFiles()][code:restore-files] D-Bus method accepts arbitrary
`filePaths` as parameter to be restored from a version found in a snapshot.
Clients need to authenticate as an administrator to do this, so there is no
direct attack surface. Let's consider the path `/var/lib/colord/mapping.db` to
be restored, however:

```sh
# On openSUSE Tumbleweed this directory is owned and writable by `colord`
$ ls -lh /var/lib/colord
drwxr-xr-x 3 colord colord 4.0K Mar 6 2024 .
```

At the time the qSnapper service [performs the
`chown()`][code:restore-files-chown] system call, the `colord` service user can
stage a symlink attack in the `colord` directory and cause arbitrary files in
the system to receive `colord` ownership, allowing a `colord` to `root`
exploit. A similar issue affects the [`copyRegularFile()`
function][code:copy-regular-file], where a file on the live file system is
[newly created][code:create-file-via-open].

This issue is hard to fix, given the many different file system situations
that the restore operation can end up in. The basic algorithm to address the
problem would need to use low-level system calls like `openat()`, `fchown()`
and `fstatat()` to safely traverse file system paths and inspect any symbolic
links on the way. Given the complexity of the bugfix and limited impact, we
agreed with the upstream author that this fix does not need to be prepared
during the coordinated disclosure period but can be developed in the open
afterwards.

Given the amount of front-line security issues already found in qSnapper in
the course of this review, we refrained from assigning a dedicated CVE for
these Defense-in-Depth issues in this case.

{: #issue-other}
3.6) Other Issues
-----------------

This section covers a number of other issues that are not fully-fledged
security issues, but still represent weaknesses or possible hardenings for the
qSnapper implementation.

- the D-Bus method [`RestoreFiles()`][code:restore-files] implements complex
  file operations to rollback changes of a file path to the state found in a
  snapshot. These file operations allow authenticated clients to achieve nearly
  arbitrary file operations:
  * recursive deletion of arbitrary paths
  * copy of arbitrary files to arbitrary locations
  * change of ownership of files to arbitrary users
  * change of the file mode to arbitrary values

  This is because the method is not verifying whether the claimed file exists
  in the snapshot in the first place and whether the `filePaths` contain any
  `../` directory components to escape the snapshot directory. While this
  method is protected by Polkit's `auth_admin` setting, any D-Bus method should
  be written conservatively and in such a way that the intended purpose of the
  method cannot be bypassed. The very similar method
  [`RestoreFilesDirect()`][code:restore-files-direct] has the same issues and
  also contains a lot of duplicate code which should be merged with the other
  method's code.
- the [Quit() method][code:quit] can be called by anyone in the system without
  authentication. This is kind of a local DoS against an active qSnapper
  daemon in use by other users in the system.
- the logfile created in `/var/log/qSnapper` will be world-readable, which
  could leak sensitive information. For hardening purposes it could be made
  private to `root`.

4) Upstream Bugfixes
====================

The upstream author closely followed our suggestions to fix the security
issues described in this report. [Version 1.3.3][github:bugfix-release] of
qSnapper contains the following bugfixes:

- [commit a6caf538][commit:auth-and-path-fixes] addresses the following
  issues:
  - the Polkit `UnixProcess` subject is replaced by the `SystemBusName`
    subject to avoid the race condition during authentication ([issue
    3.1][section:issue-polkit-bypass]).
  - the `configName` parameter in all D-Bus methods is now carefully verified
    and rejected if it allows path traversal ([issue
    3.2][section:issue-path-traversal]).
  - the authentication caching is removed ([issue
    3.4][section:issue-auth-caching]).
  - the `RestoreFiles` methods reject path traversal attempts (see [section
    3.6][section:issue-other]).
- [commit f375b74c][commit:split-actions-and-hardening] addresses the
  following issues:
  - a new `view-diff` Polkit action is introduced to generate file diffs which
    requires `auth_admin` authentication to prevent information leaks ([issue
    3.3][section:issue-info-leak]).
  - the unauthenticated `Quit` D-Bus method was dropped (see [section
    3.6][section:issue-other]).
  - log files are now created without world-readable bit (see
    [section 3.6][section:issue-other]).

The more complex defense-in-depth issues outlined in [section
3.5][section:issue-defense-in-depth] will be addressed by upstream in the open
at a later time.

5) Disclosure Process
=====================

Once we established contact with the upstream author, we had a very
constructive discussion of the coordinated disclosure process. Upstream
quickly acknowledged the issues, opted for coordinated disclosure and
communicated a time schedule when bugfixes were expected to be available for
review and when a bugfix release of qSnapper would be published.
When we agreed on the final bugfixes in the middle of May, we agreed on
choosing an earlier publication date than originally intended.

We want to thank the upstream author for handling this report in a very
professional fashion and for greatly improving the security and robustness of
qSnapper.

6) Timeline
===========

|2026-04-09|Lacking any other point of contact, we created a [public GitHub issue][github:issue] asking for a security contact.|
|2026-04-13|The upstream developer responded in the issue providing an email address for us to reach out to.|
|2026-04-13|We reached out to the developer privately by email providing a detailed report and offering coordinated disclosure.|
|2026-04-14|Due to issues with mail servers our email did not reach the upstream developer. Upstream offered us another email address to try.|
|2026-04-15|We received a reply from the upstream developer confirming the issues and requesting coordinated disclosure. Upstream accepted our offer to assign CVEs for the issues. A preliminary disclosure date of 2026-07-07 was established.|
|2026-04-17|We assigned CVEs and shared them with upstream.|
|2026-05-08|We received a tarball containing the current release candidate code of qSnapper.|
|2026-05-11|We asked the upstream author if individual bugfixes could be supplied instead.|
|2026-05-12|We received the individual patches we asked for.|
|2026-05-12|We provided feedback on the current state of the patches. Apart from minor details and hardening suggestions the patches were already in good shape.|
|2026-05-14|We received updated patches for review and found no further issues. Given the good progress on the bugfixes, an earlier coordinated release date of 2026-05-26 was agreed upon.|
|2026-05-26|As planned, upstream released [qSnapper 1.3.3][github:bugfix-release] containing the bugfixes.|
|2026-05-26|Publication of this report.|

7) References
=============

- [qSnapper GitHub repository][github:qsnapper]
- [qSnapper 1.3.3 bugfix release][github:bugfix-release]
- [openSUSE review bug for qSnapper][bug:qsnapper]

[bug:qsnapper]: https://bugzilla.suse.com/show_bug.cgi?id=1261537
[code:check-authorization]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L449
[code:config-name]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L470
[code:copy-regular-file]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L1431
[code:create-file-via-open]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L1721
[code:dbus-impl]: https://github.com/presire/qSnapper/blob/v1.3.2/src/dbusservice/snapshotoperations.cpp
[code:delete-snapshot]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L803
[code:list-snapshots-action]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/polkit/com.presire.qsnapper.policy#L8
[code:quit]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L410
[code:restore-files-chown]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L1418
[code:restore-files-direct]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L1510
[code:restore-files]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L1318
[code:write-snapper-config]: https://github.com/presire/qSnapper/blob/485a7ee9256c8e25de87a5d69d538e318e49b56d/src/dbusservice/snapshotoperations.cpp#L349
[commit:auth-and-path-fixes]: https://github.com/presire/qSnapper/commit/a6caf538fca1e678b81b1c85500c3d071a5edc6d
[commit:split-actions-and-hardening]: https://github.com/presire/qSnapper/commit/f375b74c34e0d07c0edc48f62c02846ad3c9f3ec
[github:bugfix-release]: https://github.com/presire/qSnapper/releases/tag/v1.3.3
[github:issue]: https://github.com/presire/qSnapper/issues/5
[github:qsnapper]: https://github.com/presire/qSnapper.git
[github:report-tag]: https://github.com/presire/qSnapper/releases/tag/v1.3.2
[github:review-tag]: https://github.com/presire/qSnapper/releases/tag/v1.1.3
[polkit-race]: https://nvd.nist.gov/vuln/detail/CVE-2013-4288
[section:issue-auth-caching]: #issue-auth-caching
[section:issue-defense-in-depth]: #issue-defense-in-depth
[section:issue-info-leak]: #issue-info-leak
[section:issue-other]: #issue-other
[section:issue-path-traversal]: #issue-path-traversal
[section:issue-polkit-bypass]: #issue-polkit-bypass
[snapper:config-man-page]: http://snapper.io/manpages/snapper-configs.html
[snapper:overview]: http://snapper.io/overview.html
