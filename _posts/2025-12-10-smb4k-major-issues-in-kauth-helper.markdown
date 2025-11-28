---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "smb4k: Major Vulnerabilities in KAuth Helper (CVE-2025-66002, CVE-2025-66003)"
date:   2025-12-10
tags:   CVE KDE D-Bus
excerpt: "smb4k is a KDE desktop related utility which allows unprivileged
mounts of Samba/CIFS network shares. The utility was already rejected from
entering openSUSE in 2017 due to severe security issues. A revisit of the tool
showed that it still suffered from major vulnerabilities leading to local
Denial-of-Service or even a local root exploit. After a long coordinated
disclosure, upstream arrived at a working bugfix in version 4.0.5."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[smb4k][upstream:project] is a KDE desktop related utility which allows
unprivileged mounting of Samba/CIFS network shares. The SUSE security team
reviewed its privileged KAuth helper component [already in
2017][bugzilla:old-review] which led to [the discovery of
CVE-2017-8422][bugzilla:kauth-bypass] (general KAuth authentication bypass)
[and CVE-2017-8849][bugzilla:old-exploit] (local root exploit via smb4k mount
helper).

This September [we were asked to reconsider][bugzilla:new-review] smb4k
for inclusion in openSUSE Tumbleweed. The resulting review showed that the
mount helper still lacks input validation, is affected by race conditions and
has a bug in its existing verification logic. This leads to local attack
vectors which allow Denial-of-Service or even a local root exploit.

Many Linux distributions and also some BSDs are potentially affected by the
issues described in this report. We offered coordinated disclosure to upstream
and the maximum 90 days non-disclosure period was fully spent to arrive at a
patch which addresses all the issues. This patch is found in [commit
0dea60194a][upstream:bugfix-commit], which is part of the [4.0.5 bugfix
release][upstream:bugfix-release] of smb4k.

The [following section][section:overview] provides a short overview of the
privileged mount helper. [Section 3][section:mount-problems] looks into the
problems found in the helper's mount method. [Section
4][section:unmount-problems] in turn looks into the issues found in the
helper's unmount method. [Section 5][section:remarks] contains further
remarks on the helper's code quality and security concerns. [Section
6][section:suggested-fixes] discusses the fixes we suggested to upstream to
address the issues. [Section 7][section:bugfix] gives details about the bugfix
which was finally implemented by upstream. [Section 8][section:workarounds]
suggests possible workarounds that can be applied to avoid the issues found in
this report.  [Section 9][section:reproducers] provides reproducers for the
issues.

This report is based on [smb4k release 4.0.4][upstream:review-release].

{: #section-overview}
2) Overview of the Privileged Mount Helper
==========================================

The problematic privileged mount helper component of smb4k is relatively small
and can be found in the file [smb4kmounthelper.cpp][code:mount-helper]. The
helper runs with full root privileges and implements two KAuth actions
accessible via D-Bus: mounting and unmounting a network share. Both actions
are allowed for local users in active sessions without authentication, based
on the Polkit `yes` setting.

{: #section-mount-problems}
3) Problems in `Smb4KMountHelper::mount()`
==========================================

{: #subsection-mount-arbitrary-dir}
3.1) Arbitrary Target Directories can be used for Mounting Network Shares
-------------------------------------------------------------------------

The helper does not impose any restrictions on the target directory
where the desired Samba share will be mounted. This means the share can
also be mounted over `/bin`, for example. Should the client have control
over the contents of the network share, then this allows for a local root
exploit by placing crafted binaries e.g. for `/bin/bash` on the share, which
are bound to be executed by privileged processes at some point.

If the share's content cannot be controlled by the attacker, then this serves
as a local Denial-of-Service attack vector, as vital system programs will
become inaccessible.

To fix this, we suggest to only allow mounting of network shares in a
pre-defined location which is not controlled by unprivileged users.

{: #subsection-mount-arbitrary-args}
3.2) Arbitrary Command Line Arguments can be Passed to `mount.cifs`
-------------------------------------------------------------------

The client can specify arbitrary additional command line arguments in the
`mh_options` parameter, which [will be passed to the `mount.cifs`
program][code:mount-cmdline]. The command line constructed by the mount helper
looks like this:

```sh
/sbin/mount.cifs <URL> <mountpoint> <options>...
```

All of these arguments, except for the path to the `mount.cifs` program
itself, are actually controlled by the client. It is not the generic `mount`
program which is invoked here, otherwise the client could already perform
arbitrary mounts in the system. Instead the attacker is restricted to what the
special-purpose `mount.cifs` binary provides.

The `mount.cifs` program supports [a plethora of mount
options][man:mount-cifs]. Investigating the effect of each one would go
beyond the scope of this report. There is one simple privilege escalation
vector, however: passing `filemode=04777,uid=0` to the command line results in
every file on the network share mount receiving setuid-root permissions. If
the content of the network share is controlled by the attacker, then this can
easily be used to introduce an attacker-controlled setuid-root program into
the system. This would then allow for a local root exploit even if [issue
3.1)][subsection:mount-arbitrary-dir] would be fixed.

Other `mount.cifs` options like `port=<port>` could be used to direct the
kernel to a CIFS server controlled by the attacker itself, listening on an
unprivileged port on localhost. This way a local attacker could provide the
necessary crafted network share for executing the exploits described in this
report on its own, without relying on external network resources.

To fix this, we suggest to restrict the `mh_options` to a whitelist of allowed
parameters, and also verify the options' values in case they can contain
problematic settings.

3.3) Clients can Control the `KRB5CCNAME` Environment Variable Passed To `mount.cifs`
-------------------------------------------------------------------------------------

The client can provide an arbitrary path in the `mh_krb5ticket` parameter;
the mount helper [will place this path into the `KRB5CCNAME` environment
variable][code:mount-krb5ccname] for the `mount.cifs` child process. This is
to allow use of the client's Kerberos credentials for mounting the network
share.

The client can pass a path pointing to file system locations normally not
accessible to it. In a multi-user scenario this would allow, for
example, to hijack another user's Kerberos credentials, by passing a path to
the credentials cache of the other user. It might also lead to information
leaks of files like `/etc/shadow`, should `mount.cifs` output file content to
the system logs or on stderr (the output of which is returned to the client
via D-Bus).

Furthermore, this path could be used for file existence tests or for a local
Denial-of-Service attack (by pointing to special files like `/dev/zero` or a
named FIFO pipe).

To fix this, we recommend not to pass a path, but an already open file
descriptor from the client to the helper, to avoid the opening of arbitrary
files with root privileges.

{: #section-unmount-problems}
4) Problems in `Smb4KMountHelper::unmount()`
============================================

{: #subsection-umount-arbitrary-dir}
4.1) Missing `return` Statement on Mount Path Verification Failure
------------------------------------------------------------------

This is similar to [issue 3.1)][subsection:mount-arbitrary-dir] above
regarding mounting. In [smb4kmounthelper.cpp line
177][code:umount-path-verification] there is an `if` block that acts on the
situation when the `mh_mountpoint` path supplied by the client does not match
any of the available Samba mounts returned from
`KMountPoint::currentMountPoints()`.

The problem is that this `if` block only sets an error message, but does not
actually terminate the function execution with `return`. This means the
verification is ineffective and local users can unmount arbitrary file systems
despite the check.

This is a major local Denial-of-Service attack vector, which can lead to a
complete system outage. In some special contexts it might even allow
information leaks or privilege escalation, when file system locations have been
made inaccessible by mounting other file systems on top (we can imagine
something like this e.g. in the context of container setups).

{: #subsection-umount-arbitrary-args}
4.2) Arbitrary Command Line Parameters can be Passed to `umount`
----------------------------------------------------------------

Similar to [issue 3.2)][subsection:mount-arbitrary-args] above, the privileged
helper forwards arbitrary command line parameters provided by the client in
`mh_options` to the command line of the `umount` program. This happens in
[smb4kmounthelper.cpp line 187][code:umount-cmdline]. Basically the `umount`
program will be invoked like this:

```sh
/sbin/umount <options>... <mount-point>
```

Assuming [issue 4.1)][subsection:umount-arbitrary-dir] would be fixed, the
`<mount-point>` parameter cannot be chosen arbitrarily by the client, but must
match an existing "cifs", "smbfs" or "smb3" type mount path. As long as such a
mount path exists, the client can pass arbitrary additional mount points as
"options", which will then be unmounted as well. This is a lighter variant of
issue 4.1), leading to local Denial-of-Service if the described pre-condition
is fulfilled.

Apart from this, `umount` offers [various options][man:umount] that
can influence the way it operates. One option that sticks out is `-N
--namespace ns`, which causes the program to unmount the file system in an
arbitrary mount namespace. This could impact privileged processes, other
users' containers or jailed processes.

To fix this, we suggest to restrict the `mh_options` to a whitelist of allowed
parameters.

{: #subsection-kmountpoint}
4.3) Race Conditions Affecting `KMountPoint::currentMountPoints()`
------------------------------------------------------------------

This is not directly an issue in smb4k itself, but an issue in the [KIO
library][upstream:kio] which implements the `KMountPoint` API. During our
tests we used version [v6.17.0][upstream:kio-release] of this library.

The mount helper's `umount()` function [attempts to verify][code:mountpoints]
the input path provided by the client by comparing it against current mounts
in the system as reported by the kernel. Only active "cifs", "smbfs" and
"smb3" file system mounts are supposed to be unmounted. To this end the
current list of mounted file systems is obtained from

```c++
    KMountPoint::currentMountPoints(KMountPoint::BasicInfoNeeded | KMountPoint::NeedMountOptions);
```

The implementation of `currentMountPoints()` relies on the libmount
library [to retrieve a list of mount points][code:kio:libmount]. The
libmount library provides a proven implementation for safely parsing
files like `/proc/self/mountinfo`, which we reviewed ourselves a few years
ago and deemed robust. After safely obtaining the information from
libmount, the KIO library performs some actions on top, however, which
can lead to security relevant issues.

One minor issue is found in [kmountpoint.cpp line 365][code:kio:stat], where
`stat()` is called on the target mount directory of each mount entry. This
potentially accesses untrusted paths, also from FUSE file systems, which could
in some cases cause a local Denial-of-Service if `stat()` blocks. Also, the
supposed mount point could be unmounted by the time the `stat()` call is
performed, allowing the path to point to an arbitrary file (also following
symbolic links), which would lead to incorrect information in the `m_deviceID`
field of the information returned by `currentMountPoints()`.

Later on the code tries to ["resolve GVFS mount points" in line
382][code:kio:resolve].  The [`resolveGvfsMountPoints()`
function][code:kio:resolve-func] that implements this logic looks for mount
entries with "gvfsd-fuse" as source device name. For each of these mount
points the function will list the mount's directory contents and look for
directory entries of the form `<type>:<label>`, where `type` refers to the
file system type that is expected to be found there. The function then
synthesizes additional mount entries from this information which will be
returned to the caller, appearing as fully-fledged regular mounts.

There are two problems with this. For one, these operations are all subject to
race conditions; the mount table entries can change at any time. Secondly,
there exists a common way for unprivileged users in Linux systems to create
mount points with arbitrary source device names. This is the `fusermount`
setuid-root utility, which is used for mounting FUSE file systems. Local users
can create a fake `gvfsd-fuse` mount point like this:

```sh
    $ export _FUSE_COMMFD=0
    $ mkdir $HOME/mnt
    $ fusermount $HOME/mnt -ononempty,fsname=gvfsd-fuse
    $ mount | tail -n1
    gvfsd-fuse on /home/$USER/mnt type fuse (rw,nosuid,nodev,relatime,user_id=1000,group_id=100)
```

The default FUSE configuration prevents the `root` user from accessing
non-root controlled FUSE file systems. To overcome this limitation, an
attacker can perform the following steps:

- create a fake `gvfsd-fuse` mount like shown above.
- trigger the `unmount()` logic in smb4k's mount helper.
- attempt to unmount `$HOME/mnt` after `currentMountPoints()` obtained the
  mount information from libmount, but before it calls
  `resolveGvfsMountPoints()`.
- place directories in this location that match the expected format e.g.
  something like `cifs:mymount`. These directories can already be placed
  there in advance, of course.
- on success, the `currentMountPoints()` function will return a
  synthesized entry to the mount helper which lists a CIFS mount in the
  unprivileged user's `$HOME/mnt/cifs:mymount`.

Using this approach, the verification step in the mount helper's
`unmount()` function can be bypassed even if issues
[4.1)][subsection:umount-arbitrary-dir] and
[4.2)][subsection:umount-arbitrary-args] would be fixed.

There are further potential issues in the `KMountPoint` logic, e.g. in
`finalizeCurrentMountPoint()` the source device name is resolved if the
`KMountPoint::NeedRealDeviceName` flag is passed by the caller. This
provides another opportunity for unprivileged FUSE mounts with fake
source device names to influence the outcome, e.g. to perform
file existence tests or otherwise trick the caller of the KIO library.

Due to these problems, the information obtained from
`currentMountPoints()` currently cannot be used to base security related
decisions on. Generally `root` should not perform these additional
queries at all. The library could check for `geteuid() == 0` to prevent
the execution of this dangerous logic in privileged contexts.

For unprivileged applications we could imagine the addition of a flag like
`KMountPoint::AllowUnsafe`, which opts in to the problematic behaviour. Only
applications that are aware of the potential problems would then pass this
flag.

When we reported this, KDE security at first stated that the problems
described in this section would only affect smb4k and no other users of the
KMountPoint API. We found it questionable to consider a library's API secure
only based on its supposed current users. Beyond that, even unprivileged
processes using this API might fall victim to other users in the system
crafting gvfsd mount information. One could argue that there is an issue in
the `fusermount` utility to begin with. The `KMountPoint` API is explicitly
processing a FUSE-based file system, however, and thus it should be prepared
to deal with the peculiarities this entails.

When we pointed out our continued concern to KDE security, it was suggested
that we create an upstream issue, or ideally provide a bugfix ourselves. While
we are happy to help where we can, the issue at hand is a larger API design
topic, and we believe it should be dealt with carefully by the responsible
upstream developers, allowing them also to learn from this experience. For
this reason we only created the [upstream issue][upstream:kio-bug-report], as
was suggested to us.

4.4) Arbitrary Network Share Mounts can be Unmounted
----------------------------------------------------

Even if all the other issues discussed in this section would be fixed, the
current mount helper code allows to unmount arbitrary Samba shares, no matter
if they have been originally mounted by smb4k itself (for the same user or a
different one), or by other components in the system (e.g. via a fixed entry
in `/etc/fstab`).

Similarly to [issue 3.1)][subsection:mount-arbitrary-dir] above, we suggest to
restrict smb4k mounts to a pre-defined location not controlled by unprivileged
users to address this issue.

{: #section-remarks}
5) Other Remarks
================

5.1) Superfluous `mh_command` Client Parameter
----------------------------------------------

Both helper actions compare an arbitrary path supplied by the client in
`mh_command` to the trusted "mount" or "unmount" program path returned
from `findMountExecutable()` or `findUmountExecutable()`, respectively. This
is odd. It seems this comparison is a remnant from the attempted fix of
CVE-2017-8849. This is superfluous logic that increases the complexity of both
client and helper unnecessarily and can cause confusion, at best.

The helper should choose the trusted mount program on its own and stop
considering the `mh_command` parameter at all.

5.2) Redundant "online check" Code
----------------------------------

There is a redundant check for online network interfaces in
[smb4kmounthelper.cpp line 38][code:online-check1] and [line
205][code:online-check2]. This code should be placed into a separate function
instead, to avoid code duplication and to increase readability.

This online check is also highly heuristic, and it might be possible for
unprivileged users to influence its outcome e.g. by creating
unprivileged pseudo network devices that appear to be online.

5.3) `mount.cifs` and `umount` Follow Symbolic Links
----------------------------------------------------

Both `mount.cifs` and `umount` follow symbolic links in path arguments. This
means that even if the mount helper would try to verify a path pointing to a
client-controlled location, this could be replaced with a symbolic link
by the time the actual `mount.cifs` or `umount` utility runs, and the mount
logic would then operate on a completely different location than expected by
the helper.

{: #section-suggested-fixes}
6) Suggested Fixes
==================

Apart from the individual suggestions mentioned in the context of the
issues above, we believe the range and severity of the issues uncovered shows
that a major redesign of the mount helper utility is necessary to address all
the problems in a robust way.

Here are some suggestions regarding a larger redesign:

- the helper should not allow mounting or unmounting of user provided
  paths at all. A dedicated directory like `/mounts/smb4k`, only controlled by
  `root`, should be used for these purposes. Some form of tracking which mount
  belongs to which user would be needed (e.g.  giving ownership of the mount to
  the client that requested it).  This is more like [udisks][upstream:udisks]
  solves the problem of mounting devices on user request.
- passing through arbitrary parameters from unprivileged clients to
  `mount.cifs` or `umount` won't work securely. A more abstract interface with
  well-defined settings for mounting or unmounting would help to restrict the
  degrees of freedom that a client has. This would also improve the decoupling
  of the helper's interface from the concrete implementation, this way the
  helper could e.g. change the implementation to call the `mount()` and
  `umount()` system calls directly, instead of going through the mount
  utilities.

{: #section-bugfix}
7) Upstream Bugfix
==================

During the course of a month we discussed various versions of patches with the
smb4k upstream developer, until we arrived at [a workable
patch][upstream:bugfix-commit] just in time for publication of this report
after the 90 days maximum embargo period we offered. The main aspects of the
bugfix are as follows:

- For `mount` and `unmount` the options passed by the client are now more
  closely scrutinized, and only settings present in a whitelist of options are
  allowed anymore.
- The `filemode` mount option, which is still basically supported, is now
  checked to make sure no special file bits are present.
- The `uid` and `gid` mount options can only be set to the UID/GID of the
  caller, not to arbitrary IDs anymore.
- Network share mounts are now restricted to a directory hierarchy rooted in
  `/run/smb4k`. This way, unprivileged users can no longer place symlinks in
  the mount destination paths. Mounts are placed in per-UID subdirectories
  such that different clients cannot influence each other's mounts anymore.
- For passing Kerberos credentials, clients now pass already open file
  descriptors to the mount helper, thereby avoiding any issues with regards to
  operating on untrusted paths.
- The problematic `KMountPoint` API is no longer used and has been replaced by
  Qt's `QStorageInfo` API. Formally the investigation of existing mount points
  would no longer be necessary at all with the trusted mount tree location,
  but the upstream developer preferred to keep this extra verification step
  for the time being.

We want to express our thanks to Alexander Reinholdt, the smb4k upstream
developer, for cooperating with us and finishing the patch in time for
publication. This way a series of long-standing issues in smb4k could finally
be addressed.

{: #section-workarounds}
8) Possible Workarounds
=======================

If the upstream bugfix cannot be used right away, the following suggestions
can be considered to remove the attack surface described in this report:

- Raise the Polkit authentication requirements for the mount and unmount
  helper actions to `auth_admin`. This way the problematic logic can only be
  reached by already privileged users. This contradicts the original purpose of
  smb4k, however, to allow unprivileged mounts and unmounts of network shares.
- Restrict D-Bus access to the mount helper utility to members of an opt-in
  group like `smb4k`. Coupled with a security disclaimer, this would allow
  users that really want to use this feature to opt-in.

{: #section-reproducers}
9) Reproducers
==============

The KAuth D-Bus interface cannot easily be invoked via utilities like `gdbus`,
because it expects a serialized `QVariantMap` as input. We offer two C++
programs which can be used to perform standalone tests of smb4k's mount helper
API for the purposes of reproducing the attack vectors described in this
report, [`smb4k_mount.cpp`](/download/smb4k_mount.cpp) and
[`smb4k_unmount.cpp`](/download/smb4k_unmount.cpp). There are comments in the
source code of the reproducers that explain how to compile and use them.

{: #section-cves}
10) CVE Assignment
==================

Formally the findings in this report could justify a large count of CVEs, but
we decided to condense them into the two main aspects that result from the
issues:

- CVE-2025-66002: local users can perform arbitrary unmounts via the smb4k
  mount helper due to lack of input validation.
- CVE-2025-66003: local users can perform a local root exploit via the smb4k
  mount helper if they can access and control the contents of a Samba network
  share.

When the end of the 90 days maximum non-disclosure period we offered upstream
approached, due to lack of feedback from KDE Security, we assigned these CVEs
as we originally suggested them to upstream.

{: #section-disclosure}
11) Coordinated Disclosure
==========================

We reached out to KDE security on September 11 and shared the full details
about the issues described in this report, offering coordinated disclosure.
For nearly the first two months of the maximum 90 days non-disclosure period,
we had difficulties getting clear answers from KDE security about the expected
publication date, whether they acknowledged the findings or even whether they
wanted to practice coordinated disclosure at all.

We only saw some visible progress at the beginning of November, when the
smb4k upstream developer joined the discussion and started developing
bugfixes. The progress remained slow, however, due to limited resources on the
end of the developer. Still, from this point onwards the discussion turned out
helpful and cooperative, and we could finally see that the non-disclosure time
was actually being put to use. We managed to agree on a bugfix that addresses
all the issues only less than a week before the 90 days maximum embargo period
would be reached.

In summary, we are not completely happy about how the coordinated disclosure
developed in this case. We perceived an unwillingness on the end of KDE security
to communicate and to help in coordinating the disclosure. We believe the
issue could have been fixed faster by suggesting a workaround to users and
by developing a bugfix in the open, with the help of the rest of the
community.

12) Timeline
============

|2025-09-11|We forwarded our report to security@kde.org, offering coordinated disclosure.|
|2025-09-17|We received acknowledgement of receipt from KDE security.|
|2025-09-29|Not having heard anything else from upstream, we asked at least for a confirmation of the issues described in the report and a formal decision whether coordinated disclosure was desired. We asked to get feedback until October 2, lest we would publish the information on our end.|
|2025-10-01|We got a reply from KDE security that they were working on the issue, without answering our questions. We replied again and tried to clarify that we did not intend to put time pressure on upstream, but would like to clearly setup the coordinated disclosure process.|
|2025-10-02|We got a short reply that they could not give us an expected publication date, repeating again that they were working on the issue. Our questions pertaining the process still remained unanswered. We once more explained that we would like to be involved in reviewing potential bugfixes where we could offer our help, and that we would like to avoid non-disclosure time passing without any visible progress.|
|2025-10-07|KDE security informed us that the fix was moving forward without giving further details.|
|2025-11-07|The smb4k developer, Alexander Reinholdt, contacted us directly sharing a first batch of suggested bugfixes.|
|2025-11-12|We provided detailed feedback on the security relevant part of the patch, pointing out various problems that remained, and new problems that got introduced.|
|2025-11-12|KDE security chimed in about the [KMountPoint][subsection:kmountpoint] topic, stating that smb4k would be the only privileged component using this API.|
|2025-11-13|We replied to KDE security explaining in more detail the remaining concerns we had regarding the KMountPoint API.|
|2025-11-16|The smb4k developer thanked us for the review of the patch, and sent back detailed comments on our input. He told us he would be working on a follow-up patch set.|
|2025-11-26|The smb4k developer informed us that it would take still more time for him to provide the improved version of the patch.|
|2025-11-26|We thanked the developer for his continued effort, but also reminded all participants that the end of the 90 days maximum non-disclosure period we offered was approaching in two weeks. We suggested the alternative of publishing a temporary workaround instead (like increasing authentication requirements), should a full bugfix be out of reach within the remaining time. We also suggested to involve the [distros mailing list][distros-list] at this time, to give other Linux and BSD distributions a chance to prepare before general publication of the report.|
|2025-11-27|On the topic of the KMountPoint API, KDE security clarified that they ideally would like a merge request from us addressing our concerns.|
|2025-11-28|We assigned [the CVEs][section:cves] the way we initially suggested them to upstream, to provide them as additional information to the distros mailing list. We also shared the CVEs with upstream.|
|2025-11-30|The upstream developer shared an improved patch set with us.|
|2025-12-01|We sent another round of comments back to the upstream developer. The new patch was still lacking in a number of areas.|
|2025-12-01|We forwarded a draft of this report to the distros mailing list, announcing publication of the issues on 2025-12-10. We pointed out that no proper bugfix was available for sharing at this time.|
|2025-12-03|We received yet another version of the suggested patch from the upstream developer.|
|2025-12-04|This time we found no remaining security issues, agreed on the patch, but still commented on a couple of quality and style aspects.|
|2025-12-04|We forwarded the bugfix from the upstream developer to the distros mailing list.|
|2025-12-05|We asked the upstream developer to publish a bugfix release on 2025-12-10, which he agreed upon.|
|2025-12-10|Upstream published the [bugfix release 4.0.5][upstream:bugfix-release] as planned.|
|2025-12-10|Publication of this report.|

13) References
==============

- [smb4k KDE Project][upstream:project]
- [smb4k 4.05 bugfix release][upstream:bugfix-release]
- [upstream bugfix for the issues in this report][upstream:bugfix-commit]
- [SUSE Bugzilla review bug for smb4k][bugzilla:new-review]
- [Bug report against the KIO library regarding KMountPoint API issues][upstream:kio-bug-report]

[upstream:project]: https://invent.kde.org/network/smb4k.git
[upstream:review-release]: https://invent.kde.org/network/smb4k/-/tags/4.0.4
[upstream:bugfix-release]: https://sourceforge.net/p/smb4k/blog/2025/12/smb4k-405-security-bug-fix-release
[upstream:bugfix-commit]: https://invent.kde.org/network/smb4k/-/commit/0dea60194ab6eb8f6e34ca2e6cb0f97b90c46f1e
[upstream:kio]: https://invent.kde.org/frameworks/kio
[upstream:kio-release]: https://invent.kde.org/frameworks/kio/-/tree/v6.17.0?ref_type=tags
[upstream:kio-bug-report]: https://bugs.kde.org/show_bug.cgi?id=513176
[bugzilla:old-review]: https://bugzilla.suse.com/show_bug.cgi?id=1033300
[bugzilla:kauth-bypass]: https://bugzilla.suse.com/show_bug.cgi?id=1036244
[bugzilla:old-exploit]: https://bugzilla.suse.com/show_bug.cgi?id=1036245
[bugzilla:new-review]: https://bugzilla.suse.com/show_bug.cgi?id=1249004
[code:mount-helper]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags
[code:mount-cmdline]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L73
[code:mount-krb5ccname]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L97
[code:umount-path-verification]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L177
[code:umount-cmdline]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L187
[code:mountpoints]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L163
[code:online-check1]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L205
[code:online-check2]: https://invent.kde.org/network/smb4k/-/blob/4.0.4/helpers/smb4kmounthelper.cpp?ref_type=tags#L38
[code:kio:libmount]: https://invent.kde.org/frameworks/kio/-/blob/v6.17.0/src/core/kmountpoint.cpp?ref_type=tags#L341
[code:kio:stat]: https://invent.kde.org/frameworks/kio/-/blob/v6.17.0/src/core/kmountpoint.cpp?ref_type=tags#L365
[code:kio:resolve]: https://invent.kde.org/frameworks/kio/-/blob/v6.17.0/src/core/kmountpoint.cpp?ref_type=tags#L382
[code:kio:resolve-func]: https://invent.kde.org/frameworks/kio/-/blob/v6.17.0/src/core/kmountpoint.cpp?ref_type=tags#L267
[man:mount-cifs]: https://man7.org/linux//man-pages/man8/mount.cifs.8.html
[man:umount]: https://man7.org/linux/man-pages/man8/umount.8.html
[section:reproducers]: #section-reproducers
[section:suggested-fixes]: #section-suggested-fixes
[section:bugfix]: #section-bugfix
[section:workarounds]: #section-workarounds
[section:overview]: #section-overview
[section:mount-problems]: #section-mount-problems
[section:unmount-problems]: #section-unmount-problems
[section:remarks]: #section-remarks
[section:cves]: #section-cves
[subsection:kmountpoint]: #subsection-kmountpoint
[subsection:mount-arbitrary-dir]: #subsection-mount-arbitrary-dir
[subsection:mount-arbitrary-args]: #subsection-mount-arbitrary-args
[subsection:umount-arbitrary-args]: #subsection-umount-arbitrary-args
[subsection:umount-arbitrary-dir]: #subsection-umount-arbitrary-dir
[upstream:udisks]: https://github.com/storaged-project/udisks
[distros-list]: https://oss-security.openwall.org/wiki/mailing-lists/distros
