---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "SUSE Security Team Spotlight Autumn 2024"
date:   2024-12-09
tags:   spotlight
excerpt: "This is the second edition of our new spotlight series. Autumn is
always a busy time at SUSE, when new service packs and products are
prepared. This results also in an increased amount of review requests arriving
for the SUSE security team. This post features a mixture of D-Bus interfaces,
Polkit authentication, temporary file handling issues, a small PAM module
and setgid-binary, Varlink IPC in systemd as well as some other topics."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

Introduction
============

Welcome to the second edition of our new spotlight series. With these posts we
want to give you an insight into activities of the SUSE security team beyond
major security findings for which we are publishing dedicated reports. Autumn
is always a busy time at SUSE, when new service pack releases and new products
are prepared. This results also in an increased amount of review requests
arriving for the SUSE security team. This time we will be looking at various
D-Bus interfaces, Polkit authentication, temporary file handling issues, a
small PAM module and setgid-binary, Varlink IPC in systemd as well as some
other topics.

Keepalived Follow-up Review
===========================

In [bsc#1218688](https://bugzilla.suse.com/show_bug.cgi?id=1218688) we looked
into [Keepalived](https://www.keepalived.org/), a load-balancing software
written in C. A colleague in the team noticed suspicious handling of temporary
files in `/tmp` and asked for a more in-depth review.

Temporary File Handling
-----------------------

The creation of temporary files in Keepalived is indeed a bit peculiar. The
[`make_tmp_filename()`](https://github.com/acassen/keepalived/blob/v2.3.2/lib/utils.c#L1370)
helper function takes the basename of a temporary file and returns a path to this file in
`$TMPDIR`. An example use would be `make_tmp_filename("keepalived.json")` and
the function will return `/tmp/keepalived.json`. This can easily lead to
unsafe temporary file creation.

In the code the resulting filenames are always coupled with another utility
function
[`fopen_safe()`](https://github.com/acassen/keepalived/blob/v2.3.2/lib/utils.c#L1030),
though. This function intercepts attempts to open files for writing (`"w"`
mode) and calls the `mkostemp()` function behind the scenes to safely create a
temporary file. The resulting file will then not be used as-is, though, but
will be `rename()`'d to the expected predictable filename. This is safe,
because `rename()` will not follow symlinks or otherwise reuse the target
path, but simply replace it.

D-Bus Implementation
--------------------

Keepalived also implements a D-Bus system service running as _root_. Our team
reviewed this component [many years
ago](https://bugzilla.suse.com/show_bug.cgi?id=1015141), which led to
multiple CVE assignments. Therefore it seemed like a good idea to have a fresh
look at the current situation, while we're at it. We couldn't find any
problems, though. The code is non-trivial but robust. The D-Bus methods can
only be called by root. Only some D-Bus properties can be accessed by
unprivileged users, but they are not sensitive in nature.

DKIMproxy Symlink Attack
========================

Our team is monitoring changes to systemd services across all of openSUSE
Tumbleweed. One such change occurred in
[DKIMproxy](https://dkimproxy.sourceforge.net) and led us to
[bsc#1217173](https://bugzilla.suse.com/show_bug.cgi?id=1217173). DKIMproxy
is a proxy designed for the Postfix mail server. It implements the DKIM
standard for signing outgoing email or verifying incoming email.

The package's systemd service is not part of the upstream sources, but has
been added by the package maintainer on packaging level [in the Open Build
Service](https://build.opensuse.org/projects/openSUSE:Factory/packages/dkimproxy/files/dkimproxy-in.service?expand=1).
In this service unit a shell script is executed via `ExecStartPre` with _root_
privileges, while the actual service runs with the lowered privileges of a
dedicated service user and group. The shell script performs naive write
operations in a directory owned by the unprivileged user. Therefore the
unprivileged user can prepare symlink attacks to cause arbitrary file
overwrite in the system, as soon as the script is executed again. The content
that is written is not controlled by the attacker, therefore this only has
denial-of-service impact and does not allow to raise privileges.

We can observe a number of aspects in this case that, based on our experience,
represent typical patterns. In the following sections we will look at these in
more detail.

Files Added on Packaging Level
------------------------------

Assets like configuration files, scripts or code that are added on packaging
level have an increased probability of introducing problems. Some of the
reasons for this could be:

- there are less people that review such contributions.
- the process for adding these files is less formalized than e.g. in a GitHub
  project.
- packagers that add such files might be lacking knowledge about the upstream
  project.
- packagers might accept such files from others that want a certain feature or
  behavior and don't know exactly what it does.
- packagers might take over such files from other Linux distributions,
  assuming that they are of high quality.

Since we identified that such packaging assets carry an increased risk for
issues, we are monitoring additions of and changes to such files in the Open
Build Service to look out for problems proactively.

Pre- or Post-Scripts in systemd Services
----------------------------------------

When privilege separation is in place for a systemd service, we can often
find such `ExecStartPre` and `ExecStartPost` scripts that are run with raised
privileges. This mixture of two different security domains can easily
introduce local security issues. This risk is further increased by the fact
that these programs are often shell scripts that offer no built-in mechanisms
to safely access files owned by unprivileged users as _root_.

Privilege Separation added after the Fact
-----------------------------------------

Especially in older software that was initially designed to run with full
_root_ privileges, privilege separation is sometimes only added as an
afterthought, or an unofficial downstream add-on on packaging level. On the
surface, such setups often seem to provide privilege separation, i.e. one or
more components are running as non-root accounts. This privilege separation
can often be easily circumvented as soon as the unprivileged account is
compromised, however.

Such weak privilege separation can still offer some level of protection and
is usually an improvement over services running as full _root_. Still, the
lack of robustness means that a false promise is given to administrators:
namely, that strong separation of privileges exists for such services. The
defense in depth is lacking, though, and a change of security scope can
happen. Thus, such issues are usually considered worthy of a CVE assignment.
In our team we assign or request CVEs for such issues on a case-by-case basis,
depending on the severity of the issue, the popularity of the affected
software and so on. In the case of DKIMproxy only a denial-of-service can
happen and the software is not that widespread, thus we decided not to assign
a CVE for it.

Handling of a Vulnerability Report in MirrorCache (CVE-2024-49505)
==================================================================

We have been privately approached by security researcher Erick Fernando about
a reflected XSS vulnerability in the openSUSE
[MirrorCache](https://github.com/openSUSE/MirrorCache) repository. MirrorCache
is a web server that redirects download requests to a mirror according to
configuration. We handled the report in
[bsc#1232341](https://bugzilla.suse.com/show_bug.cgi?id=1232341) and assigned
CVE-2024-49505 to it. The responsible maintainer applied a fix for the issue
and our team member [Paolo Perego](mailto:pperego@suse.de) verified the patch.

Luckily the MirrorCache project is not part of any official products or server
side infrastructure of SUSE. We want to thank Erick Fernando again for
reaching out to us and reporting this issue.

Issues with Temporary Files in Hardinfo2
========================================

[Hardinfo2](https://github.com/hardinfo2) is a utility to obtain hardware
information on Linux, create reports from that data and compare different
systems for benchmarking. Hardinfo2 has been newly packaged for openSUSE
Tumbleweed in October, and the following lines showed up in our systemd
monitoring:


    RPM: hardinfo2-2.1.14-1.1.x86_64.rpm on x86_64
    Package: hardinfo2
    Service path: /usr/lib/systemd/system/hardinfo2.service
    Runs as: root:root
    Exec lines:
        ExecStart=/bin/sh -c "
            cat /proc/iomem >/tmp/hardinfo2_iomem;
            chmod a+r /tmp/hardinfo2_iomem;
            cat /proc/ioports >/tmp/hardinfo2_ioports;
            chmod a+r /tmp/hardinfo2_ioports;
            chmod a+r /sys/firmware/dmi/tables/*;
            modprobe -q spd5118;modprobe -q ee1004;modprobe -q at24 || true"

The use of fixed temporary file paths sticks out right away, so we created
[bsc#1231839](https://bugzilla.suse.com/show_bug.cgi?id=1231839) to handle the
issues resulting from this. By default, kernel protections like
`protected_symlinks` prevent more severe issues like overwriting system files,
which would lead to denial-of-service. Even with these protection measures, a
local user can pre-create these files and Hardinfo2 will then use the attacker
controlled data found in them, causing integrity violation.

Furthermore this logic causes information leaks. The data from `/proc/ioports`
is made world-readable via the temporary file `/tmp/hardinfo2_ioports`. By
default this information is already public in `/proc` on openSUSE. But it seems
on some systems this was not the case, because Hardinfo2 performs these steps
to allow unprivileged processes to access that data in `/tmp`. Another
information leak is the `chmod a+r` operation for
`/sys/firmware/dmi/tables/*`. The permissions of pseudo files should not be
altered in a drive-by fashion by system services this way.

We reported the issues to upstream, which quickly worked on improvements in
these areas. The shell code has been moved into a proper script named
`hwinfo2_fetch_sysdata`. The problematic files in `/tmp` are now placed
into a dedicated directory in `/run/hardinfo2`. Users that want to use
`hardinfo2` now need to be a member of a newly introduced "hardinfo2" group
to be able to access the data placed into this directory. The permissions
of files in `/sys` are no longer changed.

Upstream created a new release 2.2.1 containing the changes. We did not
request a CVE for these issues, since the biggest impact they can have by
default is integrity violation of Hardinfo2 itself.

Aeon-Check Encryption Key in Fixed Temporary File (CVE-2024-49506)
==================================================================

[Aeon-Check](https://github.com/AeonDesktop/aeon-check) is a small utility
used in [openSUSE Aeon](https://aeondesktop.github.io). Currently it consists
only of a simple bash script invoked via a systemd unit. This script can
detect a bug in the TPM-based LUKS disk encryption setup and fix it. To this
end, an additional LUKS key slot is temporarily added to the root LUKS device:

```sh
keyfile=/tmp/aeon-check-keyfile
dd bs=512 count=4 if=/dev/urandom of=${keyfile} iflag=fullblock
chmod 400 ${keyfile}

<snip>

# Writing keyfile to slot 31 (end of the LUKS2 space) to avoid clashes with any customisation/extra keys
cryptsetup luksAddKey --token-only --batch-mode --new-key-slot=31 ${rootdev} ${keyfile}
```

The temporary file used to store the ephemeral LUKS key has a fixed filename
in `/tmp`. Fortunately the script has the `errexit` option set; combined with
the `protected_regular` and `protected_symlinks` kernel features, no unsafe use
of an already existing file in that path will succeed. Without the kernel
protection, though, another local user could pre-create this file, and
intercept or stage the data used as temporary LUKS key. Even then the chances
for exploitation are small, since this systemd service typically only runs
once during boot, and the time window during which the temporary LUKS key is
valid is short.

Since LUKS encryption is a sensitive area, we still decided to assign a CVE for
the issue. We handled the problem in
[bsc#1228861](https://bugzilla.suse.com/show_bug.cgi?id=1228861), and a simple
bugfix has been made by the author of the script to use `mktemp` for safe
creation of the temporary file holding the LUKS key data.

SDDM Follow-Up Review of D-Bus Interface
========================================

The openSUSE package for the [SDDM display
manager](https://github.com/sddm/sddm) has been forked for the [openSUSE
Kalpa](https://en.opensuse.org/Portal:Kalpa) flavour. This made a new
D-Bus service whitelisting necessary, which was requested in
[bsc#1232647](https://bugzilla.suse.com/show_bug.cgi?id=1232647). The
sddm-kalpa package is a Wayland-only version of SDDM, but the sources used in
the package are the same as for regular SDDM.

We still used this opportunity to take a fresh look at the situation in SDDM.
The D-Bus service shipped with it is practically only a skeleton without
implementation. Only a single D-Bus method
[`SwitchToGreeter()`](https://github.com/sddm/sddm/blob/v0.21.0/src/daemon/DisplayManager.cpp#L152)
is implemented. There is no Polkit authorization, which means that any user
can trigger the logic to switch to the greeter. While this situation is not
ideal, it is not critical. Therefore we accepted the new package.

Libcgroup Revisited
===================

[Libcgroup](https://github.com/libcgroup/libcgroup) is a library and set of
utilities for using control groups on Linux systems. These days systemd is
taking care of this job and, since libcgroup upstream was unmaintained, the
package was dropped from openSUSE in 2018. We received a request to
reintroduce libcgroup in [bsc#1231381](https://bugzilla.suse.com/show_bug.cgi?id=1231381).
Upstream is active again and there seem to exist some use cases for the package.

Our team was involved because the package contains a setgid binary and a PAM
module. We also had a look at the main daemon `cgrulesengd`, which is running
as _root_. At startup, the daemon iterates over all running processes in
`/proc` and assigns them to control groups according to configuration. Then a
netlink socket is set up to obtain events from the kernel about newly created
processes and `exec()` events. These new processes will also be placed into
control groups based on configuration.

The approach taken by the daemon is subject to race conditions by design,
which is also [kind of
documented](https://github.com/libcgroup/libcgroup/blob/release-3.1/README#L46)
in the upstream repository. Entries in `/proc/<pid>` can disappear or change
security scope e.g. when setuid-root binaries are involved. The configuration
is matched to processes based on their name as found in `/proc/<pid>/status`
and the process' effective _uid_ and _gid_. We can imagine that a dedicated
local attacker will be able to have the libcgroup daemon wrongly assign an
unprivileged process to a control group destined only for privileged processes
e.g. by exploiting race conditions and using setuid-root binaries like `sudo`.
Since this is by design, we did not approach upstream about this possibility.
Users of the package should be aware that this could result in local DoS
attack vectors, though.

The setgid program `cgexec` found in the package is a simple program
that only forwards an IPC request to the libcgroup daemon, asking it to mark
the calling process as "sticky". The binary requires special group permissions
to be allowed to connect to the UNIX domain socket of the libcgroup daemon.
The extra privileges are dropped right after connecting to the socket. The
socket is also closed right after sending the request. So escalating group
privileges, leaking the socket file descriptor or otherwise influencing the
IPC communication done by `cgexec` is not a concern.

The PAM module shipped with the package only implements a PAM `session` type
hook. It calls into the libcgroup library to assign the calling process to an
appropriate control group, thereby placing new sessions into control groups
according to configuration.

Supergfxctl D-Bus Service
=========================

[Supergfxctl](https://gitlab.com/asus-linux/supergfxctl) is a D-Bus daemon
that takes care of low level kernel settings in NVIDIA hybrid GPU systems. The
software has been newly packaged in November and we've been asked to whitelist
it in [bsc#1232776](https://bugzilla.suse.com/show_bug.cgi?id=1232776).

There are some worries with this daemon, mostly with regards to local
denial-of-service attack surface. For example there is some racy logic in the
daemon that looks up and kills all processes that have `/dev/nvidia0` open.
The D-Bus methods allow to completely control the daemon's configuration and
are by default accessible to all members of the _sudo_, _users_, _adm_ and
_wheel_ groups. This selection of groups is rather broad and surely targeted
towards maximum compatibility with various Linux distributions. It is unlucky,
because there is a possibly large range of users that are allowed to control
the supergfxctl daemon this way.

To make the new service acceptable for openSUSE we asked the packager to limit
access to the D-Bus service to members of the _video_ group instead. Users
that are in the _video_ group have increased privileges with regards to
accessing the video hardware in the system, thus it is a better match for
supergfxctl than just the _users_ group, for example. An even better approach
would be to add Polkit authentication in this D-Bus service, but this is
something that would require larger efforts by upstream and is not currently
in sight.

Systemd v257 Polkit for Varlink IPC
===================================

We routinely review additions to the D-Bus and Polkit interfaces in new
systemd releases. This time [we have been asked](https://bugzilla.suse.com/show_bug.cgi?id=1233295)
to check a few new Polkit actions in `systemd-containerd`, `systemd-homed`,
`systemd-networkd`, and `systemd-resolved`. Interestingly these daemons have
all been migrated from using D-Bus to using [Varlink](https://varlink.org/)
for Inter-Process-Communication (IPC).

In our experience, the code quality of systemd components is generally high.
These additions were no different. All new Polkit actions are limited to
`auth_admin` authorization, thus no additional attack surface is made
available to unprivileged local users.

At first sight the switch to Varlink doesn't change much security-wise:
there are still individual methods in a service that can be invoked by clients
and some or all of them can be protected by Polkit authentication. The switch
to Varlink requires new glue code for the authorization against Polkit,
however. Thus we looked deeper into how this is done in systemd.

When using D-Bus the
[SystemBusName](https://www.freedesktop.org/software/polkit/docs/latest/PolkitSystemBusName.html)
Polkit subject is used, which identifies a client process by its D-Bus sender
address. This way `polkitd` can securely identify the credentials of the
client process by asking the `dbus-daemon` about the credentials of the
owner of the UNIX domain socket used by the client to connect to D-Bus.

With Varlink this is no longer possible. Instead the
[UnixProcess](https://www.freedesktop.org/software/polkit/docs/latest/PolkitUnixProcess.html)
subject is used to identify the client. This made us a bit nervous at first,
because the UnixProcess subject is deprecated and often used insecurely. The
problem here is that `polkitd` needs to use racy logic to lookup the process
by PID in the `/proc` file system and extract its credentials. Former SUSE
security team member Sebastian Krahmer [discovered this in
2014](https://www.openwall.com/lists/oss-security/2014/03/24/2), and it
affected a lot of programs that implemented Polkit actions using this subject. The
use of this subject in systemd to authenticate Varlink methods is robust,
though. The client's credentials are obtained from the UNIX domain socket
underlying the Varlink connection, and thus via the kernel. Also a
[pidfd](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) can be passed
to Polkit nowadays, which allows `polkitd` to operate in a race-free fashion
on the client process.

As the Polkit glue code turned out all right we accepted the changes and
whitelisted the additions in systemd v257.

Miscellaneous
=============

The following reviews didn't yield much of interest, so we're just providing a
short listing here for reference:

- GNOME Remote Desktop follow-up review ([bsc#1230406](https://bugzilla.suse.com/show_bug.cgi?id=1230406)).
  Last time we looked into GNOME Remote Desktop, we found [a couple of issues in
  its D-Bus implementation](/2024/05/22/gnome-remote-desktop-system-dbus.html).
  Another D-Bus service "org.gnome.RemoteDesktop.Configuration.service" has been
  added in the meantime and we have been asked to take a look. The new service is
  rather small and all of its methods are protected by a single Polkit
  action "org.gnome.remotedesktop.configure-system-daemon", which requires
  Polkit `auth_admin` authentication. So there shouldn't be additional attack
  surface for local non-privileged users in the system. Overall the complexity
  of GNOME in this area continues to grow, though, and it is a challenge to
  review it fully without being an expert in GNOME and the remote desktop
  protocols.
- Additional D-Bus and Polkit features in the UPower Daemon
  ([bsc#1232835](https://bugzilla.suse.com/show_bug.cgi?id=1232835)). This
  just adds a boolean switch to control whether a battery charging threshold
  should be active or not. It is allowed for users in a local session without
  authentication.
- Added "memoryinformation" D-Bus Method in kinfocenter6 ([bsc#1231659](https://bugzilla.suse.com/show_bug.cgi?id=1231659)).
  Our packager backported this feature from a newer upstream version. This new
  action allows users in a local session to obtain the output of `dmidecode
  --type 17`, which contains some low-level information about physical RAM in
  the system. The implementation of this is straight-forward and we had no
  worries accepting this change.

Conclusion
==========

We hope that with this post we have been able to give you some additional
insights into our daily review work for openSUSE and SUSE products. Feel free
to reach out to us if you have any questions about the content discussed in
this article. We expect the winter issue of the spotlight series to be
available in about three months from now.
