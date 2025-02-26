---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "KDE: Admittance of kio-admin into openSUSE"
date:   2025-02-21
tags:   KDE Polkit
excerpt: "kio-admin is a KDE component which allows to perform
privileged file operations in GUI applications. A first request to add this
package to openSUSE had been rejected by the SUSE security team in 2022. After
careful reevaluation of the situation, this is about to change. This post
explores the background of this development."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[kio-admin][upstream:kio-admin-git] is a KDE component which allows to
perform privileged file operations in GUI applications. It implements a D-Bus
service running as `root` and uses Polkit for authentication. A typical use
case of kio-admin is found in KDE's Dolphin file manager, which allows to
enter an admin mode, in which file manager operations are carried out as
`root` instead of as the unprivileged user.

The [initial 2022 request][bug:kio-admin-initial] to add kio-admin to openSUSE
was rejected by us due to security concerns. Some time ago [we have been asked
to revisit][bug:kio-admin-revisited] this package to see if it could be added
now. The security assessment of kio-admin is a difficult one, nonetheless we
decided to accept it into openSUSE this time since the probability of actual
exploits is low. The following sections explore the history of privileged file
operations in KDE up to kio-admin, the rationale for accepting it into
openSUSE at this point and recommendations for safely performing privileged
file operations in complex scenarios.

2) History of Privileged File Operations in KDE
===============================================

KTextEditor File Saving Operation
---------------------------------

Historically, for performing privileged operations in GUI applications, the
complete application had to be executed as `root`. Doing so is generally
discouraged, since GUI programs are complex and not always written with
potential security issues in mind. Also the inner workings of the X11 protocol
and X server implementations have been a reason for security woes when running
graphical applications with raised privileges.

One way out of this "all or nothing" approach was the introduction of
[Polkit][upstream:polkit-git], which allows to define individual actions for
privileged operations. These actions are authenticated by the `polkitd`
daemon. Applications are then typically separated in two parts. An
unprivileged graphical application which contains the majority of the code
communicates with a back end to execute the privileged operations.
The back end is much smaller in size and runs as `root`.

This approach works well when the nature of the privileged operation has a
clearly defined scope like "enable a VPN connection" or "connect to a
Bluetooth device". Problems arise, though, when this is not the case. This
happened in KDE in 2017, [when a D-Bus service with Polkit
authentication was added to KTextEditor][bug:ktexteditor]. This service is
part of a feature which allows an unprivileged user to save a file to a
privileged file system location after entering the `root` password. From the end
user's point of view this makes perfect sense: why shouldn't the user of a
typical single-user desktop system be allowed to change configuration files
this way?

Former security team member Sebastian Krahmer was [kind of
outraged][bug:ktexteditor-krahmer] by this idea, though, because the Polkit
action lacked a well-defined scope. Writing arbitrary data to arbitrary
files on disk can lead to all kinds of problematic situations. Let's consider
a few scenarios:

- a file is saved in a system configuration directory owned by `root`, like
  `/etc/fstab`. This is likely the typical use case considered by the upstream
  developers.
- a file is (accidentally) saved to an unprivileged location the user controls
  anyway like `/home/$USERNAME/some_file`. The privilege escalation would not
  even be necessary in this case, but acting with `root` privileges in this
  location is dangerous.
- a file is saved to a configuration or state directory owned by an
  unprivileged service user like `/var/lib/chrony`. Now three different user
  accounts are involved: the unprivileged user providing the file content and
  asking for the operation, the `root` user performing the privileged
  operation and the service user `chrony` which actually controls the file
  system location where the write is about to happen.
- a file on a pseudo file system like `/proc` or `/sys` could be changed this way.
  Pseudo files often have special semantics with regards to the way data is
  written to them. Without being aware of this, the privileged KTextEditor
  helper component could cause side effects or simply not fulfill correctly
  what the user had in mind.
- a target path might not yet exist. Should it be newly created? What
  ownership and mode should be applied to such a newly created file?
- a target path might exist, but have a special file type. By naively
  accessing such files, the write could be redirected to unintended locations
  (by following symbolic links) or denial-of-service could occur (by blocking on
  a FIFO pipe). What should be done in this case: should the write operation
  fail, should the special file be silently replaced or should the user be asked
  interactively what to do?

We can see from this list that many different situations can result from what
looked like just a simple "file save" operation in the beginning. We reviewed
the code for this KTextEditor feature more closely and discovered
[CVE-2018-10361][oss-sec:ktexteditor], a local root exploit when the
privileged back end attempts to save a file in a directory owned by another
unprivileged user.

After the finding was fixed by upstream we asked for a number of improvements
before we would accept this D-Bus service into openSUSE:

- the destination path should be added to the Polkit authentication message
  ([bsc#1147035][bug:ktexteditor-auth-message]). Currently it would only show a
  generic message about manipulating a privileged file. To prevent potential
  accidents or even spoofing, the message should clearly state _what_ is
  being authenticated.
- the target file ownership and mode should be completely defined either by
  the back end, or by the front end ([bsc#1147038][bug:ktexteditor-file-meta]).
  Currently the front end could optionally pass the file owner and group, but
  not the mode. For creating new files, the GUI part should ideally actively ask
  the user for the desired file properties. This is because neither the back
  end nor the front end can reliably guess the mode for new files. Should it
  be world readable or not? Should it be controlled by `root`, or by a service
  account or even another interactive user? This is something that can only be
  answered by the user asking for the operation to be performed.
- the back end should not replace anything except regular files. Symlinks
  should not be followed, any other special files should not be accessed or
  replaced ([bsc#1147041][bug:ktexteditor-only-regular]).
- when writing to a directory not owned by `root`, then the back end component
  should drop privileges to the owner of the directory before performing file
  operations within it ([bsc#1147043][bug:ktexteditor-privdrop]).
- a restriction on destination file systems should be implemented, e.g. to
  prevent the operation on pseudo file systems
  ([bsc#1147045][bug:ktexteditor-fs-filter]).

We never heard back from upstream or our KDE maintainers on any of these
points, therefore this part of KTextEditor is still not enabled on openSUSE.
Implementing most of the changes we requested would have been well within
reach; only the dynamic authentication message involved some obstacles,
because the Qt and KDE framework libraries for Polkit did not fully support
this at the time.

KIO Framework for Privileged File System Operations
---------------------------------------------------

While there was no progress with the requested improvements of the "save file
to an arbitrary location" feature in KTextEditor, developers of the [KIO
framework][upstream:kio-git] around the same time attempted to extend the
concept of privileged file operations via D-Bus and Polkit even further. There
was an [effort to make a full range of privileged file operations available to
GUI applications][upstream:kio-polkit-feature]: `chmod()`, `chown()`,
`unlink()`, `mkdir()`, `rmdir()`, `open()`, `opendir()`, `rename()`,
`symlink()` and `utime()`. We were [asked to participate in design
discussions][bug:kio-framework] about this feature.

The resulting D-Bus service ended up being something like a mini kernel in user
space, offering all kinds of file system APIs. Some of the problems observed
in KTextEditor became even worse in this approach. While in KTextEditor it is at
least clear that only regular files are supposed to be accessed, nothing is
known about the context of the file operations in KIO. All the individual
operations are detached from each other. Applications typically need to
perform a specific task covering a certain range of file operations that are
logically related. One such task might be to atomically replace a file in a
privileged location by a new version of the file. This would require a
sequence of calls like `open()` for the new file to be created, a `chown()` to
assign the desired ownership to it and finally a `rename()` to replace the old
file by the new file. The KIO D-Bus service did not have this additional
context information and thus could not clearly inform the user about what is
going to happen.

Only a single Polkit action "org.kde.kio.file.exec" was used to authenticate
any of these privileged file system operations. The authentication message
displayed to users is, like in KTextEditor, a generic one. Users won't be
able to determine exactly what kind of file operation they are authenticating.
The user will either be presented with multiple authentication requests for a
single task (`auth_admin` Polkit setting) or the D-Bus service will cache
authentication for some time (`auth_admin_keep` Polkit setting) thereby
allowing an unknown amount and range of file operations to be performed for an
indefinite time span. In both cases the scope of what is authenticated is
unclear to an average end user.

Since a generic D-Bus service that offers file operations cannot know what the
logical goal of a client application is, the service basically needs to expose
all variants of file system operations and the flags influencing them to
applications. Modelling this on D-Bus correctly and completely is a difficult
task. Such an approach also puts a burden on the applications that now need to
implement complex sequences of system calls indirectly via an asynchronous
D-Bus IPC interface.

Another approach to make an interface like this work in a robust and
safe way could be to implement some form of transaction handling. The
application would request a task like "replace /etc/fstab" and register a
sequence of calls that are logically related for this task like:
open `/etc/fstab.new`, chmod `/etc/fstab.new`, rename `/etc/fstab.new` to
`/etc/fstab`. The back end would then only authenticate and allow these file
operations on the requested paths. This again would lead to a highly complex
interface, however.

Securely operating in arbitrary file system locations with raised privileges
is already a highly difficult task when doing so using plain system calls.
The program has to take into account the necessity to perform a privilege drop
to the owner of a directory, it needs to avoid following symbolic links in
many situations, it might need to open files using the `O_PATH` flag to avoid
accessing dangerous special files unwittingly. The task just seems too complex
to cover it generically using an abstract IPC interface. Polkit as an
authentication mechanism is also not suited well for such a kind of generic
API.

As a consequence of the involved complexities, [after long
discussions][upstream:kio-priv-discussion], upstream [abandoned this
feature][upstream:abandoned-kio-pr]. The code is still present in the KIO
repository, but the privileged `file_helper` [is not
installed][kio:disabled-helper].

The kio-admin Back End
----------------------

With this we arrive at [kio-admin][upstream:kio-admin-git]. We were
[asked for inclusion][bug:kio-admin-initial] of this D-Bus service in 2022. It
is another variation on the "privileged file operation" theme. Only this time
it is not an integral feature of the KIO framework, but a separate component
running as `root` that acts as a regular client towards KIO.

We decided not to accept kio-admin for mostly the same reasons as we have
stated previously regarding KTextEditor and the KIO framework feature above.
In 2024 we have been asked [to revisit][bug:kio-admin-revisited] kio-admin, to
check if it improved in the meantime.

Sadly the situation did not change much. The range of file operations offered
is very similar to what was proposed for KIO: `chown()`, `chmod()`, `mkdir()`,
listing directory contents and so on. In some respects the API is even worse
than what was proposed for KIO earlier, because all operations are performed
on paths, not on file descriptors. There is less control over individual
operations with regards to following symbolic links and other behaviour of
system calls. The implementation of the D-Bus service is more complex,
requests are asynchronously forwarded by kio-admin to KIO. The kio-admin D-Bus
API also uses
[URIs](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) like
"file:///etc/fstab" instead of plain paths.

Again there exists only a single Polkit action "org.kde.kio.admin.commands"
which uses a generic authentication message for authorization of any of the
offered operations. The scope of the request that gets authenticated remains
again unclear to users.

The actual implementation of the file operations found in the KIO framework is
often naive with respect to occurrence of symbolic links and also subject to
race conditions, should a third user account in the system have control over
the directory in which the operations take place.

Integration of kio-admin into the Dolphin File Manager
------------------------------------------------------

One of the main use cases of the kio-admin component is found in the [Dolphin
file manager][upstream:dolphin-git] "admin mode" feature. This is a mode in
which all file operations are forwarded to the kio-admin back end, to perform
them with raised privileges.

The way this feature is implemented in Dolphin is actually well thought out.
There are clear warnings and a visible red bar at the top as long as the
"acting as admin" mode is active. Also Dolphin rejects changing symbolic link
targets and correctly displays that link permissions cannot be changed.

This cannot completely fix things like race conditions on part of the
kio-admin back end, however. When Dolphin sees a regular file for example, and
triggers a request at kio-admin to operate on it, the path could be replaced
by some other file type by the time the KIO framework starts operating on it.

3) Assessment of Security Concerns
==================================

The concerns we have about privileged file operations exposed via D-Bus APIs
affect local system security. These days it is often argued that nearly all
Linux desktop systems are single-user desktops and thus local system security
is not important. The attack surface found in kio-admin can still affect
defense-in-depth, though. Consider file operations taking place in directories
owned by unprivileged service users or by `nobody`. If such an account is
compromised, then attack vectors like symlink attacks can lead to full
privilege escalation. In this sense, every Linux system could be considered a
multi-user system, even if no other human interactive users are present.

The general purpose nature of such APIs makes it hard to judge what future
uses might look like. Once such an API is accepted into the distribution, it
is difficult to keep track of additional consumers of the API. The
proliferation of its use, maybe also in the area of non-interactive background
tasks, could increase the dangers we already identified.

For these reasons we rejected the inclusion of the kio-admin API into openSUSE
up until now.

4) Rationale for Accepting kio-admin into openSUSE
==================================================

We have dealt with these types of APIs in KDE since 2017 without achieving any
notable improvements. As we are responsible for product security we tried to
protect our users from potentially harmful components. At this point, though,
we don't believe that this situation will change anytime soon. Meanwhile users
still want to use features like the one found in Dolphin, and don't understand
why openSUSE does not include them.

We realize that using non-robust APIs is still an improvement over running
graphical applications completely as `root`. Also in its current form, the
likelihood that an operation interactively performed via kio-admin is actually
exploited, is low.

There also exists a GNOME desktop component called [gvfs][upstream:gvfs-wiki]
which is very similar to kio-admin. It was [accepted into openSUSE in
2017][bug:gvfs-initial] without looking in detail at its purpose and API
design. In the context of the discussions about KTextEditor we performed [a
second more in-depth review][bug:gvfs-revisited], during which we found
problems closely resembling the concerns about kio-admin discussed in this
article.  Still, we decided to keep it in openSUSE, due to historical reasons.

Thus, on the grounds of equal treatment and to allow for a good user experience
on openSUSE, we have now decided to set aside our concerns about kio-admin and
admit it into openSUSE. This feels like the pragmatic choice to us given the
circumstances. We would have liked to see a more robust and transparent API
design, however. We hope that upstream developers find ways to better address
our concerns in the future, meanwhile we still recommend end users to be
careful when using these features and take heed of the recommendations we give
in the next section.

5) Recommendations for Users of kio-admin or gvfs
=================================================

Unfortunately there are many pitfalls when performing privileged file
operations. We assume that even power users tend to make mistakes when running
shell commands as `root` operating in directories controlled or influenced by
non-root users, like in `/tmp`. Following is some general advice that can help
to avoid such mistakes.

For a start, APIs like kio-admin and gvfs are usually safe to use when file
operations happen in directories owned by `root`, like in `/etc` (note that
sub-directories of `/etc` can again be owned by non-root users). Special care
should be taken when changing files in directories controlled by another
user, like another user's home directory or files owned by a service user
account.

In such scenarios it is safer to perform the operations in a `root` shell, and
one should be very careful not to follow symbolic links while doing so. Many
file management utilities offer specific switches to avoid following them. The
`chmod` utility, for example, will by default follow symbolic links in the
target file path unless the `-h` switch is passed to it.

Even these switches only protect against symbolic links in the final component
of a path.  Consider the command `chmod -h 644
/var/lib/chrony/sub-dir/target`.  `/var/lib/chrony` is controlled by the
`chrony` service user account. Thus the unprivileged `chrony` user can turn
`sub-dir` into a symbolic link pointing to a privileged location like `/etc`.
If `/etc/target` existed then the command above would make this file
world-readable.

Therefore an even better approach to editing files owned by another account is
to assume their identity, for example by invoking `sudo -u <user> -g <group>
/bin/bash`. This way no elevated privileges that could be abused by a
compromised account are present in the first place.

6) Next Steps for Inclusion of kio-admin
========================================

Documenting our concerns in this blog post is the first step of the process to
add kio-admin to openSUSE. We will reference this blog post and some hints in
dedicated README files added to the kio-admin and gvfs packages. We will also
document this in the openSUSE wiki.  When all of this is done we will perform
the necessary steps to allow kio-admin into openSUSE Tumbleweed, which we
believe will happen within the next two weeks.

7) References
=============

- [kio-admin Git Repository][upstream:kio-admin-git]
- [Dolphin file manager Git repository][upstream:dolphin-git]
- [KTextEditor Git repository][upstream:ktexteditor-git]
- [GNOME gvfs wiki page][upstream:gvfs-wiki]

[upstream:kio-admin-git]: https://invent.kde.org/system/kio-admin
[upstream:kio-git]: https://invent.kde.org/frameworks/kio
[upstream:dolphin-git]: https://invent.kde.org/system/dolphin
[upstream:ktexteditor-git]: https://invent.kde.org/frameworks/ktexteditor
[upstream:polkit-git]: https://github.com/polkit-org/polkit
[upstream:gvfs-wiki]: https://wiki.gnome.org/Projects/gvfs
[bug:kio-admin-initial]: https://bugzilla.suse.com/show_bug.cgi?id=1205607
[bug:kio-admin-revisited]: https://bugzilla.suse.com/show_bug.cgi?id=1229913
[bug:ktexteditor]: https://bugzilla.suse.com/show_bug.cgi?id=1033055
[bug:ktexteditor-krahmer]: https://bugzilla.suse.com/show_bug.cgi?id=1033055#c2
[bug:ktexteditor-auth-message]: https://bugzilla.suse.com/show_bug.cgi?id=1147035
[bug:ktexteditor-file-meta]: https://bugzilla.suse.com/show_bug.cgi?id=1147038
[bug:ktexteditor-only-regular]: https://bugzilla.suse.com/show_bug.cgi?id=1147041
[bug:ktexteditor-privdrop]: https://bugzilla.suse.com/show_bug.cgi?id=1147043
[bug:ktexteditor-fs-filter]: https://bugzilla.suse.com/show_bug.cgi?id=1147045
[bug:kio-framework]: https://bugzilla.suse.com/show_bug.cgi?id=1062040
[bug:gvfs-initial]: https://bugzilla.suse.com/show_bug.cgi?id=1073214
[bug:gvfs-revisited]: https://bugzilla.suse.com/show_bug.cgi?id=1124494
[upstream:abandoned-kio-pr]: https://invent.kde.org/frameworks/kio/-/merge_requests/731
[upstream:kio-priv-discussion]: https://phabricator.kde.org/D14467
[upstream:kio-polkit-feature]: https://phabricator.kde.org/T6561
[kio:disabled-helper]: https://invent.kde.org/frameworks/kio/-/blob/v6.10.0/src/kioworkers/file/kauth/CMakeLists.txt?ref_type=tags#L9
[oss-sec:ktexteditor]: https://seclists.org/oss-sec/2018/q2/65
