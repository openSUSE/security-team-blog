---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "dnf5daemon-server: Incomplete fix of CVE-2024-1929 (CVE-2024-2746)"
date:   2024-04-03
tags:   CVE local D-Bus
excerpt: "The dnf5 D-Bus daemon security issues we found previously have been incompletely fixed. This allows for local DoS, possibly Privilege Escalation."
---

Table of Contents
================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

CVE-2024-1929 that we [previously reported][dnf5-main-report] for the dnf5
D-Bus component has not been completely fixed. This post deals with the
remaining issue we discovered.

2) Unsafe Configuration Item "reposdir" in Whitelist
====================================================

The problem with CVE-2024-1929 was that the dnf5 D-Bus daemon accepted
arbitrary configuration parameters from unprivileged users, which allowed a
local root exploit by tricking the daemon into loading a user controlled
"plugin". All of this happened before Polkit authentication was even started.

The [original bugfix][incomplete-bugfix] consists of a whitelist of
configuration items, that unprivileged users are allowed to override, when
using the dnf5 D-Bus interface. While checking each of the whitelisted items,
we found that the setting "reposdir" allows to specify the path to an
arbitrary directory, in which repository configuration files (`*.repo`) [will
be processed][reposdir-processing-loop] by the privileged dnf5 daemon.

The dnf5 library code does not check whether non-root users control the
directory in question. The code [does check for file type and filename
extension][reposdir-race-condition] of contained files; it follows symlinks
and is subject to a race condition, however:

```c++
    std::filesystem::directory_iterator di(dir_path, ec);
    std::vector<std::filesystem::path> paths;

    for (auto & dentry : di) {
        auto & path = dentry.path();
        if (dentry.is_regular_file() && path.extension() == ".repo") {
            paths.push_back(path);
        }
    }

    std::sort(paths.begin(), paths.end());

    for (auto & path : paths) {
        create_repos_from_file(path);
    }
```

By the time the (checked) path is passed to `create_repos_from_file()`, the
user controlling the directory can replace it with an arbitrary other file or
symlink, thereby tricking the library to operate on arbitrary file types and
file paths.

On one hand, this poses a Denial-of-Service attack vector by making the daemon
operate on a blocking file (e.g. named FIFO special file) or a very large file
that causes an out-of-memory situation (e.g. /dev/zero). On the other hand,
this can be used to let the daemon process privileged files like /etc/shadow.
The file in question is parsed as an INI file. Error diagnostics resulting from
parsing privileged files could cause information leaks, if these diagnostics
are accessible to unprivileged users. In the case of libdnf5, no such user
accessible diagnostics should exist, though.

Even more interestingly, a local attacker can place a valid repository
configuration file in this directory. This configuration file allows to
specify [a plethora of additional configuration
options][reposdir-config-parser]. This makes various additional code paths in
libdnf5 accessible to the attacker. This, and the possibility to configure
arbitrary repositories, could very well allow further privilege escalation,
although we did not investigate more deeply if and how this would be possible.

This follow-up issue confirms the sentiment expressed in our original report,
that one has to be extremely careful about feeding untrusted input into the
libdnf5 library, which is not designed to run in mixed security scope setups.

3) Bugfix and CVE Assignment
============================

The [bugfix][whitelist-bugfix] simply consists of the removal of the
"reposdir" entry from the whitelist of configuration items. Upstream
[release 5.1.17][bugfix-release] contains the bugfix. The Red Hat security
team assigned CVE-2024-2746 to track this incomplete fix of CVE-2024-1929.

4) Discovery Process
====================

We noticed the incomplete fix only at a late time, when our openSUSE dnf5
package maintainer asked for the inclusion of the fixed package into openSUSE
Tumbleweed. It is unfortunate that this happened too late to prevent an
incomplete fix for CVE-2024-1929, and thus made a follow-up CVE assignment and
coordinated release process necessary.

Since the original issues had been handled as part of a coordinated
disclosure process, there should have been a review of the proposed patches
before publication. Due to the circumstances of an early publication of the
fixes, outside of the coordinated release process, there never was a defined
point in time for us to actually review them. We aim to avoid such
situations in the future by being more careful about reviewing patches,
especially when no straightforward coordinated release process can be
established with upstream.

5) Timeline
===========

|2024-03-11|We reported the issue to secalert@redhat.com.|
|2024-03-13|The discussion for the issue was moved to a new group of contacts involving the dnf5 developers.|
|2024-03-20|One of the dnf5 developers confirmed the issue and suggested dropping "reposdir" from the whitelist.|
|2024-03-20|Red Hat security assigned CVE-2024-2746 for the follow-up issue.|
|2024-03-26|Discussions about the coordinated release date took place, 2024-04-02 has been mentioned.|
|2024-04-02|Red Hat security informed us that they actually had 2024-04-03 in mind.|
|2024-04-03|Upstream published release 5.1.17 containing the bugfix.|

6) References
=============

- [Previous report of dnf5 D-Bus daemon security issues][dnf5-main-report]
- [Bugfix commit for the follow-up security issue][whitelist-bugfix]
- [dnf5 Bugfix release 5.1.17][bugfix-release]

[dnf5-main-report]: /2024/03/04/dnf5daemon-server-local-root.html
[incomplete-bugfix]: https://github.com/rpm-software-management/dnf5/commit/6e51bf2f0d585ab661806076c1e428c6482ddf86
[reposdir-processing-loop]: https://github.com/rpm-software-management/dnf5/blob/5.1.16/libdnf5/repo/repo_sack.cpp#L597
[reposdir-race-condition]: https://github.com/rpm-software-management/dnf5/blob/5.1.16/libdnf5/repo/repo_sack.cpp#L584
[reposdir-config-parser]: https://github.com/rpm-software-management/dnf5/blob/5.1.16/libdnf5/repo/config_repo.cpp#L96
[whitelist-bugfix]: https://github.com/rpm-software-management/dnf5/commit/07c5770482605ca78aaed41f7224d141c5980de4
[bugfix-release]: https://github.com/rpm-software-management/dnf5/releases/tag/5.1.17
