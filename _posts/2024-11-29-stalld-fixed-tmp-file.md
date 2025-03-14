---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "stalld: unpatched fixed temporary file use and other issues"
date:   2024-11-29
tags:   local tmpfiles
excerpt: "Stalld is a daemon to prevent starvation of operating system threads
on Linux. We discovered a problematic use of a fixed temporary file and other
issues in the project, but upstream did not respond to our findings."
---

Table of Contents
================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

Stalld is a daemon that aims to prevent starvation of operating system threads
on Linux. It has recently been added to openSUSE Tumbleweed and we performed a
routine review of the contained systemd service. During the review we noticed a
couple of security issues that should be addressed.

We reached out to upstream via their GitLab issue tracker and created [a
public][daemon-mask-issue] and [a private issue][tempfile-issue] (still
private), but never got any reaction. After nearly three months without a
reply we decided to publish the available information now.

This report is based on stalld version v1.19.6.

2) Use of Fixed Temporary File Path `/tmp/rtthrottle` in `scripts/throttlectl.sh`
=================================================================================

The [throttlectl.sh script][code-throttlectl], which is called with root
privileges as a pre and post script in stalld's systemd unit, is using the
fixed /tmp path `/tmp/rtthrottle` to cache the original values found in
`/proc/sys/kernel/sched_rt_runtime_us` and
`/proc/sys/kernel/sched_rt_period_us`. This allows for a symlink attack and
a file pre-creation attack.

2.a) Symlink Attack
-------------------

A symlink attack can only work if the Linux kernel's `protected_symlinks`
setting is not in effect. If that would be the case then an attacker could
place a symlink at the location causing `throttlectl` to overwrite arbitrary
files in the system, allowing for a local Denial-of-Service.

2.b) File Pre-Creation Attack
----------------------------

Pre-creating the path in `/tmp/rtthrottle` will always work, even if the
`protected_regular` setting in the kernel is active. This is the case because
the shell redirection in the script (like in the line `echo $period >
$path/sched_rt_period_us`) will fall back to opening the target file without
`O_CREAT` in the `open()` flags, if creating the file fails. Without `O_CREAT`
the `protected_regular` logic no longer triggers.

This means that if a local attacker pre-creates the file, the script will write
to a file owned by the attacker. By the time the script tries to restore the
values from this file, the local attacker can place arbitrary values in it,
which will in turn be written to the pseudo files in
`/proc/sys/kernel/sched_rt_*`. This is a kind of local Denial-of-Service or a
local integrity violation. It is not an information leak, because the content
of these pseudo files is world-accessible anyway.

2.c) Exploitability
------------------

When stalld starts at boot time, there is not much opportunity for
unprivileged local users to exploit this issue. If the service is started at a
later time, or restarted, then the attack vector is exploitable, though.

2.d) Suggested Fix
-----------------

To fix this, we suggest to place the file into the `/run/stalld` directory,
which is owned by root. This directory is already created via stalld's systemd
unit.

In the systemd unit some hardenings like `PrivateTmp=yes` could also be
applied to prevent any future temporary file issues of this type.

The `throttlectl` script should also set the `errexit` shell option to make it
exit upon any unexpected errors.

3) The `fill_process_comm()` Function Might Read Unexpected Control Characters
==============================================================================

The [`fill_process_comm()` function][code-fill-process-comm] reads the content
of `/proc/<pid>/comm` from potentially untrusted processes in the system. The
data found in there is obtained from the name of the executable that the
kernel executed. Executable names can contain any data, except for the `/`
character. This also includes control characters like `\r` or even terminal
control sequences. This string is used by `stalld` to write information to
logs. By embedding a carriage return in an executable name, a local attacker
could achieve log spoofing.

To fix this, we suggest to transform any non-alphanumeric characters in the
string into some safe character like `?`.

4) Experimental FIFO Boosting Feature might have a Danger of Locking up the System
==================================================================================

Via the `--force_fifo` command line switch, stalld can be instructed to
"boost" stalled tasks by switching them to `SCHED_FIFO` scheduling. We are
wondering what happens if a "rogue task" is assigned to this scheduler. As far
as we know, if such a task never yields the CPU again, the whole system could
lock up. This might require `stalld` to run under `SCHED_FIFO` itself,
using a higher scheduling priority than the boosted task, to prevent any such
situation.

5) Potential Race Conditions when Accessing `/proc/<pid>/{status,comm}`
=======================================================================

As usual, when iterating over the processes in the `/proc` file system, race
conditions can occur. Target processes could attempt to replace themselves by
other processes, confusing stalld. We don't believe that the "stall" situation
can be provoked easily by a local attacker, though, thus the possibility to
exploit anything in this direction is likely small.

We just mention this as a hint to the reader, maybe we're overlooking something
more critical here.

6) Weird `umask()` Setting used in `daemonize()`
================================================

The [`daemonize()` function][code-daemonize] applies a new umask to the daemon
process by calling `umask(DAEMON_UMASK)`. [The constant for this][code-umask]
has a weird value, though:

```
/*
 * Daemon umask value.
 */
#define DAEMON_UMASK  0x133  /* 0644 */
```

We don't know why an octal `0644` value isn't used in the first place, instead
of writing this as a comment only. The constant `0x133` corresponds to an
octal value of `0463`, though. It will mask out the owner-readable bit,
read-write bits for the group and write-execute bits for world. This is likely
not what was intended here.

Luckily no world-writable files will come into existence this way, but the
misconfiguration could lead to strange effects in the future, e.g. because the
owner of the file will not have read permissions for it.

We don't believe this is a security issue, which is why we created [a public
issue][daemon-mask-issue] in the upstream GitLab tracker for this.

7) CVE Assignments
==================

Since upstream did not react and therefore also didn't confirm any of these
issues, we did not request any CVEs from Mitre until now. The fixed temporary
file usage issue 2) likely is worthy of a CVE assignment, though.

8) Timeline
===========

2024-09-09|We reported the issues ([1][daemon-mask-issue], [2][tempfile-issue]) in the upstream GitLab project, offering coordinated disclosure for the sensitive issues.|
2024-11-13|After getting no reaction for such a long time we commented in the issue, asking for a reply until 2024-11-22, otherwise we would publish the issue on our end.|
2024-11-28|We published the information without upstream fixes being available.|

9) References
=============

- [stalld GitLab project][stalld-gitlab]
- [GitLab issue regarding weird DAEMON\_UMASK][daemon-mask-issue]
- [(Private) GitLab issue regarding fixed tempfile use][tempfile-issue]

[stalld-gitlab]: https://gitlab.com/rt-linux-tools/stalld
[daemon-mask-issue]: https://gitlab.com/rt-linux-tools/stalld/-/issues/26
[tempfile-issue]: https://gitlab.com/rt-linux-tools/stalld/-/issues/25
[code-throttlectl]: https://gitlab.com/rt-linux-tools/stalld/-/blob/v1.19.6/scripts/throttlectl.sh#L13
[code-fill-process-comm]: https://gitlab.com/rt-linux-tools/stalld/-/blob/v1.19.6/src/utils.c?ref_type=tags#L54
[code-daemonize]: https://gitlab.com/rt-linux-tools/stalld/-/blob/v1.19.6/src/utils.c?ref_type=tags#L355
[code-umask]: https://gitlab.com/rt-linux-tools/stalld/-/blob/v1.19.6/src/stalld.h?ref_type=tags#L49
