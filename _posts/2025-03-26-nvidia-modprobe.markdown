---
layout: post
author: <a href='mailto:wfrisch@suse.de'>Wolfgang Frisch</a>
title:  "wait3() System Call as a Side Channel in Setuid Programs: nvidia-modprobe case study (CVE-2024-0149)"
date:   2025-03-26
tags:   local setuid CVE
excerpt: "The nvidia-modprobe utility, a setuid-root helper for the proprietary
Nvidia GPU display driver, contained an information disclosure vulnerability in
versions prior to 550.144.03. Unprivileged users were able to determine the
existence of arbitrary files on the system via the `wait3()` system call."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

[nvidia-modprobe][upstream:github] is a setuid-root helper utility for the
proprietary Nvidia GPU display driver that loads kernel modules and creates
character devices required for userspace GPU access. Normally, drivers do this
via udev. However, kernel licensing restrictions prohibit Nvidia's proprietary
kernel module from generating uevents, which are required for udev to work.
Therefore this special helper is needed.

We reviewed nvidia-modprobe as part of our whitelisting process, which requires
an audit for all newly introduced setuid binaries in openSUSE.  The version we
reviewed was [550.127.05][upstream:550.127.05] and this report is based on that
version.  Upstream released a bugfix in version
[550.144.03][upstream:550.144.03] and a [security advisory][upstream:advisory].

2) `wait3()` as a Side Channel in Setuid Programs
=================================================

The `wait3()` system call allows the calling process to obtain status
information for child processes, similar to `waitpid()`. Unlike `waitpid()`,
`wait3()` also returns resource usage information. The measurements returned by
this call include CPU time, memory consumption and lower-level information such
as the number of minor and major page faults that occurred during the child's
runtime. See also [`man 2 getrusage`][man:getrusage].

Perhaps surprisingly, `wait3()` also works for setuid sub-processes, leaking
quite a bit of information about the behavior of the target program, which is
running with elevated privileges.

A convenient way to try this out is [GNU Time][gnu-time], a small utility that
spawns a target process and prints the output of `wait3()`, for example:

```sh
/usr/bin/time -v nvidia-modprobe
```

3) File Existence Test (CVE-2024-0149)
======================================

In the case of nvidia-modprobe, we can leverage `wait3()` for a file existence
test.

When executed with the option `-f NVIDIA-CAPABILITY-DEVICE-FILE` (an arbitrary
path), nvidia-modprobe performs the following steps:

- attempt to open the supplied path as root
  - if the path does exist:
    - read one or more lines
    - parse each line (implemented safely)
    - exit silently, return code 0
  - if the path does not exist:
    - exit silently, return code 0

It turns out that reading the first line of the supplied path sometimes causes
a minor page fault. The number of page faults is not perfectly constant across
multiple executions, depending on whether the page mapped by the kernel is
dirty or not. However, if the file does not exist, it cannot be read, and
therefore no page faults will be triggered. We can execute nvidia-modprobe
repeatedly, calculate the median number of page faults, and infer whether the
supplied path exists or not, even if the caller does not have the necessary
file system permissions.

Simplified example:

```
$ /usr/bin/time -q --format=%R nvidia-modprobe -f /root/.bash_history
80

$ /usr/bin/time -q --format=%R nvidia-modprobe -f /root/does/not/exist
79
```

The output fluctuates, but it only takes a few repetitions to get a reliable
signal from the median.

4) Bugfix
=========

Upstream published a [bugfix][upstream:bugfix]. This commit limits the queried
path to files below `/proc/driver/nvidia` before attempting to read from it,
eliminating the information leak.

5) CVE Assignment
=================

Upstream assigned CVE-2024-0149 for this issue.

6) Other Packages
=================
Considering the relatively obscure nature of this side channel attack, we
decided to briefly look into a couple of other packages exhibiting similar
usage patterns:

- `shadow`
  - `chsh`: negative
- `util-linux`
  - `mount -T`: negative
  - `umount`: negative
- `v4l-linux`: positive, but does not require `wait3()`, and the issue was
  already known (CVE-2020-1369).

Even though we did not find additional instances of this problem, and the
severity of this vulnerability is rather low, it's still one of many pitfalls
to keep in mind when writing or auditing setuid programs.


7) Timeline
===========

|2024-10-02|We noticed the issue and started tracking it privately in [bsc#1231257][opensuse:bsc#1231257].|
|2024-10-09|We shared the information with NVIDIA PSIRT via email, offering coordinated disclosure.|
|2024-10-12|We received an initial confirmation from Nvidia.|
|2024-10-22|After a fruitful discussion, mostly regarding tangential questions, we agreed on 2025-01-16 as the Coordinated Release Date.|
|2025-01-16|CVE-2024-0149 was assigned by Nvidia.|
|2025-01-16|Nvidia released the fix as part of version [550.144.03][upstream:550.144.03]|

8) References
=============

- [nvidia-modprobe GitHub repository][upstream:github]
- [Nvidia security advisory][upstream:advisory]
- [Bugfix commit 83b777c][upstream:bugfix]
- [getrusage(2)][man:getrusage]

[upstream:github]: https://github.com/NVIDIA/nvidia-modprobe
[upstream:advisory]: https://nvidia.custhelp.com/app/answers/detail/a_id/5614/~/security-bulletin%3A-nvidia-gpu-display-driver---january-2025
[upstream:550.127.05]: https://github.com/NVIDIA/nvidia-modprobe/releases/tag/550.127.05
[upstream:550.144.03]: https://github.com/NVIDIA/nvidia-modprobe/releases/tag/550.144.03
[upstream:affected-function]: https://github.com/NVIDIA/nvidia-modprobe/blob/30657d327c22c3c88927bc75246d9bebda77f77f/modprobe-utils/nvidia-modprobe-utils.c#L931
[upstream:bugfix]: https://github.com/NVIDIA/nvidia-modprobe/commit/83b777c5fbbcdfd48004b0b099cf0a8a9ee9359f
[gnu-time]: https://www.gnu.org/software/time/
[opensuse:bsc#1231257]: https://bugzilla.opensuse.org/show_bug.cgi?id=1231257
[man:getrusage]: https://manpages.opensuse.org/Tumbleweed/man-pages/getrusage.2.en.html
