---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>, <a href='mailto:filippo.bonazzi@suse.com'>Filippo Bonazzi (editor)</a>
title:  "scx: Unauthenticated scx_loader D-Bus Service can lead to major Denial-of-Service"
date:   2025-11-06
tags:   local DoS D-Bus
excerpt: "
The scx project offers a range of dynamically loadable custom schedulers which
make use of the Linux kernel's `sched_ext` feature. An optional D-Bus
service `scx_loader` provides an interface accessible to all users, allowing
them to nearly arbitrarily change the scheduling properties of the system,
leading to Denial-of-Service and other attack vectors. Upstream rejected parts
of our report, moved the `scx_loader` component into a separate repository and
no bugfix is available as of now.
"
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [scx project][upstream:github] offers a range of dynamically loadable
custom schedulers implemented in Rust and C, which make use of the Linux
kernel's `sched_ext` feature. An optional D-Bus service called `scx_loader`
provides an interface accessible to all users in the system, which allows to
load and configure the schedulers provided by scx. This D-Bus service is
present in scx up to version v1.0.17. As a response to this report,
`scx_loader` has been moved into a [dedicated repository][upstream:new-repo].

A SUSE colleague packaged scx for addition to openSUSE Tumbleweed, and the
D-Bus service it contained [required a review][bugzilla:review] by our team.
The review showed that the D-Bus service runs with full root privileges and
is missing an authentication layer, thus allowing any user to nearly
arbitrarily change the scheduling properties of the system, leading to
Denial-of-Service and other attack vectors.

[Upstream declined coordinated disclosure][section:timeline] for this report
and asked us to handle it in the open right away. In the discussion that
followed, upstream rejected parts of our report and presented no clear path
forward to fix the issues, which is why there is no bugfix available at the
moment.

[Section 2][section:overview] provides an overview of the `scx_loader` D-Bus
service and its lack of authentication. [Section 3][section:parameters] takes
a look into problematic command line parameters which can be influenced by
unprivileged clients. [Section 4][section:root-exploit] looks into attempts to
achieve a local root exploit using the `scx_loader` API. [Section
5][section:affected] lists affected Linux distributions. [Section
6][section:suggested-fixes] discusses possible approaches to fix the issues
found in this report. [Section 7][section:bugfix] takes a look at the upstream
efforts to fix the issues.

This report is based on [version 1.0.16][upstream:version-tag] of scx.

{: #section-overview}
2) Overview of the Unauthenticated `scx_loader` D-Bus Service
=============================================================

The [`scx_loader` D-Bus service][upstream:scx-loader] is implemented in Rust
and offers a completely unauthenticated D-Bus interface on the system bus. The
upstream repository contains configuration files and documentation
[advertising this service as suitable to be automatically
started][upstream:dbus-autostart] via D-Bus requests. Thus arbitrary users in
the system (including low privilege service users or even `nobody`) are
allowed to make unrestricted use of the service.

The [service's interface][code:dbus-api] offers functions to start, stop or
switch between a number of scx schedulers. The start and switch methods also
offer to specify an arbitrary list of parameters which will be directly passed
to the binary implementing the scheduler.

Every scheduler is implemented in a dedicated binary and found e.g. in
`/usr/bin/scx_bpfland` for the bpfland scheduler. Not all schedulers that are
part of scx are accessible via this interface. The list of schedulers
supported by `scx_loader` in the reviewed version is:

    scx_bpfland scx_cosmos scx_flash scx_lavd
    scx_p2dq scx_tickless scx_rustland scx_rusty

We believe the ability to more or less arbitrarily tune the scheduling
behaviour of the system already poses a local Denial-of-Service (DoS) attack
vector that might even make it possible to lock up the complete system. We did
not look into a concrete set of parameters that might achieve that, but it
seems likely, given the range of schedulers and their parameters made
available via the D-Bus interface.

{: #section-parameters}
3) Passing Arbitrary Parameters to Schedulers
=============================================

The ability to pass arbitrary command line parameters to any of the supported
scheduler binaries increases the attack surface of the D-Bus interface
considerably. This makes a couple of concrete attacks possible, especially
when the scheduler in question accepts file paths as input. Apart from
parameters that influence scheduler behaviour, all schedulers offer the
generic "Libbpf Options", of which the following four options stick out in
this context:

```
--pin-root-path <PIN_ROOT_PATH>      Maps that set the 'pinning' attribute in their definition will have
                                     their pin_path attribute set to a file in this directory, and be
                                     auto-pinned to that path on load; defaults to "/sys/fs/bpf"
--kconfig <KCONFIG>                  Additional kernel config content that augments and overrides system
                                     Kconfig for CONFIG_xxx externs
--btf-custom-path <BTF_CUSTOM_PATH>  Path to the custom BTF to be used for BPF CO-RE relocations. This custom
                                     BTF completely replaces the use of vmlinux BTF for the purpose of CO-RE
                                     relocations. NOTE: any other BPF feature (e.g., fentry/fexit programs,
                                     struct_ops, etc) will need actual kernel BTF at /sys/kernel/btf/vmlinux
--bpf-token-path <BPF_TOKEN_PATH>    Path to BPF FS mount point to derive BPF token from. Created BPF token
                                     will be used for all bpf() syscall operations that accept BPF token
                                     (e.g., map creation, BTF and program loads, etc) automatically within
                                     instantiated BPF object. If bpf_token_path is not specified, libbpf will
                                     consult LIBBPF_BPF_TOKEN_PATH environment variable. If set, it will be
                                     taken as a value of bpf_token_path option and will force libbpf to
                                     either create BPF token from provided custom BPF FS path, or will
                                     disable implicit BPF token creation, if envvar value is an empty string.
                                     bpf_token_path overrides LIBBPF_BPF_TOKEN_PATH, if both are set at the
                                     same time. Setting bpf_token_path option to empty string disables
                                     libbpf's automatic attempt to create BPF token from default BPF FS mount
                                     point (/sys/fs/bpf), in case this default behavior is undesirable
```

libbpf is a userspace support library for BPF programs [found in the Linux
source tree][code:libbpf]. The following sub-sections take a look at each of
the attacker-controlled paths passed to this library in detail.

The `--pin-root-path` Option
----------------------------

The `--pin-root-path` option potentially causes libbpf to create the
parent directory of this path in
[`bfp_object__pin_programs()`][code:libbpf-pin]. We are not entirely
sure under which conditions the logic is triggered, however, and if these
conditions are controlled by an unprivileged caller in the context of the
`scx_loader` D-Bus API.

The `--kconfig` Option
----------------------

The file found in the `--kconfig` path is completely read into memory in
[`libbpf_clap_opts.rs` line 91][code:bpfopt-kconfig]. This makes
a number of attack vectors possible:

- pointing to a device file like `/dev/zero` leads to an out of memory
  situation in the selected scheduler binary.
- pointing to a private file like `/etc/shadow` causes the scheduler binary to
  read in the private data. We did not find a way for this data to leak out
  into the context of an unprivileged D-Bus caller, however. This technique
  still allows to perform file existence tests in locations that are normally
  not accessible to unprivileged users.
- pointing to a FIFO named pipe will block the scheduler binary indefinitely,
  breaking the D-Bus service. Also, by feeding data to such a PIPE, _nearly_
  all memory can be used up, keeping the system in a low-memory situation
  and possibly leading to the kernel's OOM killer targeting unrelated
  processes.
- by pointing to a regular file controlled by the caller, crafted KConfig
  information can be passed into libbpf. The impact of this appears to be
  minimal, however.

The following command line is an example reproducer which will cause the
`scx_bpfland` process to consume all system memory until it is killed by
the kernel:

    user$ gdbus call -y -d org.scx.Loader -o /org/scx/Loader \
        -m org.scx.Loader.SwitchSchedulerWithArgs scx_bpfland \
	    '["--kconfig", "/dev/zero"]'

The `--btf-custom-path` Option
------------------------------

The `--btf-custom-path` option offers similar attack vectors as the
`--kconfig` option discussed above. Additionally, crafted binary symbol
information can be fed to the scheduler via this path, which will be processed
either by [`btf_parse_raw()`][code:libbpf-parse-raw] or
[`btf_parse_elf()`][code:libbpf-parse-elf] found in libbpf. This can lead to
integrity violation of the scheduler / the kernel, the impact of which we
cannot fully judge as we lack expertise in this low level area and did not
want to invest more time than necessary for the analysis.

The `--bpf-token-path` Option
-----------------------------

The `--bpf-token-path`, if it refers to a directory, [will be opened by
libbpf][code:libbpf-token-path] and the file descriptor will be passed to the
bpf system call like this:

    bpf(BPF_TOKEN_CREATE, {token_create={flags=0, bpffs_fd=20}}, 8) = -1 EINVAL (Invalid argument)

This does not seem to achieve anything, however, because the kernel code
rejects the caller if it lives in the initial user namespace (which the
privileged D-Bus service always does). The path could maybe serve as an
information leak to test file existence and type, if the behaviour of the
scheduler "start" operation shows observable differences depending on the
input.

{: #section-root-exploit}
4) On the Verge of a Local Root Exploit
=======================================

With this much control over the command line parameters of many different
scheduler binaries, which offer a wide range of options, we initially assumed
that a full local root exploit would not be difficult to achieve. We tried
hard, however, and did not find any working attack vector so far. It could be
that we overlooked something in the area of the low level BPF handling
regarding the attacker-controlled input files discussed in the previous
section, however.

`scx_loader` is saved from a trivial local root exploit merely by the fact
that only a subset of the available scx scheduler binaries is accessible via
its interface. The `scx_chaos` scheduler, which is not among the schedulers
offered by the D-Bus service, supports [a positional command line
argument][code:scx-chaos-arg] referring to a "Program to run under the chaos
scheduler". Would this scheduler be accessible via D-Bus, then unprivileged
users could cause user controlled programs to be executed with full root
privileges, leading to arbitrary code execution.

From discussions with upstream it sounds like the exclusion of schedulers like
`scx_chaos` from the D-Bus interface does not stem from security concerns, but
rather from functional restrictions, because some schedulers are not supported
in all contexts, or are not stable yet.

{: #section-affected}
5) Affected Linux Distributions
===============================

From our investigations and communication with upstream it seems that only
Arch Linux is affected by the problem in its default installation of scx.
Gentoo Linux comes with an ebuild for scx, but for some reason there is no
integration of `scx_loader` into the init system and also the D-Bus autostart
configuration file is missing. Thus it will only be affected if an admin
manually invokes the service.

Otherwise we did not find a packaging of `scx_loader` on current Fedora Linux,
Ubuntu LTS or Debian Linux. Due to the outcome of this review we never allowed
the D-Bus service into openSUSE, which is therefore also not affected.

{: #section-suggested-fixes}
6) Suggested Fixes
==================

Restrict Access to a Group on D-Bus Level
-----------------------------------------

A quick fix for the worst aspects of the issue would be to restrict the
[D-Bus configuration in `org.scx.Loader.conf`][upstream:dbus-config] to allow
access to the interface only for members of a dedicated group like `scx`. This
at least prevents random unprivileged users from abusing the API.

We offer a [patch for download][download:dbus-policy-group-patch] which does
exactly this.

Use Polkit for Authentication
-----------------------------

By integrating Polkit authentication, the use of this interface can be
restricted to physically present interactive users. Even in this case we
suggest to restrict full API access to users that can authenticate as admin,
via Polkit's `auth_admin_keep` setting. Read-only operations can still be
allowed without authentication.

Making the API more Robust
--------------------------

The individual methods offered by the scx.Loader D-Bus service should not
allow to perform actions beyond the intended scope, even if a caller
would have authenticated in some form as outlined in the previous sections.

To this end, dangerous parameters for schedulers should either be rejected
(e.g. by enforcing a whitelist of allowed parameters) or verified (e.g. by
determining whether a provided path is only under control of root and similar
checks).

Regarding input files, the client ideally should not pass path names at all,
but send file descriptors instead, to avoid unexpected surprises and the
burden of verifying input paths in the privileged D-Bus service.

Use systemd Sandboxing
----------------------

The systemd service for `scx_loader` could make use of various hardening
options that systemd offers (like `ProtectSystem=full`), as long as these
do not interfere with the functionality of the service. This would
prevent more dangerous attack vectors from succeeding if the first line of
defense fails.

{: #section-bugfix}
7) Missing Upstream Bugfix
==========================

Upstream showed [a reluctant reaction][upstream:issue-rejections] to the report
we provided [in a GitHub issue][upstream:issue], rejecting parts of our
assessment. An attempt to [introduce a Polkit authentication
layer][upstream:ai-pr] based on AI-generated code was abandoned quickly,
and upstream instead split off the `scx_loader` service into a [new
repository][upstream:new-repo] to separate it from the `scx` core project. Our
original GitHub issue has been closed, and we [cloned it][upstream:new-issue]
in the new repository to keep track of the issue.

Downstream integrators of `scx_loader` can can limit access to the D-Bus
service to members of an `scx` group by applying the patch we offer in the
[Suggested Fixes][section:suggested-fixes] section. This way access to the
problematic API becomes opt-in, and is restricted to more privileged users
that actually intend to use this service.

8) CVE Assignment
=================

We suggested to upstream to assign at least one cumulative CVE to generally
cover the unauthenticated D-Bus interface aspect leading to local DoS,
potential information disclosure and integrity violation. We offered to assign
a CVE from the SUSE pool to simplify the process.

Upstream did not respond to this and did not clearly confirm the issues we
raised, but rather rejected certain elements of our report. For this reason
there is currently no CVE assignment available.

{: #section-timeline}
9) Timeline
===========

{: #section-timeline}
|2025-09-30|We contacted one of the upstream developers by email and asked for a security contact of the project, since none was documented in the repository.|
|2025-09-30|The upstream developer agreed to handle the report together with a fellow developer of the project.|
|2025-09-30|We shared a detailed report with the two developers.|
|2025-10-02|After analysis of the report, the upstream developer suggested to create a public GitHub issue, [which we did][upstream:issue].|
|2025-10-03|An upstream developer [responded to the issue][upstream:issue-rejections] rejecting various parts of our report.|
|2025-10-28|With some delay we provided [a short reply][upstream:issue-response-short], pointing out that the rejections seem to miss the central point of the change of privilege which is taking place.|
|2025-10-28|Upstream [created a pull request][upstream:ai-pr] based on AI-generated code to add an authentication layer to the D-Bus service.|
|2025-10-28|Upstream closed the unmerged pull request shortly after. The discussion sounded like upstream no longer intends to support the `scx_loader` D-Bus service in this repository.|
|2025-11-03|We provided a [more detailed reply][upstream:issue-response-long] to the issue discussion.|
|2025-11-04|Upstream closed the GitHub issue and split off [a dedicated repository][upstream:new-repo] for `scx_loader`|
|2025-11-06|We [cloned the original issue][upstream:new-issue] in the new repository|
|2025-11-06|Publication of this report.|

10) Links
=========

- [scx GitHub repository][upstream:github]
- [scx GitHub issue for this report][upstream:issue]
- [newly created `scx_loader` GitHub repository][upstream:new-repo]
- [cloned GitHub issue in the new `scx_loader` repository][upstream:new-issue]
- [openSUSE Bugzilla review bug][bugzilla:review]
- [suggested patch to restrict access to the D-Bus service][download:dbus-policy-group-patch]

[upstream:github]: https://github.com/sched-ext/scx
[upstream:new-repo]: https://github.com/sched-ext/scx-loader
[upstream:issue]: https://github.com/sched-ext/scx/issues/2847
[upstream:new-issue]: https://github.com/sched-ext/scx-loader/issues/12
[upstream:issue-rejections]: https://github.com/sched-ext/scx/issues/2847#issuecomment-3365496251
[upstream:issue-response-short]: https://github.com/sched-ext/scx/issues/2847#issuecomment-3455392651
[upstream:issue-response-long]: https://github.com/sched-ext/scx/issues/2847#issuecomment-3480324604
[upstream:ai-pr]: https://github.com/sched-ext/scx/pull/2970
[upstream:version-tag]: https://github.com/sched-ext/scx/releases/tag/v1.0.16
[upstream:scx-loader]: https://github.com/sched-ext/scx/tree/v1.0.16/tools/scx_loader
[upstream:dbus-autostart]: https://github.com/sched-ext/scx/blob/v1.0.16/tools/scx_loader/README.md?plain=1#L76
[upstream:dbus-config]: https://github.com/sched-ext/scx/blob/e25cc6e5920f33d5bbe2bd62b2e7a5854de88a19/tools/scx_loader/org.scx.Loader.conf
[code:dbus-api]: https://github.com/sched-ext/scx/blob/v1.0.16/tools/scx_loader/src/dbus.rs#L16
[code:scx-chaos-arg]: https://github.com/sched-ext/scx/blob/e25cc6e5920f33d5bbe2bd62b2e7a5854de88a19/scheds/rust/scx_chaos/src/lib.rs#L711
[code:libbpf]: https://github.com/torvalds/linux/tree/c9cfc122f03711a5124b4aafab3211cf4d35a2ac/tools/lib/bpf
[code:libbpf-pin]: https://github.com/torvalds/linux/blob/6146a0f1dfae5d37442a9ddcba012add260bceb0/tools/lib/bpf/libbpf.c#L8801
[code:libbpf-parse-raw]: https://github.com/torvalds/linux/blob/6146a0f1dfae5d37442a9ddcba012add260bceb0/tools/lib/bpf/btf.c#L1304
[code:libbpf-parse-elf]: https://github.com/torvalds/linux/blob/6146a0f1dfae5d37442a9ddcba012add260bceb0/tools/lib/bpf/btf.c#L1192
[code:bpfopt-kconfig]: https://github.com/sched-ext/scx/blob/e25cc6e5920f33d5bbe2bd62b2e7a5854de88a19/rust/scx_utils/src/libbpf_clap_opts.rs#L91
[code:libbpf-token-path]: https://github.com/torvalds/linux/blob/6146a0f1dfae5d37442a9ddcba012add260bceb0/tools/lib/bpf/libbpf.c#L5030
[bugzilla:review]: https://bugzilla.suse.com/show_bug.cgi?id=1250449
[section:timeline]: #section-timeline
[section:overview]: #section-overview
[section:parameters]: #section-parameters
[section:root-exploit]: #section-root-exploit
[section:affected]: #section-affected
[section:suggested-fixes]: #section-suggested-fixes
[section:bugfix]: #section-bugfix
[download:dbus-policy-group-patch]: /download/0001-scx_loader-D-Bus-configuration-restrict-access-to-me.patch
