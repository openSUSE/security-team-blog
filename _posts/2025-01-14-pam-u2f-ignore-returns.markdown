---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "pam-u2f: problematic PAM_IGNORE return values in pam_sm_authenticate() (CVE-2025-23013)"
date:   2025-01-14
tags:   local PAM CVE
excerpt: "pam-u2f allows to use U2F (Universal 2nd Factor) devices like
YubiKeys in the PAM authentication stack. Improper use of PAM_IGNORE return
values in the module implementation could allow bypass of the second factor or
password-less login without inserting the proper device."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

The [pam-u2f][u2f-yubico] module allows to use U2F (Universal 2nd Factor)
devices like YubiKeys in the PAM authentication stack. The hardware tokens can
be used as a second authentication factor, or to allow password-less login.

We have been checking all PAM modules in the openSUSE code base for bad return
values. During this effort we found that improper use of `PAM_IGNORE` return
values in the pam-u2f module implementation could allow bypass of the second
factor or password-less login without inserting the proper device.

This report is based on pam-u2f [release 1.3.0][pam-u2f-1-3-0].

2) Improper use of `PAM_IGNORE` Return Values
=============================================

PAM modules basically consist of a set of hook functions that are invoked by
libpam based on the active PAM stack configuration. Each PAM module function
returns an `int` containing one of the [`PAM_*` return
values][code-pam-return-values] defined in the libpam headers. These return
values are vital for the outcome of a PAM authentication procedure, since
libpam reports authentication success or failure depending on the return
values encountered while processing the modules configured in the `auth`
management group of the active PAM stack configuration.

The main business logic of the pam-u2f module is found in function
[`pam_sm_authenticate()`][code-pam-sm-auth], which contains multiple code
paths that will result in a `PAM_IGNORE` return value. The following is a list
of the possible situations that can cause this to happen:

- if an error occurs in `gethostname()`.
- if various memory allocation errors occur in `strdup()` or `calloc()`.
- if `resolve_authfile_path()` fails (which fails if `asprintf()` fails).
- if `pam_modutil_drop_priv()` or `pam_modutil_regain_priv()` fail.

Returning `PAM_IGNORE` signifies to libpam that the pam-u2f module shall not
contribute to the return value that the application obtains. If no module
reports a decisive return value, then libpam will report an authentication
failure by default. However, if any other module in the `auth`
management group returns `PAM_SUCCESS`, and no module marks an error
condition, the overall result of the authentication will be "success".
How exactly this can happen is explored in the rest of this section.

In the [pam-u2f documentation][u2f-yubico-examples] two main use cases for the
PAM module are stated:

```sh
# as a second factor
auth required pam_u2f.so authfile=/etc/u2f_mappings cue

# for password-less authentication:
auth sufficient pam_u2f.so authfile=/etc/u2f_mappings cue pinverification=1
```

In the "second factor" scenario, a `PAM_IGNORE` return from pam-u2f means that
login will be possible without actually providing a second factor. The first
factor authentication module (typically something like `pam_unix`) will set a
`PAM_SUCCESS` return value, which will become the overall authentication
result.

In the "password-less" authentication scenario, when pam-u2f is used
exclusively for authentication, a `PAM_IGNORE` return could mean that login
will succeed without providing any authentication at all. The precondition for
this is that another module in the `auth` management group returns
`PAM_SUCCESS`. There exist utility modules that don't actually authenticate
but perform helper functions or enforce policy. An example is the
[`pam_faillock`][pam-faillock-man-page] module, which can be added to the
`auth` management group to record failed authentication attempts and lock the
account for a certain time if too many failed attempts occur. This module will
return `PAM_SUCCESS` when running in "preauth" mode and if the maximum number
of failed attempts has not been reached yet. In such a case `PAM_SUCCESS`
would become the overall authentication result when pam-u2f returns
`PAM_IGNORE`.

An attacker can attempt to provoke a situation that results in a `PAM_IGNORE`
return value in pam-u2f to achieve one of these outcomes. In particular,
provoking an out-of-memory situation comes to mind - for example if a local
attacker already has user level access and wants to escalate privileges via
`sudo` or `su`.

3) Upstream Bugfix
==================

We suggested to upstream to change the problematic `PAM_IGNORE` return values
to others that mark the authentication as failed, e.g. `PAM_BUF_ERR` for
memory allocation errors or `PAM_ABORT` for other critical errors. Furthermore
we suggested to harmonize the error handling in the affected function, because
[different styles of return values][code-pam-sm-auth-retval] have been used in
the `retval` variable (`PAM_*` constants mixed with literal integers returned
from sub-functions).

Upstream implemented a bugfix along these lines, which is available in commit
[a96ef17f74b8e4][u2f-bugfix-commit]. This bugfix is available as part of
[release 1.3.1][u2f-bugfix-release]. Yubico also offer their own
[security advisory][u2f-advisory] for this CVE.

4) Remaining Uses of `PAM_IGNORE`
=================================

`PAM_IGNORE` should only be used in clearly defined circumstances, like when
necessary configuration for the PAM module is missing. Even then, this
behaviour ideally should require an explicit opt-in by administrators, by
passing configuration settings to the module's PAM configuration line.

Two such cases remain in pam-u2f with the bugfix applied. These cases trigger
if no auth file exists for the user to be authenticated and if the "nouserok"
option has been passed to the PAM module.

5) Possible Workaround
======================

If applying the bugfix is not possible right away, then a temporary workaround
for the issue can be applied via the PAM stack configuration by changing
the `pam_u2f` line as follows:

```sh
auth       [success=ok default=bad]    pam_u2f.so [...]
```

This way even a `PAM_IGNORE` return in `pam_u2f.so` will be considered a bad
authentication result by libpam.

6) Timeline
===========

2024-11-20|We reported the issue to [Yubico security](mailto:security@yubico.com), offering coordinated disclosure.|
2024-11-22|Yubico security accepted coordinated disclosure and stated that they are working on a fix.|
2024-12-06|Yubico security notified us that a bugfix release is planned in early January.|
2024-12-12|Yubico security shared their suggested bugfix with us. We sent back minor suggestions for improvement.|
2025-01-08|Yubico security informed us of the release date of 2025-01-14.|
2025-01-10|Yubico security shared the CVE identifier and their formal security advisory with us.|
2025-01-14|The upstream [bugfix release 1.3.1][u2f-bugfix-release] has been published as planned.|

7) References
=============

- [pam-u2f bugfix commit addressing the issue][u2f-bugfix-commit]
- [pam-u2f bugfix release 1.3.1][u2f-bugfix-release]
- [pam-u2f GitHub project][u2f-github]
- [pam-u2f project website][u2f-yubico]
- [Yubico security advisory][u2f-advisory]

[u2f-github]: https://github.com/Yubico/pam-u2f
[u2f-yubico]: https://developers.yubico.com/pam-u2f/
[u2f-yubico-examples]: https://developers.yubico.com/pam-u2f/#examples
[u2f-bugfix-commit]: https://github.com/Yubico/pam-u2f/commit/a96ef17f74b8e4ed80a97322120af1a228a1ffb7
[u2f-bugfix-release]: https://github.com/Yubico/pam-u2f/releases/tag/pam_u2f-1.3.1
[u2f-advisory]: https://www.yubico.com/support/security-advisories/ysa-2025-01/
[pam-u2f-1-3-0]: https://github.com/Yubico/pam-u2f/tree/pam_u2f-1.3.0
[code-pam-sm-auth]: https://github.com/Yubico/pam-u2f/blob/pam_u2f-1.3.0/pam-u2f.c#L169
[code-pam-sm-auth-retval]: https://github.com/Yubico/pam-u2f/blob/773bf275e207a5a626313cf0a92d3827f8784b85/pam-u2f.c#L391
[code-pam-return-values]: https://github.com/linux-pam/linux-pam/blob/ea980d991196df67cdd56b3f65d210b73218d08a/libpam/include/security/_pam_types.h#L29
[pam-faillock-man-page]: https://linux.die.net/man/8/pam_faillock
