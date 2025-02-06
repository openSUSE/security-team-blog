---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "pam_pkcs11: Possible Authentication Bypass in Error Situations (CVE-2025-24531)"
date:   2025-02-06
tags:   local PAM CVE
excerpt: "This PAM module allows to use smart cards as an authentication
factor on Linux. In its 0.6.12 release the use of PAM_IGNORE return values
introduced a regression that can lead to complete authentication bypass in
some scenarios."
---

Table of Contents
=================
{:.no_toc}

* ToC
{:toc}

1) Introduction
===============

This report is about a regression in [pam\_pkcs11][upstream:github] [version
0.6.12][upstream:affected-release]. In this release the implementation of
[`pam_sm_authenticate()`][code:pam-sm-authenticate] has been changed to return
`PAM_IGNORE` in many exit paths, which can lead to a complete authentication
bypass in some scenarios. This report is based on upstream Git tag
"pam\_pkcs11-0.6.12". A bugfix is found in [release
0.6.13][upstream:bugfix-release].

Whether this issue can be exploited is a complex question that depends a lot
on the system configuration. The following section gives some insight into how
we discovered the issue and why its severity can be high in some
circumstances. Section 3) looks in detail into the issue found in pam\_pkcs11.
The rest of the report explores which Linux distributions might be affected by
the issue, a possible workaround and the upstream bugfix. Finally we will be
taking a look at the lessons that can be learned from this finding.

2) Discovery of the Issue / Relation to GDM Smart Card Authentication
=====================================================================

Fellow SUSE engineer Marcus Rückert uses a YubiKey for login at his openSUSE
Tumbleweed desktop system. In October 2024 [he noticed a
change][bugzilla-report] in behaviour in his GDM login setup. By digging a bit
deeper he noticed that in some situations login was possible without entering
a password or using his YubiKey at all.

While analysing the issue we found that there is [a
bug][gdm:yubi-key-smart-card-issue] (or a feature?) in GDM 3 that causes
YubiKeys to be treated as smart cards. This is one ingredient that comes into
play here. A number of Linux distributions use a dedicated
"gdm-smartcard" PAM stack configuration file for smart card login in GDM. On
openSUSE we rely on pam\_pkcs11 as the sole (proper) authentication module in
[this gdm-smartcard PAM stack][obs:gdm-smartcard-stack]. It took us a while to
understand where exactly this gdm-smartcard PAM stack is used in GDM. The
logic to select this PAM stack is found in a wholly different Gnome component,
namely [gnome-shell][code:gnome-shell-gdm-smartcard]. There, some JavaScript is
responsible for detecting smart cards via the D-Bus interface of the
gnome-settings-daemon, and for changing the authentication mode of GDM.

We reproduced the situation by using smart card emulation in a QEMU Virtual
machine, to be able to achieve proper smart card detection in both GDM
and pam\_pkcs11. As soon as the smart card is properly setup in the system,
GDM switches into smart card authentication mode (support for this is enabled
by default). A user list is no longer shown in the display manager, instead
the username has to be entered manually. After entering the username, the
"gdm-smartcard" PAM stack is executed, and with it pam\_pkcs11. No password is
asked for and login succeeds.

What happens in this test setup, as well as in the real life setup using a
YubiKey, is that pam\_pkcs11 stops execution after logging "Failed to
initialize crypto" and, surprisingly, login succeeds. The reason for this lies
in pam\_pkcs11, as is described in the next section.

We did not investigate why exactly the "initialize crypto" error occurs, as we
don't believe it is relevant for the security issue. Even when errors occur,
the outcome of the PAM stack execution shouldn't allow authentication without
providing credentials.

3) The `PAM_IGNORE` Issue in pam\_pkcs11
========================================

The successful login without proper authentication in pam\_pkcs11 stems from a
change that found its way into pam\_pkcs11 version 0.6.12. The issue
has been introduced with [commit bac6cf8][upstream:introducing-commit] (note
that there seems to exist an artifact in the upstream Git repository: a
seemingly identical [commit 88a87d5][upstream:artifact-commit] in the commit
log on "master").

With this change, many exit paths of the
[`pam_sm_authenticate()`][code:pam-sm-authenticate] function now return
`PAM_IGNORE` instead of `PAM_CRED_INSUFFICIENT`. In particular, the code found
at [line 284][code:pam-ignore-default] means that the default return value on
error conditions is `PAM_IGNORE`, if there is no "login token name":

```c
if (!configuration->card_only || !login_token_name) {
    /* Allow to pass to the next module if the auth isn't
       restricted to card only. */
    pkcs11_pam_fail = PAM_IGNORE;
} else {
  pkcs11_pam_fail = PAM_CRED_INSUFFICIENT;
}
```

The `card_only` flag refers to a [module
parameter][upstream:readme-card-only-setting], whose meaning seems to have
changed over time and is no longer fully conforming to what is documented. It
is enabled in the "gdm-smartcard" stack, thus this part of the `if` condition
will not trigger. The background of the `login_token_name` is that the PAM
module contains special logic for unlocking the screen saver, but only if the
session login was performed using pam\_pkcs11. This will always be `false`
during initial login, and thus this part of the `if` condition applies in this
case.

When a PAM module returns `PAM_IGNORE`, its outcome should not be used to
determine the result of the PAM stack execution. openSUSE uses the `required`
control setting for pam\_pkcs11 in its "gdm-smartcard" configuration. In
extended PAM syntax `required` is expressed like this:

```sh
    required
        [success=ok new_authtok_reqd=ok ignore=ignore default=bad]
```

When pam\_pkcs11 returns `PAM_IGNORE` then the "required" control setting no
longer results in what the average administrator will expect, namely that
authentication fails if no successful smart card authentication is possible.

What happens instead depends on the rest of the modules present in
the "auth" section on the PAM stack. When no other PAM module at all is on
the stack, then authentication fails, because the PAM library expects at least
one decisive return value from any module on the stack. When there is another
PAM module on the stack that actually authenticates, then that module will
set a failed state if no credentials are provided, thereby preventing
successful login.

To judge the situation with the "gdm-smartcard" PAM stack, let's look more
closely at its "auth" section:

```sh
auth       requisite                   pam_faillock.so      preauth
auth       required                    pam_pkcs11.so        wait_for_card card_only
auth       required                    pam_shells.so
auth       requisite                   pam_nologin.so
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       [success=ok default=1]      pam_gdm.so
auth       optional                    pam_gnome_keyring.so
```

There are a lot of other modules configured, alas, none of them is actually
authenticating. These are what we like to call "utility modules" in this
discussion: they provide support functions. Examples are the pam\_faillock
module which checks whether excess authentication errors occurred, or
pam\_gnome\_keyring which attempts to intercept the cleartext password used
for login to transparently unlock the user keyring. Commonly, such modules
return `PAM_SUCCESS` in most situations. As a result, when pam\_pkcs11 returns
`PAM_IGNORE`, the overall outcome of the PAM authentication will become
`PAM_SUCCESS`, supplied by non-authenticating modules in the "gdm-smartcard"
PAM stack.

Below the code location in `pam_sm_authenticate()` function shown above, only
two code paths return something other than `PAM_IGNORE`:

- in [line 510][code:line510] if `pkcs11_login()` fails
- in [line 695][code:line695] if `verify_signature()` fails

Both return paths will reset `pkcs11_pam_fail` to a safe `PAM_AUTH_ERR` value.
The following is a list of all the other return paths which will return
`PAM_IGNORE`:

- [line 305][code:line305]: if a user is logging in from remote, or can
  control the DISPLAY environment variable (e.g. in sudo context).
- [line 316][code:line316]: if the `crypto_init()` call fails.
- [line 328][code:line328]: if a screen saver context is detected and no login token is
  recorded, then an explicit jump to a `PAM_IGNORE` return is performed.
- [lines 343, 357][code:line343]: if loading or initializing the PKCS#11 module fails.
- [line 374][code:line374]: if the configured token is not found and `card_only` is not set.
  This might be okay in light of the semantics of `card_only`, but it is still
  strange. If system administrators want to make pam\_pkcs11
  authentication optional then they can do so by using the PAM stack configuration
  already, by using the `optional` control setting. Changing the module result
  semantics this drastically through a seemingly harmless module option is
  unusual.
- [line 416][code:line416]: if no smart card is found even after potentially waiting for it.
  If a smart card is found, but one of various PKCS#11 library functions or certificate
  checks fail, then further `PAM_IGNORE` returns can happen if any of the
  following operations fail:
  - `open_pkcs11_session()` (line 432)
  - `get_slot_login_required()` (line 443)
  - when reading in a password fails (line 471)
  - empty password was read without `nullok` set (line 486)
  - `get_certificate_list()` (line 522)
  - `pam_set_item(..., PAM_USER, ...)` (line 597)
  - `match_user()` (line 613)
  - `(no matching certificate found)` (line 634)
  - `get_random_value()` (line 663)
  - `sign_value()` (line 677)
  - `close_pkcs11_session()` (line 776)

As this long list demonstrates, it is likely that a local attacker will be able
to provoke a `PAM_IGNORE` return value in pam\_pkcs11. For a physical attacker
the simplest way is to insert an arbitrary smart card into an existing reader,
or attach a peripheral smart card device to the system. The pam\_pkcs11
module, if configured, will attempt to access the smart card: if the access
fails, then the module returns `PAM_IGNORE`, resulting in a possible
authentication bypass.

4) Affected Distributions and Configurations
============================================

The issue was introduced in pam\_pkcs11 version 0.6.12, released in July 2021.
Any PAM stack that relies on pam\_pkcs11 as the only authentication factor
will be affected by the issue.

On openSUSE Tumbleweed the issue became apparent only due to the
[mentioned changes in GDM][gdm:yubi-key-smart-card-issue], which cause
YubiKeys to be treated as smart cards in some situations. We believe plugging
in any kind of mismatching smart card (or YubiKey) on openSUSE Tumbleweed with
GDM as a display manager will allow to bypass login.

Similar situations could occur on other Linux distributions if GDM smart card
login is enabled and smart cards are autodetected. Even then, an affected
"gdm-smartcard" PAM stack still needs to be in place for the issue to trigger.
gdm-smartcard PAM stacks relying on pam\_pkcs11 are found in the GDM
repository for:

- [Arch Linux][gdm:arch-pam-stack]
- [Exherbo Linux][gdm:exherbo-pam-stack]
- [Linux from Scratch][gdm:lfs-pam-stack]

We tried reproducing the issue on Arch Linux. There the gdm-smartcard PAM stack
is installed along with GDM, but there is no pam\_pkcs11 package in the
standard repositories. It can be installed from the
[AUR](https://aur.archlinux.org/), however. When doing so and also installing
the gdm and ccid packages, then the issue becomes basically exploitable as
well. We only tested this with a crafted sudo PAM stack, though, since we did
not manage to get gdm into smart card authentication mode on Arch Linux. It
seems some ingredient was still missing to trigger that.

On Arch Linux we also noticed that the AUR pam\_pkcs11 package does not
place any default "pam\_pkcs11.conf" file into `/etc`. This also avoids the
security problem, because when the [`slot_num`][code:slot_num] setting
is left unconfigured to its built-in default value of -1, then
`pam_sm_authenticate()` will return early with `PAM_AUTHINFO_UNAVAIL`. On
openSUSE we do ship a default configuration of `slot_num = 0`, however.

Current Fedora Linux does not use pam\_pkcs11 for smart card authentication
anymore (pam\_sss is used instead). Older versions of Fedora might still be
affected.

5) Possible Workaround
======================

A quick workaround to prevent login bypass is to use the following PAM stack
configuration line instead of what is found e.g. in the gdm-smartcard PAM
stacks:

```sh
auth [success=ok default=bad] pam_pkcs11.so wait_for_card card_only
```

Instead of using `ignore=ignore` as seen in the `required` control setting
shown in section 3), the PAM library will consider `ignore` (actually any other
outcome than success) a bad result for the authentication stack. This will
cause authentication to fail even if pam\_pkcs11 returns `PAM_IGNORE`.

6) Bugfix
=========

After extensive discussions about the nature of the problem and potential
compatibility issues, upstream arrived at a rather straightforward bugfix
which is found in [commit 2ecba68d40][upstream:bugfix]. Basically the
`PAM_IGNORE` return values have been changed into `PAM_CRED_INSUFFICIENT`
again.

This bugfix is part of [upstream release 0.6.13][upstream:bugfix-release],
which also fixes another vulnerability in the PAM module, which has been
discovered independently.

7) Lessons Learned
==================

We could not find any clear advice in PAM admin or developer documentation
regarding the proper use of `PAM_IGNORE`. Therefore we try to give an overview
of the current situation and suggested best practices in this section.

On the use of `PAM_IGNORE`
--------------------------

As there have been doubts if pam\_pkcs11 is to blame for its use of
`PAM_IGNORE`, we made a survey of other PAM modules packaged in openSUSE. We
found one PAM module, pam\_u2f, that also had problematic uses of `PAM_IGNORE`
in error situations and we published the issue already [in a previous
report][blog:pam-u2f-report]. This report already resulted in [a discussion
on the oss-security mailing list][oss-sec:pam-discussion] about possible
structural problems when implementing PAM modules.

Apart from this we found the following uses of `PAM_IGNORE`:

**Core PAM Modules**

- pam\_wheel: this is only kind of a filter module, such that non-`root` will be
  denied, while for `root` it returns `PAM_IGNORE`; the actual authentication
  decision is made by other modules.
- pam\_sepermit: returns `PAM_IGNORE` if users are not listed in the
  configuration file.
- pam\_lastlog: uses `PAM_IGNORE` if the lastlog file (in a privileged
  location) cannot be read.
- pam\_userdb: returns `PAM_IGNORE` if no database is configured.
- pam\_listfile: returns `PAM_IGNORE` if the user about to login does not
  match the configured criteria.

**Third Party PAM Modules**

- pam\_google\_authenticator: returns `PAM_IGNORE` if there is no state file
  and the `nullok` option is passed the module.
- nss-pam-ldapd: returns `PAM_IGNORE` if the user is unknown or no auth info
  is available, but only if explicitly configured to do so
  (`cfg->ignore_authinfo_unavail`, `cfg->ignore_unknown_user`)
- pam\_krb5:
  - returns `PAM_IGNORE` if the user it not known, but only if
    `options->ignore_unknown_principals` is set.
  - returns `PAM_IGNORE` if a `minimum_uid` is configured and the user doesn't
    match that.
- pam\_radius: returns `PAM_IGNORE` if the network is unavailable and ignore
  has been explicitly configured via the `localifdown` option.
- pam\_yubico: returns `PAM_IGNORE` if there are no tokens for the user and
  the `nullok` option is passed to the module.

As can be seen from this list, most PAM modules only return `PAM_IGNORE` if
there is an explicit opt-in either through a configuration option or a setting
in a privileged configuration file. Most of the time the meaning of the return
value is that the authentication mechanism is not configured at all, or not
configured for the user that is authenticated. Such configurations can only be
used in a safe way if the module in question is an optional authentication
mechanism, and a fallback PAM module for authentication is present on the
stack.

From the issues seen in pam\_pkcs11 and pam\_u2f we believe it is especially
important for PAM module implementations to take care not to use `PAM_IGNORE`
in unclear error situations, since local or physically present attackers might
be able to trigger them.

On the use of `PAM_SUCCESS`
---------------------------

PAM modules that only serve utility functions but do not actually authenticate
could consider not returning `PAM_SUCCESS` but `PAM_IGNORE` instead. This
would avoid unintended successful authentication in a situation like described
in this report. It seems natural to PAM module authors to return `PAM_SUCCESS`
if nothing in their module failed, however. A lot of modules work this way and
changing them all would be a big effort.

Conservative PAM Stack Configuration
------------------------------------

Sadly PAM can be difficult to understand for non-developers and sometimes even
for PAM module authors. Even more so admins and integrators should be careful
when writing PAM stacks, especially when less common PAM modules are used as
the only authentication requirement. Extended PAM syntax like used in our
suggested workaround could be used in such situations for hardening purposes,
to make sure no unexpected authentication outcomes can occur.

8) Timeline
===========

|2024-11-06|There was no maintainer, security contact or disclosure process documented in pam\_pkcs11 or the OpenSC project. In an attempt to find a suitable upstream contact we approached Ludovic Rousseau, who was a contributor to pam\_pkcs11 and a member of the OpenSC organization on GitHub.|
|2024-11-06|Ludovic replied that he is no longer active in the project and pointed to public means of reporting the issue, which we would rather not use at this point.|
|2024-11-07|We approached Paul Wolneykien, another recent pam\_pkcs11 contributor, and asked for guidance.|
|2024-11-07|Paul replied that Ludovic would be the proper maintainer, with Frank Morgner as a fallback. He also pointed to the (public) opensc developer mailing list.|
|2024-11-08|Still without a conclusive contact we [publicly asked for a security contact](https://sourceforge.net/p/opensc/mailman/message/58838740/) on the opensc developer mailing list.|
|2024-11-08|In response to our question, Frank Morgner of the OpenSC project enabled private security reporting in the [pam\_pkcs11 GitHub repository][upstream:github].|
|2024-11-11|We [shared our report][upstream:private-issue] using the now available GitHub private issue reporting, offering coordinated disclosure and an embargo period of up to 90 days.|
|2024-11-12|A couple of upstream developers joined the private GitHub issue and various discussions started.|
|2024-11-13|Due to uncertainty on the proper use of `PAM_IGNORE` and what the proper fix in pam\_pkcs11 could be, we suggested an early publication of the issue to allow a public discussion of the issue.|
|2024-11-17|Different opinions were expressed with regards to publishing the issue, so no agreement could be found at this point. No planned release date could be established.|
|2024-11-20|While looking into other PAM modules and their use of `PAM_IGNORE`, we found that the `pam-u2f` module suffered from a similar problem. We reported the issue to Yubico upstream, see [our earlier report][blog:pam-u2f-report].|
|2024-11-26|[linux-pam](https://github.com/linux-pam/linux-pam) developer Dmitry V. Levin got pulled into the discussion to judge whether the use of `PAM_IGNORE` in pam\_pkcs11 is problematic or not. He stated that the switch to `PAM_IGNORE` is problematic when end users are not aware of the behavioural change.|
|2024-12-05|With no clear path forward we suggested to share the report with the linux-distros mailing list soon to achieve some progress. No agreement regarding publication could be found, though.|
|2025-01-07|Upstream developers discussed a patch to fix the issue, but communication died down since December 12. We asked once more about a path forward to publish the report and bugfix.|
|2025-01-13|Upstream asked us to request a CVE for the issue. We requested it from Mitre, but the request [got stuck][oss-sec:mitre-discussion] for nearly two weeks.|
|2025-01-14|The spin-off [pam-u2f][blog:pam-u2f-report] issue was published. It was unfortunate that this got published first, since we could not publicly discus the bigger picture involving pam\_pkcs11 at this time.|
|2025-01-20|An upstream developer stated that a private branch containing a bugfix is available, and asked whether this should be published. We asked not to publish anything without an agreement on the date and procedure.|
|2025-01-23|The issue with the Mitre CVE request got resolved and CVE-2025-24531 was assigned for it. We shared this CVE in the private upstream issue.|
|2025-01-23|We asked once more for a coordinated release date and suggested to share the issue with the linux-distros mailing list on Jan 30 and to perform general publication on Feb 6.|
|2025-01-24|General agreement was achieved for the suggested publication dates.|
|2025-01-30|We shared the report and bugfix with the [linux-distros mailing list](https://oss-security.openwall.org/wiki/mailing-lists/distros), communicating an embargo period until publication on Feb 6.|
|2025-02-06|Upstream published [bugfix release 0.6.13][upstream:bugfix-release] as planned.|

9) References
=============

- [pam\_pkcs11 repository][upstream:github]
- [pam\_pkcs11 GitHub Security Issue Discussion and Advisory][upstream:private-issue]
- [upstream bugfix for the issue][upstream:bugfix]
- [upstream bugfix release 0.6.13][upstream:bugfix-release]
- [problematic gdm-smartcard PAM stack used in openSUSE][obs:gdm-smartcard-stack]
- [previous blog post about bad `PAM_IGNORE` use in pam-u2f][blog:pam-u2f-report]

[upstream:github]: https://github.com/OpenSC/pam_pkcs11
[upstream:private-issue]: https://github.com/OpenSC/pam_pkcs11/security/advisories/GHSA-7mf6-rg36-qgch
[upstream:affected-release]: https://github.com/OpenSC/pam_pkcs11/releases/tag/pam_pkcs11-0.6.12
[upstream:bugfix-release]: https://github.com/OpenSC/pam_pkcs11/releases/tag/pam_pkcs11-0.6.13
[upstream:introducing-commit]: https://github.com/OpenSC/pam_pkcs11/commit/bac6cf8e0b242e508e8b715e7f78d52f1227840a
[upstream:artifact-commit]: https://github.com/OpenSC/pam_pkcs11/commit/88a87d54ff0a9f1c425906bb1fe260e40bd7751c 
[upstream:bugfix]: https://github.com/OpenSC/pam_pkcs11/commit/2ecba68d404c3112546a9e802e3776b9f6c50a6a
[upstream:readme-card-only-setting]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/README#L105
[blog:pam-u2f-report]: /2025/01/14/pam-u2f-ignore-returns.html
[bugzilla-report]: https://bugzilla.suse.com/show_bug.cgi?id=1231843
[oss-sec:mitre-discussion]: https://www.openwall.com/lists/oss-security/2025/01/22/2
[oss-sec:pam-discussion]: https://www.openwall.com/lists/oss-security/2025/01/15/1
[code:pam-sm-authenticate]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L207
[code:pam-ignore-default]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L284
[code:line305]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L305
[code:line316]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L316
[code:line328]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L328
[code:line343]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L343
[code:line374]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L374
[code:line416]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L416
[code:line510]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L510
[code:line695]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L695
[code:slot_num]: https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L249
[gdm:yubi-key-smart-card-issue]: https://gitlab.gnome.org/GNOME/gdm/-/issues/877
[gdm:arch-pam-stack]: https://gitlab.gnome.org/GNOME/gdm/-/blob/be3a3de7130b212b3ba84c5644e0e057e41556d8/data/pam-arch/gdm-smartcard.pam
[gdm:exherbo-pam-stack]: https://gitlab.gnome.org/GNOME/gdm/-/blob/be3a3de7130b212b3ba84c5644e0e057e41556d8/data/pam-exherbo/gdm-smartcard.pam
[gdm:lfs-pam-stack]: https://gitlab.gnome.org/GNOME/gdm/-/blob/be3a3de7130b212b3ba84c5644e0e057e41556d8/data/pam-exherbo/gdm-smartcard.pam
[obs:gdm-smartcard-stack]: https://build.opensuse.org/projects/GNOME:Factory/packages/gdm/files/gdm-smartcard.pamd?expand=1&rev=50feb25477832ba767b0c6702d80bc04
[code:gnome-shell-gdm-smartcard]: https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/17ce108a35d35447c82899bfe5011b4860862a53/js/gdm/util.js#L28
