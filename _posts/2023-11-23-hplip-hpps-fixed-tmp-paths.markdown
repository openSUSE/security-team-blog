---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "hplip: Security Issues in hpps Program due to Fixed /tmp Path Usage"
date:   2023-11-23 10:37:00 +0100
tags:   tmpfiles
excerpt: "This report is about the problematic use of fixed temporary paths in the
<i>hpps</i> program from the hplip project. Hplip is a collection of
utilities for HP printer and scanner devices."
---

This report is about the problematic use of fixed temporary paths in the
`hpps` program from the [hplip project][hplip-repo]. Hplip is a collection of
utilities for HP printer and scanner devices.

There is currently no upstream fix available for this issue and this
publication happens after 90 days of attempted coordinated disclosure, but
upstream did not react to my report.

**Update 2024-01-04**: I have been informed that upstream release 3.23.12
published on 2023-11-30 silently fixes this issue. The fix is based on the
patch that I suggested in this report.

This report is based on the latest upstream [release
3.23.8][hplip-reviewed-release] of hplip.

The Issue
=========

The program /usr/lib/cups/filter/hpps uses a number of insecure fixed
temporary files that can be found in prnt/hpps/hppsfilter.c:

    prnt/hpps/hppsfilter.c:1027:        sprintf(booklet_filename, "/tmp/%s.ps","booklet");
    prnt/hpps/hppsfilter.c:1028:        sprintf(temp_filename, "/tmp/%s.ps","temp");
    prnt/hpps/hppsfilter.c:1029:        sprintf(Nup_filename, "/tmp/%s.ps","NUP");

These paths are only used if "booklet printing" is enabled. For testing, the
logic can be forced by invoking the program similar to this:

    $ export PPD=/usr/share/cups/model/manufacturer-PPDs/hplip-plugin/hp-laserjet_1020.ppd.gz
    $ /usr/lib/cups/filter/hpps some-job some-user some-title 10 HPBookletFilter=10,fitplot,Duplex=DuplexTumble,number-up=1

The program will expect data to print on stdin this way. Just typing in
some random data and pressing Ctrl-d will make it continue. There is a
chance that it will crash, though, since error returns from parsing
errors are largely not checked in this program.

The three paths are created and opened using `fopen()`, so no special
open flags are in effect that would prevent following symlinks, also the
`O_EXCL` flag is missing to prevent opening existing files. The
resulting system calls look like this (for creation / opening for
reading):

    openat(AT_FDCWD, "/tmp/temp.ps", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
    openat(AT_FDCWD, "/tmp/temp.ps", O_RDONLY)

Furthermode there is a `chmod()` on the /tmp/temp.ps file:

    hppsfilter.c:110 chmod(temp_filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

The data to print (from stdin) is written to this file, and the file is
also made world readable explicitly via this `chmod()`. The issues with
these paths are multifold:

- There is a local information leak, since the print job data will
  become visible to everybody in the system.
- There is violated data integrity, since other users can pre-create these
  files and manipulate e.g. the data to print.
- This may allow to create files in unexpected places, by placing symbolic
  links, if the Linux kernel's symlink protection is not active.
- Similarly it may allow to grant world read privileges to arbitrary
  files by following symlinks during the `chmod()`.
- It may allow further unspecified impact if crafted data is placed into
  /tmp/temp.ps which is processed by the complex `PS_Booklet()` function.

I did not research the impact of the issue further to see whether this
could lead to local code execution in the context of the user that is
invoking `hpps`.

Suggested Patch
===============

To fix this issue all three fixed temporary paths need to be replaced by
unpredictably named temporary files that are safely created. I authored a
[suggested patch][suggested-patch] that accomplishes this. This patch
also drops the `chmod()`. The purpose of it is unclear, so it is
possible that this breaks something, if other processes with different
privileges need to access this file.

There is no patch or any other information available from upstream.

Affectedness
============

Since, to my knowledge, there is no public version control system for
hplip, it is difficult to determine when this issue has been introduced.
By taking some samples from older SUSE distributions I found the issue
to be present at least since upstream release 3.19.12 from 2019-12-12.

CVE Assignment
==============

Since HP is a CVE CNA, it is itself responsible for assigning a CVE.
Since there is no reaction from upstream I don't know if or when CVEs
will be available.

Timeline
========

|2023-08-21|I reported the finding privately to upstream via [Launchpad][hplip-launchpad-issue], offering coordinated disclosure. No other means of contact are documented for hplip.|
|2023-09-05|Since I did not get any feedback yet I urged upstream via Launchpad to provide a response.|
|2023-10-04|I shared the suggested patch with upstream, still no response.|
|2023-11-17|The 90 days maximum embargo time we offer approached and we published the finding.|
|2024-01-04|I got informed that upstream silently fixed the issue on 2023-11-30 in release 3.23.12.|

References
==========

- [hplip SourceForge Project page][hplip-repo]
- [hplip release 3.23.8 which this review was based on][hplip-reviewed-release]
- [private hplip Launchpad security issue detailing these issues][hplip-launchpad-issue]
- [suggested patch to fix the issue][suggested-patch]

[hplip-repo]: https://sourceforge.net/projects/hplip
[hplip-reviewed-release]: https://sourceforge.net/projects/hplip/files/hplip/3.23.8
[hplip-launchpad-issue]: https://bugs.launchpad.net/hplip/+bug/2032375
[suggested-patch]: /download/0001-hppsfilter-booklet-printing-change-insecure-fixed-tm.patch
