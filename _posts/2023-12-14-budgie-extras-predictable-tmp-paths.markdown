---
layout: post
author: <a href='mailto:matthias.gerstner@suse.de'>Matthias Gerstner</a>
title:  "budgie-extras: Multiple Predictable /tmp Path Issues in Various Applications"
date:   2023-12-14 15:15 +0100
tags:   CVE tmpfiles
excerpt: "This report is about a range of predictable /tmp path issues in various applications in the budgie-extras repository. This repository contains a range of helper applications for the Budgie desktop environment."
---

This report is about a range of predictable /tmp path issues in various
applications in the [budgie-extras][budgie-extras-repo] repository. This
repository contains a range of helper applications for the Budgie desktop
environment.

During a routine review of applications that are autostarted in X11
environments I found the issues 1) to 4) outlined below. Upstream found
two additional cases of predictable /tmp path uses that they addressed,
as outlined in items 5) and 6). Upstream released [version
1.7.1][budgie-extras-bugfix-release] today which fixes all the issues.

Introduction
============

The affected programs are mostly written in the Vala programming
language, some are also scripted in Python. In all cases predictable
paths in /tmp containing only the username or no variable components at
all are used. In these paths regular files or directories are created.
The paths are often used as a kind of inter-process-communication
between two or more budgie-extras components.

The impact of the issues differs a lot depending on the actual affected
program and ranges from denial-of-service to information leaks to
integrity issues through manipulation of the data which is used e.g. for
displaying images on the desktop. All the issues are restricted to local
attackers, naturally.

Without the Linux kernel's protect symlink sysctl setting the severity
of the issues will in some cases be worse. Even with this protection
enabled it is often possible to pre-create the files or directories as
another local user, granting world read and write access, which will
cause the budgie-extras applications to use them even though they are
attacker controlled.

Without the Linux kernel's symlink protection many of these findings
where files are created look like they might allow symlink attacks to
have files created in arbitrary locations. The Vala file creation calls
I looked into are mostly translated into the following system call,
though:

    openat(AT_FDCWD, <path>, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0666)

Even tough this is missing the `O_NOFOLLOW` flag, symlinks would not be
followed, due to the combination of `O_CREAT` and `O_EXCL`. I will point
out cases where symlink attacks might still be possible in spite of
this.

As a quick fix for all of these issues I suggested to use
`$XDG_RUNTIME_DIR` instead of /tmp. This directory is private to the
logged in user and cannot be manipulated by other users in the system.
In the instances where these files are used as a simple communication
mechanism ("trigger" logic) it could be considered using sockets, the
D-Bus session bus or named FIFOs instead - also placed in safe
locations, of course.

Following is a detailed listing of all individual issues based on the
budgie-extras [Git repository tag for version
1.7.0][budgie-extras-review-version-tag].

1) budgie-window-shuffler (CVE-2023-49344)
==========================================

1.1) Path `/tmp/shufflerapplettrigger_<user>`
----------------------------------------

In [`src/shuffler_control.vala` line 1740][window-shuffler-trigger-srcloc]
first an attempt is made to delete this path. Then it starts monitoring the
path, reacting to its creation, by automatically selecting (popping up) the
"Applet" listbox GUI entry.

The counterpart to this is found in [`applet/src/ShufflerApplet.vala` line
91][window-shuffler-trigger-srcloc2], where this file is created to let the
settings dialog open.

The worst that can happen here is likely confusing the victims GUI so it
is low severity.

1.2) Path `/tmp/<user>_shufflertriggers/layoutspopup`
-----------------------------------------------------

In [`src/toggle_layouts_popup.vala` line 62][window-shuffler-popup-srcloc]
first an attempt is made to create the directory, ignoring any potential
errors - considering it to already exist. Then the "layoutspopup" file is
created within the directory. Depending on program evaluation logic the string
"fromcontrol" is written to the file, otherwise the file remains empty.

In [`src/layouts_popup.vala` line 1384][window-shuffler-popup-srcloc2]
monitoring for this file is setup, its content is read (it is checked whether
it contains "fromcontrol") and then a popup window is either created or
destroyed, depending on the current program state.

Another user in the system can pre-create this directory and then
control the creation and destruction of the popup dialog, thereby
confusing the victim's GUI. By placing a FIFO instead of a regular file
at "layoutspopup", the layout popup will be subject to denial-of-service
(either by blocking it indefinitely or by feeding it large amounts of
data, leading to an out-of-memory situation).

Without the Linux kernel's symlink protection the issue can be used to
make the `layouts_popup` program read from arbitrary files, or to
operate in arbitrary directories.

1.3) Path `/tmp/<user>_running_layout`
--------------------------------------

In [`src/run_layout.vala` line 203][window-shuffler-layout-srcloc] this file
is created to "temporarily disable possibly set windowrules". In line 379 this
path is (needlessly) constructed again and passed to function
`create_busyfile()`, although this parameter remains unused by the function.
In line 478 `stat()` and `unlink()` are attempted on the file.

In [`src/windowshufflerdaemon.vala` line 831][window-shuffler-layout-srcloc2]
an existence check for this file is made. If it exists then the `run_rule`
program will not be executed for any windows.

This path allows a local attacker to prevent the victim's `run_rule`
ever to be executed.

1.4) Path `/tmp/<user>_gridtrigger`
-----------------------------------

In [`src/togglegui.vala` line 33][window-shuffler-gridtrigger-srcloc] an
existence check is made for this path and depending on the outcome it is
either created as an empty file, or deleted.

In [`src/windowshufflerdaemon.vala` line
992][window-shuffler-gridtrigger-srcloc2] in function `actonfile()`
there is a reaction to the creation and deletion of this path. Depending
on this the `gridguiruns` boolean is set to true or false respectively.
If it is set to `false` then a window will be destroyed in line 1148.

In [`src/gridwindow.vala` line 637][window-shuffler-gridtrigger-srcloc3] a
monitor is setup for this file and depending on it being created or being
deleted the `gridwindow` is being displayed or destroyed.

This path basically allows a local attacker to make the "grid window"
managed by the `gridwindow` program appear, thereby confusing the
victim's GUI. The other way around `windowshufflerdaemon` can be
caused to destroy its "preview window" if this state file is under a
local attacker's control.

1.5) Path `/tmp/shuffler-warning.png`
-------------------------------------

In [`src/windowshufflerdaemon.vala` line 1017][window-shuffler-warning-srcloc]
in function `create_warningbg()` this path is used to write a programmatically
created PNG image into. In function `show_awarning()` in line 338 the program
`sizeexceeds_warning` is executed which in turn in
[`src/sizeexceeds_warning.vala` line 68][window-shuffler-warning-srcloc2]
displays the generated PNG image on the desktop.

A local attacker can attempt to place arbitrary PNG data in this path
and have it displayed on the victim's desktop. Placing crafted PNG data
could allow to exploit further security issues in image processing
libraries.

1.6) Path `/tmp/<user>_istestingtask`
-------------------------------------

This path is potentially created in [`src/layouts_popup.vala` line
492][window-shuffler-testing-srcloc].  The file receives data from the GUI
interface. In [`src/run_layout.vala` line
407][window-shuffler-testing-srcloc2] this path is picked up again and its
content is interpreted in `extractlayout_fromfile()`.

Since this file's content is evaluated and used for further program
logic there is a chance for a local attacker to massively break the
`run_layout` program's logic or maybe even achieve code execution. The
Linux kernel's `protected_regular` sysctl setting comes to the rescue
here, though. The `open()` with `O_CREAT` will fail. It can then
still present a denial-of-service vector, though.

Upstream Fix
------------

This is fixed in [upstream commit 11b0201][window-shuffler-bugfix]. The public
/tmp directory has been replaced by the user's private `$XDG_RUNTIME_DIR`,
with a fallback to the user's home directory.

2) budgie-wpreviews (CVE-2023-49347)
====================================

2.1) Path `/tmp/<user>_window-previews`
---------------------------------------

This path is used for a directory. In [`src/separate_shot.vala` line
43][wpreviews-user-srcloc] it is created, errors are ignored. In line 105
screenshots of certain X11 windows are placed in the directory following the
name scheme `<window-id>.<workspace-name>.png`.

In [`src/previews_creator.vala` line 74][wpreviews-user-srcloc2] an attempt to
create the directory the same way is found. In line 241 the directory is
iterated over and each file found there, independently of its name, will be
assembled in a file list. This file list is luckily only used for removing
files of non-existent windows in this program.

In [`src/previews_daemon.vala` line 719][wpreviews-user-srcloc2] there is
another attempt to create the directory the same way as in the other two
locations. In line 523 the directory is again iterated over and a list of the
contained filenames is assembled, independently of their names. In line 404
the filenames are interpreted and split into X11 window IDs and workspace
names again. It seems the code expects all filenames to match the pattern, if
this is not the case then the program will likely crash. The resulting file
list is (luckily) matched against the existing X11 window IDs in line 421.

Even without exploiting the fixed temporary directory path this
directory has security issues, since it is created world-readable. Any
other users in the system can access the window screenshots that are
created there and thus this is an information leak.

Since all errors trying to create the directory are ignored, another
local user can pre-create this directory world-writable, and the
wpreviews applications will still use the directory which is now under
attacker control. The attacker can place additional PNG image files
there, trying to confuse the victim's GUI experience. A local DoS
against the `previews_daemon` seems also possible by placing
non-conforming files into the directory. Since the `previews_daemon`
only uses files from the directory for which an existing X11 window is
found, the complexity for a local attacker to inject arbitrary PNG files
into the preview logic is raised. It can still be possible by observing
the PNG files created by e.g. the `separate_shot` program and replacing
them with crafted data.

Without the Linux kernel's symlink protection a local attacker can place
a symlink there instead of a directory, causing the programs to operate
in arbitrary other directory locations.

2.2) Paths `/tmp/<user>_prvtrigger_*`, `/tmp/<user>_previoustrigger`, `/tmp/<user>_nexttrigger`
-----------------------------------------------------------------------------------------------

This long list of trigger files:

    /tmp/<user>_prvtrigger_all
    /tmp/<user>_prvtrigger_current
    /tmp/<user>_prvtrigger_all_hotcorner
    /tmp/<user>_prvtrigger_curr_hotcorner
    /tmp/<user>_previoustrigger
    /tmp/<user>_prvtrigger_all
    /tmp/<user>_nexttrigger

is used both in [`src/previews_triggers.vala` line
43][wpreviews-trigger-srcloc] and [`src/previews_daemon.vala` line
664][wpreviews-trigger-srcloc2].

The `previews_triggers` program selects one of these trigger paths
depending on command line arguments, various logical evaluations and
depending on whether some of the paths already exist. The selected path
is then simply created with empty content.

In `previews_daemon` these paths are monitored and their existence is
evaluated in a complex fashion to display previews of existing windows.

In conjunction with the issues in 2.1) this can be used to display
attacker controlled images on the victim's screen at arbitrary times,
provided that the victim user is running the `previews_daemon`.

Apart from the security related problems this group of files for
controlling a daemons behaviour seems ill devised. Instead proper IPC
mechanisms should be used.

Upstream Fix
------------

This is fixed in [upstream commit 588cbe6][wpreviews-bugfix]. The public /tmp
directory has been replaced by the user's private `$XDG_RUNTIME_DIR`, with a
fallback to the user's home directory.

3) budgie-takeabreak (CVE-2023-49345)
=====================================

3.1) Path `/tmp/nextbreak_<user>`
---------------------------------

This file is read in [`budgie_takeabreak.py` line 245][takeabreak-srcloc] and
the resulting string is split on ".", the first element resulting from this is
used as the new "time" displayed in the GUI.

In [`takeabreak_run` line 80][takeabreak-srcloc2] this path is created and the
next "break time" is written to it.

A local attacker can pre-create this file and have arbitrary string
content displayed instead of the actual "next time". A denial-of-service
will also be possible e.g. by placing a FIFO there.

Upstream Fix
------------

This is fixed in [upstream commit 588cbe6][takeabreak-bugfix]. The public /tmp
directory has been replaced by the user's private `$XDG_RUNTIME_DIR`, with a
fallback to the user's home directory.

4) budgie-weathershow (CVE-2023-49346)
======================================

4.1) Path `/tmp/<username>_weatherdata`
---------------------------------------

In [`src/weathershow/WeatherShow.vala` line 354][weathershow-srcloc] the
current "weather data" is written to this location. Before this an attempt is
made to delete an already existing file. Errors for both, deletion and
creation of the file, are ignored unconditionally.

In line 236 the content from this file is read and interpreted for updating
GUI window data.

A local attacker can pre-create this file and thus manipulate the data
displayed by the weather applet. Also a denial-of-service will be
possible e.g. by placing a FIFO there.

Upstream Fix
------------

This is fixed in [upstream commit 0092025][weathershow-bugfix]. The public
/tmp directory has been replaced by the user's private `$XDG_RUNTIME_DIR`,
with a fallback to the user's home directory.

5) budgie-clockworks (CVE-2023-49342)
=====================================

This issue was not discovered by me but by upstream while working on the
fixes for the other issues I reported. For completeness I mention it in
this report as well.

5.1) Path `/tmp/<user>_clockworks`
----------------------------------

This path is used as a directory in the Python script
[`cwtools.py`][clockworks-srcloc]. It
is reused if it already exists. The scripts generates SVG vector
graphics in there, converts them to the PNG image format and saving them
in the users home directory in `~/.config/budgie-extras/clockworks`.

Here, again, the image data can be manipulated by a local attacker by
pre-creating this directory. In this case the data will even be
persisted in the user's home directory. Crafted SVG of PNG data could be
placed in the directory to try attacking the image processing libraries
used.

Upstream Fix
------------

This is fixed in [upstream commit d030837][clockworks-bugfix]. The public /tmp
directory has been replaced by the user's private `$XDG_RUNTIME_DIR`, with a
fallback to the user's home directory.

6) budgie-dropby (CVE-2023-49343)
=================================

Like issue 5), this issue was not discovered by me but by upstream while
working on the other issues I reported. For completeness I mention it in
this report as well.

6.1) Path `/tmp/<user>_keepdropbywin`
-------------------------------------

This path is used as a "timer" file in the [`checkonwin`][dropby-srcloc] and
[`dropover`][dropby-srcloc2] Python scripts. The file's content is not
evaluated, but the `checkonwin` script runs `wmctrl -c dropby_popup` if the
file doesn't exist for more than six seconds.

The Python `openat()` call uses `O_CREAT | O_EXCL` flags so symlink
attacks are not a problem even without kernel symlink protection. Other
users in the system can shorten the "timer" logic of the `checkonwin`
script, though, by creating the file path at an arbitrary time.

6.2) Path `/tmp/<user>_call_dropby`
-----------------------------------

The script [`budgie_dropby.py`][dropby-srcloc3] creates this file as a trigger
for the `dropover` script which reacts to the creation of this path by
scanning the current list of USB block devices and their mount points in the
system. A GUI dialog is displayed or updated as a reaction to this.

A local attacker can cause this dialog to be displayed by creating this
file. It can also be used as a kind of local DoS vector to keep the
`dropover` script busy all the time, iterating over block devices.

6.3) Path `/tmp/<user>_dropby_icon_copy`
----------------------------------------

This is used as a trigger file in [`budgie_dropby.py`][dropby-srcloc3]. If the
file is created then a GUI dialog is changed and updated. In the
[`copy_flash`][dropby-srcloc4] Python script this trigger is created to signal
that some files have been copied.

A local attacker can cause this dialog to be displayed by creating this
file at arbitrary times.

Upstream Fix
------------

This is fixed in [upstream commit e75c94a][dropby-bugfix]. The public /tmp
directory has been replaced by the user's private `$XDG_RUNTIME_DIR`, with a
fallback to the user's home directory.

7) Timeline
===========

|2023-10-16| I reported the issues 1) - 4) to fossfreedom@ubuntu.com, offering coordinated disclosure.|
|2023-10-17| Upstream accepted coordinated disclosure aiming at a publication date towards the end of the year.|
|2023-11-28| Upstream communicated to us the CVEs they assigned for the issues plus for the two additional items 5) - 6) they discovered. They communicated that an upcoming version 1.7.1 will contain the fixes.|
|2023-12-03| Upstream communicated a preliminary publication date of 2023-12-14 for version 1.7.1 containing the fixes. They shared the individual patches for issues 1) - 6) with us.|
|2023-11-14| The publication date has been reached, the upstream version 1.7.1 as well as GitHub security advisories have been published.|

8) References
=============

- [budgie-extras GitHub repository][budgie-extras-repo]
- [budgie-extras v1.7.1 bugfix release][budgie-extras-bugfix-release]
- [budgie-extras v1.7.0 tag: this was the code based used in this review][budgie-extras-review-version-tag]
- [bugfix commit for window-shuffler application][window-shuffler-bugfix]
- [bugfix commit for the wpreviews application][wpreviews-bugfix]
- [bugfix commit for the takeabreak application][takeabreak-bugfix]
- [bugfix commit for the weathershow application][weathershow-bugfix]
- [bugfix commit for the clockworks application][clockworks-bugfix]
- [bugfix commit for the dropby application][dropby-bugfix]

[budgie-extras-repo]: https://github.com/UbuntuBudgie/budgie-extras
[budgie-extras-bugfix-release]: https://github.com/UbuntuBudgie/budgie-extras/releases/tag/v1.7.1
[budgie-extras-review-version-tag]: https://github.com/UbuntuBudgie/budgie-extras/tree/v1.7.0
[window-shuffler-trigger-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/shuffler_control.vala#L1740
[window-shuffler-trigger-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/applet/src/ShufflerApplet.vala#L91
[window-shuffler-popup-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/toggle_layouts_popup.vala#L62
[window-shuffler-popup-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/layouts_popup.vala#L1384 
[window-shuffler-layout-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/run_layout.vala#L203
[window-shuffler-layout-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/windowshufflerdaemon.vala#L831
[window-shuffler-gridtrigger-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/togglegui.vala#L33
[window-shuffler-gridtrigger-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/windowshufflerdaemon.vala#L992
[window-shuffler-gridtrigger-srcloc3]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/gridwindow.vala#L637
[window-shuffler-warning-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/windowshufflerdaemon.vala#L1017
[window-shuffler-warning-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/sizeexceeds_warning.vala#L68
[window-shuffler-testing-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/layouts_popup.vala#L492
[window-shuffler-testing-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-window-shuffler/src/run_layout.vala#L407
[window-shuffler-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/11b02011ad2f6d46485b292713af09f7314843a5
[wpreviews-user-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-wpreviews/src/separate_shot.vala#L43
[wpreviews-user-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-wpreviews/src/previews_creator.vala#L74
[wpreviews-user-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-wpreviews/src/previews_daemon.vala#L719 
[wpreviews-trigger-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-wpreviews/src/previews_triggers.vala#L43
[wpreviews-trigger-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-wpreviews/src/previews_daemon.vala#L664
[wpreviews-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/588cbe6ffa72df904213d77728a3fd5bfae7195e
[takeabreak-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-takeabreak/budgie_takeabreak.py#L245
[takeabreak-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-takeabreak/takeabreak_run#L80
[takeabreak-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/ffa29d4bfe880217e28d99de99026760ae6fe1d4
[weathershow-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-weathershow/src/weathershow/WeatherShow.vala#L354
[weathershow-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/0092025ef25b48c287a75946c0ee797d3c142760
[clockworks-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-clockworks/cwtools.py
[clockworks-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/d03083732569126d2f21c8810d5a69554ccc5900
[dropby-srcloc]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-dropby/checkonwin
[dropby-srcloc2]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-dropby/dropover
[dropby-srcloc3]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-dropby/budgie_dropby.py
[dropby-srcloc4]: https://github.com/UbuntuBudgie/budgie-extras/blob/v1.7.0/budgie-dropby/copy_flash
[dropby-bugfix]: https://github.com/UbuntuBudgie/budgie-extras/commit/e75c94af249191bdbd33eebf7a62d4234a0d8be5
