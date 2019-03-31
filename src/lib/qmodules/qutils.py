# qutils.py - utility functions for Python
#
# Copyright (c) 2018, Quantonium Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the Quantonium nor the names of its contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL QUANTONIUM BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

class QutilsError(Exception):
	pass

import struct, socket, os, sys

# Addr64 number to string
def addr64_n2a(addr):
	s = ""
	for i in range(0, 4):
		v = (addr >> i * 16) & 0xffff
		s += "%x" %  socket.ntohs(v)
		if (i != 3):
			s += ":"

	return s

# Addr64 string to number. Input is a string with form "W:X:Y:Z"
def addr64_a2n(str):
	fields = str.split(':')
	if (len(fields) != 4):
		raise QutilsError("Bad fields count")
		return

	try:
		ret = struct.pack(">HHHH",
		    int(fields[0], 16), int(fields[1], 16),
		    int(fields[2], 16), int(fields[3], 16))
	except ValueError:
		raise QutilsError("Error converting %s to addr64" % str)
		return
	except struct.error:
		raise QutilsError("Error structuring %s as addr64" % str)
		return

	return ret

# Ifindex to name. (No obvious way to do this in Python)
def llindex2name(ifindex):
	if (ifindex == 0):
		return "*"
	else:
		return "%d" % ifindex

# Parse address string as an IPv6 address
def parse_address(str):
	try:
		return socket.inet_pton(socket.AF_INET6, str)
	except socket.error as err:
		raise QutilsError("Unable to parse address %s: %s" % (str, format(err)))

# Output an IPv6 address given two 64bit quads
def quads2ip(addr1, addr2):
	return socket.inet_ntop(socket.AF_INET6,
	    struct.pack("QQ", addr1, addr2))

def daemonize():
	"""
	do the UNIX double-fork magic, see Stevens' "Advanced
	Programming in the UNIX Environment" for details (ISBN 0201563177)
	http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
	"""
	try:
		pid = os.fork()
		if pid > 0:
			# exit first parent
			sys.exit(0)
	except OSError as e:
		sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
		sys.exit(1)

	# decouple from parent environment
	os.chdir("/")
	os.setsid()
	os.umask(0)

	# do second fork
	try:
		pid = os.fork()
		if pid > 0:
			# exit from second parent
			sys.exit(0)
	except OSError as e:
		sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
		sys.exit(1)

	# close standard file descriptors
	sys.stdin.close()
	sys.stdout.close()
	sys.stderr.close()
