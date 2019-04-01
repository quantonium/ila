# tac.py - FAST ticket agent test
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

# This program sends a request to a FAST ticket agent and prints the
# replied ticket.
#

DEFAULT_FAST_PORT = 6666

import sys, getopt, redis, struct, socket, ila, qutils
from collections import namedtuple
import http.client

FastOpt = namedtuple('FastOpt', 'opt_type, opt_len, fast_type, \
	    rsvd, rsvd2, expiration, service_profile, locator')

def usage_err(errstr):
	if (errstr != ""):
		print(errstr)
		print("")

	print("Usage:")
	print("    tac get IDENT")

	sys.exit(2)

def get_tac_info(host, port, args):
	lookup = args[0]

	print("TAC lookup %s:%u for %s\n" % (host, port, args[0]))

	conn = http.client.HTTPConnection("%s:%u" % (host, port))
	conn.request("GET", "/?query=%s" % lookup)
	r1 = conn.getresponse()
	print(r1.status, r1.reason)
	data = r1.read()  # This will return entire content.

	if (len(data) != 22):
		print("Got data length %u\n" % len(data))

		for i in range(len(data)):
			print("%02x " % data[i], end='')

		print("")

		return

	opt_tuple = FastOpt._make(struct.unpack("<BBBBHIIQ", data))

	try:
		loc = qutils.addr64_n2a(opt_tuple.locator)
	except qutils.QutilsError as e:
		raise IlaParseError("Format locator: " + str(e))
		return

	print("Opt type: %u" % opt_tuple.opt_type);
	print("Opt len: %u" % opt_tuple.opt_len);
	print("Fast type: %u" % (opt_tuple.fast_type >> 4));
	print("Reserved: %u" % opt_tuple.rsvd);
	print("Expiration: %u" % socket.ntohl(opt_tuple.expiration));
	print("Service profile: %u" % socket.ntohl(opt_tuple.service_profile));
	print("Locator: %s" % loc);

try:
	mypopts, args = getopt.getopt(sys.argv[1:], "h:p:")
except getopt.GetoptError as e:
	usage_err(str(e))
	sys.exit(2)

try:
	port_set = False
	host = "::1"

	for o, a in mypopts:
		if o == '-h':
			host = a
		elif o == '-p':
			port = a
			port_set = True

	if len(args) < 2:
		usage_err("Need at least two arguments")
		sys.exit(2)

	cmd = args[0]

	args = args[1:]

	if cmd == 'get':
		if not port_set:
			port = DEFAULT_FAST_PORT
		get_tac_info(host, port, args)
	else:
		usage_err("Unknown tac command '%s'" % cmd)
		sys.exit(2)

except ila.IlaParseError as e:
	usage_err(str(e))
	sys.exit(2)
except ila.IlaConnectionError as e:
	print(str(e))
	sys.exit(2)
