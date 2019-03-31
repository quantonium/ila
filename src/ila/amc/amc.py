# amc.py - Address mapping AMPF management interface program
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

import sys, getopt, redis, struct, socket, amfp, qutils
from collections import namedtuple

def usage_err(errstr):
	if (errstr != ""):
		print(errstr)
		print("")

	print("Usage:")
	print("    amc [-h host] [-p port] get IDENT")
	print("")
	print("IDENT = iid | luid | virt-v4 | virt-uni-v6 |")
	print("        virt-multi-v6 | monlocal-addr | use-format")

	sys.exit(2)

try:
	mypopts, args = getopt.getopt(sys.argv[1:], "h:p:")
except getopt.GetoptError as e:
	usage_err(str(e))
	sys.exit(2)

try:
	port_set = False
	host = "::1"
	port = 5555

	for o, a in mypopts:
		if o == '-h':
			host = a
		elif o == '-p':
			port = a
			port_set = True

	if len(args) < 1:
		usage_err("Need at least two arguments")
		sys.exit(2)

	cmd = args[0];
	args = args[1:]

	amfp.amfp_process_get_map_entry(host, int(port), cmd, args)

except socket.error as e:
	print("Socket error:%s", str(e))
	sys.exit(2)
