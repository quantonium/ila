# ilac.py - ILA management interface program
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

# This program interacts with three databases. The 'map', 'ident' and
# 'loc'.
#

DEFAULT_MAP_PORT = 6379
DEFAULT_IDENT_PORT = 6380
DEFAULT_LOC_PORT = 6381

import sys, getopt, redis, struct, socket, ila
from collections import namedtuple

def usage_err(errstr):
	if (errstr != ""):
		print(errstr)
		print("")

	print("Usage:")
	print("    ilac map list")
	print("    ilac map flush")
	print("    ilac map { --csum-mode=CSUM } { --ident-type=IDENT }")
	print("            { --hook-type=HOOK } ADDR ADDR64")
	print("    ilac map del ADDR")
	print("")
	print("    ilac ident list")
	print("    ilac ident flush")
	print("    ilac ident make NUM ADDR")
	print("    ilac ident attach NUM NUM")
	print("    ilac ident unattach NUM")
	print("    ilac ident destroy NUM")
	print("")
	print("    ilac loc list")
	print("    ilac loc flush")
	print("    ilac loc make NUM ADDR64")
	print("    ilac loc destroy NUM")
	print("")
	print("NUM = 0..2^64")
	print("ADDR = IPv6 address")
	print("ADDR64 = WWWW:XXXX:YYYY:ZZZZ")
	print("CSUM = adj-transport | neutral-map |")
	print("       no-action | neutral-map-auto")
	print("IDENT = iid | luid | virt-v4 | virt-uni-v6 |")
	print("        virt-multi-v6 | monlocal-addr | use-format")
	print("HOOK = input | output")

	sys.exit(2)

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

	db = args[0]
	cmd = args[1]

	args = args[2:]

	if db == 'map':
		if not port_set:
			port = DEFAULT_MAP_PORT
		ila.ila_process_map(host, port, cmd, args)
	elif db == 'ident':
		if not port_set:
			port = DEFAULT_IDENT_PORT
		ila.ila_process_ident(host, port, cmd, args)
	elif db == 'loc':
		if not port_set:
			port = DEFAULT_LOC_PORT
		ila.ila_process_loc(host, port, cmd, args)
	else:
		usage_err("Unknown DB '%s'" % db)
		sys.exit(2)

except ila.IlaParseError as e:
	usage_err(str(e))
	sys.exit(2)
except ila.IlaConnectionError as e:
	print(str(e))
	sys.exit(2)
