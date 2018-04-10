# ilactl.py - helper functions to start/stop ILA nodes
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

# Start the ILA-M. This starts the ident, loc, and mapping databases
# locally and then runs the ilactld daemon to provide service to ILA-Rs.

ILA_DEFAULT_MAP_PORT = 6379
ILA_DEFAULT_IDENT_PORT = 6380
ILA_DEFAULT_LOC_PORT = 6381
ILA_DEFAULT_DB_HOST = "::1"

import sys, getopt, redis, struct, socket, subprocess, os, time, qutils
import common_conf as tc
import utility as ut

def usage_err(strerr):
	if (strerr != ""):
		print(strerr)
		print()

	print("Usage:")
	print("   ilactl ILA-M start")
	print("   ilactl ILA-M stop")
	print("")
	print("   ilactl ILA-R start { --map_db_host=HOST }")
	print("        { --map_db_port=PORT } VIA DEVICE")
	print("   ilactl ILA-R stop")
	print("")
	print("   ilactl ILA-N start LOCATOR LOC_MATCH")
	print("   ilactl ILA-N stop")
	print("")
	print("HOST = host or address")
	print("PORT = 0..2^16")
	print("VIA = IPv6 address")
	print("DEVICE = Network interface")

	sys.exit(2)

def modprobe(module):
	subprocess.run([tc.MODPROBECMD, module])

def rmmod(module):
	subprocess.run([tc.RMMODCMD, module])

def start_ila_M():
	start_redis("6379")
	start_redis("6380")
	start_redis("6381")

	time.sleep(3)

	# Flush tables

	exec([tc.ILACCMD, "ident", "flush"])
	exec([tc.ILACCMD, "loc", "flush"])
	exec([tc.ILACCMD, "map", "flush"])

	# Start ilactld

	exec([tc.ILACTLDCMD, "-d"])

def stop_ila_M():
	ut.killall("redis-server");
	ut.killall("ilactld");

def process_ila_M(cmd, args):
	if cmd == "start":
		stop_ila_M()
		start_ila_M()
	elif cmd == "stop":
		stop_ila_M()
	else:
		usage_err("Unknown ILA-M command '%s'" % cmd)

def start_ila_R(args):
	map_db_host = ILA_DEFAULT_DB_HOST
	map_db_port = ILA_DEFAULT_MAP_PORT

	try:
		opts, args = getopt.getopt(args, "",
			[ "map_db_host=", "map_db_port=" ])
	except getopt.GetoptError as err:
		usage_err("Unable to parse ILA-R options: %s" % str(err))

	for o,a in opts:
		if o == "--map_db_host":
			map_db_host = a
		elif o == "--map_db_port":
			map_db_port = a

	print("Host %s port %s" % (map_db_host, map_db_port))

	if (len(args) < 2):
		usage_err("Too few arguments for ILA-R start")
		sys.exit(2)

	# Try to parse address before giving it daemon
	try:
		qutils.parse_address(args[0])
	except qutils.QutilsError as e:
		usage_err("Unable to parse ILA-R address %s: %s" %
			  (args[0], str(e)))

	via_addr = args[0]
	device = args[1]

	modprobe("ila")

	exec([tc.ILADCMD, "-d", "-D", "host=::1",
	     "-R", "via=%s,dev=%s" % (via_addr, device)])

def stop_ila_R():
	ut.killall("ilad")
	rmmod("ila")

def process_ila_R(cmd, args):
	if cmd == "start":
		stop_ila_R()
		start_ila_R(args)
	elif cmd == "stop":
		stop_ila_R()
	else:
		usage_err("Unknown ILA-M command '%s'" % cmd)

def start_ila_N(args):
	if (len(args) < 2):
		usage_err("Too few arguments for ILA-N start")
		sys.exit(2)

	loc = args[0]
	loc_match = args[1]

	# Try to parse locator before giving it daemon
	try:
		qutils.addr64_a2n(loc)
	except qutils.QutilsError as e:
		usage_err("Unable to parse ILA-N locator %s: %s" %
			  (loc, str(e)))

	# Try to parse loc_match before giving it daemon
	try:
		qutils.addr64_a2n(loc_match)
	except qutils.QutilsError as e:
		usage_err("Unable to parse ILA-N loc_match %s: %s" %
			  (loc_match, str(e)))

	modprobe("ila")

	exec([tc.IPCMD, "ila", "add", "loc_match", loc_match, "loc", loc,
	      "csum-mode", "neutral-map-auto", "ident-type", "luid"])

def stop_ila_N():
	rmmod("ila")

def process_ila_N(cmd, args):
	if cmd == "start":
		stop_ila_N()
		start_ila_N(args)
	elif cmd == "stop":
		stop_ila_N()
	else:
		usage_err("Unknown ILA-N command '%s'" % cmd)

def start_redis(config):
	subprocess.run([tc.REDISBIN, tc.REDISCONF % config])

def exec(cmd):
	subprocess.run(cmd)


args = sys.argv

# Skip over arg0
args = args[1:]


if (len(args) < 2):
	usage_err("Need at least two arguments")
	sys.exit(2)

type = args[0]
cmd = args[1]

args = args[2:]

if type == "ILA-M":
	process_ila_M(cmd, args)
elif type == "ILA-R":
	process_ila_R(cmd, args)
elif type == "ILA-N":
	process_ila_N(cmd, args)
else:
	usage_err("Unknown ILA node type '%s'" % type)
	sys.exit(2)

sys.exit(2)

stop_ila_m()
stop_ila_r()
start_ila_m()
start_ila_r()
