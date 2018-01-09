# ila.py - library to manipulate ILA databases
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

# Library functions to manipulate ILA database from the command line.
# This program interacts with three database. The 'map', 'ident' and
# 'loc'.
#
# For the 'map' the operations are 'list', 'flush, 'add', 'del'
#

class IlaParseError(Exception):
	pass

class IlaConnectionError(Exception):
	pass

ILA_DEFAULT_MAP_PORT = 6379
ILA_DEFAULT_IDENT_PORT = 6380
ILA_DEFAULT_LOC_PORT = 6381

import sys, getopt, redis, struct, socket, qutils
from collections import namedtuple

# ILA checksum types. Must matchs uapi/linux/ila.h
ILA_CSUM_ADJUST_TRANSPORT = 0
ILA_CSUM_NEUTRAL_MAP = 1
ILA_CSUM_NO_ACTION = 2
ILA_CSUM_NEUTRAL_MAP_AUTO = 3

# ILA csum mode to string name
def ila_csum_mode2name(csum_mode):
	if (csum_mode == ILA_CSUM_ADJUST_TRANSPORT):
		return "adj-transport"
	elif (csum_mode == ILA_CSUM_NEUTRAL_MAP):
		return "neutral-map"
	elif (csum_mode == ILA_CSUM_NO_ACTION):
		return "no-action"
	elif (csum_mode == ILA_CSUM_NEUTRAL_MAP_AUTO):
		return "neutral-map-auto"
	else:
		return "unknown"

# ILA csum string name to mode
def ila_csum_name2mode(str):
	if (str == "adj-transport"):
		return ILA_CSUM_ADJUST_TRANSPORT
	elif (str == "neutral-map"):
		return ILA_CSUM_NEUTRAL_MAP
	elif (str == "no-action"):
		return ILA_CSUM_NO_ACTION
	elif (str == "neutral-map-auto"):
		return ILA_CSUM_NEUTRAL_MAP_AUTO
	else:
		return -1

# ILA identifier types. Must matchs uapi/linux/ila.h
ILA_ATYPE_IID = 0
ILA_ATYPE_LUID = 1
ILA_ATYPE_VIRT_V4 = 2
ILA_ATYPE_VIRT_UNI_V6 = 3
ILA_ATYPE_VIRT_MULTI_V6 = 4
ILA_ATYPE_NONLOCAL_ADDR = 5

ILA_ATYPE_USE_FORMAT = 32

# ILA identifier type to string name
def ila_ident_type2name(ident_type):
	if (ident_type == ILA_ATYPE_IID):
		return "iid"
	elif (ident_type == ILA_ATYPE_LUID):
		return "luid"
	elif (ident_type == ILA_ATYPE_VIRT_V4):
		return "virt-v4"
	elif (ident_type == ILA_ATYPE_VIRT_UNI_V6):
		return "virt-uni-v6"
	elif (ident_type == ILA_ATYPE_VIRT_MULTI_V6):
		return "virt-multi-v6"
	elif (ident_type == ILA_ATYPE_NONLOCAL_ADDR):
		return "nonlocal-addr"
	elif (ident_type == ILA_ATYPE_USE_FORMAT):
		return "use-format"
	else:
		return "unknown"

# ILA identifier string name to type
def ila_ident_name2type(str):
	if (str == "iid"):
		return ILA_ATYPE_IID
	elif (str == "luid"):
		return ILA_ATYPE_LUID
	elif (str == "virt-v4"):
		return ILA_ATYPE_VIRT_V4
	elif (str == "virt-uni-v6"):
		return ILA_ATYPE_VIRT_UNI_V6
	elif (str == "virt-multi-v6"):
		return ILA_ATYPE_VIRT_MULTI_V6
	elif (str == "nonlocal-addr"):
		return ILA_ATYPE_NONLOCAL_ADDR
	elif (str == "use-format"):
		return ILA_ATYPE_USE_FORMAT
	else:
		return -1

# ILA hook types. Must matchs uapi/linux/ila.h
ILA_HOOK_ROUTE_OUTPUT = 0
ILA_HOOK_ROUTE_INPUT = 1

# ILA hook type to string name
def ila_hook_type2name(hook_type):
	if (hook_type == ILA_HOOK_ROUTE_OUTPUT):
		return "output"
	elif (hook_type == ILA_HOOK_ROUTE_INPUT):
		return "input"
	else:
		return "unknown"

# ILA hook string name to type
def ila_hook_name2type(str):
	if (str == "output"):
		return ILA_HOOK_ROUTE_OUTPUT
	elif (str == "input"):
		return ILA_HOOK_ROUTE_INPUT
	else:
		return -1

# Mapping database (currently Redis specific)
class IlaMapDb:
	def __init__(self, host, port):
		self.r = redis.Redis(host = host, port = port, db = 0)

	def set(self, key, data):
		self.r.set(key, data)

	def get(self, key):
		return self.r.get(key)

	def delete(self, key):
		self.r.delete(key)

	def iter_all(self):
		return self.r.scan_iter("*")

# Display map entry given database and key
def ila_process_get_map(Map, map_db, key):
	try:
		data = map_db.get(key)
	except redis.exceptions.ConnectionError:
		return

	if data is None:
		print("Not found")
		return

	map_tuple = Map._make(struct.unpack("QiBBBB", data))

	try:
		loc = qutils.addr64_n2a(map_tuple.locator)
	except qutils.QutilsError as e:
		raise IlaParseError("Format locator: " + str(e))
		return

	print("%s %s %s %s %s %s" % (
	    socket.inet_ntop(socket.AF_INET6, key), loc,
	    qutils.llindex2name(map_tuple.ifindex),
	    ila_csum_mode2name(map_tuple.csum_mode),
	    ila_ident_type2name(map_tuple.ident_type),
	    ila_hook_type2name(map_tuple.hook_type)))

# Process a map manipulation. Args is normal argv[] list
def ila_process_map(host, port, cmd, args):
	try:
		map_db = IlaMapDb(host, port)
	except redis.exceptions.ConnectionError as e:
		raise IlaConnectionError("Error connecting to DB: %s" % str(e))
		return

	Map = namedtuple('Map', 'locator, ifindex, csum_mode, \
	    ident_type, hook_type, byte4')

	if cmd == 'list':
		try:
			for key in map_db.iter_all():
				ila_process_get_map(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "get":
		if (len(args) < 1):
			IlaParseError("Need more args")
			return

		try:
			key = qutils.parse_address(args[0])
		except qutils.QutilsError as e:
			raise IlaParseError("Parse address: " + str(e))
			return

		try:
			ila_process_get_map(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == 'add':
		# Default values for csum, identifier type, and hook type
		ident_type = ILA_ATYPE_LUID
		csum_mode = ILA_CSUM_NEUTRAL_MAP_AUTO
		hook_type = ILA_HOOK_ROUTE_OUTPUT

		try:
			opts, args = getopt.getopt(args, "",
			    [ "ident-type=", "csum-mode=", "hook-type=" ])
		except getopt.GetoptError as err:
			raise IlaParseError("Parse opts: " + str(err))
			return

		for o, a in opts:
			if o == "--ident-type":
				ident_type = ila_ident_name2type(a)
				if (ident_type < 0):
					IlaParseError("Bad identifier type %s" % a)
					return
			elif o == "--csum-mode":
				csum_mode = ila_csum_name2mode(a)
				if (csum_mode < 0):
					raise IlaParseError("Bad csum mode %s" % a)
					return
			elif o == "hook-type":
				hook_type = ila_hook_name2type(a)
				if (hook_type < 0):
					raise IlaParseError("Bad hook type %s" % a)
					return

		if (len(args) < 2):
			raise IlaParseError("Need more args")
			return

		try:
			# Get identifier
			key = qutils.parse_address(args[0])
		except qutils.QutilsError as e:
			raise IlaParseError("Parse address: " + str(e))
			return

		try:
			# Get locator
			anum = qutils.addr64_a2n(args[1])
		except qutils.QutilsError as e:
			raise IlaParseError("Parse locator: " + str(e))
			return

		loc = struct.unpack("Q", anum)

		try:
			map_db.set(key, struct.pack("QiBBBB", loc[0], 0, csum_mode,
			    ident_type, hook_type, 0))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "flush":
		try:
			for key in map_db.iter_all():
				map_db.delete(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "del":
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		try:
			key = qutils.parse_address(args[0])
		except qutils.Qutils.Error as e:
			raise IlaParseError("Parse address: " + str(e))
			return

		try:
			map_db.delete(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	else:
		raise IlaParseError("Unknown command '%s'" % cmd)
		return

# Display identifier entry given database and key
def ila_process_get_ident(Map, map_db, key):
	try:
		data = map_db.get(key)
	except redis.exceptions.ConnectionError as e:
		raise IlaConnectionError("Error connecting to DB: %s" % str(e))
		return

	if data is None:
		print("Not found")
		return

	map_tuple = Map._make(struct.unpack("QQQ", data))

	if (map_tuple.loc_num == 0):
		loc_str = "unattached"
	else:
		loc_str = str(map_tuple.loc_num)

	print("%d %s %s" % (
	    struct.unpack("Q", key)[0],
	    qutils.quads2ip(map_tuple.addr1, map_tuple.addr2),
	    loc_str))

# Process an identifier manipulation. Args is normal argv[] list
def ila_process_ident(host, port, cmd, args):
	try:
		map_db = IlaMapDb(host, port)
	except redis.exceptions.ConnectionError as e:
		raise IlaConnectionError("Error connecting to DB: %s" % str(e))
		return

	Map = namedtuple('Ident', 'addr1, addr2, loc_num')

	if cmd == 'list':
		try:
			for key in map_db.iter_all():
				ila_process_get_ident(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == 'get':
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		try:
			key = struct.pack("Q", int(args[0]))
			ila_process_get_ident(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
		except ValueError:
			raise IlaParseError("Value error in argument")
			return

	elif cmd == "make":
		if (len(args) < 2):
			raise IlaParseError("Need more args")
			return

		try:
			key = struct.pack("Q", int(args[0]))
			addr = qutils.parse_address(args[1])
		except qutils.Qutils.Error as e:
			raise IlaParseError("Parse address: " + str(e))
			return
		except ValueError:
			raise IlaParseError("Value error in argument")
			return

		data = struct.unpack("QQ", addr)
		try:
			map_db.set(key, struct.pack("QQQ", data[0], data[1], 0))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "destroy":
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		try:
			map_db.delete(struct.pack("Q", int(args[0])))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
		except ValueError:
			raise IlaParseError("Value error in argument")
			return

	elif cmd == "attach":
		if (len(args) < 2):
			raise IlaParseError("Need more args")
			return

		key = struct.pack("Q", int(args[0]))
		try:
			data = map_db.get(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
		map_tuple = Map._make(struct.unpack("QQQ", data))

		try:
			map_db.set(key, struct.pack("QQQ", map_tuple.addr1,
			    map_tuple.addr2, int(args[1])))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return


	elif cmd == "unattach":
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		key = struct.pack("Q", int(args[0]))
		try:
			data = map_db.get(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
		map_tuple = Map._make(struct.unpack("QQQ", data))

		try:
			map_db.set(key, struct.pack("QQQ", map_tuple.addr1,
			    map_tuple.addr2, 0))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "flush":
		try:
			for key in map_db.iter_all():
				map_db.delete(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
	else:
		raise IlaParseError("Unknown command '%s'" % cmd)
		return

# Display locator entry given database and key
def ila_process_get_loc(Map, map_db, key):
	try:
		data = map_db.get(key)
	except redis.exceptions.ConnectionError as e:
		return

	if data is None:
		print("Not found")
		return

	map_tuple = Map._make(struct.unpack("Q", data))

	try:
		loc = qutils.addr64_n2a(map_tuple.locator)
	except qutils.Qutils.Error as e:
		raise IlaParseError("Display locator: " + str(e))
		return

	print("%d %s" % (struct.unpack("Q", key)[0], loc))

	return

# Process a locator manipulation. Args is normal argv[] list
def ila_process_loc(host, port, cmd, args):
	map_db = IlaMapDb(host, port)
	Map = namedtuple('Loc', 'locator')

	if cmd == 'list':
		try:
			for key in map_db.iter_all():
				ila_process_get_loc(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "make":
		if (len(args) < 2):
			raise IlaParseError("Need more args")
			return

		try:
			key = struct.pack("Q", int(args[0]))
			loc = qutils.addr64_a2n(args[1])
		except qutils.QutilsError as e:
			raise IlaParseError("Parse address: " + str(e))
			return
		except ValueError:
			raise IlaParseError("Value error in argument")
			return

		data = struct.unpack("Q", loc)
		try:
			map_db.set(key, struct.pack("Q", data[0]))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error set key: %s" % str(e))
			return

	elif cmd == 'get':
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		try:
			key = struct.pack("Q", int(args[0]))
			ila_process_get_loc(Map, map_db, key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return
		except ValueError:
			raise IlaParseError("Value error in argument")
			return


	elif cmd == "destroy":
		if (len(args) < 1):
			raise IlaParseError("Need more args")
			return

		try:
			map_db.delete(struct.pack("Q", int(args[0])))
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	elif cmd == "flush":
		try:
			for key in map_db.iter_all():
				map_db.delete(key)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

	else:
		raise IlaParseError("Unknown command '%s'" % cmd)
		return
