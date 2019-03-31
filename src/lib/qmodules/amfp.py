# amfp.py - library to communicate with AMS router using AMFP
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

import bitstruct, struct, socket, qutils
from collections import namedtuple

class IlaParseError(Exception):
	pass

def amfp_send_request(host, port, data):
	with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
		s.connect((host, port))
		s.sendall(data)
		data = s.recv(1024)

		Reply = namedtuple('Reply', 'type, length, rsvd, sub_type, ' \
		     'loc_type , id_type')
		reply_tuple = Reply._make(bitstruct.unpack("u4u12u4u4u4u4",
		    data))

		if (reply_tuple.type != 2):
			print("Unknown reply type", reply_tuple)
			return

		if (reply_tuple.sub_type != 1):
			print("Unexpected sub_type", reply_tuple.sub_type)

		if (reply_tuple.id_type != 1 |
		    reply_tuple.loc_type != 1):
			print("Unknown idloc type", reply_tuple.id_type,
			      "or", reply_tuple.loc_type)
			return

		num_pairs = (reply_tuple.length - 4) // 32
		offset = 4

		for i in range(num_pairs):
			try:
				print(socket.inet_ntop(socket.AF_INET6,
					data[offset:offset + 16]), "->",
				      socket.inet_ntop(socket.AF_INET6,
					data[offset + 16:offset + 32]))

				offset = offset + 32

			except ValueError as e:
				print(str(e))

# Process a map manipulation. Args is normal argv[] list
def amfp_process_get_map_entry(host, port, cmd, args):
	if cmd == "get":
		if (len(args) < 1):
			IlaParseError("Need more args")
			return

		data = bitstruct.pack('u4u12u12u4', 1, 4 + len(args) * 16,
			0, 1)
		for i in range(len(args)):
			try:
				data = data + qutils.parse_address(args[i])
			except qutils.Qutils.Error as e:
				raise IlaParseError("Parse address: " + str(e))
				return

		try:
			amfp_send_request(host, port, data)
		except redis.exceptions.ConnectionError as e:
			raise IlaConnectionError("Error connecting to DB: %s" % str(e))
			return

