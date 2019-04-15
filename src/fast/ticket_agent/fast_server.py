# fast_server.py - FAST server
#
# Copyright (c) 2019, Quantonium Inc. All rights reserved.
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

# Firewall and Service Ticket (FAST) server

from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import socketserver, syslog
import sys, getopt, redis, struct, socket, ila, qutils
from collections import namedtuple

DEFAULT_MAP_PORT = 6379

port = DEFAULT_MAP_PORT

try:
	map_db = ila.IlaMapDb("1115:1::8000:0:0:1", port)
except redis.exceptions.ConnectionError as e:
	raise ila.IlaConnectionError("Error connecting to DB: %s" % str(e))
	exit

Map = namedtuple('Map', 'locator, ifindex, csum_mode, \
		 ident_type, hook_type, byte4')

def get_mapping(address):
	try:
		key = qutils.parse_address(address)
	except qutils.QutilsError as e:
		raise ila.IlaParseError("Parse address: " + str(e))
		return

	try:
		data = map_db.get(key)
	except redis.exceptions.ConnectionError:
		syslog.syslog(syslog.LOG_DEBUG, "No map key in DB")
		return

	if data is None:
		syslog.syslog(syslog.LOG_DEBUG, "Not found")
		return

	map_tuple = Map._make(struct.unpack("QiBBBB", data))

	try:
		loc = qutils.addr64_n2a(map_tuple.locator)
	except qutils.QutilsError as e:
		raise ila.IlaParseError("Format locator: " + str(e))
		return

	syslog.syslog(syslog.LOG_DEBUG, "%s %s %s %s %s %s" % (
	    socket.inet_ntop(socket.AF_INET6, key), loc,
	    qutils.llindex2name(map_tuple.ifindex),
	    ila.ila_csum_mode2name(map_tuple.csum_mode),
	    ila.ila_ident_type2name(map_tuple.ident_type),
	    ila.ila_hook_type2name(map_tuple.hook_type)))

	return map_tuple

def make_FAST_eh(map_tuple):
	# Create a HBH FAST option with common 4 byte header,
	# 4 byte expiration time, 4 byte service parameters,
	# and 8 byte locator

	val = struct.pack("<BBBBBBIIQ", 0x3e,
			  (24 - 4), 1 << 4, 0, 0, 0, socket.ntohl(44),
			  socket.ntohl(127), map_tuple.locator)

	return val
	
class S(SimpleHTTPRequestHandler):
	def log_message(self, format, *args):
		syslog.syslog(syslog.LOG_DEBUG, format % args)
		return
		
	def do_GET(self):
		query = urlparse(self.path).query
		query_components = dict(qc.split("=") for qc in query.split("&"))
		try:
			map_tuple = get_mapping(query_components['query'])
		except ila.IlaParseError as e:
			syslog.syslog(syslog.LOG_ERR, str(e))
			sys.exit(2)
		except ila.IlaConnectionError as e:
			syslog.syslog(syslog.LOG_ERR, str(e))
			sys.exit(2)

		if (map_tuple != None):
			val = make_FAST_eh(map_tuple)
			self.send_response(200)
			self.send_header('Content-type', 'application/octet-stream')
			self.send_header('Content-length', len(val))
			self.end_headers()
			self.wfile.write(val)
		else:
			self.send_response(200)
			self.send_header('Content-type', 'application/octet-stream')
			self.send_header('Content-length', 0)
			self.end_headers()

class HTTPServerV6(HTTPServer):
	address_family = socket.AF_INET6

def run(port):
	server = HTTPServerV6(('::', port), S)
	server.serve_forever()

if __name__ == "__main__":
	from sys import argv

	try:
		mypopts, args = getopt.getopt(sys.argv[1:], "p:d")
	except getopt.GetoptError as e:
		usage_err(str(e))
		sys.exit(2)

	port = 6666
	do_daemonize = False

	for o, a in mypopts:
                if o == '-d':
                        do_daemonize = True
                elif o == '-p':
                        port = int(a)
                        port_set = True

	print("Starting FAST ticket agent")

	if (do_daemonize):
		qutils.daemonize()

	syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_DEBUG));
	syslog.openlog("fast_server",
	    syslog.LOG_PID|syslog.LOG_CONS|syslog.LOG_NDELAY,
	    syslog.LOG_DAEMON);

	syslog.syslog(syslog.LOG_INFO, "Starting FAST server")

	run(port)
