# utility.py - helper functions for gw scripts
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

import sys, getopt, redis, struct, socket, subprocess, os, time
import common_conf as tc

from collections import namedtuple

def make_addr_suffix(number):
	s = ""
	for i in range(0, 4):
		v = (number >> ((3 - i) * 16)) & 0xffff
		if (v != 0 or i == 3):
			s += "%x" %  v
			if (i != 3):
				s += ":"

	if (s == ""):
		s = "0"

	return s

def make_sub_addr(number, blocks):
	s = ""
	for i in range(0, blocks):
		v = (number >> (((blocks - 1 - i) * 16))) & 0xffff
		s += "%x" %  v
		if (i != blocks - 1):
			s += ":"

	return s

def exec_in_netns(ns, cmd):
	cmd = [tc.IPCMD, "netns", "exec", ns] + cmd
	subprocess.run(cmd)

def exec_in_netns_null_stdout(ns, cmd):
	cmd = [tc.IPCMD, "netns", "exec", ns] + cmd
	subprocess.call(cmd, stdout=subprocess.DEVNULL)

def make_netns(ns):
	subprocess.run([tc.IPCMD, "netns", "add", ns])
	exec_in_netns(ns, [tc.IFCONFIGCMD, "lo", "up"])

def delete_netns(ns):
	subprocess.run([tc.IPCMD, "netns", "delete", ns])

def delete_all_netns():
	proc = subprocess.Popen([tc.IPCMD, "netns"], stdout=subprocess.PIPE)

	for line in proc.stdout:
		line = line.rstrip().decode("utf-8").split()
		delete_netns(line[0])

def killall(name):
	subprocess.run([tc.KILLALLCMD, name])

def modprobe(module):
	subprocess.run([tc.MODPROBECMD, module])

def veth_add(name1, name2):
	subprocess.run([tc.IPCMD, "link", "add", name1, "type", "veth",
			"peer", "name", name2])

def link_set(name, ns):
	subprocess.run([tc.IPCMD, "link", "set", "dev", name, "netns", ns])
	exec_in_netns(ns, [tc.IFCONFIGCMD, name, "up"])

def ns_link_unset(ns, name):
	exec_in_netns(ns, [tc.IPCMD, "link", "set", "dev", name, "netns", "1"])

def ns_add_addr(ns, ifnam, addr, plen):
	if (plen != 0):
		addr = "%s/%u" %(addr, plen)

	exec_in_netns(ns, [tc.IPCMD, "addr", "add", addr, "dev", ifnam])

def ns_del_addr(ns, ifnam, addr, plen):
	if (plen != 0):
		addr = "%s/%u" %(addr, plen)

	exec_in_netns(ns, [tc.IPCMD, "addr", "del", addr, "dev", ifnam])

def ns_set_sysctl(ns, sysctlname, value):
	exec_in_netns_null_stdout(ns, [tc.SYSCTLCMD, "%s=%s" %
				       (sysctlname, value)])

def ns_enable_forwarding(ns):
	ns_set_sysctl(ns, "net.ipv6.conf.all.forwarding", "1")

def ns_start_redis(ns, config):
	exec_in_netns(ns, [tc.REDISBIN, tc.REDISCONF % config])

def ns_set_via_route(ns, dest, via, dev):
	exec_in_netns(ns, [tc.IPCMD, "route", "add", dest, "via", via,
			  "dev", dev])

def ns_del_via_route(ns, dest, via, dev):
	exec_in_netns(ns, [tc.IPCMD, "route", "del", dest, "via", via,
			  "dev", dev])

def ns_set_blackhole_route(ns, dest):
	exec_in_netns(ns, [tc.IPCMD, "route", "add", "blackhole", dest])

def ns_set_ila_xlat(ns, loc_match, loc):
	exec_in_netns(ns, [tc.IPCMD, "ila", "add", "loc_match", loc_match,
                "loc", loc, "csum-mode", "neutral-map-auto", "ident-type",
		"luid"])

