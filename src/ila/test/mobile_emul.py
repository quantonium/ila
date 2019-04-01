# mobile_emul.py - helper functions to create emulated mobile network
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
import test_conf as tc

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

def exec_user_in_netns(ns, cmd, username):
	libpath = "LD_LIBRARY_PATH="+os.environ["LD_LIBRARY_PATH"]
	print(libpath)
	cmd = [tc.IPCMD, "netns", "exec", ns, "sudo", "-u", username, libpath] + cmd
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

def ns_set_via_route_src(ns, dest, via, dev, src):
	exec_in_netns(ns, [tc.IPCMD, "route", "add", dest, "via", via,
			  "dev", dev, "src", src])

def ns_del_via_route(ns, dest, via, dev):
	exec_in_netns(ns, [tc.IPCMD, "route", "del", dest, "via", via,
			  "dev", dev])

def ns_set_blackhole_route(ns, dest):
	exec_in_netns(ns, [tc.IPCMD, "route", "add", "blackhole", dest])

def ns_set_ila_xlat(ns, loc_match, loc):
	exec_in_netns(ns, [tc.IPCMD, "ila", "add", "loc_match", loc_match,
                "loc", loc, "csum-mode", "neutral-map-auto", "ident-type",
		"luid"])

def make_ue(number, ran_num):
	print("Make UE ue_%u with address %s::%x" % (number, tc.SIR_PREFIX,
						   number))
	ifnam0 = "veth0_ue%u" % number
	ifnam1 = "veth1_ue%u" % number
	ue_ns = "ue_%u" % number
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(number)
	ue_addr = "%s::%s" % (tc.SIR_PREFIX, suffix)

	make_netns(ue_ns)

	veth_add(ifnam0, ifnam1)

	link_set(ifnam0, ue_ns)

	ns_add_addr(ue_ns, ifnam0, tc.UE_ROUTE_ADDR0, 64)

	ns_add_addr(ue_ns, ifnam0, ue_addr, 128)

	exec_in_netns(ran_ns, [tc.ILACCMD, "ident", "make", str(number), ue_addr])

	start_ping_servers(ue_ns)

def set_one_ue_route(number):
	ifnam0 = "veth0_ue%u" % number
	ue_ns = "ue_%u" % number
	suffix = make_addr_suffix(number)
	ue_addr = "%s::%s" % (tc.SIR_PREFIX, suffix)

	ns_set_via_route_src(ue_ns, "default", tc.UE_ROUTE_ADDR1, ifnam0, ue_addr)

def start_gate_ilad(number):
	print("Start gate ilad %u" % number)

	ifnam0 = "veth0_gate%u" % number
	gw_ns = "gw_%u" % number
	suffix = make_addr_suffix(number)
	addr1 = tc.GW_ROUTE_ADDR1 % suffix

	ns_set_via_route(gw_ns, tc.LOCATOR_ROUTE, addr1, ifnam0)

def make_gateway(number, ran_num):
	print("Make gateway %u" % number)

	ifnam0 = "veth0_gate%u" % number
	ifnam1 = "veth1_gate%u" % number
	gw_ns = "gw_%u" % number
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(number)
	addr0 = tc.GW_ROUTE_ADDR0 % suffix
	addr1 = tc.GW_ROUTE_ADDR1 % suffix

	make_netns(gw_ns)

	ns_enable_forwarding(gw_ns)

	veth_add(ifnam0, ifnam1)

	link_set(ifnam0, gw_ns)
	link_set(ifnam1, ran_ns)

	ns_add_addr(gw_ns, ifnam0, addr0, 64)
	ns_add_addr(ran_ns, ifnam1, addr1, 64)
	ns_set_via_route(gw_ns, tc.SIR_PREFIX + "::/64", addr1, ifnam0)

	start_ping_servers(gw_ns)

def make_host(number, gw_num, ran_num):
	print("Make host %u" % number)

	host_ns = "host_%u" % number
	gw_ns = "gw_%u" % gw_num
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(number)
	addr0 = tc.HOST_ROUTE_ADDR0 % suffix
	addr1 = tc.HOST_ROUTE_ADDR1 % suffix
	gsuffix = make_addr_suffix(gw_num)
	gaddr0 = tc.GW_ROUTE_ADDR0 % gsuffix
	gifnam1 = "veth1_gate%u" % gw_num

	ifnam0 = "veth0_host%u" % number
	ifnam1 = "veth1_host%u" % number

	make_netns(host_ns)

	veth_add(ifnam0, ifnam1)

	link_set(ifnam0, host_ns)
	link_set(ifnam1, gw_ns)

	ns_add_addr(host_ns, ifnam0, addr0, 64)
	ns_add_addr(gw_ns, ifnam1, addr1, 64)

	ns_set_via_route(host_ns, "default", addr1, ifnam0)

	ns_set_via_route(ran_ns, addr0 + "/64", gaddr0, gifnam1)

	start_ping_servers(host_ns)

def start_enb_ilad(number, type, anchor_num, loglevel):
	print("Start enb ilad %u" % number)

	ifnam0 = "veth0_enb%u" % number
	enb_ns = "enb_%u" % number
	suffix = make_addr_suffix(number)
	addr1 = tc.ENB_ROUTE_ADDR1 % suffix

	if (type == "router"):
		exec_in_netns(enb_ns, [tc.ILADCMD, "-d", "-r",
			       "-D", "host=%s" % addr1,
			       "-R", "via=%s,dev=%s" % (addr1, ifnam0)])

	elif (type == "forwarder"):
		suffix = make_addr_suffix(anchor_num)
		addr2 = tc.ANCHOR_ROUTE_ADDR0 % suffix
		exec_in_netns(enb_ns, [tc.ILADCMD, "-d", "-f",
			       "-L", "ilad_enb_%u" % number,
			       "-l", loglevel,
			       "-R", "via=%s,dev=%s" % (addr1, ifnam0),
			       "-A", "router=%s" % addr2])
		print("-d -f -R via=%s,dev=%s -A router=%s" %
                    (addr1, ifnam0, addr2))

def start_udp_ping_server(ns):
	exec_in_netns(ns, [tc.UDPPINGSERVERCMD, "-d"])

def start_tcp_ping_server(ns):
	exec_in_netns(ns, [tc.TCPPINGSERVERCMD, "-d"])

def start_ping_servers(ns):
	start_udp_ping_server(ns)
	start_tcp_ping_server(ns)

def start_anchor_ilad(number, loglevel):
	print("Start anchor ilad %u" % number)

	ifnam0 = "veth0_anchor%u" % number
	anchor_ns = "anchor_%u" % number
	suffix = make_addr_suffix(number)
	addr1 = tc.ANCHOR_ROUTE_ADDR1 % suffix

	exec_in_netns(anchor_ns, [tc.ILADCMD, "-d",
			       "-L", "ilad_anchor_%u" % number,
			       "-l", loglevel,
			       "-D", "host=%s" % addr1,
			       "-R", "via=%s,dev=%s" % (addr1, ifnam0)])

	exec_in_netns(anchor_ns, [tc.TCCMD, "qdisc", "add", "dev", ifnam0,
			       "root", "netem", "delay", "10.0ms"])

def make_enb(number, ran_num):
	print("Make ENB %u" % number)

	ifnam0 = "veth0_enb%u" % number
	ifnam1 = "veth1_enb%u" % number
	enb_ns = "enb_%u" % number
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(number)
	addr0 = tc.ENB_ROUTE_ADDR0 % suffix
	addr1 = tc.ENB_ROUTE_ADDR1 % suffix
	locator = tc.LOCATOR % make_sub_addr(number, 3)

	make_netns(enb_ns)

	ns_enable_forwarding(enb_ns)

	veth_add(ifnam0, ifnam1)

	link_set(ifnam0, enb_ns)
	link_set(ifnam1, ran_ns)

	ns_add_addr(enb_ns, ifnam0, addr0, 64)
	ns_add_addr(ran_ns, ifnam1, addr1, 64)

	ns_set_via_route(enb_ns, "default", addr1, ifnam0)

	ns_set_via_route(ran_ns, locator + "::/64", addr0, ifnam1)

	ns_set_ila_xlat(enb_ns, locator, tc.SIR_PREFIX)

	exec_in_netns(ran_ns, [tc.ILACCMD, "loc", "make", str(number), locator])

	start_ping_servers(enb_ns)

def make_anchor(number, ran_num):
	print("Make ANCHOR %u" % number)

	ifnam0 = "veth0_anchor%u" % number
	ifnam1 = "veth1_anchor%u" % number
	anchor_ns = "anchor_%u" % number
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(number)
	addr0 = tc.ANCHOR_ROUTE_ADDR0 % suffix
	addr1 = tc.ANCHOR_ROUTE_ADDR1 % suffix

	make_netns(anchor_ns)

	ns_enable_forwarding(anchor_ns)

	veth_add(ifnam0, ifnam1)

	link_set(ifnam0, anchor_ns)
	link_set(ifnam1, ran_ns)

	ns_add_addr(anchor_ns, ifnam0, addr0, 64)
	ns_add_addr(ran_ns, ifnam1, addr1, 64)

	ns_set_via_route(ran_ns, tc.SIR_PREFIX + "::/64", addr0, ifnam1)

	ns_set_via_route(anchor_ns, "default", addr1, ifnam0)

def do_unattach_ue(ue_num, ran_num):
	ifnam1 = "veth1_ue%u" % ue_num
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(ue_num)

	# First find out if UE is attached and to which locator

	proc = subprocess.Popen([tc.IPCMD, "netns", "exec", ran_ns, tc.ILACCMD,
				 "ident", "get", str(ue_num)],
				stdout=subprocess.PIPE)

	line = proc.stdout.readline().rstrip().decode("utf-8").split()

	if (len(line) != 3):
		return

	if (line[0] != str(ue_num)):
		return

	if (line[2] == "unattached"):
		return

	enb_num = line[2]
	enb_ns = "enb_%u" % int(enb_num)

	ns_link_unset(enb_ns, ifnam1)

	exec_in_netns(ran_ns, [tc.ILACCMD, "ident", "unattach",
			       str(ue_num)])

def unattach_ue(ue_num, ran_num):
	print("Unattach UE %d" % ue_num)

	do_unattach_ue(ue_num, ran_num)

def attach_ue_to_enb(ue_num, enb_num, ran_num):
	print("Attach UE %d to enb %d" % (ue_num, enb_num))

	# Make sure were unattached first
	do_unattach_ue(ue_num, ran_num)

	ifnam0 = "veth0_ue%u" % ue_num
	ifnam1 = "veth1_ue%u" % ue_num
	ue_ns = "ue_%u" % ue_num
	enb_ns = "enb_%u" % enb_num
	ran_ns = "ran_%u" % ran_num
	suffix = make_addr_suffix(ue_num)
	ue_addr = "%s::%s" % (tc.SIR_PREFIX, suffix)

	link_set(ifnam1, enb_ns)

	ns_add_addr(enb_ns, ifnam1, tc.UE_ROUTE_ADDR1, 64)
	ns_set_via_route(enb_ns, tc.SIR_PREFIX + "::" + suffix,
		         tc.UE_ROUTE_ADDR0, ifnam1)

	exec_in_netns(ran_ns, [tc.ILACCMD, "ident", "attach",
			       str(ue_num), str(enb_num)])

def make_ran(number):
	print("Make RAN %u" % number)

	ran_ns = "ran_%u" % number

	make_netns(ran_ns)

	ns_enable_forwarding(ran_ns)

	ns_start_redis(ran_ns, "6379")
	ns_start_redis(ran_ns, "6380")
	ns_start_redis(ran_ns, "6381")

	exec_in_netns(ran_ns, [tc.ILACCMD, "ident", "flush"])
	exec_in_netns(ran_ns, [tc.ILACCMD, "loc", "flush"])
	exec_in_netns(ran_ns, [tc.ILACCMD, "map", "flush"])

	exec_in_netns(ran_ns, [tc.ILACTLDCMD, "-d"])

	start_ping_servers(ran_ns)
