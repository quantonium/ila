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

	ns_set_via_route(ue_ns, "default", tc.UE_ROUTE_ADDR1, ifnam0)

	exec_in_netns(ran_ns, [tc.ILACCMD, "ident", "make", str(number), ue_addr])

def start_gate_ilad(number):
	print("Start gate ilad %u" % number)

	ifnam0 = "veth0_gate%u" % number
	gw_ns = "gw_%u" % number
	suffix = make_addr_suffix(number)
	addr1 = tc.GW_ROUTE_ADDR1 % suffix

	exec_in_netns(gw_ns, [tc.ILADCMD, "-d",
			       "-D", "host=%s" % addr1,
			       "-R", "via=%s,dev=%s" % (addr1, ifnam0)])

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
	ns_set_blackhole_route(gw_ns, tc.SIR_PREFIX + "::/64")
	ns_add_addr(ran_ns, ifnam1, addr1, 64)

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

def start_enb_ilad(number):
	print("Start enb ilad %u" % number)

	ifnam0 = "veth0_enb%u" % number
	enb_ns = "enb_%u" % number
	suffix = make_addr_suffix(number)
	addr1 = tc.ENB_ROUTE_ADDR1 % suffix

	exec_in_netns(enb_ns, [tc.ILADCMD, "-d",
			       "-D", "host=%s" % addr1,
			       "-R", "via=%s,dev=%s" % (addr1, ifnam0)])

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

	ns_set_blackhole_route(enb_ns, tc.SIR_PREFIX + "::/64")

	exec_in_netns(ran_ns, [tc.ILACCMD, "loc", "make", str(number), locator])

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
