# test_conf.py - test configuration
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

import os

QDIR= os.environ['QDIR']

BIN=QDIR + "/bin"
SBIN=QDIR + "/sbin"

IPCMD= SBIN + "/ip"
IFCONFIGCMD="ifconfig"
SYSCTLCMD="sysctl"
MODPROBECMD="modprobe"
KILLALLCMD="killall"
TCCMD="tc"

ILADIR= BIN
ILACCMD=ILADIR + "/ilac"
ILACTLDCMD=ILADIR + "/ilactld"
ILADCMD=ILADIR + "/ilad"
AMCCMD=ILADIR + "/amc"

UDPPINGSERVERCMD=BIN + "/udp_ping_server"
TCPPINGSERVERCMD=BIN + "/tcp_ping_server"

FASTSERVERCMD=SBIN + "/fast_server"
REDISDIR=QDIR + "/bin"
REDISBIN=REDISDIR + "/redis-server"
REDISCONF= QDIR + "/etc/redis_%s.conf"

UE_ROUTE_ADDR0="1111::8000:0:0:0"
UE_ROUTE_ADDR1="1111::8000:0:0:1"
ENB_ROUTE_ADDR0="1112:%s::8000:0:0:0"
ENB_ROUTE_ADDR1="1112:%s::8000:0:0:1"
HOST_ROUTE_ADDR0="1113:%s::8000:0:0:0"
HOST_ROUTE_ADDR1="1113:%s::8000:0:0:1"
GW_ROUTE_ADDR0="1114:%s::8000:0:0:0"
GW_ROUTE_ADDR1="1114:%s::8000:0:0:1"
ANCHOR_ROUTE_ADDR0="1115:%s::8000:0:0:0"
ANCHOR_ROUTE_ADDR1="1115:%s::8000:0:0:1"
LOCATOR="2017:%s"
LOCATOR_ROUTE="2017::/16"
SIR_PREFIX="3333:0:0:0"

