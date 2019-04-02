# run_ns.py - run a command in a network namespace
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

import sys, mobile_emul, getopt

def usage_err(errstr):
	if (errstr != ""):
		print(errstr)
		print("")

	print("Usage: run_ns NS CMD { ARGS ... }")

try:
	mypopts, args = getopt.getopt(sys.argv[1:], "u:")
except getopt.GetoptError as e:
        usage_err(str(e))
        sys.exit(2)

as_user = False

for o, a in mypopts:
	if o == '-u':
		as_user = True
		username = a

if (len(args) < 2):
	usage_err("Need at least two arguments")
	sys.exit(2)

ns = args[0]
args = args[1:]

# Ignore all excpetions here

try:
	if (as_user):
		mobile_emul.exec_user_in_netns(ns, args, username)
	else:
		mobile_emul.exec_in_netns(ns, args)
except:
	pass
