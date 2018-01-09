/*
 * ila.h - common userspace definitions for ILA.
 *
 * Copyright (c) 2018, Quantonium Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Quantonium nor the names of its contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL QUANTONIUM BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ILA_H__
#define __ILA_H__

#include <arpa/inet.h>
#include <linux/types.h>

typedef __u64 Locator;
typedef __u64 Identifier;

struct IlaMapKey {
	struct in6_addr addr;
};

struct IlaMapValue {
	Locator loc;
	int ifindex;
	__u8 csum_mode;
	__u8 ident_type;
	__u8 hook_type;
	__u8 rsvd;
};

struct IlaIdentKey {
	__u64 num;
};

struct IlaIdentValue {
	struct in6_addr addr;
	__u64 loc_num;
};

struct IlaLocKey {
	__u64 num;
};

struct IlaLocValue {
	Locator locator;
};

/* ila_route_ops define an interface to set ILA routes (e.g.
 * setting kernel LWT routes).
 *
 * Functions are:
 *
 *   init	Inititialize ILA routing.
 *
 *   parse_args
 *
 *		Parse arguments specific to the backend dbif database
 *		implementation. This are assumed to be a subopts string.
 *		A logfile argument is used to log messages about
 *		bad arguments.
 *
 *   start	Start ILA routing system.
 *
 *   done	Done with routing system, any resources can be released.
 *
 *   set_route	Set an ILA route. Input is an ILA map key and value.
 *
 *   del_route	Delete an ILA route. Input is a ILA map key.
 */
struct ila_route_ops {
	int (*init)(void **context, FILE *logf);
	int (*parse_args)(void *context, char *subopts);
	int (*start)(void *context);
	void (*done)(void *context);
	int (*set_route)(void *context, struct IlaMapKey *key,
			 struct IlaMapValue *value);
	int (*del_route)(void *context, struct IlaMapKey *key);
};

struct ila_route_ops *ila_get_kernel(void);

#endif
