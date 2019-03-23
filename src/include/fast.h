/*
 * fast.h - definitions for Firewall and Service Tickets agent
 *
 * Copyright (c) 2019, Quantonium Inc. All rights reserved.
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

#ifndef __FAST_H__
#define __FAST_H__

#include <stdbool.h>

struct fast_ila {
	__u8 opt_type;
	__u8 opt_len;
	__u8 fast_type;
	__u8 rsvd;
	__u16 rsvd2;
	__u32 expiration;
	__u32 service_profile;
	__u64 locator;
} __attribute((packed));

void *fast_init(void);
size_t fast_query_verbose(struct in6_addr *in6, void *ctx, void *buf,
			  size_t len, struct in6_addr *http_addr,
			  int http_port, bool verbose);
void fast_done(void *ctx);

static inline size_t fast_query(struct in6_addr *in6, void *ctx, void *buf,
				size_t len, struct in6_addr *http_addr,
				int http_port)
{
	return fast_query_verbose(in6, ctx, buf, len, http_addr, http_port,
				  false);
}

#endif /* __FAST_H__ */
