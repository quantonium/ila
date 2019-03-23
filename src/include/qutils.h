/*
 * qutils.h - Quantonium utilities library
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

#ifndef __QUTILS_H__
#define __QUTILS_H__

#include <netinet/in.h>
#include <linux/ipv6.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

int daemonize(FILE *logfile);
int get_address_from_name(char *name, int socktype, struct in6_addr *in6);

static inline void timespec_diff(struct timespec *start, struct timespec *stop,
				 struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec +
		    1000000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
	}
}

#define ipv6_optlen(p)	(((p)->hdrlen+1) << 3)

int ipv6_opt_validate_tlvs(struct ipv6_opt_hdr *opt);
int ipv6_opt_validate_single_tlv(unsigned char *tlv, size_t len);
int ipv6_opt_tlv_find(struct ipv6_opt_hdr *opt, unsigned char *targ_tlv,
		      unsigned int *start, unsigned int *end);
struct ipv6_opt_hdr *ipv6_opt_tlv_insert(struct ipv6_opt_hdr *opt,
					 unsigned char *tlv);
struct ipv6_opt_hdr *ipv6_opt_tlv_delete(struct ipv6_opt_hdr *opt,
					 unsigned char *tlv);
void show_ipv6_tlvs(void);
void set_ipv6_tlvs(void);

#endif
