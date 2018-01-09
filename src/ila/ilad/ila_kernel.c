/*
 * ila_kernel.c - Implements interface to manage ILA routes
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

#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/ila.h>
#include <linux/ip.h>
#include <linux/lwtunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ila.h"
#include "libgenl.h"
#include "utils.h"

struct ila_kernel_context {
	Locator local_locator;
	struct in6_addr via;
	int ifindex;
	FILE *logf;
};

#define IKPRINTF(ikc, format, ...) do {				\
	if (ikc->logf)						\
		fprintf(ikc->logf, format, ##__VA_ARGS__);	\
} while (0)

struct ila_route {
	struct in6_addr addr;
	struct in6_addr via;
	Locator loc;
	int ifindex;
	__u8 csum_mode;
	__u8 ident_type;
	__u8 hook_type;
	__u8 rsvd;
};

/* Netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

static struct rtnl_handle rth = { .fd = -1 };

#define ILA_REQUEST(_req, _bufsiz, _cmd, _flags)			\
struct {								\
	struct nlmsghdr		n;					\
	struct genlmsghdr       g;                                      \
	char			buf[NLMSG_ALIGN(0) + (_bufsiz)];	\
} _req = {								\
	.n = {                                                          \
		.nlmsg_type = (genl_family),				\
		.nlmsg_flags = (_flags),				\
		.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),			\
	},								\
	.g = {								\
		.cmd = (_cmd),						\
		.version = ILA_GENL_VERSION,				\
	},								\
}

#define ILA_RTA(g) ((struct rtattr *)(((char *)(g)) +   \
	NLMSG_ALIGN(sizeof(struct genlmsghdr))))

static int flush_kernel(struct ila_kernel_context *ikc);

static int ila_kernel_init(void **context, FILE *logf)
{
	struct ila_kernel_context *ikc;

	ikc = malloc(sizeof(*ikc));
	if (!ikc) {
		if (logf)
			fprintf(stderr, "ila_kernel: Malloc context failed\n");
		return -1;
	}

	ikc->logf = logf;

	if (rtnl_open(&rth, 0) < 0) {
		free(ikc);
		IKPRINTF(ikc, "ila_kernel: Cannot open ip rtnetlink: %s\n",
			 strerror(errno));
		return -1;
	}

	if (flush_kernel(ikc) < 0)
		return -1;

	if (genl_init_handle(&genl_rth, ILA_GENL_NAME, &genl_family)) {
		IKPRINTF(ikc, "ila_kernel: Cannot init genl: %s\n",
			 strerror(errno));
		return -1;
	}

	*context = ikc;

	return 0;
}

enum {
	OPT_DEV = 0,
	OPT_VIA,
	OPT_LOCAL_LOCATOR,
	THE_END
};

static char *token[] = {
	[OPT_DEV] = "dev",
	[OPT_VIA] = "via",
	[OPT_LOCAL_LOCATOR] = "local-locator",
	[THE_END] = NULL
};

static int ila_kernel_parse_args(void *context, char *subopts)
{
	struct ila_kernel_context *ikc = context;
	char *value;

	if (!subopts)
		return 0;

	while (*subopts != '\0') {
		switch (getsubopt((char **__restrict)&subopts, token, &value)) {
		case OPT_DEV:
			ikc->ifindex = ll_name_to_index(value);
			break;
		case OPT_VIA:
			inet_pton(AF_INET6, value,
				  (char *)&ikc->via);
			break;
		case OPT_LOCAL_LOCATOR:
			if (get_addr64(&ikc->local_locator, value) < 0) {
				IKPRINTF(ikc, "ila_kernel: Bad locator '%s'\n",
					 value);
				return -1;
			}
			break;
		default:
			IKPRINTF(ikc, "ila_kernel: Bad ILA kernell opt '%s'\n",
				 value);
			return -1;
		}
	}

	return 0;
}

static int ila_kernel_start(void *context)
{
	return 0;
}

static void ila_kernel_done(void *context)
{
}

static int set_encap(struct ila_kernel_context *ikc, struct ila_route *irt,
		     struct rtattr *rta)
{
	struct rtattr *nest;

	nest = rta_nest(rta, 1024, RTA_ENCAP);

	rta_addattr64(rta, 1024, ILA_ATTR_LOCATOR, irt->loc);
	rta_addattr8(rta, 1024, ILA_ATTR_CSUM_MODE, irt->csum_mode);
	rta_addattr8(rta, 1024, ILA_ATTR_IDENT_TYPE, irt->ident_type);
	rta_addattr8(rta, 1024, ILA_ATTR_HOOK_TYPE, irt->hook_type);

	rta_nest_end(rta, nest);

	rta_addattr16(rta, 1024, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_ILA);

	return 0;
}

#define RTPROT_IDLOCD	18	/* Identifier/locator daemon (idlocd) */

static int flush_cb(const struct sockaddr_nl *who,
		    struct nlmsghdr *n, void *arg)
{
	struct ila_kernel_context *ikc = arg;
	struct rtmsg *r = NLMSG_DATA(n);
	struct {
		struct nlmsghdr n;
		struct rtmsg            r;
		char                    buf[1024];
	} req;

	if (r->rtm_protocol != RTPROT_IDLOCD)
		return 0;

	memcpy(&req, n, n->nlmsg_len);

	req.n.nlmsg_type = RTM_DELROUTE;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_seq = ++rth.seq;

	if (rtnl_send_check(&rth, &req, n->nlmsg_len) < 0) {
		IKPRINTF(ikc, "ila_kernel: Failed to send flush request: %s",
			 strerror(errno));
		return -2;
	}

	return 0;
}

static int flush_kernel(struct ila_kernel_context *ikc)
{
	if (rtnl_wilddump_request(&rth, AF_INET6, RTM_GETROUTE) < 0) {
		IKPRINTF(ikc, "ila_kernel: Failed to send dump request: %s",
			 strerror(errno));
		return -1;
	}

	if (rtnl_dump_filter(&rth, flush_cb, ikc) < 0) {
		IKPRINTF(ikc, "ila_kernel: Dump filter exited %s",
			 strerror(errno));
		return -1;
	}

	return 0;
}

static int modify_route_mapping(struct ila_kernel_context *ikc,
				struct ila_route *irt, int cmd, int flags)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg            r;
		char                    buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.r.rtm_family = AF_INET6,
		.r.rtm_table = RT_TABLE_MAIN,
		.r.rtm_scope = RT_SCOPE_NOWHERE,
	};

	char buf[1024];
	struct rtattr *rta = (void *)buf;

	if (cmd != RTM_DELROUTE) {
		req.r.rtm_protocol = RTPROT_BOOT;
		req.r.rtm_scope = RT_SCOPE_UNIVERSE;
		req.r.rtm_type = RTN_UNICAST;
	}

	req.r.rtm_family = AF_INET6;
	req.r.rtm_dst_len = 128;
	req.r.rtm_protocol = RTPROT_IDLOCD;
	addattr_l(&req.n, sizeof(req), RTA_DST, &irt->addr, sizeof(irt->addr));

	/* rmap is NULL in case od RTM_DELROUTE */

	if (cmd != RTM_DELROUTE) {
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &irt->via,
			  sizeof(irt->via));

		/* Encap setup */

		rta->rta_type = RTA_ENCAP;
		rta->rta_len = RTA_LENGTH(0);

		if (set_encap(ikc, irt, rta) < 0)
			return -1;

		if (rta->rta_len > RTA_LENGTH(0))
			addraw_l(&req.n, 1024, RTA_DATA(rta), RTA_PAYLOAD(rta));

		if (irt->ifindex)
			addattr32(&req.n, sizeof(req), RTA_OIF, irt->ifindex);
	}

	if (rtnl_talk(&rth, &req.n, NULL, 0) < 0) {
		IKPRINTF(ikc, "ila_kernel: Talk to kernel failed: %s",
			 strerror(errno));

		return -2;
	}

	return 0;
}

static int set_route(struct ila_kernel_context *ikc, struct ila_route *irt)
{
	if (irt->loc == ikc->local_locator) {
		/* Locator match so we don't want to set a mapping.
		 * It's possible that there was a previous mapping
		 * so lets try to remove it. Ignore ENOENT here.
		 */
		modify_route_mapping(ikc, irt, RTM_DELROUTE, 0);

		return 0;
	}

	return modify_route_mapping(ikc, irt, RTM_NEWROUTE,
				    NLM_F_CREATE|NLM_F_EXCL);
}

static int del_route_mapping(void *context, struct IlaMapKey *key)
{
	struct ila_kernel_context *ikc = context;
	struct ila_route irt;

	memset(&irt, 0, sizeof(irt));

	irt.addr = key->addr;

	return modify_route_mapping(ikc, &irt, RTM_DELROUTE, 0);
}

static int set_route_mapping(void *context, struct IlaMapKey *key,
			     struct IlaMapValue *rmap)
{
	struct ila_kernel_context *ikc = context;
	struct ila_route irt;

	memset(&irt, 0, sizeof(irt));

	irt.addr = key->addr;
	irt.loc = rmap->loc;
	irt.ifindex = rmap->ifindex ? rmap->ifindex : ikc->ifindex;
	irt.csum_mode = rmap->csum_mode;
	irt.ident_type = rmap->ident_type;
	irt.hook_type = rmap->hook_type;
	irt.via = ikc->via;

	return set_route(ikc, &irt);
}

struct ila_route_ops ila_kernel_ops = {
	.init = ila_kernel_init,
	.parse_args = ila_kernel_parse_args,
	.start = ila_kernel_start,
	.done = ila_kernel_done,
	.set_route = set_route_mapping,
	.del_route = del_route_mapping,
};

struct ila_route_ops *ila_get_kernel(void)
{
	return &ila_kernel_ops;
}

