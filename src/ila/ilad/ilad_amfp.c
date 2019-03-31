/*
 * ilad_amfp.c - ILA daemon AMFP processing
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

#include <errno.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "amfp.h"
#include "dbif.h"
#include "dbif_redis.h"
#include "ila.h"
#include "libnetlink.h"
#include "linux/rtnetlink.h"
#include "linux/ila.h"
#include "qutils.h"
#include "utils.h"
#include "json_print.h"

struct ila_amfp_conn_ctx;

struct ila_amfp_ctx {
	struct ila_map_sys *ims;
	struct rtnl_handle rth;
	struct event ev_notify_read;
	int route_addr_cnt;
	struct in6_addr router_addrs[10];
	struct ila_amfp_conn_ctx *conns;
	FILE *logf;
};

struct ila_amfp_conn_ctx {
	struct ila_amfp_ctx *ictx;
	struct bufferevent *bev;
	size_t want_bytes;
	int cid;
};

static inline void amfp_log(int pri, struct ila_amfp_ctx *ictx,
			    char *format, ...)
{
	char buffer[256];
	va_list args;

	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	syslog(pri, "%s: %s", logname, buffer);
}

static inline void amfpcnx_log(int pri, struct ila_amfp_conn_ctx *cctx,
			       char *format, ...)
{
	char buffer[256];
	va_list args;

	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	syslog(pri, "%s: %s", logname, buffer);
}

static int make_non_blocking (int sfd)
{
	int flags = fcntl (sfd, F_GETFL, 0);

	if (flags < -1) {
		perror ("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;

	if (fcntl(sfd, F_SETFL, flags) < 0) {
		perror ("fcntl");
		return -1;
	}

	return 0;
}

static void ilad_send_msg(struct ila_amfp_conn_ctx *cctx,
			  void *msg, size_t rlen)
{
	struct evbuffer *output = bufferevent_get_output(cctx->bev);

	/* Send map info reply */
	if (evbuffer_add(output, msg, rlen) < 0)
		amfpcnx_log(LOG_WARNING, cctx,
			    "Failure to add to event buffer\n");
}

static struct amfp0_map_info *get_minfo(size_t num_pairs, size_t ident_size,
					size_t loc_size, size_t *rlenp,
					unsigned int reason)
{
	struct amfp0_map_info *minfo;
	size_t rlen = sizeof(struct amfp0_map_info ) +
	    num_pairs * (ident_size + loc_size);

	minfo = (struct amfp0_map_info *)malloc(rlen);

	/* Set up map info message */
	minfo->cmn_hdr.type = AMFP0_MSG_MAP_INFO;
	minfo->cmn_hdr.length_high = rlen >> 8;
	minfo->cmn_hdr.length_low = rlen & 0xff;
	minfo->rsvd = 0;
	minfo->sub_type = reason;
	minfo->loc_type = AMFP0_IDLOC_TYPE_IPV6_ADDR;
	minfo->id_type = AMFP0_IDLOC_TYPE_IPV6_ADDR;

	*rlenp = rlen;

	return minfo;
}

static void ilad_process_map_request(struct ila_amfp_conn_ctx *cctx,
				     __u8 *packet, size_t len,
				     struct evbuffer *output)
{
	struct amfp0_map_request *mreq;
	struct IlaAddress *addr, *waddr;
	struct amfp0_map_info *minfo;
	size_t alen = sizeof(*addr);
	int num_addrs;
	size_t rlen;
	int i;

	amfpcnx_log(LOG_DEBUG, cctx, "Got a map request\n");

	if (len < sizeof(*mreq)) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Bad map request length received\n");
		return;
	}

	mreq = (struct amfp0_map_request *)packet;

	if (mreq->id_type != AMFP0_IDLOC_TYPE_IPV6_ADDR) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Map request ident type not recognized\n");
		return;
	}


	if ((len - sizeof(*mreq)) % alen != 0) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Map request Bad addrs length received\n");
		return;
	}

	num_addrs = ((len - sizeof(*mreq)) / alen);

	minfo = get_minfo(num_addrs, sizeof(*addr), sizeof(*addr),
			  &rlen, AMFP0_MSG_SUBTYPE_MAP_REPLY);

	if (!minfo)
		return;

	addr = (struct IlaAddress *)mreq->identifiers;
	waddr = (struct IlaAddress *)minfo->id_loc_pairs;;
	for (i = 0; i < num_addrs; i++, addr++) {
		struct ila_map_sys *ims = cctx->ictx->ims;;
		struct IlaMapValue value;
		size_t value_size;
		int res;

		/* Copy identifier to reply */
		*waddr = *addr;
		waddr++;

		value_size = sizeof(value);
		res = ims->db_ops->read(ims->db_ctx, addr,
			sizeof(*addr), &value, &value_size);

		switch (res) {
		case 0:
			if (value_size != sizeof(value)) {
				amfpcnx_log(LOG_WARNING, cctx,
					    "Unexpected DB value size\n");
				return;
			}

			/* Found it in DB, write output address */
			waddr->loc = value.loc;
			waddr->ident = addr->ident;
			break;
		case -2:
			/* Not in DB, zero locator */
			memset(waddr, 0, sizeof(*waddr));
			break;
		default:
		case -1:
			/* Each reading DB */
			amfpcnx_log(LOG_WARNING, cctx,
				    "Read DB mapping failed\n");
			break;
		}

		waddr++;
	}

	/* Send map info reply */
	ilad_send_msg(cctx, minfo, rlen);

	free(minfo);
}

static void ilad_process_map_info(struct ila_amfp_conn_ctx *cctx,
				  __u8 *packet, size_t len)
{
	struct ila_map_sys *ims = cctx->ictx->ims;
	struct amfp0_map_info *minfo;
	struct IlaAddress *waddr;
	size_t num_pairs;
	int i;

	if (len < sizeof(*minfo)) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Bad length for map info\n");
		return;
	}

	minfo = (struct amfp0_map_info *)packet;

	switch (minfo->sub_type) {
	case AMFP0_MSG_SUBTYPE_REDIRECT:
		amfpcnx_log(LOG_WARNING, cctx,
			    "Got a redirect\n");
		break;
	default:
		break;
	}

	if (minfo->loc_type != AMFP0_IDLOC_TYPE_IPV6_ADDR ||
	    minfo->id_type != AMFP0_IDLOC_TYPE_IPV6_ADDR) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Map info received only handle IPv6 "
			    "addresses for now\n");
		return;
	}

	len -= sizeof(*minfo);

	num_pairs = len / (2 * sizeof(*waddr));

	if (len % (2 * sizeof(*waddr))) {
		amfpcnx_log(LOG_WARNING, cctx,
			    "Addresses length mismatch in received map info\n");
		return;
	}

	amfpcnx_log(LOG_DEBUG, cctx, "Got good map info with %lu pairs\n",
		    num_pairs);

	waddr = (struct IlaAddress *)minfo->id_loc_pairs;
	for (i = 0; i < num_pairs; i++) {
		char buf1[INET6_ADDRSTRLEN];
		char buf2[INET6_ADDRSTRLEN];
		struct IlaMapKey key;
		struct IlaMapValue value;

		inet_ntop(AF_INET6, (char *)waddr, buf1,
				  sizeof(buf1));
		key.addr = waddr->addr;
		waddr++;

		inet_ntop(AF_INET6, (char *)waddr, buf2,
				  sizeof(buf2));

		if (loglevel >= LOG_DEBUG) {
			char buf1[INET_ADDRSTRLEN];
			char buf2[INET_ADDRSTRLEN];
			inet_ntop(AF_INET6, (char *)&key.addr, buf1,
							  sizeof(buf1));
			addr64_n2a(waddr->loc, buf2, sizeof(buf2));

			amfpcnx_log(LOG_DEBUG, cctx, "Got map info %s->%s\n",
				    buf1, buf2);
		}


		value.ifindex = 0;
		value.csum_mode = ILA_CSUM_NEUTRAL_MAP_AUTO;
		value.ident_type = ILA_ATYPE_LUID;
		value.hook_type = ILA_HOOK_ROUTE_OUTPUT;
		value.rsvd = 0;
		value.loc = waddr->loc;

		waddr++;

		/* Found it in DB, set in forwarding table */
                if (ims->route_ops->set_route(ims->route_ctx, &key,
                                              &value) < 0) {
			amfpcnx_log(LOG_WARNING, cctx, "Map info set route "
				    "failed\n");
                        return;
                }

	}
}

static void ilad_process_amfp(struct ila_amfp_conn_ctx *cctx,
			      __u8 *packet, size_t len,
			      struct evbuffer *output)
{
	struct amfp_cmn_header *chdr = (struct amfp_cmn_header *)packet;

	switch(chdr->type) {
	case AMFP0_MSG_MAP_REQUEST:
		ilad_process_map_request(cctx, packet, len, output);
		break;
	case AMFP0_MSG_MAP_INFO:
		ilad_process_map_info(cctx, packet, len);
		break;
	case AMFP0_MSG_EXT_MAP_INFO:
		break;
	case AMFP0_MSG_LOCATOR_UNREACHABLE:
		break;
	default:
		break;
	}
}

static void amfp_read_cb(struct bufferevent *bev, void *vctx)
{
        struct evbuffer *input = bufferevent_get_input(bev);
        struct evbuffer *output = bufferevent_get_output(bev);
	struct ila_amfp_conn_ctx *cctx = vctx;
	struct amfp_cmn_header *chdr;
	__u16 length;
	void *msg;

	while (1) {
		if (!cctx->want_bytes) {

			/* At new message */

			if (evbuffer_get_length(input) < sizeof(*chdr)) {
				/* Need more bytes */
				return;
			}

			chdr = (struct amfp_cmn_header *)
			    evbuffer_pullup(input, sizeof(*chdr));
			if (!chdr)
				goto error;

			length = (chdr->length_high << 8) + chdr->length_low;
			/* Found header */
			if (length < sizeof(*chdr)) {
				/* Bad length */
				goto error;
			}

			cctx->want_bytes = length;
		}

		if (evbuffer_get_length(input) < cctx->want_bytes) {
			/* Need more bytes */
			return;
		}

		msg = evbuffer_pullup(input, cctx->want_bytes);
		if (!msg)
			goto error;

		ilad_process_amfp(cctx, msg, cctx->want_bytes, output);

		evbuffer_drain(input, cctx->want_bytes);

		/* Reset for next packet */
		cctx->want_bytes = 0;
	}

error:
	return;
}

static void amfp_event_cb(struct bufferevent *bev, short events, void *ctx)
{
        if (events & BEV_EVENT_ERROR)
                perror("Error from bufferevent");
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
                bufferevent_free(bev);
        }
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *vctx)
{
        /* We got a new connection! Set up a bufferevent for it. */
        struct event_base *base = evconnlistener_get_base(listener);
	struct ila_amfp_ctx *ictx = vctx;
	struct ila_amfp_conn_ctx *cctx;
	unsigned short loc_id;
	char buf[INET6_ADDRSTRLEN];

	switch (address->sa_family) {
	case AF_INET:
		if (loglevel >= LOG_DEBUG) {
			struct sockaddr_in *sin = (struct sockaddr_in *)address;

			inet_ntop(AF_INET, (char *)&sin->sin_addr, buf,
				  sizeof(buf));

			amfp_log(LOG_INFO, ictx, "Accept from %s\n", buf);
		}
		/* Don't support this right yet */
		return;
	case AF_INET6: {
		struct sockaddr_in6 *sin =
		    (struct sockaddr_in6 *)address;

		loc_id = ntohs(sin->sin6_addr.s6_addr[2] +
			       (sin->sin6_addr.s6_addr[3] << 8));

		if (loglevel >= LOG_DEBUG) {

			if (!inet_ntop(AF_INET6, (char *)&sin->sin6_addr, buf,
				  sizeof(buf)))
				amfp_log(LOG_ERR, ictx, "FAILDDD\n");

			amfp_log(LOG_INFO, ictx, "Accept from %s with "
				 "loc-id %u\n", buf, loc_id);
		}
		break;
		}
	default:
		amfp_log(LOG_ERR, ictx, "Accept from unknown address family\n");
		return;
	}

	cctx = &ictx->conns[loc_id];

	cctx->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!cctx->bev) {
		free(cctx);
		return;
	}

	cctx->ictx = ictx;

        bufferevent_setcb(cctx->bev, amfp_read_cb, NULL, amfp_event_cb, cctx);
        bufferevent_enable(cctx->bev, EV_READ|EV_WRITE);
}

static void
accept_error_cb(struct evconnlistener *listener, void *vctx)
{
	struct ila_amfp_ctx *ictx = vctx;

        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();

	amfp_log(LOG_ERR, ictx, "Got an error %d (%s) on the listener. "
                "Shutting down.\n", err, evutil_socket_error_to_string(err));

        event_base_loopexit(base, NULL);
}

static int ilad_amfp_init(void **context, struct ila_map_sys *ims, FILE *logf)
{
	struct ila_amfp_ctx *ictx;

	ictx = calloc(sizeof(struct ila_amfp_ctx), 1);
	if (!ictx) {
		ilad_log(LOG_ERR, "ila_amfp: Malloc context failed\n");
		return -1;
	}

	ictx->ims = ims;
	ictx->logf = logf;
	*context = ictx;

	return 0;
}

static int ilad_amfp_router_parse_args(void *vctx, char *subopts)
{
	return 0;
}

enum {
	OPT_ROUTER = 0,
	THE_END
};

static char *forwarder_token[] = {
	[OPT_ROUTER] = "router",
	[THE_END] NULL
};

static int ilad_amfp_forwarder_parse_args(void *vctx, char *subopts)
{
	struct ila_amfp_ctx *ictx = vctx;
	char *value;


	if (!subopts)
		return 0;

        while (*subopts != '\0') {
                switch (getsubopt((char **__restrict)&subopts, forwarder_token,
				  &value)) {
                case OPT_ROUTER:
			if (ictx->route_addr_cnt >= 10) {
				amfp_log(LOG_ERR, ictx,
				    "Too many router addresses\n");
				return -1;
			}

                        inet_pton(AF_INET6, value,
				  (char *)&ictx->router_addrs[
						ictx->route_addr_cnt++]);
                        break;
                default:
			amfp_log(LOG_ERR, ictx,
			    "Bad ILA kernel opt '%s'\n");
                        return -1;
                }
        }

        return 0;
}

static void print_notify_db(char *banner, int res, struct IlaMapKey *key,
			    struct IlaMapValue *value,
			    struct ila_amfp_ctx *ictx)
{
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];

	if (loglevel < LOG_DEBUG)
		return;

	if (res != 0) {
		amfp_log(LOG_DEBUG, ictx, "DB lookup failed\n");
		return;
	}

	inet_ntop(AF_INET6, &key->addr, buf1, sizeof(buf1));
	addr64_n2a(value->loc, buf2, sizeof(buf2));

	amfp_log(LOG_DEBUG, ictx, "%s%s %s\n", banner, buf1, buf2);
}

static int process_routenotify(struct nlmsghdr *n, struct ila_amfp_ctx *ictx)
{
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *rta_tb[RTA_MAX+1];
	struct IlaMapValue value;
	size_t value_size;
	struct ila_map_sys *ims = ictx->ims;;
	struct IlaMapKey key;
	__u8 *v;
	int res;
	unsigned int loc_id;

	if (n->nlmsg_type != RTM_NOTIFYROUTE)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		amfp_log(LOG_ERR, ictx, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(rta_tb, RTA_MAX, RTM_RTA(r), len);

	if (get_real_family(r->rtm_type, r->rtm_family) != AF_INET6) {
		amfp_log(LOG_ERR, ictx, "Route notify Not INET6\n");
		return 0;
	}

	if (!rta_tb[RTA_DST] || !rta_tb[RTA_SRC]) {
		amfp_log(LOG_ERR, ictx, "Need both RTA_DST and RTA_SRC\n");
		return 0;
	}

	key.addr = *(struct in6_addr *)RTA_DATA(rta_tb[RTA_SRC]);
	value_size = sizeof(value);
	res = ims->db_ops->read(ims->db_ctx, &key, sizeof(key),
                                &value, &value_size);

	print_notify_db("SRC lookup ", res, &key, &value, ictx);

	if (res != 0)
		return 0;

	v = (__u8 *)&value.loc;
	loc_id = ntohs(v[6] + (v[7] << 8));

	key.addr = *(struct in6_addr *)RTA_DATA(rta_tb[RTA_DST]);
	value_size = sizeof(value);
	res = ims->db_ops->read(ims->db_ctx, &key, sizeof(key),
                                &value, &value_size);

	print_notify_db("DST lookup ", res, &key, &value, ictx);

	if (res != 0)
		return 0;

	if (ictx->conns[loc_id].ictx) {
		struct amfp0_map_info *minfo;
		struct IlaAddress *waddr;
		size_t rlen;

		minfo = get_minfo(1, sizeof(*waddr), sizeof(*waddr), &rlen,
				  AMFP0_MSG_SUBTYPE_MAP_REPLY);
		if (!minfo)
			return -1;

		waddr = (struct IlaAddress *)minfo->id_loc_pairs;

		waddr->addr = key.addr;
		waddr++;
		waddr->loc = value.loc;
		waddr->ident = ((struct IlaAddress *)&key)->ident;

		amfp_log(LOG_DEBUG, ictx, "Found target sending redirect "
					  "using loc-id %u\n", loc_id);

		ilad_send_msg(&ictx->conns[loc_id], minfo, rlen);

		free(minfo);
	} else {
		amfp_log(LOG_DEBUG, ictx, "No target %u\n", loc_id);
	}

	return 0;
}

static void on_notify_read(int fd, short ev, void *arg)
{
	struct ila_amfp_ctx *ictx = arg;
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(ictx->rth.fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return;
			amfp_log(LOG_ERR, ictx,
				 "netlink receive error %s (%d)\n",
				 strerror(errno), errno);
			if (errno == ENOBUFS)
				continue;
			return;
		}
		if (status == 0) {
			amfp_log(LOG_ERR, ictx, "EOF on netlink\n");
			return;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			amfp_log(LOG_ERR, ictx,
				"Sender address length == %d\n",
				msg.msg_namelen);
			return;
		}

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					amfp_log(LOG_ERR, ictx,
					"Truncated message\n");
					return;
				}
				amfp_log(LOG_ERR, ictx,
					"!!!malformed message: len=%d\n",
					len);
				return;
			}

			switch (h->nlmsg_type) {
			case RTM_NOTIFYROUTE:
				process_routenotify(h, ictx);
				break;
			default:
				break;
			}

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			amfp_log(LOG_ERR, ictx, "Message truncated\n");
			continue;
		}
		if (status) {
			amfp_log(LOG_ERR, ictx,
				 "!!!Remnant of size %d\n", status);
			return;
		}
	}
}

static int ilad_amfp_start_notify_monitor(struct ila_amfp_ctx *ictx)
{
	if (rtnl_open(&ictx->rth, nl_mgrp(RTNLGRP_ROUTE_NOTIFY)) < 0)
		return -1;

	make_non_blocking(ictx->rth.fd);

	event_set(&ictx->ev_notify_read, ictx->rth.fd, EV_READ|EV_PERSIST,
		  on_notify_read, ictx);

	event_base_set(ictx->ims->event_base, &ictx->ev_notify_read);

	event_add(&ictx->ev_notify_read, NULL);

	return 0;
}

#define MAX_CONNS (1 << 16)

static int ilad_amfp_router_start(void *vctx)
{
	struct ila_amfp_ctx *ictx = vctx;
	struct evconnlistener *listener;
	struct sockaddr_in6 sin;
	int port = 5555;

	amfp_log(LOG_DEBUG, ictx, "Start AMFP router\n");

	/* Create AMFP listener */

	ictx->conns = calloc(sizeof(struct ila_amfp_conn_ctx),
			     MAX_CONNS);
	if (!ictx->conns) {
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_addr = in6addr_any;
	sin.sin6_port = htons(port);

	listener = evconnlistener_new_bind(ictx->ims->event_base,
	    accept_conn_cb, ictx,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
	    (struct sockaddr*)&sin, sizeof(sin));
	if (!listener) {
		perror("Couldn't create listener");
		return 1;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);

	if (ilad_amfp_start_notify_monitor(ictx) < 0)
		return 1;

	amfp_log(LOG_DEBUG, ictx, "AMFP router started\n");

	return 0;
}

static void amfp_forwarder_event_cb(struct bufferevent *bev, short events,
				    void *vctx)
{
	struct ila_amfp_conn_ctx *cctx = vctx;

	if (!(events & BEV_EVENT_CONNECTED)) {
		if (events & BEV_EVENT_ERROR) {
			amfpcnx_log(LOG_DEBUG, cctx, "NOT connected!\n");
			return;
		}
	}

	if (loglevel >= LOG_DEBUG) {
		char buf[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6,
			  (char *)&cctx->ictx->router_addrs[cctx->cid],
			  buf, sizeof(buf));

		amfpcnx_log(LOG_DEBUG, cctx, "Connected to %s\n", buf);
	}
}

static int ilad_amfp_forwarder_start(void *vctx)
{
	struct ila_amfp_ctx *ictx = vctx;
	struct sockaddr_in6 sin;
	int port = 5555;
	int i;

	/* Kick off connections to routers */

	ictx->conns = calloc(sizeof(struct ila_amfp_conn_ctx),
			     ictx->route_addr_cnt);
	if (!ictx->conns) {
		return -1;
	}

	for (i = 0; i < ictx->route_addr_cnt; ++i) {
		struct bufferevent *bev = bufferevent_socket_new(
				ictx->ims->event_base, -1,
				BEV_OPT_CLOSE_ON_FREE);

		bufferevent_setcb(bev, amfp_read_cb, NULL,
				  amfp_forwarder_event_cb, &ictx->conns[i]);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
	//	evbuffer_add(bufferevent_get_output(bev), message, block_size);

		memset(&sin, 0, sizeof(sin));
		sin.sin6_family = AF_INET6;
		sin.sin6_addr = ictx->router_addrs[i];
		sin.sin6_port = htons(port);

		if (bufferevent_socket_connect(bev,
				(struct sockaddr *)&sin, sizeof(sin)) < 0) {
			/* Error starting connection */
			bufferevent_free(bev);
			amfp_log(LOG_ERR, ictx, "error connect");
			return -1;
		}

		ictx->conns[i].cid = i;
		ictx->conns[i].bev = bev;
		ictx->conns[i].ictx = ictx;
	}

	return 0;
}

static void ilad_amfp_done(void *context)
{
}

struct ila_amfp_ops ila_amfp_router_ops = {
	.init = ilad_amfp_init,
	.parse_args = ilad_amfp_router_parse_args,
	.start = ilad_amfp_router_start,
	.done = ilad_amfp_done,
};

struct ila_amfp_ops ila_amfp_forwarder_ops = {
	.init = ilad_amfp_init,
	.parse_args = ilad_amfp_forwarder_parse_args,
	.start = ilad_amfp_forwarder_start,
	.done = ilad_amfp_done,
};

struct ila_amfp_ops *ila_get_router_amfp(void)
{
	return &ila_amfp_router_ops;
}

struct ila_amfp_ops *ila_get_forwarder_amfp(void)
{
	return &ila_amfp_forwarder_ops;
}

