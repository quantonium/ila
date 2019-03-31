/*
 * ilad_main.c - ILA daemon
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
#include <event2/event.h>
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
#include "qutils.h"
#include "utils.h"

#define ILA_REDIS_DEFAULT_PORT 6379
#define ILA_REDIS_DEFAULT_HOST "::1"

#define ARGS "dfrl:L:D:R:A:"

static struct option long_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "daemonize", no_argument, 0, 'd' },
	{ "logfile", required_argument, 0, 'L' },
	{ "dbopts", required_argument, 0, 'D' },
	{ "routeopts", required_argument, 0, 'R' },
	{ "amfpopts", required_argument, 0, 'A' },
	{ NULL, 0, 0, 0 },
};

bool do_daemonize;
bool is_forwarder;
char *logname = "ilad";
int loglevel = LOG_ERR;
struct ila_map_sys ims;
FILE *logfile = NULL;

static void usage(char *prog_name)
{
	fprintf(stderr, "Usage: ilad [-dvfr] [-L logfile] "
			"[-l {EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO"
			"|DEBUG}] [-D dbopts] "
			"[-R routeopts] [-A amfpsubopts]\n");
	fprintf(stderr, "  -L, --logname      log name\n");
	fprintf(stderr, "  -l, --loglevel     log level\n");
	fprintf(stderr, "  -D, --dbopts       database options\n");
	fprintf(stderr, "  -R, --routeopts    route options\n");
	fprintf(stderr, "  -A, --amfpopts     AMFP options\n");
}

static int parse_args(int argc, char *argv[], char **db_subopts,
		      char **route_subopts, char **amfp_subopts)
{
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, ARGS, long_options,
				&option_index)) != EOF) {
		switch (c) {
		case 'd':
			do_daemonize = true;
			break;
		case 'f':
			is_forwarder = true;
			break;
		case 'r':
			is_forwarder = false;
			break;
		case 'L':
			logname = optarg;
			break;
		case 'l':
			if (!strcmp(optarg, "EMERG"))
				loglevel = LOG_EMERG;
			else if (!strcmp(optarg, "ALERT"))
				loglevel = LOG_ALERT;
			else if (!strcmp(optarg, "CRIT"))
				loglevel = LOG_CRIT;
			else if (!strcmp(optarg, "ERR"))
				loglevel = LOG_ERR;
			else if (!strcmp(optarg, "WARNING"))
				loglevel = LOG_WARNING;
			else if (!strcmp(optarg, "NOTICE"))
				loglevel = LOG_NOTICE;
			else if (!strcmp(optarg, "INFO"))
				loglevel = LOG_INFO;
			else if (!strcmp(optarg, "DEBUG"))
				loglevel = LOG_DEBUG;
			else {
				usage(argv[0]);
				return -1;
			}
			break;
		case 'D':
			*db_subopts = optarg;
			break;
		case 'R':
			*route_subopts = optarg;
			break;
		case 'A':
			*amfp_subopts = optarg;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

static void watch_cb(void *key, size_t key_size, void *data)
{
	struct ila_map_sys *ims = data;
	struct IlaMapKey *ikey = key;
	struct IlaMapValue value;
	size_t value_size;
	int res;

	value_size = sizeof(value);
	res = ims->db_ops->read(ims->db_ctx, key, key_size,
				&value, &value_size);

	switch (res) {
	case 0:
		if (value_size != sizeof(value)) {
			ilad_log(LOG_ERR, "Unexpected value size in DB\n");
			return;
		}

		if (loglevel >= LOG_DEBUG) {
			char buf1[INET_ADDRSTRLEN];
			char buf2[INET_ADDRSTRLEN];

			inet_ntop(AF_INET6, (char *)&ikey->addr, buf1,
                                  sizeof(buf1));

			addr64_n2a(value.loc, buf2, sizeof(buf2));

			ilad_log(LOG_DEBUG, "Got one from watch DB "
			       "%s->%s\n", buf1, buf2);
		}

		/* Found it in DB, set in forwarding table */
		if (ims->route_ops->set_route(ims->route_ctx, ikey,
					      &value) < 0) {
			ilad_log(LOG_ERR, "Set enty failed in watch DB\n");
			return;
		}
		break;
	case -2:
		/* Not in DB, probably was deleted. Remove from
		 * forwarding table if possible.
		 */
		if (ims->route_ops->del_route(ims->route_ctx, ikey) < 0 &&
		    errno != ESRCH) {
			ilad_log(LOG_ERR, "Delete enty failed in watch DB\n");
			return;
		}
		break;
	default:
	case -1:
		/* Each reading DB */
		ilad_log(LOG_ERR, "Read mapping failed in watch DB\n");
	}
}

static int start_watch_all(struct ila_map_sys *ims)
{
	if (ims->db_ops->watch_all(ims->db_ctx, watch_cb, ims,
				   &ims->watch_all_handle,
				    ims->event_base) < 0) {
		ilad_log(LOG_ERR, "Unable to start watch all\n");
		return -1;
	}

	return 0;
}

static void init_router(char *route_subopts, char *db_subopts,
			char *amfp_subopts)
{
	ilad_log(LOG_DEBUG, "Init router start");

	ims.db_ops = dbif_get_redis();
	if (!ims.db_ops) {
		ilad_log(LOG_ERR, "Unable to get Redis dbif\n");
		exit(-1);
	}

	ims.route_ops = ila_get_kernel();
	if (!ims.route_ops) {
		ilad_log(LOG_ERR, "Unable to get route ops\n");
		exit(-1);
	}

	ims.amfp_ops = ila_get_router_amfp();
	if (!ims.amfp_ops) {
		ilad_log(LOG_ERR, "Unable to get AMFP ops\n");
		exit(-1);
	}

	if (ims.db_ops->init(&ims.db_ctx, logfile, ILA_REDIS_DEFAULT_HOST,
			      ILA_REDIS_DEFAULT_PORT) < 0) {
		ilad_log(LOG_ERR, "Init DB ops failed\n");
		exit(-1);
	}

	if (ims.route_ops->init(&ims.route_ctx, logfile) < 0) {
		ilad_log(LOG_ERR, "Init route ops failed\n");
		exit(-1);
	}

	if (ims.amfp_ops->init(&ims.amfp_ctx, &ims, logfile) < 0) {
		ilad_log(LOG_ERR, "Init AMFP ops failed\n");
		exit(-1);
	}

	if (db_subopts && ims.db_ops->parse_args(ims.db_ctx, db_subopts) < 0) {
		ilad_log(LOG_ERR, "Parse DB args failed\n");
		exit(-1);
	}

	if (route_subopts &&
	    ims.route_ops->parse_args(ims.route_ctx, route_subopts) < 0) {
		ilad_log(LOG_ERR, "Parse route args failed\n");
		exit(-1);
	}

	if (amfp_subopts &&
	    ims.amfp_ops->parse_args(ims.amfp_ctx, amfp_subopts) < 0) {
		ilad_log(LOG_ERR, "Parse AMFP args failed\n");
		exit(-1);
	}

	if (ims.db_ops->start(ims.db_ctx) < 0) {
		ilad_log(LOG_ERR, "Start DB failed\n");
		exit(-1);
	}

	if (ims.route_ops->start(ims.route_ctx) < 0) {
		ilad_log(LOG_ERR, "Start route failed\n");
		exit(-1);
	}

	if (ims.amfp_ops->start(ims.amfp_ctx) < 0) {
		ilad_log(LOG_ERR, "Start AMFP failed\n");
		exit(-1);
	}

	if (start_watch_all(&ims) < 0) {
		ilad_log(LOG_ERR, "Start watch all failed\n");
		exit(-1);
	}

	if (ims.db_ops->scan(ims.db_ctx, watch_cb, &ims)) {
		ilad_log(LOG_ERR, "Initial DB scan failed\n");
		exit(-1);
	}

	ilad_log(LOG_DEBUG, "Init router complete\n");
}

static void init_forwarder(char *route_subopts, char *amfp_subopts)
{
	ilad_log(LOG_DEBUG, "Init forwarder start");

	ims.route_ops = ila_get_kernel();
	if (!ims.route_ops) {
		ilad_log(LOG_ERR, "Unable to get route ops\n");
		exit(-1);
	}

	ims.amfp_ops = ila_get_forwarder_amfp();
	if (!ims.amfp_ops) {
		ilad_log(LOG_ERR, "Unable to get AMFP ops\n");
		exit(-1);
	}

	if (ims.route_ops->init(&ims.route_ctx, logfile) < 0) {
		ilad_log(LOG_ERR, "Init route ops failed\n");
		exit(-1);
	}

	if (ims.amfp_ops->init(&ims.amfp_ctx, &ims, logfile) < 0) {
		ilad_log(LOG_ERR, "Init AMFP ops failed\n");
		exit(-1);
	}

	if (route_subopts &&
	    ims.route_ops->parse_args(ims.route_ctx, route_subopts) < 0) {
		ilad_log(LOG_ERR, "Parse route args failed\n");
		exit(-1);
	}

	if (amfp_subopts &&
	    ims.amfp_ops->parse_args(ims.amfp_ctx, amfp_subopts) < 0) {
		ilad_log(LOG_ERR, "Parse AMPF args failed\n");
		exit(-1);
	}

	if (ims.route_ops->start(ims.route_ctx) < 0) {
		ilad_log(LOG_ERR, "Start route failed\n");
		exit(-1);
	}

	if (ims.amfp_ops->start(ims.amfp_ctx) < 0) {
		ilad_log(LOG_ERR, "Start AMFP failed\n");
		exit(-1);
	}

	ilad_log(LOG_DEBUG, "Init forwarder complete\n");
}

int main(int argc, char *argv[])
{
	char *db_subopts = NULL;
	char *route_subopts = NULL;
	char *amfp_subopts = NULL;

	memset(&ims, 0, sizeof(ims));

	if (parse_args(argc, argv, &db_subopts, &route_subopts,
		       &amfp_subopts) < 0)
		exit(-1);

	if (do_daemonize)
		daemonize(logfile);

	setlogmask(LOG_UPTO(loglevel));
	openlog("ilad", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_DAEMON);

	ims.event_base = event_base_new();
	if (!ims.event_base) {
		perror("event_base_new");
		exit(-1);
	}

	if (is_forwarder)
		init_forwarder(route_subopts, amfp_subopts);
	else
		init_router(route_subopts, db_subopts, amfp_subopts);

	ilad_log(LOG_INFO, "ilad started\n");

	/* Event loop */
	event_base_dispatch(ims.event_base);

}
