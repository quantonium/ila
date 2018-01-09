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

#include "dbif.h"
#include "dbif_redis.h"
#include "ila.h"
#include "qutils.h"

#define ILA_REDIS_DEFAULT_PORT 6379
#define ILA_REDIS_DEFAULT_HOST "::1"

#define ARGS "dLD:R:"

static struct option long_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "daemonize", no_argument, 0, 'd' },
	{ "logfile", required_argument, 0, 'L' },
	{ "dbopts", required_argument, 0, 'D' },
	{ "routeopts", required_argument, 0, 'R' },
	{ NULL, 0, 0, 0 },
};

bool do_daemonize;
FILE *logfile;

static void usage(char *prog_name)
{
	fprintf(stderr, "Usage: ilad [-dv] [-L logfile] [-D dbopts] "
			"[-R routeopts\n");
	fprintf(stderr, "  -L, --logfile      log file\n");
	fprintf(stderr, "  -D, --dbopts       database options\n");
	fprintf(stderr, "  -R, --routeopts    route options\n");
}

/* Instance of a mapping system. */

struct ila_map_sys {
	struct dbif_ops *db_ops;
	void *db_ctx;
	struct ila_route_ops *route_ops;
	void *route_ctx;
	void *watch_all_handle;
	struct event_base *event_base;
};

static int parse_args(int argc, char *argv[], char **db_subopts,
		      char **route_subopts)
{
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, ARGS, long_options,
				&option_index)) != EOF) {
		switch (c) {
		case 'd':
			do_daemonize = true;
			break;
		case 'L':
			if (!logfile) {
				logfile = fopen(optarg, "w");
				if (!logfile) {
					perror("Open log file");
					return -1;
				}
			}
			break;
		case 'D':
			*db_subopts = optarg;
			break;
		case 'R':
			*route_subopts = optarg;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!logfile)
		logfile = stderr;

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
			fprintf(stderr, "Unexpected value size\n");
			return;
		}

		/* Found it in DB, set in forwarding table */
		if (ims->route_ops->set_route(ims->route_ctx, ikey,
					      &value) < 0) {
			fprintf(stderr, "Set failed\n");
			return;
		}
		break;
	case -2:
		/* Not in DB, probably was deleted. Remove from
		 * forwarding table if possible.
		 */
		if (ims->route_ops->del_route(ims->route_ctx, ikey) < 0 &&
		    errno != ESRCH) {
			fprintf(stderr, "Del failed\n");
			return;
		}
		break;
	default:
	case -1:
		/* Each reading DB */
		fprintf(stderr, "Read mapping failed\n");
	}
}

static int start_watch_all(struct ila_map_sys *ims)
{
	if (ims->db_ops->watch_all(ims->db_ctx, watch_cb, ims,
				   &ims->watch_all_handle,
				    ims->event_base) < 0) {
		fprintf(stderr, "Unable to start watch all\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct ila_map_sys ims;
	char *db_subopts = NULL;
	char *route_subopts = NULL;

	memset(&ims, 0, sizeof(ims));

	if (parse_args(argc, argv, &db_subopts, &route_subopts) < 0)
		exit(-1);

	ims.db_ops = dbif_get_redis();
	if (!ims.db_ops) {
		fprintf(stderr, "Unable to get Redis dbif\n");
		exit(-1);
	}

	ims.route_ops = ila_get_kernel();
	if (!ims.route_ops) {
		fprintf(stderr, "Unable to get Redis dbif\n");
		exit(-1);
	}

	if (ims.db_ops->init(&ims.db_ctx, logfile, ILA_REDIS_DEFAULT_HOST,
			      ILA_REDIS_DEFAULT_PORT) < 0)
		exit(-1);

	if (ims.route_ops->init(&ims.route_ctx, logfile) < 0)
		exit(-1);

	if (db_subopts && ims.db_ops->parse_args(ims.db_ctx, db_subopts) < 0)
		exit(-1);

	if (route_subopts &&
	    ims.route_ops->parse_args(ims.route_ctx, route_subopts) < 0)
		exit(-1);

	ims.event_base = event_base_new();
	if (!ims.event_base) {
		perror("event_base_new");
		exit(-1);
	}

	if (ims.db_ops->start(ims.db_ctx) < 0) {
		fprintf(stderr, "Error initializing DB\n");
		exit(-1);
	}

	if (ims.route_ops->start(ims.route_ctx) < 0) {
		fprintf(stderr, "Error initializing route\n");
		exit(-1);
	}

	if (start_watch_all(&ims) < 0) {
		fprintf(stderr, "Start watch all failed\n");
		exit(-1);
	}

	if (ims.db_ops->scan(ims.db_ctx, watch_cb, &ims)) {
		fprintf(stderr, "Initial scan failed\n");
		exit(-1);
	}

	if (do_daemonize)
		daemonize(logfile);

	/* Event loop */
	event_base_dispatch(ims.event_base);
}
