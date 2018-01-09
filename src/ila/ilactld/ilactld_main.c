/*
 * ilactld_main.c - ILA control daemon
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
#include <fcntl.h>
#include <getopt.h>
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
#include "linux/ila.h"
#include "qutils.h"

#define ILA_REDIS_DEFAULT_MAP_PORT 6379
#define ILA_REDIS_DEFAULT_IDENT_PORT 6380
#define ILA_REDIS_DEFAULT_LOC_PORT 6381

#define ARGS "vdR:M:I:L:"

static struct option long_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "daemonize", no_argument, 0, 'd' },
	{ "logfile", required_argument, 0, 'L' },
	{ "mapopts", required_argument, 0, 'D' },
	{ "identopts", required_argument, 0, 'I' },
	{ "locopts", required_argument, 0, 'O' },
	{ NULL, 0, 0, 0 },
};

bool do_daemonize;
FILE *logfile;

static void usage(char *prog_name)
{
	fprintf(stderr, "Usage: ilactld [-dv] [-L logfile] [-D dbopts] "
			"[-I identopts] [-O locopts][\n");
	fprintf(stderr, "  -L, --logfile      log file\n");
	fprintf(stderr, "  -D, --dbopts       map database options\n");
	fprintf(stderr, "  -I, --identopts    ident database options\n");
	fprintf(stderr, "  -O, --locopts       log database options\n");
}

/* Instance of control mapping system. There are three databases
 * used, reference by db_*_ctx. There are the map (ILA mapping
 * database), ident (ILA identifiers) and loc (ILA locators).
 */
struct ila_ctl_sys {
	struct dbif_ops *db_ops;
	void *db_map_ctx;
	void *db_ident_ctx;
	void *db_loc_ctx;
	void *watch_handle;
	struct event_base *event_base;
};

static int parse_args(int argc, char *argv[], char **map_subopts,
		      char **ident_subopts, char **loc_subopts)
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
		case 'M':
			*map_subopts = optarg;
			break;
		case 'I':
			*ident_subopts = optarg;
			break;
		case 'O':
			*loc_subopts = optarg;
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

static void set_entry(struct ila_ctl_sys *ics, struct IlaIdentKey *ikey,
		      struct IlaIdentValue *ival)
{
	struct IlaLocKey lkey;
	struct IlaMapKey mkey;
	struct IlaLocValue lval;
	struct IlaMapValue mval;
	size_t lval_size = sizeof(lval);
	int res;

	lkey.num = ival->loc_num;

	res = ics->db_ops->read(ics->db_loc_ctx, &lkey,
				sizeof(lkey), &lval,
				&lval_size);
	if (res < 0)
		return;

	/* Have everything to write mapping now */
	mkey.addr = ival->addr;
	mval.loc = lval.locator;
	mval.ifindex = 0;
	mval.csum_mode = ILA_CSUM_NEUTRAL_MAP_AUTO;
	mval.ident_type = ILA_ATYPE_LUID;
	mval.hook_type = ILA_HOOK_ROUTE_OUTPUT;

	res = ics->db_ops->write(ics->db_map_ctx, &mkey, sizeof(mkey),
				 &mval, sizeof(mval));

	if (res)
		fprintf(stderr, "Mapping failed\n");
}

static void remove_entry(struct ila_ctl_sys *ics, struct IlaIdentKey *ikey,
			 struct IlaIdentValue *ival)
{
	struct IlaMapKey mkey;

	mkey.addr = ival->addr;

	if (ics->db_ops->delete(ics->db_map_ctx, &mkey, sizeof(mkey)) < 0 &&
	    errno != ESRCH) {
		fprintf(stderr, "Del failed\n");
		return;
	}
}

static void watch_cb(void *key, size_t key_size, void *data)
{
	struct IlaIdentKey *ikey = key;
	struct ila_ctl_sys *ics = data;
	struct IlaIdentValue ival;
	size_t ival_size = sizeof(ival);
	int res;

	res = ics->db_ops->read(ics->db_ident_ctx, key, key_size,
				&ival, &ival_size);

	switch (res) {
	case 0:
		if (ival.loc_num)
			set_entry(ics, ikey, &ival);
		else
			remove_entry(ics, ikey, &ival);
		break;
	case -2:
		/* Not in DB, probably was deleted. Remove from
		 * forwarding table if possible.
		 */
		remove_entry(ics, ikey, &ival);
		break;
	default:
	case -1:
		/* Each reading DB */
		fprintf(stderr, "Read mapping failed\n");
	}
}

extern struct ila_db_ops ila_db_ops;

#define ILA_REDIS_DEFAULT_HOST "::1"

static int start_db(const struct ila_ctl_sys *ics, FILE *logfile, void **ctx,
		    char *subopts, char *def_host, __u16 def_port,
		    const char *name)
{
	if (ics->db_ops->init(ctx, logfile, def_host, def_port) < 0) {
		fprintf(stderr, "Init DB %s: %s\n", name, strerror(errno));
		return -1;
	}

	if (subopts && ics->db_ops->parse_args(ctx, subopts) < 0) {
		fprintf(stderr, "Parse arg DB %s: %s\n", name, strerror(errno));
		return -1;
	}

	if (ics->db_ops->start(*ctx) < 0) {
		fprintf(stderr, "Start DB %s: %s\n", name, strerror(errno));
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct ila_ctl_sys ics;
	char *map_subopts = NULL;
	char *ident_subopts = NULL;
	char *loc_subopts = NULL;

	memset(&ics, 0, sizeof(ics));

	if (parse_args(argc, argv, &map_subopts, &ident_subopts,
		       &loc_subopts) < 0)
		exit(-1);

	ics.db_ops = dbif_get_redis();
	if (!ics.db_ops) {
		fprintf(stderr, "Unable to get Redis dbif\n");
		exit(-1);
	}

	ics.event_base = event_base_new();
	if (!ics.event_base) {
		perror("event_base_new");
		exit(-1);
	}

	if (start_db(&ics, logfile, &ics.db_map_ctx, map_subopts,
		     ILA_REDIS_DEFAULT_HOST, ILA_REDIS_DEFAULT_MAP_PORT,
		     "map") < 0)
		exit(-1);

	if (start_db(&ics, logfile, &ics.db_ident_ctx, ident_subopts,
		     ILA_REDIS_DEFAULT_HOST, ILA_REDIS_DEFAULT_IDENT_PORT,
		     "ident") < 0)
		exit(-1);

	if (start_db(&ics, logfile, &ics.db_loc_ctx, loc_subopts,
		     ILA_REDIS_DEFAULT_HOST, ILA_REDIS_DEFAULT_LOC_PORT,
		     "ident") < 0)
		exit(-1);

	if (ics.db_ops->scan(ics.db_ident_ctx, watch_cb, &ics) < 0) {
		fprintf(stderr, "Initial scan failed\n");
		exit(-1);
	}

	if (ics.db_ops->watch_all(ics.db_ident_ctx, watch_cb,
				   &ics, &ics.watch_handle,
				   ics.event_base) < 0) {
		fprintf(stderr, "Watch all failed\n");
		exit(-1);
	}

	if (do_daemonize)
		daemonize(stderr);

	/* Event loop */
	event_base_dispatch(ics.event_base);
}

