/*
 * dbif.h - Generic API to access a backend database.
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

#ifndef __DBIF_H__
#define __DBIF_H__

#include <event2/event.h>
#include <linux/types.h>

/* dbif_ops define the operations of dbif interface.
 *
 * Functions are:
 *
 *   init	Initialize database interface. Includes a default
 *		host name and port for connecting to a database
 *		via TCP.
 *
 *   parse_args
 *		Parse arguments specific to the backend dbif database
 *		implementation. These are assumed to be a subopts string.
 *		A logfile argument may be set to log messages about
 *		bad arguments.
 *
 *   start	Start backend database.
 *
 *   done	Done with database, any resources can be release.
 *
 *   write	Write object. Arguments include key and value.
 *
 *   read	Read object. Arguments are key and returned value.
 *
 *   delete	Delete an object. Argument is a key.
 *
 *   scan	Scan the entries in the database. For each entry
 *		a callback function is called that has the key
 *		as the object argument.
 *
 *   watch_all	Watch for changes to an object in a database.
 *		Argument is a callback function that takes a key
 *		as an argument and is called when a change is
 *		detected.
 *
 *   watch_one	Watch for changes to key in the database.
 *		Argument is a callback function that takes a key
 *		as an arugment and is called when a change is
 *		detected.
 *
 *   stop_watch
 *		Stop watching a database. Argument is the watch
 *		handle returned by watch_all or watch_one.
 */

struct dbif_ops {
	int (*init)(void **ctxp, FILE *logf, char *def_host, __u16 def_port);
	int (*parse_args)(void *ctx, char *subopts);
	int (*start)(void *ctx);
	void (*done)(void *ctx);
	int (*write)(void *ctx, void *key, size_t key_size,
		     void *value, size_t value_size);
	int (*read)(void *ctx, void *key, size_t key_size,
		    void *value, size_t *value_size);
	int (*delete)(void *ctx, void *key, size_t key_size);
	int (*scan)(void *ctx,
		    void (*cb)(void *key, size_t key_size, void *data),
		    void *data);
	int (*watch_all)(void *ctx,
			 void (*cb)(void *key, size_t key_size, void *data),
			 void *data, void **handlep,
			 struct event_base *event_base);
	int (*watch_one)(void *ctx, void *key, size_t key_size,
			 void (*cb)(void *key, size_t key_size, void *data),
			 void *data, void **handlep,
			 struct event_base *event_base);
	void (*stop_watch)(void *ctx, void *handle);
};

struct dbif {
	const struct dbif_ops db_ops;
};

#endif
