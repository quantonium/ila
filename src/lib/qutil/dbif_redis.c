/*
 * dbif_redis.c - Redis backend for dbif
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

/* Redis backend for dbif interface. This allows using the generic dbif to
 * access a Redis database.
 */

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <hiredis/async.h>
#include <hiredis/hiredis.h>
#include <hiredis/adapters/libevent.h>

#include "dbif.h"
#include "dbif_redis.h"

struct redis_context {
	redisContext *ctx;
	char *host;
	__u16 port;
	FILE *logf;
};

#define DBPRINTF(rdc, format, ...) do {				\
	if (rdc->logf)						\
		fprintf(rdc->logf, format, ##__VA_ARGS__);	\
} while (0)

struct redis_scan_data {
	void (*cb)(void *key, size_t key_size, void *data);
	void *data;
};

/* Initialize dbif database instance. Context is returned in ctxp */
static int redis_init(void **ctxp, FILE *logf, char *def_host, __u16 def_port)
{
	struct redis_context *rdc;

	rdc = malloc(sizeof(*rdc));
	if (!rdc)
		return -1;

	rdc->host = def_host;
	rdc->port = def_port;
	rdc->logf = logf;

	*ctxp = rdc;

	return 0;
}

enum {
	OPT_HOST = 0,
	OPT_PORT,
	THE_END
};

static char *token[] = {
	[OPT_HOST] = "host",
	[OPT_PORT] = "port",
	[THE_END] = NULL
};

/* Parse Redis specific arguments as subopts */
static int redis_parse_args(void *ctx, char *subopts)
{
	struct redis_context *rdc = ctx;
	char *value;

	if (!subopts)
		return 0;

	while (*subopts != '\0') {
		switch (getsubopt(&subopts, token, &value)) {
		case OPT_HOST:
			rdc->host = strdup(value);
			break;
		case OPT_PORT:
			rdc->port = strtol(value, NULL, 10);
			break;
		default:
			DBPRINTF(rdc, "dbif_redis: Bad redis opt '%s'\n",
				 value);
			return -1;
		}
	}

	return 0;
}

/* Start redis database instance. Open a connection to given host
 * and port.
 */
static int redis_start(void *ctx)
{
	struct redis_context *rdc = ctx;
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *dbctx;

	dbctx = redisConnectWithTimeout(rdc->host, rdc->port, timeout);
	if (dbctx == NULL || dbctx->err) {
		if (dbctx) {
			DBPRINTF(rdc, "redis: Connection error: %s\n",
				dbctx->errstr);
			redisFree(dbctx);
		} else {
			DBPRINTF(rdc, "dbif_redis: Connection error: can't "
				      "allocate redis context\n");
		}
		return -1;
	}

	rdc->ctx = dbctx;

	return 0;
}

static void redis_done(void *ctx)
{
	struct redis_context *rdc = ctx;

	redisContext *dbctx = rdc->ctx;

	rdc->ctx = NULL;

	/* Disconnects and frees the context */
	redisFree(dbctx);
}

static int redis_write(void *ctx, void *key, size_t key_size,
		       void *value, size_t value_size)
{
	struct redis_context *rdc = ctx;
	redisReply *reply;

	reply = redisCommand(rdc->ctx, "SET %b %b", key, key_size,
			     value, value_size);

	freeReplyObject(reply);

	return 0;
}

static int redis_read(void *ctx, void *key, size_t key_size,
		      void *value, size_t *value_size)
{
	struct redis_context *rdc = ctx;
	redisContext *dbctx = rdc->ctx;
	redisReply *reply;

	reply = redisCommand(dbctx, "GET %b", key, key_size);

	if (!reply->str)
		return -2;

	if (reply->len > *value_size)
		return -1;

	*value_size = reply->len;
	memcpy(value, reply->str, *value_size);

	freeReplyObject(reply);

	return 0;
}

static int redis_delete(void *ctx, void *key, size_t key_size)
{
	struct redis_context *rdc = ctx;
	redisReply *reply;

	reply = redisCommand(rdc->ctx, "DEL %b", key, key_size);

	freeReplyObject(reply);

	return 0;
}

static int redis_scan(void *ctx,
		      void (*cb)(void *key, size_t key_size, void *data),
		      void *data)
{
	struct redis_context *rdc = ctx;
	redisReply *reply;
	int i, index = 0;

	do {
		reply = redisCommand(rdc->ctx, "SCAN %u", index);

		if (reply->type != REDIS_REPLY_ARRAY ||
		    reply->elements < 1)
			return -1;

		index = strtol(reply->element[0]->str, NULL, 10);

		for (i = 0; i < reply->element[1]->elements; i++)
			cb(reply->element[1]->element[i]->str,
			   reply->element[1]->element[i]->len, data);

	} while (index);

	return 0;
}

static void redis_callback(redisAsyncContext *c, void *r, void *data)
{
	struct redis_scan_data *rdsd = data;

	redisReply *reply = r;

	if (reply == NULL)
		return;

	/* Three element in array? */

	if (reply->type != REDIS_REPLY_ARRAY || reply->elements != 4)
		return;

	rdsd->cb(reply->element[3]->str, reply->element[3]->len, rdsd->data);
}

static redisAsyncContext *redis_async_connect(struct redis_context *rdc,
					      void (*cb)(void *key,
							 size_t key_size,
							 void *data),
					      void *data,
					      struct redis_scan_data **rdsdp,
					      struct event_base *event_base)
{
	struct redis_scan_data *rdsd;

	redisAsyncContext *c;

	rdsd = malloc(sizeof(*rdsd));
	if (!rdsd) {
		perror("malloc sync context");
		return NULL;
	}

	c = redisAsyncConnect(rdc->host, rdc->port);
	if (c->err) {
		DBPRINTF(rdc, "dbif_redis: Async connect error: %s\n",
			 c->errstr);
		free(rdsd);
		return NULL;
	}

	rdsd->cb = cb;
	rdsd->data = data;
	*rdsdp = rdsd;

	redisLibeventAttach(c, event_base);

	return c;
}

static int redis_watch_all(void *ctx,
			   void (*cb)(void *key, size_t key_size, void *data),
			   void *data, void **handlep,
			   struct event_base *event_base)
{
	struct redis_context *rdc = ctx;
	struct redis_scan_data *rdsd;

	redisAsyncContext *c = redis_async_connect(rdc, cb, data,
						   &rdsd, event_base);

	if (!c)
		return -1;

	redisAsyncCommand(c, redis_callback, rdsd, "PSUBSCRIBE __key*__:*");

	*handlep = rdsd;

	return 0;
}

static int redis_watch_one(void *ctx,  void *key, size_t key_size,
			   void (*cb)(void *key, size_t key_size, void *data),
			   void *data, void **handlep,
			   struct event_base *event_base)
{
	struct redis_context *rdc = ctx;
	struct redis_scan_data *rdsd;

	redisAsyncContext *c = redis_async_connect(rdc, cb, data, &rdsd,
						   event_base);

	if (!c)
		return -1;

	redisAsyncCommand(c, redis_callback, rdsd, "SUBSCRIBE %b",
			  key, key_size);

	*handlep = rdsd;

	return 0;
}

static void redis_stop_watch(void *ctx, void *handle)
{
	/* NOTE: can only find Redis UNWATCH that cancels all watches.
	 * This will need to be fixed somehow.
	 */

	struct redis_context *rdc = ctx;

	redisCommand(rdc->ctx, "UNWATCH");
}

static struct dbif_ops redis_ops = {
	.init = redis_init,
	.parse_args = redis_parse_args,
	.start = redis_start,
	.done = redis_done,
	.write = redis_write,
	.read = redis_read,
	.delete = redis_delete,
	.scan = redis_scan,
	.watch_all = redis_watch_all,
	.watch_one = redis_watch_one,
	.stop_watch = redis_stop_watch,
};

struct dbif_ops *dbif_get_redis(void)
{
	return &redis_ops;
}

