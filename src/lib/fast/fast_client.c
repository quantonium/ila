/*
 * fast_client.c - utility to query FAST ticket agent
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
#include <arpa/inet.h>
#include <stdio.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/ipv6.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "fast.h"
 
struct query_data {
	bool verbose;
	void *buf;
	size_t len;
	size_t retlen;
};

static int addr64_n2a(__u64 addr, char *buff, size_t len)
{
	__u16 *words = (__u16 *)&addr;
	__u16 v;
	int i, ret;
	size_t written = 0;
	char *sep = ":";

	for (i = 0; i < 4; i++) {
		v = ntohs(words[i]);

		if (i == 3)
			sep = "";

		ret = snprintf(&buff[written], len - written, "%x%s", v, sep);
		if (ret < 0)
			return ret;

		written += ret;
	}

	return written;
}

static void print_one(__u8 *ptr)
{
	struct fast_ila *fi = (struct fast_ila *)ptr;
	char buf[INET_ADDRSTRLEN];
	size_t len = ptr[1] + 2;

	printf("Got ILA Hop-by-hop\n");
	if (len == sizeof(struct fast_ila)) {
		addr64_n2a(fi->locator, buf, sizeof(buf));

		printf("     Opt type: %u\n", fi->opt_type);
		printf("     Opt len: %u\n", fi->opt_len);
		printf("     Fast type: %u\n", fi->fast_type);
		printf("     Reserved: %u\n", fi->rsvd);
		printf("     Expiration: %u\n", ntohl(fi->expiration));
		printf("     Service profile: %u\n",
		       ntohl(fi->service_profile));
		printf("     Locator: %s\n", buf);
        } else {
                printf("     Got unknown size %lu expected %lu\n",
                       len, sizeof(struct fast_ila));
        }
}

#define IPV6_TLV_FAST 222

static size_t function_pt(void *indata, size_t size, size_t nmemb, void *data)
{
	struct query_data *qd = data;
	struct ipv6_hopopt_hdr *ioh;
	size_t len, optlen;
	__u8 *ptr = indata;
	int i;

	size = size * nmemb;
	len = size;

	memcpy(qd->buf, ptr, size);

	qd->retlen = size;

	if (!qd->verbose)
		return size;

	for (i = 0; i < size; i++)
		printf("%02x ", ptr[i]);

	printf("\n");

	ioh = indata;

	if (len != (ioh->hdrlen << 3) + 8) {
		fprintf(stderr, "Unexpected length, got %lu want %d\n",
			len, (ioh->hdrlen << 3) + 8);
		return size;
	}

	ptr = (__u8 *)&ioh[1];
        len -= sizeof(*ioh);

	while (len > 0) {
		switch (*ptr) {
		case IPV6_TLV_PAD1:
			optlen = 1;
			break;
		case IPV6_TLV_FAST:
			print_one(ptr);
			/* Fall through */
		default:
			optlen = ptr[1] + 2;
			break;
		}
		ptr += optlen;
		len -= optlen;
	}

	return size;
}

struct fast_ctx {
	CURL *curl;
};

void *fast_init(void)
{
	struct fast_ctx *fc;
	CURL *curl;

	fc = (struct fast_ctx *)malloc(sizeof(*fc));
	if (!fc)
		return NULL;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);
 
	curl = curl_easy_init();

	if (!curl) {
		free(fc);
		return NULL;
	}

	fc->curl = curl;

	return fc;
}

size_t fast_query_verbose(struct in6_addr *dst, void *ctx, void *buf,
			  size_t len, struct in6_addr *http_addr,
			  int http_port, bool verbose)
{
	struct fast_ctx *fc = ctx;
	CURL *curl = fc->curl;
	struct query_data qd;
	CURLcode res;
	size_t ret = 0;
	char abuf[INET6_ADDRSTRLEN];
	char hbuf[INET6_ADDRSTRLEN];
	char tbuf[100];

	qd.buf = buf;
	qd.len = len;
	qd.retlen = 0;
	qd.verbose = verbose;

	inet_ntop(AF_INET6, dst, abuf, sizeof(abuf));
	inet_ntop(AF_INET6, http_addr, hbuf, sizeof(hbuf));

	sprintf(tbuf, "http://[%s]:%u/?query=%s", hbuf, http_port, abuf);
	curl_easy_setopt(curl, CURLOPT_URL, tbuf);
 
#ifdef SKIP_PEER_VERIFICATION
	/*
	 * If you want to connect to a site who isn't using a certificate
	 * that is signed by one of the certs in the CA bundle you have,
	 * you can * skip the verification of the server's certificate.
	 * This makes the connection A LOT LESS SECURE.
	 *
	 * If you have a CA cert for the server stored someplace else
	 * than in the default bundle, then the CURLOPT_CAPATH option
	 * might come handy for you.
	 */ 
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
 
#ifdef SKIP_HOSTNAME_VERIFICATION
	/*
	 * If the site you're connecting to uses a different host name
	 * that what they have mentioned in their server certificate's
	 * commonName (or subjectAltName) fields, libcurl will refuse to
	 * connect. You can skip this check, but this will make the
	 * connection less secure.
	 */ 
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
 
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, function_pt);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &qd);

	/* Perform the request, res will get the return code */ 
	res = curl_easy_perform(curl);

	/* Check for errors */ 
	if (res != CURLE_OK) {
		if (verbose)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
	} else {
		char *ct;
 
      		res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
 
		if((CURLE_OK == res) && ct)
			ret = qd.retlen;
	}

	return ret;
}

void fast_done(void *ctx)
{
	struct fast_ctx *fc = ctx;
	CURL *curl = fc->curl;

	/* always cleanup */ 
	curl_easy_cleanup(curl);
 
	curl_global_cleanup();

	free(fc);
}

