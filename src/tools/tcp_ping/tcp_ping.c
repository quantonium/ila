#include <arpa/inet.h>
#include <errno.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "fast.h"
#include "path_mtu.h"
#include "qutils.h"
#include "utils.h"
 
static bool verbose;
int port = 7777;
int fast_port = 6666;
struct in6_addr fast_addr;
bool lookup_fast;
int do_num_opts;
bool set_indiv_tlvs = true;

struct tcp_data {
	__u32 length;
	__u32 seqno;
	struct timespec time;
	void *more_data[0];
};

size_t psize = sizeof(struct tcp_data);

#define IPV6_TLV_FAST 222
#define IPV6_TLV_PATH_MTU 0x3e

static void set_one_tlv(int fd, void *data, size_t len)
{
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS_TLV, data, len) < 0) {
		perror("setsockopt IPV6_HOPOPTS");
		exit(-1);
	}
}

static void setup_options(int fd)
{
	struct sockaddr_in6 sin6;
	char cbuf[10000];
	void *data = cbuf;
	size_t len = 0;
	socklen_t alen;
	size_t rlen;
	int i;

	if (lookup_fast) {
		void *fast_ctx = fast_init();
 
		if (fast_ctx) {
			alen = sizeof(sin6);
			if (getsockname(fd, (struct sockaddr *)&sin6,
					&alen) < 0) {
				perror("getsockname");
				exit(-1);
			}

			rlen = fast_query_verbose(&sin6.sin6_addr, fast_ctx,
						  data, sizeof(cbuf) - len,
						  &fast_addr,
						  fast_port, verbose);
			if (set_indiv_tlvs)
				set_one_tlv(fd, data, rlen);

			len += rlen;
			data += rlen;
		}
	}

	if (do_num_opts) {
		struct path_mtu *pm;

		rlen = do_num_opts * sizeof(*pm);

		if (rlen > sizeof(cbuf) - len) {
			fprintf(stderr, "Too big\n");
			exit(-1);
		}

		pm = data;

		for (i = 0; i < do_num_opts; i++, pm++) {
			pm->opt_type = IPV6_TLV_PATH_MTU;
			pm->opt_len = sizeof(*pm) - 2;
			pm->mtu_forward = htons(20000 + i);
			pm->mtu_reflect = htons(PATH_MTU_REFLECT);
			if (set_indiv_tlvs)
				set_one_tlv(fd, pm, sizeof(*pm));
		}

		len += rlen;
		data += rlen;
	}

	if (!len)
		return;

	if (!set_indiv_tlvs) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS_TLV,
			       cbuf, len) < 0) {
			perror("setsockopt IPV6_HOPOPTS");
			exit(-1);
		}
	}
}

static void tcp_client(struct in6_addr *in6)
{
	struct sockaddr_in6 sin6;
	int fd;
	ssize_t n, n1;
	char buf[10000];
	char buf2[10000];
	struct tcp_data *ud2, *ud = (struct tcp_data *)buf;
	struct timespec ctime, dtime;
	unsigned int seqno = 0;
	struct msghdr msg, msg2;
	struct iovec iov[1], iov2[1];

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}
 
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *in6;
	sin6.sin6_port = htons(port);

	if (connect(fd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0) {
		perror("connect");
		exit(-1);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	iov[0].iov_base = buf;
	iov[0].iov_len = psize;

	memset(&msg2, 0, sizeof(msg2));
	msg2.msg_iov=iov2;
	msg2.msg_iovlen=1;
	iov2[0].iov_base = buf2;
	iov2[0].iov_len = sizeof(buf2);;

	setup_options(fd);

	while(1) {
		double delta;
		char abuf[INET6_ADDRSTRLEN];

		ud->length = psize;
		ud->seqno = ++seqno;
		clock_gettime(CLOCK_REALTIME, &ud->time);

		n = sendmsg(fd, &msg, 0);
		if (n < 0) {
			perror("sendmsg");
			break;
		}
 
		n1 = recvmsg(fd, &msg2, 0);

		if (n1 <= 0) {
			if (n1 == 0)
				fprintf(stderr, "Connection broken\n");
			else
				perror("recvmsg");
			break;
		}
		
		if (n != n1)
			printf("MISMATCH %lu != %lu\n", n, n1);

		ud2 = (struct tcp_data *)buf2;

		clock_gettime(CLOCK_REALTIME, &ctime);
		timespec_diff(&ud2->time, &ctime, &dtime);
		delta = dtime.tv_sec + dtime.tv_nsec / 1000000000.0;

		inet_ntop(AF_INET6, &sin6.sin6_addr, abuf,
			  sizeof(abuf));

		if (n1 >= sizeof(*ud2))
			printf("%lu bytes from tcp %s:%u tcp_seq=%u "
			       "time=%.3f ms\n", n1, abuf,
				sin6.sin6_port,
				ud2->seqno, delta * 1000);
		else
			printf("%lu bytes from tcp %s:%u\n", n1, abuf,
				sin6.sin6_port);

		sleep(1);
	}
}

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-s packetsize] destination\n",
	        prog);
}

int main(int argc, char *argv[])
{
	bool set_fast_port = false;
	struct in6_addr in6;
	int c;

	while ((c = getopt(argc, argv, "s:vp:P:F:M:")) != -1) {
		switch (c) {
		case 's':
			psize = atoi(optarg);
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'F':
			if (get_address_from_name(optarg, SOCK_STREAM,
						  &fast_addr) < 0) {
				usage(argv[0]);
				exit(-1);
			}
			lookup_fast = true;
			break;
		case 'P':
			fast_port = atoi(optarg);
			set_fast_port = true;
			break;
		case 'M':
			do_num_opts = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			exit(-1);
		}
	}

	if (optind != argc - 1) {
		usage(argv[0]);
		exit(-1);
	}

	if (get_address_from_name(argv[optind], SOCK_STREAM, &in6) < 0)
		exit(-1);

	if (set_fast_port && !lookup_fast) {
		fprintf(stderr, "Need to set FAST address if port is set\n");
		exit(-1);
	}

	tcp_client(&in6);
}
