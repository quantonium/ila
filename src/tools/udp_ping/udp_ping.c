#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/ipv6.h>
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

struct udp_data {
	__u32 seqno;
	struct timespec time;
	void *more_data[0];
};

size_t psize = sizeof(struct udp_data);

static void print_one(__u8 *ptr)
{
	struct fast_ila *fi = (struct fast_ila *)ptr;
	char buf[INET_ADDRSTRLEN];
	size_t len = ptr[1] + 2;

	printf("Hop-by-hop\n");
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

static void print_one_path_mtu(__u8 *ptr)
{
	struct path_mtu *pm = (struct path_mtu *)ptr;
	size_t len = ptr[1] + 2;

	printf("Path MTU\n");
	if (len == sizeof(struct path_mtu)) {
		__u16 reflect_mtu;
		bool reflect;

		reflect_mtu = ntohs(pm->mtu_reflect);
		reflect = !!(reflect_mtu & PATH_MTU_REFLECT);
		reflect_mtu <<= 1;

		printf("     Opt type: %u\n", pm->opt_type);
		printf("     Opt len: %u\n", pm->opt_len);
		printf("     Forward MTU: %u\n", ntohs(pm->mtu_forward));
		printf("     Reflect: %s\n", reflect ? "yes" : "no");
		printf("     Reflected MTU: %u\n", reflect_mtu);
        } else {
                printf("     Got unknown size %lu expected %lu\n",
                       len, sizeof(struct path_mtu));
        }
}

#define IPV6_TLV_FAST 222
#define IPV6_TLV_PATH_MTU 0x3e

static void parse_hopopt(__u8 *ptr)
{
	struct ipv6_hopopt_hdr *ioh = (struct ipv6_opt_hdr *)ptr;
	size_t len, optlen;

	len = (ioh->hdrlen << 3) + 8;

	ptr = (__u8 *)&ioh[1];
	len -= sizeof(*ioh);

	while (len > 0) {
		switch (*ptr) {
		case IPV6_TLV_PAD1:
			optlen = 1;
			break;
		case IPV6_TLV_FAST:
			print_one(ptr);
			optlen = ptr[1] + 2;
			break;
		case IPV6_TLV_PATH_MTU:
			print_one_path_mtu(ptr);
			optlen = ptr[1] + 2;
			break;
		default:
			optlen = ptr[1] + 2;
			break;
		}
		ptr += optlen;
		len -= optlen;
	}
}

static void parse_cmsg(struct msghdr *msg)
{
	struct cmsghdr *cmsg;

	/* Receive auxiliary data in msg */
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IPV6 &&
		    cmsg->cmsg_type == IPV6_HOPOPTS)
			parse_hopopt(CMSG_DATA(cmsg));
        }
}

#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) && \
                             (cmsg)->cmsg_len <= (unsigned long) \
                             ((mhdr)->msg_controllen - \
                              ((char *)(cmsg) - (char *)(mhdr)->msg_control)))

static void udp_client(struct in6_addr *in6)
{
	struct timespec ctime, dtime;
	struct iovec iov[1], iov2[1];
	struct sockaddr_in6 sin6;
	struct msghdr msg, msg2;
	unsigned int seqno = 0;
	void *fast_ctx = NULL;
	struct cmsghdr *cmsg;
	char cbuf2[10000];
	char cbuf[10000];
	char buf2[10000];
	char buf[10000];
	struct udp_data *ud2, *ud = (struct udp_data *)buf;
	socklen_t alen;
	ssize_t n, n1;
	int on = 1;
	int i, fd;

	if (lookup_fast)
		fast_ctx = fast_init();
 
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}
 
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *in6;
	sin6.sin6_port = htons(port);

	if (connect(fd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0) {
		perror("bind");
		exit(-1);
	}

	if (setsockopt(fd, SOL_IPV6, IPV6_RECVHOPOPTS, &on,
		       sizeof(on)) < 0) {
		perror("setsockopt");
		exit(-1);
	}

	memset(cbuf, 0, sizeof(cbuf));
	memset(cbuf2, 0, sizeof(cbuf2));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	iov[0].iov_base = buf;
	iov[0].iov_len = psize;

	if (fast_ctx || do_num_opts) {
		struct ipv6_opt_hdr *ioh;
		size_t len = 0, rlen;
		void *data;

		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_IPV6;
		cmsg->cmsg_type = IPV6_HOPOPTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(cbuf));

		ioh = (struct ipv6_opt_hdr *)CMSG_DATA(cmsg);
		data = &ioh[1];
		len = 2;

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
			len += rlen;
			data += rlen;
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
			}
			len += rlen;
			data += rlen;
		}

		if (len > 2) {
			size_t ehlen;

			ehlen = (len - 1)/ 8;
			rlen = (ehlen + 1) * 8;

			for (i = len; i < rlen; i++)
				((__u8 *)data)[i] = 0;

			ioh->nexthdr = 0;
			ioh->hdrlen = ehlen;
			msg.msg_control = cbuf;
			msg.msg_controllen = cmsg->cmsg_len;
		} else {
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
		}
	}

	memset(&msg2, 0, sizeof(msg2));
	msg2.msg_name = (struct sockaddr *)&sin6;
	msg2.msg_namelen = sizeof(sin6);
	msg2.msg_iov=iov2;
	msg2.msg_iovlen=1;
	msg2.msg_control=cbuf2;
	msg2.msg_controllen=sizeof(cbuf2);
	iov2[0].iov_base = buf2;
	iov2[0].iov_len = sizeof(buf2);;

	while(1) {
		double delta;
		char abuf[INET6_ADDRSTRLEN];

		ud->seqno = ++seqno;
		clock_gettime(CLOCK_REALTIME, &ud->time);

		n = sendmsg(fd, &msg, 0);
		if (n < 0) {
			perror("sendmsg");
			break;
		}
 
		n1 = recvmsg(fd, &msg2, 0);
		if (n1 != n) {
			if (n1 < 0) {
				perror("recvmsg");
				goto skip;
			} else {
				printf("MISMATCH %lu != %lu\n", n, n1);
			}
		}

		ud2 = (struct udp_data *)buf2;

		clock_gettime(CLOCK_REALTIME, &ctime);
		timespec_diff(&ud2->time, &ctime, &dtime);
		delta = dtime.tv_sec + dtime.tv_nsec / 1000000000.0;

		inet_ntop(AF_INET6, &sin6.sin6_addr, abuf,
			  sizeof(abuf));

		if (n1 >= sizeof(*ud2))
			printf("%lu bytes from udp %s:%u udp_seq=%u "
			       "time=%.3f ms\n", n1, abuf,
				sin6.sin6_port,
				ud2->seqno, delta * 1000);
		else
			printf("%lu bytes from udp %s:%u\n", n1, abuf,
				sin6.sin6_port);

		if (verbose && msg2.msg_controllen)
			parse_cmsg(&msg2);

skip:
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

	if (get_address_from_name(argv[optind], SOCK_DGRAM, &in6) < 0)
		exit(-1);

	if (set_fast_port && !lookup_fast) {
		fprintf(stderr, "Need to set FAST address if port is set\n");
		exit(-1);
	}

	udp_client(&in6);
}
