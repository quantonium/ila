#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/ipv6.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
 
#include "fast.h"
#include "qutils.h"
#include "path_mtu.h"
#include "linux/fast.h"

bool do_daemonize;
char *logname = "udp_ping_server";
int loglevel = LOG_ERR;
FILE *logfile = NULL;
int port = 7777;

#define IPV6_TLV_FAST 0x3e
#define IPV6_TLV_PATH_MTU 0x3f

static size_t parse_cmsg(struct msghdr *msg, struct msghdr *outmsg)
{
	struct cmsghdr *outcmsg = CMSG_FIRSTHDR(outmsg);
	__u8 *outdata = (__u8 *)CMSG_DATA(outcmsg);
	struct ipv6_opt_hdr *ioh;
	struct cmsghdr *cmsg;
	size_t len, optlen;
	size_t outlen = 0;
	__u8 *ptr;

	/* Receive auxiliary data in msg */
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_IPV6 ||
		    cmsg->cmsg_type != IPV6_HOPOPTS)
			continue;

		/* Processed received HBH EH */
		ioh = (struct ipv6_opt_hdr *)CMSG_DATA(cmsg);

		len = (ioh->hdrlen << 3) + 8;

		ptr = (__u8 *)&ioh[1];
		len -= sizeof(*ioh);

		/* Set up sending EH */
		ioh = (struct ipv6_opt_hdr *)outdata;
		outlen += sizeof(*ioh);
		outdata += sizeof(*ioh);

		/* Parse HBH TLVs */
		while (len > 0) {
			switch (*ptr) {
			case IPV6_TLV_PAD1:
				optlen = 1;
				break;
			case IPV6_TLV_FAST: {
				struct fast_opt *fo;
				struct fast_ila *fi;

				optlen = ptr[1] + 2;
				if (optlen < sizeof(*fi))
					break;

				fo = (struct fast_opt *)&ptr[2];
				if (fo->prop != FAST_TICK_ORIGIN_REFLECT)
					break;

				memcpy(outdata, ptr, optlen);
				fo = (struct fast_opt *)&outdata[2];
				fo->prop = FAST_TICK_REFLECTED;
				outdata += optlen;
				outlen += optlen;

				break;
			}
			case IPV6_TLV_PATH_MTU:
			{
				struct path_mtu *pm;
				__u16 reflect_mtu;
				__u16 forward_mtu;
				bool reflect;

				optlen = ptr[1] + 2;
				if (optlen < sizeof(*pm))
					break;

				pm = (struct path_mtu *)&ptr[2];

				forward_mtu = ntohs(pm->mtu_forward);
				reflect_mtu = ntohs(pm->mtu_reflect);
				reflect = !!(reflect_mtu & PATH_MTU_REFLECT);

				if (!reflect)
					break;

				memcpy(outdata, ptr, optlen);
				pm = (struct path_mtu *)&outdata[2];

				pm->mtu_reflect = htons(forward_mtu >> 1);
				pm->mtu_forward = htons(0);

				outdata += optlen;
				outlen += optlen;

				break;
			}
			default:
				optlen = ptr[1] + 2;
				break;
			}
			ptr += optlen;
			len -= optlen;
		}
	}

	if (outlen > 2) {
		int i;
		size_t rlen, ehlen;

		/* Have something to send */

		ehlen = (outlen - 1) / 8;
		rlen = (ehlen + 1) * 8;

		/* Pad TLV */
		for (i = outlen; i < rlen; i++)
			((__u8 *)outdata)[i] = 0;

		ioh->nexthdr = 0;
		ioh->hdrlen = ehlen;

		outcmsg->cmsg_level = SOL_IPV6;
		outcmsg->cmsg_type = IPV6_HOPOPTS;
		outcmsg->cmsg_len = CMSG_LEN(rlen);

		return outcmsg->cmsg_len;
	}

	return 0;
}

static void udp_server(void)
{
	char cbuf[10000], cbuf2[10000];
	struct sockaddr_in6 servaddr;
	struct sockaddr_in6 cliaddr;
	struct msghdr msg, msg2;
	struct iovec iov[1];
	char buf[10000];
	ssize_t n, n1;
	int on = 1;
	int fd;
 
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}
 
	memset(&servaddr, 0, sizeof(servaddr));
 
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_addr = in6addr_any;
	servaddr.sin6_port = htons(port);
 
	if (bind(fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		perror("bind");
		exit(-1);
	}
 
	if (setsockopt(fd, SOL_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(-1);
	}

	while(1) {
		char abuf[INET6_ADDRSTRLEN];

		iov[0].iov_base = buf;
		iov[0].iov_len = sizeof(buf);

		msg.msg_name = (struct sockaddr *)&cliaddr;
		msg.msg_namelen = sizeof(cliaddr);
		msg.msg_iov=iov;
		msg.msg_iovlen=1;
		msg.msg_control=cbuf;
		msg.msg_controllen=sizeof(cbuf);

		n = recvmsg(fd, &msg, 0);
		if (n < 0) {
			perror("recvmsg");
			break;
		}

		inet_ntop(AF_INET6, &cliaddr.sin6_addr, abuf, sizeof(abuf));

		printf("Received from %s:%u\n", abuf, ntohs(cliaddr.sin6_port));

		iov[0].iov_base = buf;
		iov[0].iov_len = n;

		msg2.msg_name = (struct sockaddr *)&cliaddr;
		msg2.msg_namelen = sizeof(cliaddr);
		msg2.msg_iov=iov;
		msg2.msg_iovlen=1;
		msg2.msg_control=cbuf2;
		msg2.msg_controllen=sizeof(cbuf2);

		if (msg.msg_controllen) {
			msg2.msg_controllen = parse_cmsg(&msg, &msg2);
		} else {
			msg2.msg_controllen = 0;
		}

		n1 = sendmsg(fd, &msg2, 0);
		if (n1 < 0) {
			perror("sendto");
			break;
		}

		if (n != n1)
			printf("MISMATCH %lu != %lu\n", n, n1);

                printf("Echo bytes %lu\n", n1);
	}
}

#define ARGS "dl:L:p:"

static struct option long_options[] = {
	{ "daemonize", no_argument, 0, 'd' },
	{ "logname", required_argument, 0, 'L' },
	{ "loglevel", required_argument, 0, 'l' },
	{ "port", required_argument, 0, 'p' },
	{ NULL, 0, 0, 0 },
};

static void usage(char *prog_name)
{
	fprintf(stderr, "Usage: udp_server_ping [-d] [-p port] "
			"[-L logname] "
                        "[-l {EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO"
                        "|DEBUG}]"
                        "[-R routeopts] [-A amfpsubopts]\n");
        fprintf(stderr, "  -d, --daemonize    daemonize\n");
        fprintf(stderr, "  -p, --port         port\n");
        fprintf(stderr, "  -L, --logname      log name\n");
        fprintf(stderr, "  -l, --loglevel     log level\n");
}

int main(int argc, char *argv[])
{
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, ARGS, long_options,
				&option_index)) != EOF) {
		switch (c) {
		case 'd':
			do_daemonize = true;
			break;
                case 'p':
                        port = atoi(optarg);
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
                default:
                        usage(argv[0]);
                        exit(-1);
                }
        }

	if (do_daemonize)
		daemonize(logfile);

	setlogmask(LOG_UPTO(loglevel));
	openlog("udp_log_server", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_DAEMON);

	udp_server();
}
