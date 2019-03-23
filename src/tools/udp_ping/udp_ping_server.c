#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/ipv6.h>
#include <syslog.h>
#include <getopt.h>
 
#include "qutils.h"
#include "path_mtu.h"

struct fast_ila {
	__u8 nextproto;;
	__u8 len;
	__u8 opt_type;
	__u8 opt_len;
	__u8 fast_type;
	__u8 rsvd;
	__u16 rsvd2;
	__u32 expiration;
	__u32 service_profile;
	__u64 locator;
} __attribute((packed));

bool do_daemonize;
char *logname = "udp_ping_server";
int loglevel = LOG_ERR;
FILE *logfile = NULL;
int port = 7777;

#define IPV6_TLV_FAST 222
#define IPV6_TLV_PATH_MTU 0x3e

static size_t parse_cmsg(struct msghdr *msg, struct msghdr *outmsg)
{
	struct cmsghdr *cmsg, *outcmsg;
	struct fast_ila *fi;
	struct path_mtu *pm;
	size_t len;

	/* Receive auxiliary data in msg */
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IPV6 &&
		    cmsg->cmsg_type == IPV6_HOPOPTS) {
			switch (CMSG_DATA(cmsg)[2]) {
			case IPV6_TLV_FAST:
				fi = (struct fast_ila *)CMSG_DATA(cmsg);
				if ((fi->fast_type >> 4) == 1)
					goto found;
				break;
			case IPV6_TLV_PATH_MTU:
				pm = (struct path_mtu *)CMSG_DATA(cmsg);
				goto found_path_mtu;
			default:
				break;
			}
		}
	}

	return 0;

found:
	len = (fi->len + 1) << 3;

	outcmsg = CMSG_FIRSTHDR(outmsg);
	outcmsg->cmsg_level = SOL_IPV6;
	outcmsg->cmsg_type = IPV6_HOPOPTS;
	outcmsg->cmsg_len = CMSG_LEN(len);

	memcpy(CMSG_DATA(outcmsg), fi, len);

	fi = (struct fast_ila *)CMSG_DATA(outcmsg);
	fi->fast_type = (2 << 4);

	return outcmsg->cmsg_len;
found_path_mtu:
	len = (pm->opt_len + 1) << 3;

	outcmsg = CMSG_FIRSTHDR(outmsg);
	outcmsg->cmsg_level = SOL_IPV6;
	outcmsg->cmsg_type = IPV6_HOPOPTS;
	outcmsg->cmsg_len = CMSG_LEN(len);

	memcpy(CMSG_DATA(outcmsg), pm, len);

	pm = (struct path_mtu *)(CMSG_DATA(outcmsg) + 2);

	if (len - 2 >= sizeof(struct path_mtu)) {
		printf("     Opt type: %u\n", pm->opt_type);
		printf("     Opt len: %u\n", pm->opt_len);
		printf("     Forward MTU: %u\n", ntohs(pm->mtu_forward));
		printf("     Reflect: %s\n", pm->reflect ? "yes" : "no");
		printf("     Reflected MTU: %u\n", ntohs(pm->mtu_reflect));
	} else {
		printf("     Got unknown size %lu expected %lu\n",
			len - 2, sizeof(struct path_mtu));
        }

	return outcmsg->cmsg_len;
}

static void udp_server(void)
{
	struct sockaddr_in6 servaddr;
	struct sockaddr_in6 cliaddr;
	int fd;
	ssize_t n, n1;
	socklen_t alen;
	char buf[10000];
	struct msghdr msg, msg2;
	struct iovec iov[1];
	char cbuf[10000], cbuf2[10000];
	int on = 1;
 
	printf("Begin\n");

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}
 
	bzero(&servaddr, sizeof(servaddr));
 
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

		printf("Received from %u, %d %s:%u\n", cliaddr.sin6_family, alen, abuf, ntohs(cliaddr.sin6_port));

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
		} else
			msg2.msg_controllen = 0;


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
