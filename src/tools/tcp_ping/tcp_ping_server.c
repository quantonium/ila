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
 
#include "path_mtu.h"
#include "qutils.h"

bool do_daemonize;
char *logname = "tcp_ping_server";
int loglevel = LOG_ERR;
FILE *logfile = NULL;
int port = 7777;

static void process_conn(int fd, struct sockaddr_in6 *cliaddr)
{
	char buf[10000];
	struct msghdr msg, msg2;
	struct iovec iov[1];
	char cbuf[10000], cbuf2[10000];
	char abuf[INET6_ADDRSTRLEN];
	int enable = 1;
	ssize_t n, n1;

	if (setsockopt(fd, SOL_IPV6, IPV6_RECVHOPOPTS, &enable,
		       sizeof(enable)) < 0) {
		perror("setsockopt");
		exit(-1);
	}

	while(1) {
		iov[0].iov_base = buf;
		iov[0].iov_len = sizeof(buf);

		msg.msg_name = (struct sockaddr *)&cliaddr;
		msg.msg_namelen = sizeof(cliaddr);
		msg.msg_iov=iov;
		msg.msg_iovlen=1;
		msg.msg_control=cbuf;
		msg.msg_controllen=sizeof(cbuf);

		n = recvmsg(fd, &msg, 0);
		if (n <= 0) {
			if (n == 0)
				break;
			perror("recvmsg");
			break;
		}

		inet_ntop(AF_INET6, &cliaddr->sin6_addr, abuf, sizeof(abuf));

		printf("Received from %u, %lu %s:%u\n", cliaddr->sin6_family,
		    n, abuf, ntohs(cliaddr->sin6_port));

		iov[0].iov_base = buf;
		iov[0].iov_len = n;

		msg2.msg_name = (struct sockaddr *)&cliaddr;
		msg2.msg_namelen = sizeof(cliaddr);
		msg2.msg_iov=iov;
		msg2.msg_iovlen=1;
		msg2.msg_control=cbuf2;
		msg2.msg_controllen=sizeof(cbuf2);

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

#define ARGS "dl:L:p:M:"

static struct option long_options[] = {
	{ "daemonize", no_argument, 0, 'd' },
	{ "logname", required_argument, 0, 'L' },
	{ "loglevel", required_argument, 0, 'l' },
	{ "port", required_argument, 0, 'p' },
	{ NULL, 0, 0, 0 },
};

static void tcp_server(void)
{
	struct sockaddr_in6 servaddr;
	struct sockaddr_in6 cliaddr;
	int listen_fd, comm_fd;
	socklen_t alen;
	int enable = 1;
	char str[INET6_ADDRSTRLEN];
	char str2[INET6_ADDRSTRLEN];
 
	printf("Begin\n");

	listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		exit(-1);
	}
 
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
		       (const char*)&enable, sizeof(enable)) < 0) {
		perror("setsockopt");
		exit(-1);
	}

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_addr = in6addr_any;
	servaddr.sin6_port = htons(port);
 
	if (bind(listen_fd, (struct sockaddr *) &servaddr,
		 sizeof(servaddr)) < 0) {
		perror("bind");
		exit(-1);
	}
 
	if (listen(listen_fd, 10) < 0) {
		perror("listen");
		exit(-1);
	}

	while (1) {
		alen = sizeof(servaddr);
		comm_fd = accept(listen_fd, (struct sockaddr*)&cliaddr, &alen);

		alen = sizeof(servaddr);
		if (getsockname(comm_fd, (struct sockaddr *)&servaddr,
				&alen) < 0) {
			perror("getsockname");
			exit(-1);
		}
		inet_ntop(AF_INET, &cliaddr.sin6_addr, str, 100);
		inet_ntop(AF_INET, &servaddr.sin6_addr, str2, 100);

		printf("New connectionX: %s:%d to %s:%d\n", str,
		       ntohs(cliaddr.sin6_port), str2,
		       ntohs(servaddr.sin6_port));

		if (fork() == 0)
			process_conn(comm_fd, &servaddr);
		close(comm_fd);
	}
}

static void usage(char *prog_name)
{
	fprintf(stderr, "Usage: tcp_server_ping [-d] [-p port] "
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
	openlog("tcp_ping_server", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_DAEMON);

	tcp_server();
}
