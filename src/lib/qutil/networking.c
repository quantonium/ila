#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <linux/types.h>
#include <linux/ipv6.h>
#include "qutils.h"

int get_address_from_name(char *name, int socktype, struct in6_addr *in6)
{
	struct addrinfo *result, *rp;
	struct sockaddr_in6 *sin6;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = socktype; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	err = getaddrinfo(name, NULL, &hints, &result);
	if (err != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		return err;
	}

	/* Find first IPv6 address */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)rp->ai_addr;
			memcpy(in6, &sin6->sin6_addr, sizeof(*in6));
			break;
		}
	}

	if (rp == NULL) {               /* No address succeeded */
		fprintf(stderr, "No suitable address found for %s\n", name);
		return -1;
	}

	freeaddrinfo(result);           /* No longer needed */

	return 0;
}
