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
#include "fast.h"
#include "utils.h"
#include "qutils.h"
 
extern void show_ipv6_tlvs(void);
extern void set_ipv6_tlvs(void);

int main(int argc, char *argv[])
{
	show_ipv6_tlvs();
	set_ipv6_tlvs();
//	show_ipv6_tlvs();
}

