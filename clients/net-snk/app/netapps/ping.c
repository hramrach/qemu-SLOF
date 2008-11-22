/******************************************************************************
 * Copyright (c) 2004, 2007 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <netlib/icmp.h>
#include <netlib/arp.h>
#include <netlib/netlib.h>
#include <sys/socket.h>
#include <netlib/netbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netapps/args.h>

struct ping_args {
	union {
		char string[4];
		unsigned int integer;
	} server_ip;
	union {
		char string[4];
		unsigned int integer;
	} client_ip;
	union {
		char string[4];
		unsigned int integer;
	} gateway_ip;
	unsigned int timeout;
};

static void
usage()
{
	printf
	    ("\nping device-path:[device-args,]server-ip,[client-ip],[gateway-ip][,timeout]\n");

}

static int
parse_args(const char *args, struct ping_args *ping_args)
{
	unsigned int argc = get_args_count(args);
	char buf[64];
	ping_args->timeout = 10;
	if (argc == 0)
		/* at least server-ip has to be specified */
		return -1;
	if (argc == 1) {
		/* probably only server ip is specified */
		argncpy(args, 0, buf, 64);
		if (!strtoip(buf, ping_args->server_ip.string))
			return -1;
		return 0;
	}
	/* get first option from list */
	argncpy(args, 0, buf, 64);
	if (!strtoip(buf, ping_args->server_ip.string)) {
		/* it is not an IP address
		 * therefore it has to be device-args
		 * device-args are not supported and just ignored */
		args = get_arg_ptr(args, 1);
		argc--;
	}

	argncpy(args, 0, buf, 64);
	if (!strtoip(buf, ping_args->server_ip.string)) {
		/* this should have been the server IP address */
		return -1;
	} else {
		args = get_arg_ptr(args, 1);
		if (!--argc)
			return 0;
	}

	argncpy(args, 0, buf, 64);
	if (!strtoip(buf, ping_args->client_ip.string)) {
		/* this should have been the client (our) IP address */
		return -1;
	} else {
		args = get_arg_ptr(args, 1);
		if (!--argc)
			return 0;
	}
	argncpy(args, 0, buf, 64);
	if (!strtoip(buf, ping_args->gateway_ip.string)) {
		/* this should have been the gateway IP address */
		return -1;
	} else {
		args = get_arg_ptr(args, 1);
		if (!--argc)
			return 0;
	}
	argncpy(args, 0, buf, 64);
	ping_args->timeout = strtol(args, 0, 10);
	return 0;
}

int
ping(int argc, char *argv[])
{
	short arp_failed = 0;
	filename_ip_t fn_ip;
	int fd_device;
	struct ping_args ping_args;

	memset(&ping_args, 0, sizeof(struct ping_args));

	if (argc == 2) {
		if (parse_args(argv[1], &ping_args)) {
			usage();
			return -1;
		}
	} else {
		usage();
		return -1;
	}

	memset(&fn_ip, 0, sizeof(filename_ip_t));

	/* Get mac_addr from device */
	printf("\n  Reading MAC address from device: ");
	fd_device = socket(0, 0, 0, (char *) fn_ip.own_mac);
	if (fd_device == -1) {
		printf("\nE3000: Could not read MAC address\n");
		return -100;
	} else if (fd_device == -2) {
		printf("\nE3006: Could not initialize network device\n");
		return -101;
	}

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       fn_ip.own_mac[0], fn_ip.own_mac[1], fn_ip.own_mac[2],
	       fn_ip.own_mac[3], fn_ip.own_mac[4], fn_ip.own_mac[5]);

	// init network stack
	netbase_init(fd_device, fn_ip.own_mac, fn_ip.own_ip);
	// identify the BOOTP/DHCP server via broadcasts
	// don't do this, when using DHCP !!!
	//  fn_ip.server_ip = 0xFFFFFFFF;
	//  memset(fn_ip.server_mac, 0xff, 6);

	if (!ping_args.client_ip.integer) {
		/* Get ip address for our mac address */
		printf("  Requesting IP address via DHCP: ");
		arp_failed = dhcp(fd_device, 0, &fn_ip, 30);

		if (arp_failed == -1) {
			printf("\n  DHCP: Could not get ip address\n");
			return -1;
		}

	} else {
		memcpy(&fn_ip.own_ip, &ping_args.client_ip.integer, 4);
		arp_failed = 1;
		printf("  Own IP address: ");
	}

	// reinit network stack
	netbase_init(fd_device, fn_ip.own_mac, fn_ip.own_ip);

	printf("%d.%d.%d.%d\n",
	       ((fn_ip.own_ip >> 24) & 0xFF), ((fn_ip.own_ip >> 16) & 0xFF),
	       ((fn_ip.own_ip >> 8) & 0xFF), (fn_ip.own_ip & 0xFF));

	memcpy(&fn_ip.server_ip, &ping_args.server_ip.integer, 4);
	printf("  Ping to %d.%d.%d.%d ", ((fn_ip.server_ip >> 24) & 0xFF),
	       ((fn_ip.server_ip >> 16) & 0xFF),
	       ((fn_ip.server_ip >> 8) & 0xFF), (fn_ip.server_ip & 0xFF));


	if (ping_args.gateway_ip.integer) {
		if (!arp_getmac(ping_args.gateway_ip.integer, fn_ip.server_mac)) {
			printf("failed\n");
			return -1;
		}
	} else {
		if (!arp_getmac(fn_ip.server_ip, fn_ip.server_mac)) {
			printf("failed\n");
			return -1;
		}
	}

	if (!echo_request(fd_device, &fn_ip, ping_args.timeout)) {
		printf("success\n");
		return 0;
	} else {
		printf("failed\n");
		return -1;
	}
}
