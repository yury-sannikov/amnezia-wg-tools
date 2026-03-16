// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>

#include "containers.h"
#include "ipc.h"
#include "encoding.h"
#include "subcommands.h"

static const char *COMMAND_NAME;

static void metrics_usage(void)
{
	fprintf(stderr, "Usage: %s %s <interface> [peer-key-prefix]\n", PROG_NAME, COMMAND_NAME);
}

static char *peer_key_b64(const uint8_t key[static WG_KEY_LEN])
{
	static char base64[WG_KEY_LEN_BASE64];
	key_to_base64(base64, key);
	return base64;
}

static const char *endpoint_str(const struct sockaddr *addr)
{
	static char buf[4096 + 512 + 4];
	char host[4096 + 1], service[512 + 1];
	socklen_t addr_len = 0;

	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else if (addr->sa_family == AF_INET6)
		addr_len = sizeof(struct sockaddr_in6);

	if (addr_len == 0)
		return NULL;

	if (getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service),
	                NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST))
		return NULL;

	snprintf(buf, sizeof(buf),
	         (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s",
	         host, service);
	return buf;
}

static const char *state_str(uint32_t state)
{
	switch (state) {
	case 1: return "green";
	case 2: return "error";
	default: return "dark";
	}
}

static void json_string(const char *s)
{
	fputc('"', stdout);
	if (s) {
		for (; *s; s++) {
			switch (*s) {
			case '"':  fputs("\\\"", stdout); break;
			case '\\': fputs("\\\\", stdout); break;
			default:   fputc(*s, stdout);
			}
		}
	}
	fputc('"', stdout);
}

static void print_peer_json(const struct wgpeer *peer, bool first_peer)
{
	time_t now = time(NULL);

	if (!first_peer)
		printf(",\n");
	printf("  {\n");

	printf("    \"peer\": ");
	json_string(peer_key_b64(peer->public_key));
	printf(",\n");

	/* Control endpoint */
	printf("    \"control\": {\n");
	if ((peer->flags & WGPEER_HAS_CONTROL_ENDPOINT) &&
	    (peer->control_endpoint.addr.sa_family == AF_INET ||
	     peer->control_endpoint.addr.sa_family == AF_INET6)) {
		const char *ep = endpoint_str(&peer->control_endpoint.addr);
		printf("      \"endpoint\": ");
		json_string(ep);
		printf(",\n");
	} else {
		printf("      \"endpoint\": null,\n");
	}
	printf("      \"rx_bytes\": %" PRIu64 ",\n", peer->control_rx_bytes);
	printf("      \"tx_bytes\": %" PRIu64 ",\n", peer->control_tx_bytes);
	printf("      \"last_handshake_sec\": %" PRId64 ",\n", (int64_t)peer->last_handshake_time.tv_sec);
	if (peer->last_handshake_time.tv_sec > 0 && now >= peer->last_handshake_time.tv_sec)
		printf("      \"last_handshake_ago_sec\": %lld\n", (long long)(now - peer->last_handshake_time.tv_sec));
	else
		printf("      \"last_handshake_ago_sec\": -1\n");
	printf("    },\n");

	/* Endpoint strategy */
	printf("    \"endpoint_strategy\": ");
	if (peer->flags & WGPEER_HAS_ENDPOINT_STRATEGY && peer->endpoint_strategy)
		json_string(peer->endpoint_strategy);
	else
		printf("null");
	printf(",\n");

	/* Overall data transfer */
	printf("    \"rx_bytes\": %" PRIu64 ",\n", peer->rx_bytes);
	printf("    \"tx_bytes\": %" PRIu64 ",\n", peer->tx_bytes);

	/* Data endpoints */
	printf("    \"endpoints\": [\n");
	for (size_t i = 0; i < peer->endpoints_len; i++) {
		const struct wgendpoint *ep = &peer->endpoints[i];
		const char *ep_str = NULL;

		if (ep->addr.ss_family == AF_INET || ep->addr.ss_family == AF_INET6)
			ep_str = endpoint_str((const struct sockaddr *)&ep->addr);

		if (i > 0)
			printf(",\n");
		printf("      {\n");
		printf("        \"index\": %zu,\n", i + 1);
		printf("        \"endpoint\": ");
		json_string(ep_str);
		printf(",\n");
		printf("        \"direction\": \"%s\",\n", ep->is_initiator ? "initiator" : "responder");
		printf("        \"bind_port\": %u,\n", ep->bind_port);
		printf("        \"state\": \"%s\",\n", state_str(ep->state));

		if (ep->last_received_time.tv_sec > 0 && now >= ep->last_received_time.tv_sec)
			printf("        \"last_rx_ago_sec\": %lld,\n", (long long)(now - ep->last_received_time.tv_sec));
		else
			printf("        \"last_rx_ago_sec\": -1,\n");

		printf("        \"rx_bytes\": %" PRIu64 ",\n", ep->rx_bytes);
		printf("        \"tx_bytes\": %" PRIu64 ",\n", ep->tx_bytes);

		if (ep->rtt_nanos > 0)
			printf("        \"rtt_ms\": %.2f,\n", (double)ep->rtt_nanos / 1000000.0);
		else
			printf("        \"rtt_ms\": -1,\n");

		printf("        \"avg_loss_per_1000\": %u,\n", ep->avg_loss);
		printf("        \"tx_rank\": %u\n", ep->tx_rank);
		printf("      }");
	}
	if (peer->endpoints_len)
		printf("\n");
	printf("    ]\n");
	printf("  }");
}

int metrics_main(int argc, const char *argv[])
{
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	const char *iface;
	const char *peer_prefix = NULL;
	bool first = true;

	COMMAND_NAME = argv[0];

	if (argc < 2 || argc > 3) {
		metrics_usage();
		return 1;
	}
	if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) {
		metrics_usage();
		return 0;
	}

	iface = argv[1];
	if (argc == 3)
		peer_prefix = argv[2];

	if (ipc_get_device(&device, iface) < 0) {
		fprintf(stderr, "Unable to access interface %s: %s\n", iface, strerror(errno));
		return 1;
	}

	printf("[\n");
	for_each_wgpeer(device, peer) {
		if (peer_prefix) {
			char *b64 = peer_key_b64(peer->public_key);
			if (strncmp(b64, peer_prefix, strlen(peer_prefix)) != 0)
				continue;
		}
		print_peer_json(peer, first);
		first = false;
	}
	if (!first)
		printf("\n");
	printf("]\n");

	free_wgdevice(device);
	return 0;
}
