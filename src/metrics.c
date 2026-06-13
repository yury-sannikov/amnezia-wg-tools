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
#include "endpoint_stats.h"
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
	case WG_EP_STATE_GREEN: return "green";
	case WG_EP_STATE_ERROR: return "error";
	case WG_EP_STATE_BLUE: return "blue";
	case WG_EP_STATE_ORANGE: return "orange";
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

static void json_print_loss_history(const uint16_t *history, size_t len)
{
	size_t i;

	printf("[");
	for (i = 0; i < len; i++) {
		if (i > 0)
			printf(", ");
		printf("%u", (unsigned int)history[i]);
	}
	printf("]");
}

static void print_endpoint_json(const struct wgendpoint *ep, const struct wgpeer *peer, size_t endpoint_index, time_t now)
{
	const char *ep_str = NULL;
	double share_pct;
	bool has_share = ep_selected_share_pct(ep, peer, endpoint_index, &share_pct);
	uint16_t rx_avg;
	bool has_rx_avg = ep_peer_loss_avg(ep, &rx_avg);

	if (ep->addr.ss_family == AF_INET || ep->addr.ss_family == AF_INET6)
		ep_str = endpoint_str((const struct sockaddr *)&ep->addr);

	printf("        \"index\": %zu,\n", endpoint_index);
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
	printf("        \"tx_rank\": %u,\n", ep->tx_rank);

	printf("        \"weight\": %.4f,\n", ep_static_weight(ep));
	if (ep->has_computed_weight)
		printf("        \"computed_weight\": %.4f,\n", ep->computed_weight);
	else
		printf("        \"computed_weight\": null,\n");
	printf("        \"effective_weight\": %.4f,\n", ep_tx_share(ep, peer, endpoint_index));
	if (has_share)
		printf("        \"selected_share_pct\": %.1f,\n", share_pct);
	else
		printf("        \"selected_share_pct\": null,\n");

	if (ep->has_min_rtt && ep->min_rtt_nanos > 0)
		printf("        \"min_rtt_ms\": %.2f,\n", (double)ep->min_rtt_nanos / 1000000.0);
	else
		printf("        \"min_rtt_ms\": null,\n");

	if (ep->has_fast_rate)
		printf("        \"fast_rate_bps\": %" PRIu64 ",\n", ep->fast_rate_bps);
	else
		printf("        \"fast_rate_bps\": null,\n");

	if (ep->has_btlbw)
		printf("        \"btlbw_bps\": %" PRIu64 ",\n", ep->btlbw_bps);
	else
		printf("        \"btlbw_bps\": null,\n");

	printf("        \"obfuscation\": ");
	json_string(ep_obfuscation_json(ep));
	printf(",\n");

	printf("        \"loss\": {\n");
	printf("          \"tx\": {\n");
	if (ep->has_avg_loss || ep->loss_history_len > 0) {
		printf("            \"avg_per_1000\": %u,\n", ep->avg_loss);
		printf("            \"history\": ");
		json_print_loss_history(ep->loss_history, ep->loss_history_len);
		printf("\n");
	} else {
		printf("            \"avg_per_1000\": null,\n");
		printf("            \"history\": []\n");
	}
	printf("          },\n");
	printf("          \"rx\": {\n");
	if (has_rx_avg) {
		printf("            \"avg_per_1000\": %u,\n", rx_avg);
		printf("            \"history\": ");
		json_print_loss_history(ep->peer_loss_history, ep->peer_loss_history_len);
		printf("\n");
	} else {
		printf("            \"avg_per_1000\": null,\n");
		printf("            \"history\": []\n");
	}
	printf("          }\n");
	printf("        }\n");
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

	printf("    \"endpoint_strategy\": ");
	if (peer->flags & WGPEER_HAS_ENDPOINT_STRATEGY && peer->endpoint_strategy)
		json_string(peer->endpoint_strategy);
	else
		printf("null");
	printf(",\n");

	printf("    \"selected_endpoint_indices\": ");
	if (peer->selected_endpoint_indices && peer->selected_endpoint_indices[0])
		json_string(peer->selected_endpoint_indices);
	else
		printf("null");
	printf(",\n");

	printf("    \"throughput_weighting\": %s,\n",
	       (peer->flags & WGPEER_HAS_THROUGHPUT_WEIGHTING) ?
		       (peer->throughput_weighting ? "true" : "false") :
		       "false");

	printf("    \"rx_bytes\": %" PRIu64 ",\n", peer->rx_bytes);
	printf("    \"tx_bytes\": %" PRIu64 ",\n", peer->tx_bytes);

	printf("    \"endpoints\": [\n");
	for (size_t i = 0; i < peer->endpoints_len; i++) {
		if (i > 0)
			printf(",\n");
		printf("      {\n");
		print_endpoint_json(&peer->endpoints[i], peer, i + 1, now);
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
