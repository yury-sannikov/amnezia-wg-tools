// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>

#include "containers.h"
#include "ipc.h"
#include "terminal.h"
#include "encoding.h"
#include "subcommands.h"

static int peer_cmp(const void *first, const void *second)
{
	time_t diff;
	const struct wgpeer *a = *(void *const *)first, *b = *(void *const *)second;

	if (!a->last_handshake_time.tv_sec && !a->last_handshake_time.tv_nsec && (b->last_handshake_time.tv_sec || b->last_handshake_time.tv_nsec))
		return 1;
	if (!b->last_handshake_time.tv_sec && !b->last_handshake_time.tv_nsec && (a->last_handshake_time.tv_sec || a->last_handshake_time.tv_nsec))
		return -1;
	diff = a->last_handshake_time.tv_sec - b->last_handshake_time.tv_sec;
	if (!diff)
		diff = a->last_handshake_time.tv_nsec - b->last_handshake_time.tv_nsec;
	if (diff < 0)
		return 1;
	if (diff > 0)
		return -1;
	return 0;
}

/* This, hilariously, is not the right way to sort a linked list... */
static void sort_peers(struct wgdevice *device)
{
	size_t peer_count = 0, i = 0;
	struct wgpeer *peer, **peers;

	for_each_wgpeer(device, peer)
		++peer_count;
	if (!peer_count)
		return;
	peers = calloc(peer_count, sizeof(*peers));
	if (!peers)
		return;
	for_each_wgpeer(device, peer)
		peers[i++] = peer;
	qsort(peers, peer_count, sizeof(*peers), peer_cmp);
	device->first_peer = peers[0];
	for (i = 1; i < peer_count; ++i) {
		peers[i - 1]->next_peer = peers[i];
	}
	peers[peer_count - 1]->next_peer = NULL;
	free(peers);
}

static char *key(const uint8_t key[static WG_KEY_LEN])
{
	static char base64[WG_KEY_LEN_BASE64];

	key_to_base64(base64, key);
	return base64;
}

static const char *maybe_key(const uint8_t maybe_key[static WG_KEY_LEN], bool have_it)
{
	if (!have_it)
		return "(none)";
	return key(maybe_key);
}

static const char *masked_key(const uint8_t masked_key[static WG_KEY_LEN])
{
	const char *var = getenv("WG_HIDE_KEYS");

	if (var && !strcmp(var, "never"))
		return key(masked_key);
	return "(hidden)";
}

static char *ip(const struct wgallowedip *ip)
{
	static char buf[INET6_ADDRSTRLEN + 1];

	memset(buf, 0, INET6_ADDRSTRLEN + 1);
	if (ip->family == AF_INET)
		inet_ntop(AF_INET, &ip->ip4, buf, INET6_ADDRSTRLEN);
	else if (ip->family == AF_INET6)
		inet_ntop(AF_INET6, &ip->ip6, buf, INET6_ADDRSTRLEN);
	return buf;
}

static char *endpoint(const struct sockaddr *addr)
{
	char host[4096 + 1];
	char service[512 + 1];
	static char buf[sizeof(host) + sizeof(service) + 4];
	int ret;
	socklen_t addr_len = 0;

	memset(buf, 0, sizeof(buf));
	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else if (addr->sa_family == AF_INET6)
		addr_len = sizeof(struct sockaddr_in6);

	ret = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST);
	if (ret) {
		strncpy(buf, gai_strerror(ret), sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
	} else
		snprintf(buf, sizeof(buf), (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
	return buf;
}

static const char *endpoint_state_string(uint32_t state)
{
	switch (state) {
	case 1:
		return "green";
	case 2:
		return "error";
	default:
		return "dark";
	}
}

static size_t pretty_time(char *buf, const size_t len, unsigned long long left)
{
	size_t offset = 0;
	unsigned long long years, days, hours, minutes, seconds;

	years = left / (365 * 24 * 60 * 60);
	left = left % (365 * 24 * 60 * 60);
	days = left / (24 * 60 * 60);
	left = left % (24 * 60 * 60);
	hours = left / (60 * 60);
	left = left % (60 * 60);
	minutes = left / 60;
	seconds = left % 60;

	if (years)
		offset += snprintf(buf + offset, len - offset, "%s%llu " TERMINAL_FG_CYAN "year%s" TERMINAL_RESET, offset ? ", " : "", years, years == 1 ? "" : "s");
	if (days)
		offset += snprintf(buf + offset, len - offset, "%s%llu " TERMINAL_FG_CYAN  "day%s" TERMINAL_RESET, offset ? ", " : "", days, days == 1 ? "" : "s");
	if (hours)
		offset += snprintf(buf + offset, len - offset, "%s%llu " TERMINAL_FG_CYAN  "hour%s" TERMINAL_RESET, offset ? ", " : "", hours, hours == 1 ? "" : "s");
	if (minutes)
		offset += snprintf(buf + offset, len - offset, "%s%llu " TERMINAL_FG_CYAN "minute%s" TERMINAL_RESET, offset ? ", " : "", minutes, minutes == 1 ? "" : "s");
	if (seconds)
		offset += snprintf(buf + offset, len - offset, "%s%llu " TERMINAL_FG_CYAN  "second%s" TERMINAL_RESET, offset ? ", " : "", seconds, seconds == 1 ? "" : "s");

	return offset;
}

static char *ago(const struct timespec64 *t)
{
	static char buf[1024];
	size_t offset;
	time_t now = time(NULL);

	if (now == t->tv_sec)
		strncpy(buf, "Now", sizeof(buf) - 1);
	else if (now < t->tv_sec)
		strncpy(buf, "(" TERMINAL_FG_RED "System clock wound backward; connection problems may ensue." TERMINAL_RESET ")", sizeof(buf) - 1);
	else {
		offset = pretty_time(buf, sizeof(buf), now - t->tv_sec);
		strncpy(buf + offset, " ago", sizeof(buf) - offset - 1);
	}
	buf[sizeof(buf) - 1] = '\0';

	return buf;
}

static const char *latest_rx_str(const struct wgendpoint *ep)
{
	if (!ep->last_received_time.tv_sec && !ep->last_received_time.tv_nsec)
		return "never";
	return ago(&ep->last_received_time);
}

static char *every(uint16_t seconds)
{
	static char buf[1024] = "every ";

	pretty_time(buf + strlen("every "), sizeof(buf) - strlen("every ") - 1, seconds);
	return buf;
}

static char *bytes(uint64_t b)
{
	static char buf[1024];

	if (b < 1024ULL)
		snprintf(buf, sizeof(buf), "%u " TERMINAL_FG_CYAN "B" TERMINAL_RESET, (unsigned int)b);
	else if (b < 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf), "%.2f " TERMINAL_FG_CYAN "KiB" TERMINAL_RESET, (double)b / 1024);
	else if (b < 1024ULL * 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf), "%.2f " TERMINAL_FG_CYAN "MiB" TERMINAL_RESET, (double)b / (1024 * 1024));
	else if (b < 1024ULL * 1024ULL * 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf), "%.2f " TERMINAL_FG_CYAN "GiB" TERMINAL_RESET, (double)b / (1024 * 1024 * 1024));
	else
		snprintf(buf, sizeof(buf), "%.2f " TERMINAL_FG_CYAN "TiB" TERMINAL_RESET, (double)b / (1024 * 1024 * 1024) / 1024);

	return buf;
}

static const char *rtt_str(int64_t rtt_nanos)
{
	static char buf[64];

	if (rtt_nanos <= 0)
		return "(none)";
	if (rtt_nanos < 1000)
		snprintf(buf, sizeof(buf), "%" PRId64 " ns", rtt_nanos);
	else if (rtt_nanos < 1000000)
		snprintf(buf, sizeof(buf), "%.2f µs", (double)rtt_nanos / 1000);
	else if (rtt_nanos < 1000000000)
		snprintf(buf, sizeof(buf), "%.2f ms", (double)rtt_nanos / 1000000);
	else
		snprintf(buf, sizeof(buf), "%.2f s", (double)rtt_nanos / 1000000000);
	return buf;
}

/* Map loss_per_1k (0..1000) to braille dots: 0 = full (6 dots), 500+ = 1 dot, 1000 = empty. Logarithmic scale. */
static void loss_to_braille_utf8(char buf[4], uint16_t loss_per_1k)
{
	int dots;
	double scaled;

	if (loss_per_1k >= 1000) {
		buf[0] = ' ';
		buf[1] = '\0';
		return;
	}
	if (loss_per_1k == 0) {
		dots = 6;
	} else {
		/* Logarithmic: small loss visible. 500+ -> 1 dot. */
		scaled = log10(1.0 + 10.0 * (double)loss_per_1k) / log10(10001.0);
		dots = 6 - (int)(5.0 * scaled);
		if (dots < 1)
			dots = 1;
		if (dots > 6)
			dots = 6;
	}
	/* Braille U+2800 + pattern. Dots 1..N = (1<<N)-1. */
	{
		uint32_t codepoint = 0x2800 + ((1 << dots) - 1);
		buf[0] = (char)(0xE0 | (codepoint >> 12));
		buf[1] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
		buf[2] = (char)(0x80 | (codepoint & 0x3F));
		buf[3] = '\0';
	}
}

/* Print loss line: fixed-width number (4 chars) so TX and RX bars align. Pad to 16 chars total. */
static void print_loss_line(const char *label, uint16_t current, const uint16_t *history, size_t len)
{
	char braille[4];
	size_t i;

	terminal_printf("    " TERMINAL_BOLD "%s" TERMINAL_RESET ": %4u/1000   ", label, (unsigned int)current);
	for (i = 0; i < len; i++) {
		loss_to_braille_utf8(braille, history[i]);
		terminal_printf("%s", braille);
	}
	for (i = len; i < WG_LOSS_HISTORY_SIZE; i++)
		terminal_printf(" ");
	terminal_printf("\n");
}

static const char *COMMAND_NAME;
static void show_usage(void)
{
	fprintf(stderr, "Usage: %s %s { <interface> | all | interfaces } [public-key | private-key | listen-control-port | listen-data-ports | fwmark | peers | preshared-keys | endpoints | endpoint-stats | control-endpoints | allowed-ips | latest-handshakes | transfer | control-transfer | persistent-keepalive | dump | jc | jmin | jmax | s1 | s2 | s3 | s4 | h1 | h2 | h3 | h4 | i1 | i2 | i3 | i4 | i5]\n", PROG_NAME, COMMAND_NAME);
}

static void pretty_print(struct wgdevice *device)
{
	struct wgpeer *peer;
	struct wgallowedip *allowedip;

	terminal_printf(TERMINAL_RESET);
	terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "interface" TERMINAL_RESET ": " TERMINAL_FG_GREEN "%s" TERMINAL_RESET "\n", device->name);
	if (device->flags & WGDEVICE_HAS_PUBLIC_KEY)
		terminal_printf("  " TERMINAL_BOLD "public key" TERMINAL_RESET ": %s\n", key(device->public_key));
	if (device->flags & WGDEVICE_HAS_PRIVATE_KEY)
		terminal_printf("  " TERMINAL_BOLD "private key" TERMINAL_RESET ": %s\n", masked_key(device->private_key));
	if (device->listen_port || device->listen_data_ports) {
		terminal_printf("  " TERMINAL_BOLD "control port" TERMINAL_RESET ": %u\n", device->listen_port);
		if (device->listen_data_ports)
			terminal_printf("  " TERMINAL_BOLD "data ports" TERMINAL_RESET ": %s\n", device->listen_data_ports);
	}
	if (device->fwmark)
		terminal_printf("  " TERMINAL_BOLD "fwmark" TERMINAL_RESET ": 0x%x\n", device->fwmark);
	if (device->junk_packet_count)
		terminal_printf("  " TERMINAL_BOLD "jc" TERMINAL_RESET ": %u\n", device->junk_packet_count);
	if (device->junk_packet_min_size)
		terminal_printf("  " TERMINAL_BOLD "jmin" TERMINAL_RESET ": %u\n", device->junk_packet_min_size);
	if (device->junk_packet_max_size)
		terminal_printf("  " TERMINAL_BOLD "jmax" TERMINAL_RESET ": %u\n", device->junk_packet_max_size);
	if (device->init_packet_junk_size)
		terminal_printf("  " TERMINAL_BOLD "s1" TERMINAL_RESET ": %u\n", device->init_packet_junk_size);
	if (device->response_packet_junk_size)
		terminal_printf("  " TERMINAL_BOLD "s2" TERMINAL_RESET ": %u\n", device->response_packet_junk_size);
	if (device->cookie_reply_packet_junk_size)
		terminal_printf("  " TERMINAL_BOLD "s3" TERMINAL_RESET ": %u\n", device->cookie_reply_packet_junk_size);
	if (device->transport_packet_junk_size)
		terminal_printf("  " TERMINAL_BOLD "s4" TERMINAL_RESET ": %u\n", device->transport_packet_junk_size);
	if (device->init_packet_magic_header)
		terminal_printf("  " TERMINAL_BOLD "h1" TERMINAL_RESET ": %s\n", device->init_packet_magic_header);
	if (device->response_packet_magic_header)
		terminal_printf("  " TERMINAL_BOLD "h2" TERMINAL_RESET ": %s\n", device->response_packet_magic_header);
	if (device->underload_packet_magic_header)
		terminal_printf("  " TERMINAL_BOLD "h3" TERMINAL_RESET ": %s\n", device->underload_packet_magic_header);
	if (device->transport_packet_magic_header)
		terminal_printf("  " TERMINAL_BOLD "h4" TERMINAL_RESET ": %s\n", device->transport_packet_magic_header);
	if (device->i1)
		terminal_printf("  " TERMINAL_BOLD "i1" TERMINAL_RESET ": %s\n", device->i1);
	if (device->i2)
		terminal_printf("  " TERMINAL_BOLD "i2" TERMINAL_RESET ": %s\n", device->i2);
	if (device->i3)
		terminal_printf("  " TERMINAL_BOLD "i3" TERMINAL_RESET ": %s\n", device->i3);
	if (device->i4)
		terminal_printf("  " TERMINAL_BOLD "i4" TERMINAL_RESET ": %s\n", device->i4);
	if (device->i5)
		terminal_printf("  " TERMINAL_BOLD "i5" TERMINAL_RESET ": %s\n", device->i5);

	if (device->first_peer) {
		sort_peers(device);
		terminal_printf("\n");
	}
	for_each_wgpeer(device, peer) {
		terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "peer" TERMINAL_RESET ": " TERMINAL_FG_YELLOW "%s" TERMINAL_RESET "\n", key(peer->public_key));
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY)
			terminal_printf("  " TERMINAL_BOLD "preshared key" TERMINAL_RESET ": %s\n", masked_key(peer->preshared_key));
		if ((peer->flags & WGPEER_HAS_CONTROL_ENDPOINT) &&
		    (peer->control_endpoint.addr.sa_family == AF_INET || peer->control_endpoint.addr.sa_family == AF_INET6)) {
			char ctrl_ep[4096 + 512 + 4];
			strncpy(ctrl_ep, endpoint(&peer->control_endpoint.addr), sizeof(ctrl_ep) - 1);
			ctrl_ep[sizeof(ctrl_ep) - 1] = '\0';
			terminal_printf("  " TERMINAL_BOLD "control" TERMINAL_RESET ": %s\n", ctrl_ep);
			terminal_printf("    " TERMINAL_BOLD "camouflage" TERMINAL_RESET ": " TERMINAL_FG_RED "%s" TERMINAL_RESET "\n", "dns");

			if (peer->last_handshake_time.tv_sec)
    			terminal_printf("    " TERMINAL_BOLD "latest handshake" TERMINAL_RESET ": %s\n", ago(&peer->last_handshake_time));
	     	if (peer->control_rx_bytes || peer->control_tx_bytes) {
			    terminal_printf("    " TERMINAL_BOLD "transfer" TERMINAL_RESET ": ");
			    terminal_printf("%s received, ", bytes(peer->control_rx_bytes));
			    terminal_printf("%s sent\n", bytes(peer->control_tx_bytes));
		    }
		}
		for (size_t i = 0; i < peer->endpoints_len; i++) {
			struct wgendpoint *ep = &peer->endpoints[i];
			if (ep->addr.ss_family == AF_INET || ep->addr.ss_family == AF_INET6) {
				char data_ep[4096 + 512 + 4];
				strncpy(data_ep, endpoint((struct sockaddr *)&ep->addr), sizeof(data_ep) - 1);
				data_ep[sizeof(data_ep) - 1] = '\0';
				terminal_printf("  " TERMINAL_BOLD "endpoint%zu" TERMINAL_RESET ": %s\n", i + 1, data_ep);
				terminal_printf("    " TERMINAL_BOLD "camouflage" TERMINAL_RESET ": " TERMINAL_FG_GREEN "%s" TERMINAL_RESET "\n", "bwg:high-entropy");
				terminal_printf("    " TERMINAL_BOLD "state" TERMINAL_RESET ": ");
				switch (ep->state) {
				case 1:
					terminal_printf(TERMINAL_FG_GREEN "●" TERMINAL_RESET " %s,\t" TERMINAL_BOLD "latest rx" TERMINAL_RESET ": %s\n", endpoint_state_string(ep->state), latest_rx_str(ep));
					break;
				case 2:
					terminal_printf(TERMINAL_FG_RED "●" TERMINAL_RESET " %s,\t" TERMINAL_BOLD "latest rx" TERMINAL_RESET ": %s\n", endpoint_state_string(ep->state), latest_rx_str(ep));
					break;
				default:
					terminal_printf(TERMINAL_FG_GRAY "●" TERMINAL_RESET " %s,\t" TERMINAL_BOLD "latest rx" TERMINAL_RESET ": %s\n", endpoint_state_string(ep->state), latest_rx_str(ep));
					break;
				}
				terminal_printf("    " TERMINAL_BOLD "transfer" TERMINAL_RESET ": ");
				terminal_printf("%s received, ", bytes(ep->rx_bytes));
				terminal_printf("%s sent\n", bytes(ep->tx_bytes));
				if (ep->rtt_nanos > 0)
					terminal_printf("    " TERMINAL_BOLD "RTT" TERMINAL_RESET ": %s\n", rtt_str(ep->rtt_nanos));
				if (ep->loss_history_len > 0) {
					uint16_t tx_current = ep->loss_history[ep->loss_history_len - 1];
					print_loss_line("TX loss", tx_current, ep->loss_history, ep->loss_history_len);
				}
				if (ep->peer_loss_history_len > 0) {
					uint16_t rx_current = ep->peer_loss_history[ep->peer_loss_history_len - 1];
					print_loss_line("RX loss", rx_current, ep->peer_loss_history, ep->peer_loss_history_len);
				}
			}
		}
		terminal_printf("  " TERMINAL_BOLD "allowed ips" TERMINAL_RESET ": ");
		if (peer->first_allowedip) {
			for_each_wgallowedip(peer, allowedip)
				terminal_printf("%s" TERMINAL_FG_CYAN "/" TERMINAL_RESET "%u%s", ip(allowedip), allowedip->cidr, allowedip->next_allowedip ? ", " : "\n");
		} else
			terminal_printf("(none)\n");
		if (peer->rx_bytes || peer->tx_bytes) {
			terminal_printf("  " TERMINAL_BOLD "data transfer" TERMINAL_RESET ": ");
			terminal_printf("%s received, ", bytes(peer->rx_bytes));
			terminal_printf("%s sent\n", bytes(peer->tx_bytes));
		}
		if (peer->persistent_keepalive_interval)
			terminal_printf("  " TERMINAL_BOLD "persistent keepalive" TERMINAL_RESET ": %s\n", every(peer->persistent_keepalive_interval));
		if (peer->next_peer)
			terminal_printf("\n");
	}
}

static void dump_print(struct wgdevice *device, bool with_interface)
{
	struct wgpeer *peer;
	struct wgallowedip *allowedip;

	if (with_interface)
		printf("%s\t", device->name);
	printf("%s\t", maybe_key(device->private_key, device->flags & WGDEVICE_HAS_PRIVATE_KEY));
	printf("%s\t", maybe_key(device->public_key, device->flags & WGDEVICE_HAS_PUBLIC_KEY));
	printf("%u\t", device->listen_port);
	fputs(device->listen_data_ports ? device->listen_data_ports : "(null)", stdout);
	fputc('\t', stdout);
	printf("%u\t", device->junk_packet_count);
	printf("%u\t", device->junk_packet_min_size);
	printf("%u\t", device->junk_packet_max_size);
	printf("%u\t", device->init_packet_junk_size);
	printf("%u\t", device->response_packet_junk_size);
	printf("%u\t", device->cookie_reply_packet_junk_size);
	printf("%u\t", device->transport_packet_junk_size);
	fputs(device->init_packet_magic_header ? device->init_packet_magic_header : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->response_packet_magic_header ? device->response_packet_magic_header : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->underload_packet_magic_header ? device->underload_packet_magic_header : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->transport_packet_magic_header ? device->transport_packet_magic_header : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->i1 ? device->i1 : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->i2 ? device->i2 : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->i3 ? device->i3 : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->i4 ? device->i4 : "(null)", stdout);
	fputc('\t', stdout);
	fputs(device->i5 ? device->i5 : "(null)", stdout);
	fputc('\t', stdout);

	if (device->fwmark)
		printf("0x%x\n", device->fwmark);
	else
		printf("off\n");
	for_each_wgpeer(device, peer) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\t", key(peer->public_key));
		printf("%s\t", maybe_key(peer->preshared_key, peer->flags & WGPEER_HAS_PRESHARED_KEY));
		if (peer->endpoints_len) {
			for (size_t i = 0; i < peer->endpoints_len; i++) {
				struct wgendpoint *ep = &peer->endpoints[i];
				if (ep->addr.ss_family == AF_INET || ep->addr.ss_family == AF_INET6)
					printf("%s%s", endpoint((struct sockaddr *)&ep->addr), i + 1 < peer->endpoints_len ? "," : "\t");
				else
					printf("(none)%s", i + 1 < peer->endpoints_len ? "," : "\t");
			}
		} else {
			printf("(none)\t");
		}
		/* Always output control endpoint (dual-port mode) */
		if ((peer->flags & WGPEER_HAS_CONTROL_ENDPOINT) &&
		    (peer->control_endpoint.addr.sa_family == AF_INET || peer->control_endpoint.addr.sa_family == AF_INET6))
			printf("%s\t", endpoint(&peer->control_endpoint.addr));
		else if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
			printf("%s\t", endpoint(&peer->endpoint.addr)); /* fallback to data endpoint if control not set */
		else
			printf("(none)\t");
		if (peer->endpoints_len) {
			for (size_t i = 0; i < peer->endpoints_len; i++) {
				struct wgendpoint *ep = &peer->endpoints[i];
				printf("%s%s", endpoint_state_string(ep->state), i + 1 < peer->endpoints_len ? "," : "\t");
			}
			for (size_t i = 0; i < peer->endpoints_len; i++) {
				struct wgendpoint *ep = &peer->endpoints[i];
				printf("%" PRIu64 "%s", (uint64_t)ep->rx_bytes, i + 1 < peer->endpoints_len ? "," : "\t");
			}
			for (size_t i = 0; i < peer->endpoints_len; i++) {
				struct wgendpoint *ep = &peer->endpoints[i];
				printf("%" PRIu64 "%s", (uint64_t)ep->tx_bytes, i + 1 < peer->endpoints_len ? "," : "\t");
			}
			for (size_t i = 0; i < peer->endpoints_len; i++) {
				struct wgendpoint *ep = &peer->endpoints[i];
				printf("%" PRId64 "%s", (int64_t)ep->rtt_nanos, i + 1 < peer->endpoints_len ? "," : "\t");
			}
		} else {
			printf("(none)\t(none)\t(none)\t(none)\t");
		}
		if (peer->first_allowedip) {
			for_each_wgallowedip(peer, allowedip)
				printf("%s/%u%c", ip(allowedip), allowedip->cidr, allowedip->next_allowedip ? ',' : '\t');
		} else
			printf("(none)\t");
		printf("%llu\t", (unsigned long long)peer->last_handshake_time.tv_sec);
		printf("%" PRIu64 "\t%" PRIu64 "\t", (uint64_t)peer->rx_bytes, (uint64_t)peer->tx_bytes);
		printf("%" PRIu64 "\t%" PRIu64 "\t", (uint64_t)peer->control_rx_bytes, (uint64_t)peer->control_tx_bytes);
		if (peer->persistent_keepalive_interval)
			printf("%u\n", peer->persistent_keepalive_interval);
		else
			printf("off\n");
	}
}

static bool ugly_print(struct wgdevice *device, const char *param, bool with_interface)
{
	struct wgpeer *peer;
	struct wgallowedip *allowedip;

	if (!strcmp(param, "public-key")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", maybe_key(device->public_key, device->flags & WGDEVICE_HAS_PUBLIC_KEY));
	} else if (!strcmp(param, "private-key")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", maybe_key(device->private_key, device->flags & WGDEVICE_HAS_PRIVATE_KEY));
	} else if (!strcmp(param, "listen-control-port")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->listen_port);
	} else if (!strcmp(param, "listen-data-ports")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->listen_data_ports ? device->listen_data_ports : "(none)");
	} else if (!strcmp(param, "fwmark")) {
		if (with_interface)
			printf("%s\t", device->name);
		if (device->fwmark)
			printf("0x%x\n", device->fwmark);
		else
			printf("off\n");
	} else if (!strcmp(param, "jc")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->junk_packet_count);
	 } else if (!strcmp(param, "jmin")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->junk_packet_min_size);
	 } else if (!strcmp(param, "jmax")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->junk_packet_max_size);
	 } else if (!strcmp(param, "s1")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->init_packet_junk_size);
	 } else if (!strcmp(param, "s2")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->response_packet_junk_size);
	 } else if (!strcmp(param, "s3")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->cookie_reply_packet_junk_size);
	 } else if (!strcmp(param, "s4")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%u\n", device->transport_packet_junk_size);
	 } else if (!strcmp(param, "h1")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->init_packet_magic_header);
	 } else if (!strcmp(param, "h2")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->response_packet_magic_header);
	 } else if (!strcmp(param, "h3")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->underload_packet_magic_header);
	 } else if (!strcmp(param, "h4")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->transport_packet_magic_header);
	} else if (!strcmp(param, "i1")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->i1);
	} else if (!strcmp(param, "i2")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->i2);
	} else if (!strcmp(param, "i3")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->i3);
	} else if (!strcmp(param, "i4")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->i4);
	} else if (!strcmp(param, "i5")) {
		if (with_interface)
			printf("%s\t", device->name);
		printf("%s\n", device->i5);
	 } else if (!strcmp(param, "endpoints")) {
		for_each_wgpeer(device, peer) {
			if (peer->endpoints_len) {
				for (size_t i = 0; i < peer->endpoints_len; i++) {
					struct wgendpoint *ep = &peer->endpoints[i];
					if (with_interface)
						printf("%s\t", device->name);
					printf("%s\t", key(peer->public_key));
					if (ep->addr.ss_family == AF_INET || ep->addr.ss_family == AF_INET6)
						printf("%s\n", endpoint((struct sockaddr *)&ep->addr));
					else
						printf("(none)\n");
				}
			} else {
				if (with_interface)
					printf("%s\t", device->name);
				printf("%s\t(none)\n", key(peer->public_key));
			}
		}
	} else if (!strcmp(param, "endpoint-stats")) {
		for_each_wgpeer(device, peer) {
			if (peer->endpoints_len) {
				for (size_t i = 0; i < peer->endpoints_len; i++) {
					struct wgendpoint *ep = &peer->endpoints[i];
					if (with_interface)
						printf("%s\t", device->name);
					printf("%s\t%zu\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRId64 "\n", key(peer->public_key), i + 1, endpoint_state_string(ep->state), (uint64_t)ep->rx_bytes, (uint64_t)ep->tx_bytes, (int64_t)ep->rtt_nanos);
				}
			} else {
				if (with_interface)
					printf("%s\t", device->name);
				printf("%s\t0\t(none)\t0\t0\t0\n", key(peer->public_key));
			}
		}
	} else if (!strcmp(param, "control-endpoints")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t", key(peer->public_key));
			/* Always output control endpoint */
			if ((peer->flags & WGPEER_HAS_CONTROL_ENDPOINT) &&
			    (peer->control_endpoint.addr.sa_family == AF_INET || peer->control_endpoint.addr.sa_family == AF_INET6))
				printf("%s\n", endpoint(&peer->control_endpoint.addr));
			else if (peer->endpoints_len > 0 &&
			         (peer->endpoints[0].addr.ss_family == AF_INET || peer->endpoints[0].addr.ss_family == AF_INET6))
				printf("%s\n", endpoint((struct sockaddr *)&peer->endpoints[0].addr)); /* fallback */
			else
				printf("(none)\n");
		}
	} else if (!strcmp(param, "allowed-ips")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t", key(peer->public_key));
			if (peer->first_allowedip) {
				for_each_wgallowedip(peer, allowedip)
					printf("%s/%u%c", ip(allowedip), allowedip->cidr, allowedip->next_allowedip ? ' ' : '\n');
			} else
				printf("(none)\n");
		}
	} else if (!strcmp(param, "latest-handshakes")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t%llu\n", key(peer->public_key), (unsigned long long)peer->last_handshake_time.tv_sec);
		}
	} else if (!strcmp(param, "transfer")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t%" PRIu64 "\t%" PRIu64 "\n", key(peer->public_key), (uint64_t)peer->rx_bytes, (uint64_t)peer->tx_bytes);
		}
	} else if (!strcmp(param, "control-transfer")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t%" PRIu64 "\t%" PRIu64 "\n", key(peer->public_key), (uint64_t)peer->control_rx_bytes, (uint64_t)peer->control_tx_bytes);
		}
	} else if (!strcmp(param, "persistent-keepalive")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			if (peer->persistent_keepalive_interval)
				printf("%s\t%u\n", key(peer->public_key), peer->persistent_keepalive_interval);
			else
				printf("%s\toff\n", key(peer->public_key));
		}
	} else if (!strcmp(param, "preshared-keys")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\t", key(peer->public_key));
			printf("%s\n", maybe_key(peer->preshared_key, peer->flags & WGPEER_HAS_PRESHARED_KEY));
		}
	} else if (!strcmp(param, "peers")) {
		for_each_wgpeer(device, peer) {
			if (with_interface)
				printf("%s\t", device->name);
			printf("%s\n", key(peer->public_key));
		}
	} else if (!strcmp(param, "dump"))
		dump_print(device, with_interface);
	else {
		fprintf(stderr, "Invalid parameter: `%s'\n", param);
		show_usage();
		return false;
	}
	return true;
}

int show_main(int argc, const char *argv[])
{
	int ret = 0;

	COMMAND_NAME = argv[0];

	if (argc > 3) {
		show_usage();
		return 1;
	}

	if (argc == 1 || !strcmp(argv[1], "all")) {
		char *interfaces = ipc_list_devices(), *interface;

		if (!interfaces) {
			perror("Unable to list interfaces");
			return 1;
		}
		ret = !!*interfaces;
		interface = interfaces;
		for (size_t len = 0; (len = strlen(interface)); interface += len + 1) {
			struct wgdevice *device = NULL;

			if (ipc_get_device(&device, interface) < 0) {
				fprintf(stderr, "Unable to access interface %s: %s\n", interface, strerror(errno));
				continue;
			}
			if (argc == 3) {
				if (!ugly_print(device, argv[2], true)) {
					ret = 1;
					free_wgdevice(device);
					break;
				}
			} else {
				pretty_print(device);
				if (strlen(interface + len + 1))
					printf("\n");
			}
			free_wgdevice(device);
			ret = 0;
		}
		free(interfaces);
	} else if (!strcmp(argv[1], "interfaces")) {
		char *interfaces, *interface;

		if (argc > 2) {
			show_usage();
			return 1;
		}
		interfaces = ipc_list_devices();
		if (!interfaces) {
			perror("Unable to list interfaces");
			return 1;
		}
		interface = interfaces;
		for (size_t len = 0; (len = strlen(interface)); interface += len + 1)
			printf("%s%c", interface, strlen(interface + len + 1) ? ' ' : '\n');
		free(interfaces);
	} else if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")))
		show_usage();
	else {
		struct wgdevice *device = NULL;

		if (ipc_get_device(&device, argv[1]) < 0) {
			perror("Unable to access interface");
			return 1;
		}
		if (argc == 3) {
			if (!ugly_print(device, argv[2], false))
				ret = 1;
		} else
			pretty_print(device);
		free_wgdevice(device);
	}
	return ret;
}
