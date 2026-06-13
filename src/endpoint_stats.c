/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Shared endpoint metric helpers for bwg show and bwg metrics.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint_stats.h"

double ep_weight_floor(double w)
{
	if (w < WG_WEIGHT_FLOOR)
		return WG_WEIGHT_FLOOR;
	return w;
}

double ep_static_weight(const struct wgendpoint *ep)
{
	if (!ep)
		return WG_WEIGHT_DEFAULT;
	return ep->has_weight ? ep->weight : WG_WEIGHT_DEFAULT;
}

double ep_effective_weight(const struct wgendpoint *ep, const struct wgpeer *peer)
{
	if (!ep)
		return WG_WEIGHT_DEFAULT;
	if (peer && (peer->flags & WGPEER_HAS_THROUGHPUT_WEIGHTING) && peer->throughput_weighting &&
	    ep->has_computed_weight)
		/* Kernel already clamps computed_weight to [WG_WEIGHT_FLOOR, WG_WEIGHT_MAX]. */
		return ep->computed_weight;
	return ep_weight_floor(ep_static_weight(ep));
}

bool ep_in_selected_set(size_t endpoint_index, const char *selected_indices)
{
	char *copy, *val, *tok;

	if (!selected_indices || !selected_indices[0])
		return false;
	copy = strdup(selected_indices);
	if (!copy)
		return false;
	val = copy;
	while ((tok = strsep(&val, ",")) != NULL) {
		char *end;
		unsigned long idx;

		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (!*tok)
			continue;
		idx = strtoul(tok, &end, 10);
		if (*end == '\0' && idx == endpoint_index) {
			free(copy);
			return true;
		}
	}
	free(copy);
	return false;
}

double ep_selected_weight_sum(const struct wgpeer *peer, const char *selected_indices)
{
	char *copy, *val, *tok;
	double sum = 0;

	if (!peer || !selected_indices || !selected_indices[0])
		return 0;
	copy = strdup(selected_indices);
	if (!copy)
		return 0;
	val = copy;
	while ((tok = strsep(&val, ",")) != NULL) {
		char *end;
		unsigned long idx;

		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (!*tok)
			continue;
		idx = strtoul(tok, &end, 10);
		if (*end != '\0' || idx == 0 || idx > peer->endpoints_len)
			continue;
		sum += ep_effective_weight(&peer->endpoints[idx - 1], peer);
	}
	free(copy);
	return sum;
}

bool ep_selected_share_pct(const struct wgendpoint *ep, const struct wgpeer *peer, size_t endpoint_index, double *out_pct)
{
	double sum;

	if (!out_pct || !ep || !peer)
		return false;
	/* Selected for TX (sel#N / tx_rank), not blue — blue is emergency one-way mode. */
	if (ep->tx_rank == 0 && !ep_in_selected_set(endpoint_index, peer->selected_endpoint_indices))
		return false;
	sum = ep_selected_weight_sum(peer, peer->selected_endpoint_indices);
	if (sum <= 0)
		return false;
	*out_pct = ep_effective_weight(ep, peer) / sum * 100.0;
	return true;
}

uint16_t ep_loss_history_avg(const uint16_t *history, size_t len)
{
	unsigned int sum = 0;
	size_t i;

	if (len == 0)
		return 0;
	for (i = 0; i < len; i++)
		sum += history[i];
	return (uint16_t)((sum + len / 2) / len);
}

bool ep_peer_loss_avg(const struct wgendpoint *ep, uint16_t *out_avg)
{
	if (!ep || !out_avg || ep->peer_loss_history_len == 0)
		return false;
	*out_avg = ep_loss_history_avg(ep->peer_loss_history, ep->peer_loss_history_len);
	return true;
}

const char *ep_obf_short(const struct wgendpoint *ep)
{
	static char buf[280];

	if (!ep)
		return "he";
	if (ep->obf_type != 1)
		return "he";
	if (ep->obf_sni[0]) {
		snprintf(buf, sizeof(buf), "quic(%s)", ep->obf_sni);
		return buf;
	}
	return "quic";
}

const char *ep_obfuscation_json(const struct wgendpoint *ep)
{
	static char buf[280];

	if (!ep)
		return "high-entropy";
	if (ep->obf_type != 1)
		return "high-entropy";
	if (ep->obf_sni[0]) {
		snprintf(buf, sizeof(buf), "quic:%s", ep->obf_sni);
		return buf;
	}
	return "quic";
}

void format_bps_short(char *buf, size_t len, uint64_t bps)
{
	if (!buf || len == 0)
		return;
	if (bps >= 1000000000ULL)
		snprintf(buf, len, "%.1fG", (double)bps / 1e9);
	else if (bps >= 1000000ULL)
		snprintf(buf, len, "%.1fM", (double)bps / 1e6);
	else if (bps >= 1000ULL)
		snprintf(buf, len, "%.1fK", (double)bps / 1e3);
	else
		snprintf(buf, len, "%" PRIu64, bps);
}
