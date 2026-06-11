/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Shared endpoint metric helpers for bwg show and bwg metrics.
 */

#ifndef ENDPOINT_STATS_H
#define ENDPOINT_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "containers.h"

double ep_weight_floor(double w);
double ep_static_weight(const struct wgendpoint *ep);
double ep_effective_weight(const struct wgendpoint *ep, const struct wgpeer *peer);
bool ep_in_selected_set(size_t endpoint_index, const char *selected_indices);
double ep_selected_weight_sum(const struct wgpeer *peer, const char *selected_indices);
bool ep_selected_share_pct(const struct wgendpoint *ep, const struct wgpeer *peer, size_t endpoint_index, double *out_pct);
uint16_t ep_loss_history_avg(const uint16_t *history, size_t len);
bool ep_peer_loss_avg(const struct wgendpoint *ep, uint16_t *out_avg);
const char *ep_obf_short(const struct wgendpoint *ep);
void format_bps_short(char *buf, size_t len, uint64_t bps);
const char *ep_obfuscation_json(const struct wgendpoint *ep);

#endif
