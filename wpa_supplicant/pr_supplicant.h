/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PR_SUPPLICANT_H
#define PR_SUPPLICANT_H

#ifdef CONFIG_PR

int wpas_pr_init(struct wpa_global *global, struct wpa_supplicant *wpa_s,
		 const struct wpa_driver_capa *capa);
void wpas_pr_deinit(struct wpa_supplicant *wpa_s);
void wpas_pr_update_dev_addr(struct wpa_supplicant *wpa_s);
void wpas_pr_clear_dev_iks(struct wpa_supplicant *wpa_s);
void wpas_pr_set_dev_ik(struct wpa_supplicant *wpa_s, const u8 *dik,
			const char *password, const u8 *pmk, bool own);
struct wpabuf * wpas_pr_usd_elems(struct wpa_supplicant *wpa_s);
void wpas_pr_process_usd_elems(struct wpa_supplicant *wpa_s, const u8 *buf,
			       u16 buf_len, const u8 *peer_addr,
			       unsigned int freq);
int wpas_pr_initiate_pasn_auth(struct wpa_supplicant *wpa_s,
			       const u8 *peer_addr, int freq, u8 auth_mode,
			       u8 ranging_role, u8 ranging_type,
			       int forced_pr_freq);
int wpas_pr_pasn_auth_tx_status(struct wpa_supplicant *wpa_s, const u8 *data,
				size_t data_len, bool acked);
int wpas_pr_pasn_auth_rx(struct wpa_supplicant *wpa_s,
			 const struct ieee80211_mgmt *mgmt, size_t len,
			 int freq);

#else /* CONFIG_PR */

static inline int wpas_pr_init(struct wpa_global *global,
			       struct wpa_supplicant *wpa_s,
			       const struct wpa_driver_capa *capa)
{
	return -1;
}

static inline void wpas_pr_deinit(struct wpa_supplicant *wpa_s)
{
}

static inline void wpas_pr_update_dev_addr(struct wpa_supplicant *wpa_s)
{
}

static inline void wpas_pr_clear_dev_iks(struct wpa_supplicant *wpa_s)
{
}

static inline void wpas_pr_set_dev_ik(struct wpa_supplicant *wpa_s,
				      const u8 *dik, const char *password,
				      const u8 *pmk, bool own)
{
}

static inline struct wpabuf * wpas_pr_usd_elems(struct wpa_supplicant *wpa_s)
{
	return NULL;
}

static inline int wpas_pr_initiate_pasn_auth(struct wpa_supplicant *wpa_s,
					     const u8 *peer_addr, int freq,
					     u8 auth_mode, u8 ranging_role,
					     u8 ranging_type,
					     int forced_pr_freq)
{
	return 0;
}

static inline int wpas_pr_pasn_auth_tx_status(struct wpa_supplicant *wpa_s,
					      const u8 *data, size_t data_len,
					      bool acked)
{
	return 0;
}

static inline int wpas_pr_pasn_auth_rx(struct wpa_supplicant *wpa_s,
				       const struct ieee80211_mgmt *mgmt,
				       size_t len, int freq)
{
	return 0;
}

#endif /* CONFIG_PR */

#endif /* PR_SUPPLICANT_H */
