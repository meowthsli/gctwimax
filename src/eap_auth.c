/*
 * This is a reverse-engineered driver for mobile WiMAX (802.16e) devices
 * based on GCT Semiconductor GDM7213 & GDM7205 chip.
 * Copyright (�) 2010 Yaroslav Levandovsky <leyarx@gmail.com>
 *
 * EAP peer code from wpa_supplicant
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "util/includes.h"

#include "util/common.h"

#include "eap.h"
#include "eap_methods.h"
#include "eap_config.h"
#include "util/wpabuf.h"

#include "eap_auth.h"

char *eap_outer_nai = "mac@freshtel.com.ua";
char *eap_login = "";
char *eap_pass = "";
char *eap_client_cert = "";
char *eap_ca_path = "";
int eap_type = 5;

struct eap_peer_ctx {
	Boolean eapSuccess;
	Boolean eapRestart;
	Boolean eapFail;
	Boolean eapResp;
	Boolean eapNoResp;
	Boolean eapReq;
	Boolean portEnabled;
	Boolean altAccept; /* for EAP */
	Boolean altReject; /* for EAP */

	struct wpabuf *eapReqData; /* for EAP */

	unsigned int idleWhile; /* for EAP state machine */

	struct eap_peer_config eap_config;
	struct eap_sm *eap;
};


static struct eap_peer_ctx eap_ctx;


static struct eap_peer_config * peer_get_config(void *ctx)
{
	struct eap_peer_ctx *peer = ctx;
	return &peer->eap_config;
}


static Boolean peer_get_bool(void *ctx, enum eapol_bool_var variable)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return FALSE;
	switch (variable) {
	case EAPOL_eapSuccess:
		return peer->eapSuccess;
	case EAPOL_eapRestart:
		return peer->eapRestart;
	case EAPOL_eapFail:
		return peer->eapFail;
	case EAPOL_eapResp:
		return peer->eapResp;
	case EAPOL_eapNoResp:
		return peer->eapNoResp;
	case EAPOL_eapReq:
		return peer->eapReq;
	case EAPOL_portEnabled:
		return peer->portEnabled;
	case EAPOL_altAccept:
		return peer->altAccept;
	case EAPOL_altReject:
		return peer->altReject;
	}
	return FALSE;
}


static void peer_set_bool(void *ctx, enum eapol_bool_var variable,
			  Boolean value)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return;
	switch (variable) {
	case EAPOL_eapSuccess:
		peer->eapSuccess = value;
		break;
	case EAPOL_eapRestart:
		peer->eapRestart = value;
		break;
	case EAPOL_eapFail:
		peer->eapFail = value;
		break;
	case EAPOL_eapResp:
		peer->eapResp = value;
		break;
	case EAPOL_eapNoResp:
		peer->eapNoResp = value;
		break;
	case EAPOL_eapReq:
		peer->eapReq = value;
		break;
	case EAPOL_portEnabled:
		peer->portEnabled = value;
		break;
	case EAPOL_altAccept:
		peer->altAccept = value;
		break;
	case EAPOL_altReject:
		peer->altReject = value;
		break;
	}
}


static unsigned int peer_get_int(void *ctx, enum eapol_int_var variable)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return 0;
	switch (variable) {
	case EAPOL_idleWhile:
		return peer->idleWhile;
	}
	return 0;
}


static void peer_set_int(void *ctx, enum eapol_int_var variable,
			 unsigned int value)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL)
		return;
	switch (variable) {
	case EAPOL_idleWhile:
		peer->idleWhile = value;
		break;
	}
}


static struct wpabuf * peer_get_eapReqData(void *ctx)
{
	struct eap_peer_ctx *peer = ctx;
	if (peer == NULL || peer->eapReqData == NULL)
		return NULL;

	return peer->eapReqData;
}


static void peer_set_config_blob(void *ctx, struct wpa_config_blob *blob)
{
	printf("TODO: %s\n", __func__);
}


static const struct wpa_config_blob *
peer_get_config_blob(void *ctx, const char *name)
{
	printf("TODO: %s\n", __func__);
	return NULL;
}


static void peer_notify_pending(void *ctx)
{
	printf("TODO: %s\n", __func__);
}

static struct eapol_callbacks eap_cb;
static struct eap_config eap_conf;

int eap_peer_init(void)
{

	wpa_debug_level = 3-wimax_log_level; //from logging.c

	if (eap_peer_register_methods() < 0)
		return -1;
	os_memset(&eap_ctx, 0, sizeof(eap_ctx));

	eap_ctx.eap_config.anonymous_identity = (u8 *) os_strdup(eap_outer_nai);
	eap_ctx.eap_config.anonymous_identity_len = strlen(eap_outer_nai);
	
	switch (eap_type)
	{
		case 3: {
			eap_ctx.eap_config.client_cert = (u8 *) os_strdup(eap_client_cert);
			eap_ctx.eap_config.private_key = (u8 *) os_strdup(eap_client_cert);
			eap_ctx.eap_config.ca_cert = (u8 *) os_strdup(eap_ca_path);
			eap_ctx.eap_config.phase1 = (char *) os_strdup("include_tls_length=1");
			break;
		}
		case 4: {
			eap_ctx.eap_config.identity = (u8 *) os_strdup(eap_login);
			eap_ctx.eap_config.identity_len = strlen(eap_login);
			eap_ctx.eap_config.password = (u8 *) os_strdup(eap_pass);
			eap_ctx.eap_config.password_len = strlen(eap_pass);
			eap_ctx.eap_config.ca_cert = (u8 *) os_strdup(eap_ca_path);
			eap_ctx.eap_config.phase2 = (char *) os_strdup("auth=MD5");
			break;
		}
		case 5: {
			eap_ctx.eap_config.identity = (u8 *) os_strdup(eap_login);
			eap_ctx.eap_config.identity_len = strlen(eap_login);
			eap_ctx.eap_config.password = (u8 *) os_strdup(eap_pass);
			eap_ctx.eap_config.password_len = strlen(eap_pass);
			// LibEAP doesn't work with selfsigned certs; can do nothing with that
			// eap_ctx.eap_config.ca_cert = (u8 *) os_strdup(eap_ca_path);
			eap_ctx.eap_config.phase2 = (char *) os_strdup("auth=MSCHAPV2");
			break;
		}
		case 6: {
			eap_ctx.eap_config.identity = (u8 *) os_strdup(eap_login);
			eap_ctx.eap_config.identity_len = strlen(eap_login);
			eap_ctx.eap_config.password = (u8 *) os_strdup(eap_pass);
			eap_ctx.eap_config.password_len = strlen(eap_pass);
			eap_ctx.eap_config.ca_cert = (u8 *) os_strdup(eap_ca_path);
			eap_ctx.eap_config.phase2 = (char *) os_strdup("auth=CHAP");
			break;
		}
	}
	
	eap_ctx.eap_config.fragment_size = 1300;
	os_memset(&eap_cb, 0, sizeof(eap_cb));
	eap_cb.get_config = peer_get_config;
	eap_cb.get_bool = peer_get_bool;
	eap_cb.set_bool = peer_set_bool;
	eap_cb.get_int = peer_get_int;
	eap_cb.set_int = peer_set_int;
	eap_cb.get_eapReqData = peer_get_eapReqData;
	eap_cb.set_config_blob = peer_set_config_blob;
	eap_cb.get_config_blob = peer_get_config_blob;
	eap_cb.notify_pending = peer_notify_pending;

	os_memset(&eap_conf, 0, sizeof(eap_conf));
	eap_ctx.eap = eap_peer_sm_init(&eap_ctx, &eap_cb, &eap_ctx, &eap_conf);
	if (eap_ctx.eap == NULL)
		return -1;

	/* Enable "port" to allow authentication */
	eap_ctx.portEnabled = TRUE;

	return 0;
}


void eap_peer_deinit(void)
{
	eap_peer_sm_deinit(eap_ctx.eap);
	eap_peer_unregister_methods();
	wpabuf_free(eap_ctx.eapReqData);
	os_free(eap_ctx.eap_config.anonymous_identity);
	switch (eap_type)
	{
		case 3: {
			os_free(eap_ctx.eap_config.client_cert);
			os_free(eap_ctx.eap_config.private_key);
			os_free(eap_ctx.eap_config.ca_cert);
			os_free(eap_ctx.eap_config.phase1);
			break;
		}
		case 4: {
			os_free(eap_ctx.eap_config.identity);
			os_free(eap_ctx.eap_config.password);
			os_free(eap_ctx.eap_config.ca_cert);
			os_free(eap_ctx.eap_config.phase2);
			break;
		}
		case 5: {
			os_free(eap_ctx.eap_config.identity);
			os_free(eap_ctx.eap_config.password);
			// LibEAP doesn't support selfsigned certs; can do nothing with that
			// os_free(eap_ctx.eap_config.ca_cert);
			os_free(eap_ctx.eap_config.phase2);
			break;
		}
		case 6: {
			os_free(eap_ctx.eap_config.identity);
			os_free(eap_ctx.eap_config.password);
			os_free(eap_ctx.eap_config.ca_cert);
			os_free(eap_ctx.eap_config.phase2);
			break;
		}
	}
	//os_free(eap_ctx.eap_config.ca_cert);   /////////////////PROBLEM
}


int eap_peer_step(void)
{
	unsigned char data[0x4000];
	int res;
	res = eap_peer_sm_step(eap_ctx.eap);

	if (eap_ctx.eapResp) {
		struct wpabuf *resp;
		eap_ctx.eapResp = FALSE;
		resp = eap_get_eapRespData(eap_ctx.eap);
		if (resp) {
			/* Send EAP response to the server */
			memcpy(data,wpabuf_head(resp),wpabuf_len(resp));
			eap_server_rx(data,  wpabuf_len(resp));		
			
			//eap_server_rx(wpabuf_head(resp),
			//		      wpabuf_len(resp));
			wpabuf_free(resp);
		}
	}

	if (eap_ctx.eapSuccess) {
		res = 0;
		if (eap_key_available(eap_ctx.eap)) {
			const u8 *key;
			size_t key_len;
			key = eap_get_eapKeyData(eap_ctx.eap, &key_len);

			memcpy(data,key,key_len);			
			eap_key(data, key_len);
			
			wpa_hexdump(MSG_DEBUG, "EAP keying material",
				    key, key_len);
		}
	}
	
	if (eap_ctx.eapFail) {
		res = -1;
	}	
	
	return res;
}


void eap_peer_rx(const void *data, int data_len)
{
	//wpa_hexdump(MSG_DEBUG, "lala EAP Server send", data, data_len);  //Server send to peer :)
	eap_ctx.eapReq = TRUE;
	//wpabuf_free(eap_ctx.eapReqData);
	eap_ctx.eapReqData = wpabuf_alloc_copy(data, data_len);
}

/*
void eap_peer_rx(const u8 *data, size_t data_len)
{
	// Make received EAP message available to the EAP library 
	wpa_hexdump(MSG_DEBUG, "lala EAP Server send", data, data_len);  //Server send to peer :)
	eap_ctx.eapReq = TRUE;
	wpabuf_free(eap_ctx.eapReqData);
	eap_ctx.eapReqData = wpabuf_alloc_copy(data, data_len);
}
*/