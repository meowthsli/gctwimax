/*
 * This is a reverse-engineered driver for mobile WiMAX (802.16e) devices
 * based on GCT Semiconductor GDM7213 & GDM7205 chip.
 * Copyright (�) 2010 Yaroslav Levandovsky <leyarx@gmail.com>
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

#ifndef _EAP_AUTH_H
#define _EAP_AUTH_H

#include "util/includes.h"

#include "util/common.h"

#include "wimax.h"
#include "logging.h"
extern int wpa_debug_level;

char *eap_outer_nai;
char *eap_login;
char *eap_pass;
char *eap_client_cert;
char *eap_ca_path;
int eap_type;

int eap_peer_init(void);

void eap_peer_deinit(void);

int eap_peer_step(void);

void eap_peer_rx(const void *data, int data_len);
//void eap_peer_rx(const u8 *data, size_t data_len);

#endif /* _EAP_PEER_H */