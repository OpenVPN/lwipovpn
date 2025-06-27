/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 * Author: Arne Schwabe <arne@rfc2549.org>
 *
 */
#ifndef LWIP_UNIXAF_H
#define LWIP_UNIXAF_H

#include <stdbool.h>

#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

err_t unixafif_init(struct netif *netif);

/** Initialises the global state that is common to all interfaces.
 * Currently this is pcap and the fd for the communication with OpenVPN.
 * It will use main_netif parameter to determine parameter that should
 * be common for all interace like layer 2 or layer 3 */
void unixaif_global_init(struct netif *main_netif);

void unixafif_poll(struct netif *main_netif);
/**
 * Return whether we consider a netif a tap (layer 2) interface. Otherwise it
 * is considered a layer 3 tun interface
 */
static inline
bool netif_is_tap(const struct netif *netif) {
  return netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET);
}

const char *getenv_netif_idx(const char *name, struct netif *netif);

const char *getenv_indexed(const char *name, uint8_t num);

const char *getenv_indexed_name(char *buf, size_t buflen, const char *name, uint8_t num);


#ifdef __cplusplus
}
#endif

#endif /* LWIP_UNIXAF_H */
