/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * Copyright (c) 2024 Arne Schwabe
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
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"

#include "unixaf.h"
#include "unixaf_host.h"
#include "unixaf_pcap.h"
#include "lwip/sockets.h"

/* Define those to better describe your network interface. */
#define IFNAME0 'a'
#define IFNAME1 'f'

#ifndef AFUNIX_DEBUG
#define AFUNIX_DEBUG LWIP_DBG_OFF
#endif

struct unixafif_global {
  /* Add whatever per-interface state that is needed here. */
  int fd;
  struct unixafif_pcap pcap;
};

struct unixafif_global g_unixaf = { 0 };

/* Forward declarations. */
static void unixafif_input(struct netif *netif);
#if !NO_SYS
static void unixafif_thread(void *arg);
#endif /* !NO_SYS */

/**
 * Send an IPv4 packet on the given connection emulating a tun or tap device.
 */
static err_t afunix_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  LWIP_UNUSED_ARG(ipaddr);

  /* like netif_input, use interface flags to determine if this is tun or tap */
  if (netif_is_tap(netif)) {
    return etharp_output(netif, p, ipaddr);
  } else {
    return netif->linkoutput(netif, p);
  }
}

/**
 * Send an IPv6 packet on the given connection emulating a tun or tap device.
 */
static err_t afunix_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
  /* like netif_input, use interface flags to determine if this is tun or tap */
  if (netif_is_tap(netif)) {
    return ethip6_output(netif, p, ipaddr);
  } else {
    return netif->linkoutput(netif, p);
  }
}

static void set_netif_mtu(struct netif *netif) {
  long mtu = 1500;
  const char *tuntap_mtu_str = getenv("TUNTAP_MTU");
  if (tuntap_mtu_str) {
    char *endptr;
    mtu = strtol(tuntap_mtu_str, &endptr, 10);

    if (*endptr != '\0' || mtu < 68 || mtu > 65000) {
      fprintf(stderr, "Could parse environment variable TUNTAP_MTU=%s",
	      tuntap_mtu_str);
      exit(1);
    }
  }
  netif->mtu = (uint16_t) mtu;
}

static uint8_t get_random_byte(void)
{
#ifndef ARC4RANDOM_MISSING
  return (uint8_t) (arc4random());
#else
  return (uint8_t) (rand());
#endif
}


const char*
getenv_indexed(const char *name, uint8_t num)
{
    char buf[1024];
    const char *env_name = getenv_indexed_name(buf, sizeof(buf) , name, num);
    return getenv(env_name);
}

const char*
getenv_indexed_name(char *buf, size_t buflen, const char *name, uint8_t num)
{

  if (num == 1 || num == 0)
    return name;
  else
  {
    snprintf(buf, buflen, "OPENVPN_%s_%d", name, num);
    return buf;
  }
}


const char*
getenv_netif_idx(const char *name, struct netif *netif)
{
  return getenv_indexed(name, netif->num);
}



static void set_netif_mac(struct netif *netif) {
  const char *lladdr_str = getenv_netif_idx("TUNTAP_LLADDR", netif);
  if (!lladdr_str) {
    /* (We just fake an address...).
    * This is a random locally administered address with a fixed
    * prefix to make easier to identify */
    netif->hwaddr[0] = 0x0e;
    netif->hwaddr[1] = 'o';
    netif->hwaddr[2] = netif->num;
    netif->hwaddr[3] = get_random_byte();
    netif->hwaddr[4] = get_random_byte();
    netif->hwaddr[5] = get_random_byte();
    netif->hwaddr_len = 6;
    return;
  }

  if (netif->num == 0 && sscanf(lladdr_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &netif->hwaddr[0], &netif->hwaddr[1], &netif->hwaddr[2],
		   &netif->hwaddr[3], &netif->hwaddr[4], &netif->hwaddr[5])
		   != 6)
  {
    fprintf(stderr, "Could parse environment variable TUNTAP_MTU=%s",
	    lladdr_str);
    exit(1);
  }
  netif->hwaddr_len = 6;
}

static void set_tun_fd(void)
{
 const char *unix_af_path = getenv("TUN_UNIXAF_PATH");
 const char *unix_af_fd_str = getenv("TUNTAP_SOCKET_FD");


  if (unix_af_path) {
    g_unixaf.fd = open(unix_af_path, O_RDWR);
    LWIP_DEBUGF(AFUNIX_DEBUG, ("set_tun_fd: fd %d\n", g_unixaf.fd));
    if (g_unixaf.fd <  0) {
      fprintf(stderr, "set_tun_fd: cannot open %s: %s", unix_af_path,
	      strerror(errno));
      exit(1);
    }
    return;
  }

  if (!unix_af_fd_str) {
    fprintf(stderr, "Could not find environment variable TUNTAP_SOCKET_FD or "
		    "TUN_UNIXAF_PATH containing the passed socket file "
		    "descriptor/socket path");
    exit(1);
  }
  g_unixaf.fd = atoi(unix_af_fd_str);

  LWIP_DEBUGF(AFUNIX_DEBUG, ("set_tun_fd: fd %d\n", g_unixaf.fd));
  if (g_unixaf.fd <= 0) {
    fprintf(stderr, "set_tun_fd: cannot parse TUNTAP_SOCKET_FD (%s)",
	    unix_af_fd_str);
    exit(1);
  }
}


static void
low_level_init(struct netif *netif) {
  const char *dev_type;

  set_netif_mac(netif);

  /* device capabilities */
  dev_type = getenv("TUNTAP_DEV_TYPE");
  if (!dev_type) {
    fprintf(stderr, "Environment variable TUNTAP_DEV_TYPE is missing");
    exit(1);
  }

  if (!strcmp(dev_type, "tun")) {
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_IGMP;
  } else if (!strcmp(dev_type, "tap")) {
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
  } else {
    fprintf(stderr, "tunixafif_init: cannot parse TUNTAP_DEV_TYPE (%s)", dev_type);
    exit(1);
  }

  set_netif_mtu(netif);
  netif_set_link_up(netif);

#if !NO_SYS
  sys_thread_new("unixafif_thread", unixafif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif /* !NO_SYS */
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p) {
  char buf[1518]; /* max packet size including VLAN excluding CRC */

  if (p->tot_len > sizeof(buf)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("unixafif: packet too large");
    return ERR_IF;
  }

  /* initiate transfer(); copy packet contents to buf */
  uint16_t outsize = pbuf_copy_partial(p, buf, p->tot_len, 0);

  if (!outsize || outsize != p->tot_len) {
    perror("unixafif: error copying packet contents");
    return ERR_IF;
  }

  if (g_unixaf.pcap.pcap)
  {
    unixaf_pcap_write_packet(&g_unixaf.pcap, p->tot_len, buf);
  }

  /* signal that packet should be sent(); */
  size_t written = host_send(g_unixaf.fd, buf, p->tot_len, 0);
  if (written < p->tot_len) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);

    fprintf(stderr, "unixafif: fd %d send short (%zd of %d)",
	     g_unixaf.fd, written, p->tot_len);
    return ERR_IF;
  } else {
    LWIP_DEBUGF(AFUNIX_DEBUG, ("unixafif: fd %d send bytes to socket (%zd of %d)\n",
	g_unixaf.fd, written, p->tot_len));
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t) written);
    return ERR_OK;
  }
}

static ssize_t read_from_afunix_socket(int fd, char* buf, int buflen)
{
  /* Obtain the size of the packet and put it into the "len"
     variable. */
  ssize_t readlen = host_recv(fd, buf, buflen, 0);

  if (readlen < 0) {
    char errmsg[512];
    snprintf(errmsg, sizeof(errmsg), "recv of fd %d returned %zd:",
	     fd, readlen);
    perror(errmsg);
    //MIB2_STATS_NETIF_INC(netif, ifindiscards);
  }

  if (g_unixaf.pcap.pcap)
  {
    unixaf_pcap_write_packet(&g_unixaf.pcap, readlen, buf);
  }

  return readlen;
}


/*-----------------------------------------------------------------------------------*/
/*
 * unixafif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
unixafif_input(struct netif *main_intf)
{
  char buf[1518]; /* max packet size including VLAN excluding CRC */

  ssize_t len = read_from_afunix_socket(g_unixaf.fd, buf, sizeof(buf));
  if (len < 0)
  {
    snprintf(buf, sizeof(buf), "Could not read from UNIX AF: %s", strerror(len));
    perror(buf);
    return;
  }

  struct pbuf *p;
  MIB2_STATS_NETIF_ADD(main_intf, ifinoctets, len);

  // lwip seem to internally pick  the right interface, so we send all to the
  // main interface only
  //for (struct netif *netif = netif_list; (netif) != NULL; (netif) = (netif)->next) {

  struct netif *netif = main_intf;
  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  if (p != NULL) {
    pbuf_take(p, buf, len);
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
    LWIP_DEBUGF(NETIF_DEBUG, ("unixafif_input: could not allocate pbuf\n"));
    return;
  }

  if (netif->input(p, netif) != ERR_OK) {
    LWIP_DEBUGF(NETIF_DEBUG, ("unixafif_input: netif input error\n"));
    pbuf_free(p);
  }
  //}
}
/*-----------------------------------------------------------------------------------*/
/*
 * unixif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t
unixafif_init(struct netif *netif) {
  /*struct tapif *unixafif = (struct tapif *) mem_malloc(sizeof(struct unixafif));

  if (unixafif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("unixafif_init: out of memory for unixafif\n"));
    return ERR_MEM;
    netif->state = unixafif;
  }*/

  MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;

  netif->output = afunix_output_ipv4;
  netif->output_ip6 = afunix_output_ipv6;

  netif->linkoutput = low_level_output;

  low_level_init(netif);


  return ERR_OK;
}

void
unixaif_global_init(struct netif *main_netif)
{
  bool tap = main_netif->flags & NETIF_FLAG_ETHARP;
  set_tun_fd();
  unixaf_pcap_init(&g_unixaf.pcap, tap);
}

/*-----------------------------------------------------------------------------------*/
void
unixafif_poll(struct netif *main_netif) {
  unixafif_input(main_netif);
}

static void
unixafif_thread(void *arg) {
  struct netif *netif;
  fd_set fdset;
  int ret;

  netif = (struct netif *) arg;

  while (true) {
    FD_ZERO(&fdset);
    FD_SET(g_unixaf.fd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(g_unixaf.fd + 1, &fdset, NULL, NULL, NULL);

    if (ret == 1) {
      /* Handle incoming packet. */
      unixafif_input(netif);
    } else if (ret == -1) {
      perror("unixafif_thread: select");
    }
  }
}

