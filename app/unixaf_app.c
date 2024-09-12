/*
 * Copyright (c) 2001,2002 Florian Schulze.
 * Copyright (c) 2024 Arne Schwabe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  This file is has been based on part on the lwIP test.c app
 *
 */

/* C runtime includes */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>

/* lwIP core includes */
#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"

/* lwIP netif includes */
#include "lwip/etharp.h"
#include "netif/ethernet.h"

/* applications includes */
#include "lwip/apps/netbiosns.h"
#include "lwip/apps/httpd.h"
#include "apps/httpserver/httpserver-netconn.h"
#include "apps/netio/netio.h"
#include "apps/ping/ping.h"
#include "apps/rtp/rtp.h"
#include "apps/chargen/chargen.h"
#include "apps/shell/shell.h"
#include "apps/tcpecho/tcpecho.h"
#include "apps/udpecho/udpecho.h"
#include "apps/tcpecho_raw/tcpecho_raw.h"
#include "apps/socket_examples/socket_examples.h"

#include "examples/lwiperf/lwiperf_example.h"
#include "examples/mdns/mdns_example.h"
#include "examples/snmp/snmp_example.h"
#include "examples/tftp/tftp_example.h"
#include "examples/sntp/sntp_example.h"
#include "examples/mqtt/mqtt_example.h"

#include "examples/httpd/cgi_example/cgi_example.h"
#include "examples/httpd/fs_example/fs_example.h"
#include "examples/httpd/https_example/https_example.h"
#include "examples/httpd/ssi_example/ssi_example.h"

#include "lwip/sockets.h"

#include "unixaf.h"

#include "netif/ppp/ppp_opts.h"

/* include the port-dependent configuration */
#include "afunix_config.h"

/** Define this to 1 to enable a port-specific ethernet interface as default interface. */
#ifndef USE_DEFAULT_ETH_NETIF
#define USE_DEFAULT_ETH_NETIF 1
#endif

/** Use an ethernet adapter? Default to enabled if port-specific ethernet netif or PPPoE are used. */
#ifndef USE_ETHERNET
#define USE_ETHERNET  (USE_DEFAULT_ETH_NETIF || PPPOE_SUPPORT)
#endif

/** Use an ethernet adapter for TCP/IP? By default only if port-specific ethernet netif is used. */
#ifndef USE_ETHERNET_TCPIP
#define USE_ETHERNET_TCPIP  (USE_DEFAULT_ETH_NETIF)
#endif

// #define LWIPOVPN_DEBUG_STATUS 1

#ifndef USE_DHCP
#define USE_DHCP    LWIP_DHCP
#endif

/* global variables for netifs */
#if LWIP_DHCP
/* dhcp struct for the ethernet netif */
static struct dhcp netif_dhcp;
#endif /* LWIP_DHCP */

#ifndef LWIP_IPV4
#error unixaf_app requires LWIP_IPV4
#endif

#ifndef LWIP_IPV6
#error unixaf_app requires LWIP_IPV6
#endif



static const char*
status_print_ip_addr(const ip4_addr_t *addr, char *buf, size_t buflen)
{
  if (!addr || !addr->addr)
    return "(not set)";
  else
    return ip4addr_ntoa_r(addr, buf, (int) buflen);
}

static const char*
status_print_ip6_addr(const ip6_addr_t *addr, char *buf, size_t buflen)
{
  if (!addr)
    return "(not set)";
  else
    return ip6addr_ntoa_r(addr, buf, (int) buflen);
}

static void
status_print(struct netif *netif, const char *prefix) {
  char ip_local[32], ip_netmask[32], ip_gw[32];
  char ip6_local[48];


  printf("%s: type=%s mtu=%d local_ip=%s netmask=%s gw=%s local_ipv6=%s\n",
	 prefix,
	 netif_is_tap(netif) ? "tap" : "tun",
	 netif->mtu,
	 status_print_ip_addr(netif_ip4_addr(netif), ip_local, sizeof(ip_local)),
	 status_print_ip_addr(netif_ip4_netmask(netif), ip_netmask, sizeof(ip_netmask)),
	 status_print_ip_addr(netif_ip4_gw(netif), ip_gw, sizeof(ip_gw)),
	 status_print_ip6_addr(netif_ip6_addr(netif, 0), ip6_local, sizeof(ip6_local))
	);
}

static void
status_callback(struct netif *state_netif) {
#ifdef LWIPOVPN_DEBUG_STATUS
  if (netif_is_up(state_netif)) {
    status_print(state_netif, "status_callback==UP");

  } else {
    printf("status_callback==DOWN\n");
  }
#else
  // silence unused warning
  (void) state_netif;
#endif
}

static void
link_callback(struct netif *state_netif) {
#ifdef LWIPOVPN_DEBUG_STATUS
  if (netif_is_link_up(state_netif)) {
    printf("link_callback==UP\n");
  } else {
    printf("link_callback==DOWN\n");
  }
#else
  // silence unused warning
  (void) state_netif;
#endif
}

/** returns the parsed IPv4 address in network order */
static ip4_addr_t
get_ipv4_addr_from_env(const char *env_name) {
  ip4_addr_t addr;

  const char *ipv4_addr = getenv(env_name);
  if (!ipv4_addr) {
    ipv4_addr = "(not set)";
  }

  if (!lwip_inet_pton(AF_INET, ipv4_addr, &addr)) {
    char errmsg[512];
    snprintf(errmsg, sizeof(errmsg), "Could not convert %s=%s to IPv4 address",
	     env_name, ipv4_addr);
    perror(errmsg);
    addr.addr = IPADDR_ANY;
  }
  return addr;
}

static ip6_addr_t
get_ipv6_addr_from_env(const char *env_name) {
  ip6_addr_t addr = {0};

  const char *ipv6_addr = getenv(env_name);
  if (!ipv6_addr) {
    ipv6_addr = "(not set)";
  }

  if (!lwip_inet_pton(AF_INET6, ipv6_addr, &addr)) {
    char errmsg[512];
    snprintf(errmsg, sizeof(errmsg), "Could not convert %s=%s to IPv6 address",
	     env_name, ipv6_addr);
    perror(errmsg);
  }
  return addr;
}

/**
 * Configure IPv4 on the network interface
 * @return 	if dhcp should be started
 */
static bool
set_ipv4_addr_from_env(struct netif *netif) {
  if (getenv("ifconfig_local_dhcp")) {
    dhcp_set_struct(netif, &netif_dhcp);
    printf("Using DHCP to configure IPv4");
    return true;
  } else {
    /* The variables match OpenVPN's variables */
    ip4_addr_t ip_addr = get_ipv4_addr_from_env("ifconfig_local");
    ip4_addr_t ip_netmask = get_ipv4_addr_from_env("ifconfig_netmask");
    ip4_addr_t ip_remote = get_ipv4_addr_from_env("ifconfig_gateway");

    netif_set_addr(netif, &ip_addr, &ip_netmask, &ip_remote);
    return false;
  }
}

static void
set_ipv6_addr_from_env(struct netif *netif) {
  int netbits = 64;

  /* The variables match OpenVPN's variables */
  ip6_addr_t ip_addr = get_ipv6_addr_from_env("ifconfig_ipv6_local");

  char *ipv6_netbits = getenv("ifconfig_ipv6_netbits");
  if (ipv6_netbits) {
    netbits = atoi(ipv6_netbits);
  }

  /* This uses addr 0 */
  netif_create_ip6_linklocal_address(netif, 1);

  /* There seem to be no way to specify an IPv6 netmask. Just warn if the
   * netmask is different from the default /64 */
  if (netbits != 64)
  {
    printf("IPv6 prefix (%d) different from the default /64 is "
	   "not supported (ignored).\n", netbits);
  }

  /* TODO: figure out what addr_idx parameter does, looks like just the
   * index of the IP to set multiple IPs */
  netif_ip6_addr_set(netif, 0, &ip_addr);
  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_PREFERRED);
}

/* global variable holding the netif configuration */
struct netif netif = {0};

static void
init_unixaf_netif(void) {
  netif_add(&netif, NULL, NULL, NULL, NULL, unixafif_init, tcpip_input);
  netif_set_default(&netif);
}

/* This function initializes all network interfaces */
static void
afunix_netif_init(void) {
  bool startdhcp;

  init_unixaf_netif();

  /* set status callbacks */
  netif_set_status_callback(netif_default, status_callback);
  netif_set_link_callback(netif_default, link_callback);

  /* set address families from OpenVPN environment variables */
  startdhcp = set_ipv4_addr_from_env(netif_default);
  set_ipv6_addr_from_env(netif_default);

  netif_set_up(netif_default);

  if (startdhcp) {
    err_t err = dhcp_start(netif_default);
    LWIP_ASSERT("dhcp_start failed", err == ERR_OK);
  }
}

#if LWIP_DNS_APP && LWIP_DNS
static void
dns_found(const char *name, const ip_addr_t *addr, void *arg)
{
  LWIP_UNUSED_ARG(arg);
  printf("%s: %s\n", name, addr ? ipaddr_ntoa(addr) : "<not found>");
}

static void
dns_dorequest(void *arg)
{
  const char* dnsname = "3com.com";
  ip_addr_t dnsresp;
  LWIP_UNUSED_ARG(arg);

  if (dns_gethostbyname(dnsname, &dnsresp, dns_found, NULL) == ERR_OK) {
    dns_found(dnsname, &dnsresp, NULL);
  }
}
#endif /* LWIP_DNS_APP && LWIP_DNS */

/* This function initializes applications */
static void
apps_init(void) {
#if LWIP_DNS_APP && LWIP_DNS
  /* wait until the netif is up (for dhcp, autoip or ppp) */
  sys_timeout(5000, dns_dorequest, NULL);
#endif /* LWIP_DNS_APP && LWIP_DNS */

#if LWIP_CHARGEN_APP && LWIP_SOCKET
  chargen_init();
#endif /* LWIP_CHARGEN_APP && LWIP_SOCKET */

#if LWIP_PING_APP && LWIP_RAW && LWIP_ICMP
  ping_init(&netif_default->gw);
#endif /* LWIP_PING_APP && LWIP_RAW && LWIP_ICMP */

#if LWIP_NETBIOS_APP && LWIP_UDP
  netbiosns_init();
#ifndef NETBIOS_LWIP_NAME
#if LWIP_NETIF_HOSTNAME
  netbiosns_set_name(netif_default->hostname);
#else
  netbiosns_set_name("NETBIOSLWIPDEV");
#endif
#endif
#endif /* LWIP_NETBIOS_APP && LWIP_UDP */

#if LWIP_HTTPD_APP && LWIP_TCP
#if  defined(LWIP_HTTPD_APP_NETCONN) && LWIP_HTTPD_APP_NETCONN
  http_server_netconn_init();
#else /* LWIP_HTTPD_APP_NETCONN */
#if defined(LWIP_HTTPD_EXAMPLE_CUSTOMFILES) && LWIP_HTTPD_EXAMPLE_CUSTOMFILES && defined(LWIP_HTTPD_EXAMPLE_CUSTOMFILES_ROOTDIR)
  fs_ex_init(LWIP_HTTPD_EXAMPLE_CUSTOMFILES_ROOTDIR);
#endif
  httpd_init();
#if defined(LWIP_HTTPD_EXAMPLE_SSI_SIMPLE) && LWIP_HTTPD_EXAMPLE_SSI_SIMPLE
  ssi_ex_init();
#endif
#if defined(LWIP_HTTPD_EXAMPLE_CGI_SIMPLE) && LWIP_HTTPD_EXAMPLE_CGI_SIMPLE
  cgi_ex_init();
#endif
#if defined(LWIP_HTTPD_EXAMPLE_HTTPS) && LWIP_HTTPD_EXAMPLE_HTTPS
  https_ex_init();
#endif
#endif /* LWIP_HTTPD_APP_NETCONN */
#endif /* LWIP_HTTPD_APP && LWIP_TCP */

#if LWIP_NETIO_APP && LWIP_TCP
  netio_init();
#endif /* LWIP_NETIO_APP && LWIP_TCP */

#if LWIP_RTP_APP && LWIP_SOCKET && LWIP_IGMP
  rtp_init();
#endif /* LWIP_RTP_APP && LWIP_SOCKET && LWIP_IGMP */

#if LWIP_SHELL_APP && LWIP_NETCONN
  shell_init();
#endif /* LWIP_SHELL_APP && LWIP_NETCONN */
#if LWIP_TCPECHO_APP
#if LWIP_NETCONN && defined(LWIP_TCPECHO_APP_NETCONN)
  tcpecho_init();
#else /* LWIP_NETCONN && defined(LWIP_TCPECHO_APP_NETCONN) */
  tcpecho_raw_init();
#endif
#endif /* LWIP_TCPECHO_APP && LWIP_NETCONN */
#if LWIP_UDPECHO_APP && LWIP_NETCONN
  udpecho_init();
#endif /* LWIP_UDPECHO_APP && LWIP_NETCONN */
#if LWIP_SOCKET_EXAMPLES_APP && LWIP_SOCKET
  socket_examples_init();
#endif /* LWIP_SOCKET_EXAMPLES_APP && LWIP_SOCKET */
#if LWIP_MDNS_APP
  mdns_example_init();
#endif
#if LWIP_SNMP_APP
  snmp_example_init();
#endif
#if LWIP_SNTP_APP
  sntp_example_init();
#endif
#if LWIP_TFTP_APP
  tftp_example_init_server();
#endif
#if LWIP_TFTP_CLIENT_APP
  tftp_example_init_client();
#endif
#if LWIP_LWIPERF_APP
  lwiperf_example_init();
#endif
#if LWIP_MQTT_APP
  mqtt_example_init();
#endif

#ifdef LWIP_APP_INIT
  LWIP_APP_INIT();
#endif
}

/* This function initializes this lwIP test. When NO_SYS=1, this is done in
 * the main_loop context (there is no other one), when NO_SYS=0, this is done
 * in the tcpip_thread context */
static void
unixaf_app_init(void *arg) { /* remove compiler warning */
#if NO_SYS
  LWIP_UNUSED_ARG(arg);
#else /* NO_SYS */
  sys_sem_t *init_sem;
  LWIP_ASSERT("arg != NULL", arg != NULL);
  init_sem = (sys_sem_t *) arg;
#endif /* NO_SYS */

  /* init randomizer again (seed per thread) */
  srand((unsigned int) time(NULL));

  /* init network interfaces */
  afunix_netif_init();

  /* init apps */
  apps_init();

  /* print status interface */
  status_print(netif_default, "lwipovpn init complete");

#if !NO_SYS
  sys_sem_signal(init_sem);
#endif /* !NO_SYS */
}

/* This is somewhat different to other ports: we have a main loop here:
 * a dedicated task that waits for packets to arrive. This would normally be
 * done from interrupt context with embedded hardware, but we don't get an
 * interrupt in windows for that :-) */
static void
main_loop(void) {
  err_t err;
  sys_sem_t init_sem;

  /* initialize lwIP stack, network interfaces and applications */
  err = sys_sem_new(&init_sem, 0);
  LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
  LWIP_UNUSED_ARG(err);
  tcpip_init(unixaf_app_init, &init_sem);
  /* we have to wait for initialization to finish before
   * calling update_adapter()! */
  sys_sem_wait(&init_sem);
  sys_sem_free(&init_sem);

#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
  netconn_thread_init();
#endif

  /* MAIN LOOP for driver update (and timers if NO_SYS) */
  while (!LWIP_EXAMPLE_APP_ABORT()) {
    unixafif_poll(netif_default);

#if ENABLE_LOOPBACK && !LWIP_NETIF_LOOPBACK_MULTITHREADING
    /* check for loopback packets on all netifs */
    netif_poll_all();
#endif /* ENABLE_LOOPBACK && !LWIP_NETIF_LOOPBACK_MULTITHREADING */

#if 0
    {
      pid_t parent = getppid();
      if (parent == 1) {
	printf("Parent become PID 1, parent dead?");
      }
    }
#endif
  }

#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
  netconn_thread_cleanup();
#endif
}

int main(void) {
  /* no stdio-buffering, please! */
  setvbuf(stdout, NULL, _IONBF, 0);

  main_loop();

  return 0;
}

/* This function is only required to prevent arch.h including stdio.h
 * (which it does if LWIP_PLATFORM_ASSERT is undefined)
 */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file) {
  printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
  fflush(NULL);
  abort();
}
