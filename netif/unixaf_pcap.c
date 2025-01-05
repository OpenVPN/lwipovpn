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
 *
 */

#include <pcap/pcap.h>
#include <stdlib.h>

#include "lwip/pbuf.h"
#include "unixaf_pcap.h"

/* This is the same mess as unixaf_host.c. pcap.h pulls in system network
 * header files and those conflict with lwip's own functions.
 * So this file "lives" in the system network header space */

void
unixaf_pcap_init(struct unixafif_pcap *if_pcap, bool tap)
{
  const char *pcap_file = getenv("LWIP_PCAP_FILE");
  if (!pcap_file) {
    return;
  }

  /* We could use DLT_LINUX_SLL here instead and add the special header that
   * would allow preserving the information of the direction in the pcap file */
  int linktype = tap ? DLT_EN10MB : DLT_RAW;

  if_pcap->pcap = pcap_open_dead(linktype, 65000);
  if_pcap->pcap_dump = pcap_dump_open_append(if_pcap->pcap, pcap_file);

  if (if_pcap->pcap_dump)
  {
    printf("lwipovpn: Capturing packets to '%s'\n", pcap_file);
  }
  else
  {
    fprintf(stderr, "Error opening pcap file '%s' for writing: %s\n", pcap_file,
	    pcap_geterr(if_pcap->pcap));
    pcap_close(if_pcap->pcap);
    if_pcap->pcap = NULL;
  }
}

void
unixaf_pcap_write_packet(struct unixafif_pcap *if_pcap, int len, const char* buf)
{
  struct pcap_pkthdr pkthdr;
  pkthdr.len = len;
  pkthdr.caplen = len;

  gettimeofday(&pkthdr.ts, NULL);

  /* The callback pointer is unsigned char * instead of void *, so we need
   * to cast the pointer to it */
  pcap_dump((unsigned char*) if_pcap->pcap_dump, &pkthdr, (const unsigned char *) buf);
  pcap_dump_flush(if_pcap->pcap_dump);
}
