/*
** Copyright (C) 2000,2001 Christopher Cramer <cec@ee.duke.edu>
** Snort is Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Marc Norton <mnorton@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
**
** 7/2002 Marc Norton - added inline/optimized checksum routines
**                      these handle all hi/low endian issues
** 8/2002 Marc Norton - removed old checksum code and prototype
**
*/

#ifndef CHECKSUM_H
#define CHECKSUM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_debug.h"
#include <sys/types.h>

typedef struct
{
    uint32_t sip[4], dip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
} pseudoheader6;

typedef struct
{
    uint32_t sip, dip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
} pseudoheader;

/*
*  checksum IP  - header=20+ bytes
*
*  w - short words of data
*  blen - byte length
*
*/
static inline unsigned short in_chksum_ip( unsigned short * w, int blen )
{
   unsigned int cksum;

   /* IP must be >= 20 bytes */
   cksum  = w[0];
   cksum += w[1];
   cksum += w[2];
   cksum += w[3];
   cksum += w[4];
   cksum += w[5];
   cksum += w[6];
   cksum += w[7];
   cksum += w[8];
   cksum += w[9];

   blen  -= 20;
   w     += 10;

   while( blen ) /* IP-hdr must be an integral number of 4 byte words */
   {
     cksum += w[0];
     cksum += w[1];
     w     += 2;
     blen  -= 4;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short) (~cksum);
}

/*
*  checksum tcp
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp(pseudoheader *ph,
    unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* TCP hdr must have 20 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];
   cksum += d[4];
   cksum += d[5];
   cksum += d[6];
   cksum += d[7];
   cksum += d[8];
   cksum += d[9];

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (uint16_t) (*(uint8_t*)d); */

     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}
/*
*  checksum tcp for IPv6.
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp6(pseudoheader6 *ph,
    unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 36 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];
   cksum += h[6];
   cksum += h[7];
   cksum += h[8];
   cksum += h[9];
   cksum += h[10];
   cksum += h[11];
   cksum += h[12];
   cksum += h[13];
   cksum += h[14];
   cksum += h[15];
   cksum += h[16];
   cksum += h[17];

   /* TCP hdr must have 20 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];
   cksum += d[4];
   cksum += d[5];
   cksum += d[6];
   cksum += d[7];
   cksum += d[8];
   cksum += d[9];

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (uint16_t) (*(uint8_t*)d); */

     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}

/*
*  checksum udp
*
*  h    - pseudo header - 12 bytes
*  d    - udp hdr + payload
*  dlen - length of payload in bytes
*
*/
static inline unsigned short in_chksum_udp6(pseudoheader6 *ph,
    unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have  12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];
   cksum += h[6];
   cksum += h[7];
   cksum += h[8];
   cksum += h[9];
   cksum += h[10];
   cksum += h[11];
   cksum += h[12];
   cksum += h[13];
   cksum += h[14];
   cksum += h[15];
   cksum += h[16];
   cksum += h[17];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}



static inline unsigned short in_chksum_udp(pseudoheader *ph,
     unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 36 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}

/*
*  checksum icmp
*/
static inline unsigned short in_chksum_icmp( unsigned short * w, int blen )
{
  unsigned  short answer=0;
  unsigned int cksum = 0;

  while(blen >=32)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     cksum += w[4];
     cksum += w[5];
     cksum += w[6];
     cksum += w[7];
     cksum += w[8];
     cksum += w[9];
     cksum += w[10];
     cksum += w[11];
     cksum += w[12];
     cksum += w[13];
     cksum += w[14];
     cksum += w[15];
     w     += 16;
     blen  -= 32;
  }

  while(blen >=8)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     w     += 4;
     blen  -= 8;
  }

  while(blen > 1)
  {
     cksum += *w++;
     blen  -= 2;
  }

  if( blen == 1 )
  {
    *(unsigned char*)(&answer) = (*(unsigned char*)w);
    cksum += answer;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);


  return (unsigned short)(~cksum);
}

/*
*  checksum icmp6
*/
static inline unsigned short in_chksum_icmp6(pseudoheader6 *ph,
     unsigned short *w, int blen )
{
  uint16_t *h = (uint16_t *)ph;
  unsigned  short answer=0;
  unsigned int cksum = 0;

  /* PseudoHeader must have 36 bytes */
  cksum  = h[0];
  cksum += h[1];
  cksum += h[2];
  cksum += h[3];
  cksum += h[4];
  cksum += h[5];
  cksum += h[6];
  cksum += h[7];
  cksum += h[8];
  cksum += h[9];
  cksum += h[10];
  cksum += h[11];
  cksum += h[12];
  cksum += h[13];
  cksum += h[14];
  cksum += h[15];
  cksum += h[16];
  cksum += h[17];

  while(blen >=32)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     cksum += w[4];
     cksum += w[5];
     cksum += w[6];
     cksum += w[7];
     cksum += w[8];
     cksum += w[9];
     cksum += w[10];
     cksum += w[11];
     cksum += w[12];
     cksum += w[13];
     cksum += w[14];
     cksum += w[15];
     w     += 16;
     blen  -= 32;
  }

  while(blen >=8)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     w     += 4;
     blen  -= 8;
  }

  while(blen > 1)
  {
     cksum += *w++;
     blen  -= 2;
  }

  if( blen == 1 )
  {
    *(unsigned char*)(&answer) = (*(unsigned char*)w);
    cksum += answer;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);


  return (unsigned short)(~cksum);
}


#endif /* CHECKSUM_H */
