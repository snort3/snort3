/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "analyzer.h"
#include "decode.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "detect.h"
#include "log_text.h"
#include "generators.h"
#include "packet_io/active.h"
#include "sfxhash.h"
#include "snort_bounds.h"
#include "sf_iph.h"
#include "fpdetect.h"
#include "profiler.h"
#include "mempool/mempool.h"
#include "normalize/normalize.h"
#include "packet_io/sfdaq.h"

#include "codecs/decode_module.h"
#include "events/codec_events.h"

void decoder_sum()
{
//    sum_stats((PegCount*)&gdc, (PegCount*)&dc, array_size(dc_pegs));
//    memset(&dc, 0, sizeof(dc));
}

void decoder_stats()
{
//    show_percent_stats((PegCount*)&gdc, dc_pegs, array_size(dc_pegs),
//        "decoder");
}










//--------------------------------------------------------------------
// decode.c::miscellaneous public methods and helper functions
//--------------------------------------------------------------------

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
uint32_t EXTRACT_32BITS (u_char *p)
{
  uint32_t __tmp;

  memmove(&__tmp, p, sizeof(uint32_t));
  return (uint32_t) ntohl(__tmp);#endif
}
#endif /* WORDS_MUSTALIGN && !__GNUC__ */



static inline void CheckIPv4_MinTTL(Packet *p, uint8_t ttl)
{

    // this sequence of tests is best for the "normal" case where
    // the packet ttl is >= the configured min (the default is 1)
    if( ttl < ScMinTTL() )
    {
        if ( ttl == 0 )
        {
            codec_events::exec_ttl_drop(p, DECODE_ZERO_TTL);
        }
        else
        {
            codec_events::exec_ttl_drop(p, DECODE_IP4_MIN_TTL);
        }
    }
}



static inline void CheckIPv6_MinTTL(Packet *p, uint8_t hop_limit)
{
    // this sequence of tests is best for the "normal" case where
    // the packet ttl is >= the configured min (the default is 1)
    if( hop_limit < ScMinTTL() )
    {
        if ( hop_limit == 0 )
        {
            codec_events::exec_hop_drop(p, DECODE_IP6_ZERO_HOP_LIMIT);
        }
        else
        {
             codec_events::exec_hop_drop(p, DECODE_IPV6_MIN_TTL);
        }
    }
}



/* Decoding of ttl/hop_limit is based on the policy min_ttl */
void DecodePolicySpecific(Packet *p)
{
    switch(p->outer_family)
    {
        case AF_INET:
            CheckIPv4_MinTTL( p, p->outer_ip4h.ip_ttl);
            return;

        case AF_INET6:
            CheckIPv6_MinTTL( p, p->outer_ip6h.hop_lmt);
            return;

        default:
            break;
    }

    switch(p->family)
    {
        case AF_INET:
            CheckIPv4_MinTTL( p, p->ip4h->ip_ttl);
            return;

        case AF_INET6:
            CheckIPv6_MinTTL( p, p->ip6h->hop_lmt);
            return;

        default:
            break;
    }
}

