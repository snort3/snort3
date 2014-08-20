/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

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

#include "protocols/packet.h"  
#include "static_include.h"

#include "root_enc.h"
#include "../decoder_includes.h"

/* enc interface */
struct enc_header {
    uint32_t af;
    uint32_t spi;
    uint32_t flags;
};
#define ENC_HEADER_LEN          12


#ifdef DLT_ENC
/* see http://sourceforge.net/mailarchive/message.php?msg_id=1000380 */
/*
 * Function: DecodeEncPkt(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Decapsulate packets of type DLT_ENC.
 *          XXX Are these always going to be IP in IP?
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => pointer to the packet header
 *            pkt => pointer to the real live packet data
 */
void DecodeEncPkt(Packet *p, const DAQ_PktHdr_t *pkthdr, const uint8_t *pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    struct enc_header *enc_h;
    PROFILE_VARS;

    MODULE_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;

    if (cap_len < ENC_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Encap header length!  (%d bytes)\n",
                cap_len);
        }
        MODULE_PROFILE_END(decodePerfStats);
        return;
    }

    enc_h = (struct enc_header *)p->pkt;
    if (enc_h->af == AF_INET)
    {
        DecodeIP(p->pkt + ENC_HEADER_LEN + IP_HEADER_LEN,
                 cap_len - ENC_HEADER_LEN - IP_HEADER_LEN, p);
    }
    else
    {
        ErrorMessage("WARNING: Unknown address family (af: 0x%x).\n",
                enc_h->af);
    }
    MODULE_PROFILE_END(decodePerfStats);
    return;
}
#endif /* DLT_ENC */

