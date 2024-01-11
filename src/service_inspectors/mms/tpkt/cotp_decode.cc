//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// cotp_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cotp_decode.h"

using namespace snort;

TpktAppliSearchStateType tpkt_internal_search_from_cotp_layer(Cursor* tpkt_cur)
{
    // make sure there is enough data in the cursor
    if (tpkt_cur->length() >= sizeof(CotpHdr))
    {
        // overlay the struct
        const CotpHdr* hdr = (const CotpHdr*)tpkt_cur->start();

        if (hdr->pdu_type == COTP_PDU_TYPE_DT_DATA)
        {
            // move cursor to the beginning of the next layer
            if (tpkt_cur->add_pos(sizeof(CotpHdr)))
            {
                // if MMS is sent directly in COTP parse it from that layer immediately
                switch (*tpkt_cur->start())
                {
                case MMS_MSG__CONFIRMED_REQUEST:                  // fallthrough
                case MMS_MSG__CONFIRMED_RESPONSE:                 // fallthrough
                case MMS_MSG__CONFIRMED_ERROR:                    // fallthrough
                case MMS_MSG__UNCONFIRMED:                        // fallthrough
                case MMS_MSG__REJECT:                             // fallthrough
                case MMS_MSG__CANCEL_REQUEST:                     // fallthrough
                case MMS_MSG__CANCEL_RESPONSE:                    // fallthrough
                case MMS_MSG__CANCEL_ERROR:                       // fallthrough
                case MMS_MSG__INITIATE_REQUEST:                   // fallthrough
                case MMS_MSG__INITIATE_RESPONSE:                  // fallthrough
                case MMS_MSG__INITIATE_ERROR:                     // fallthrough
                case MMS_MSG__CONCLUDE_REQUEST:                   // fallthrough
                case MMS_MSG__CONCLUDE_RESPONSE:                  // fallthrough
                case MMS_MSG__CONCLUDE_ERROR:
                    return TPKT_APPLI_SEARCH_STATE__MMS_FOUND;

                // otherwise check if the session layer is in use
                default:
                    return tpkt_search_from_osi_session_layer(tpkt_cur,
                        OSI_SESSION_PROCESS_AS_DT__FALSE);
                }
            }
        }
    }

    // unsupported COTP
    return TPKT_APPLI_SEARCH_STATE__EXIT;
}

