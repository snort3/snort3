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

// osi_session_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "osi_session_decode.h"

#include "service_inspectors/mms/mms_decode.h"

using namespace snort;

static TpktAppliSearchStateType resolve_spdu_parameter(Cursor*, const OsiSessionHdr*);

uint32_t get_max_loops(Cursor* tpkt_cur)
{
    // set a maximum number of loops to the remaining number of
    //    bytes in the cursor divided by the smallest TLV (0x03)
    return (tpkt_cur->size() - tpkt_cur->get_pos()) / TPKT_SMALLEST_TLV_SIZE;
}

uint32_t get_max_pos(uint32_t idx, uint32_t length)
{
    // minus one is to account for the cursor being 0-indexed and
    //    the length being 1-indexed
    return idx + length - 1;
}

// parse the SPDU param at the current cursor position looking for an
// indication that the desired protocol is in use
static TpktAppliSearchStateType resolve_spdu_parameter(Cursor* tpkt_cur, const OsiSessionHdr* hdr)
{
    const OsiSessionSpduParameterHdr* generic_hdr = (const
        OsiSessionSpduParameterHdr*)tpkt_cur->start();

    switch (generic_hdr->type)
    {
    case OSI_SESSION_SPDU_PARAM__CN_ACCEPT_ITEM:
    {
        struct OsiSessionSpduConnectAcceptItem
        {
            OsiSessionSpduParameterHdr param_hdr;
        };

        // overlay the appropriate struct
        const OsiSessionSpduConnectAcceptItem* param = (const
            OsiSessionSpduConnectAcceptItem*)tpkt_cur->start();

        // param length is expected to be 0x06

        // increment the idx to account for the header bytes
        if (!tpkt_cur->add_pos(sizeof(OsiSessionSpduParameterHdr) + param->param_hdr.length))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;
    }

    case OSI_SESSION_SPDU_PARAM__SESSION_REQUIREMENT:
    {
        struct OsiSessionSpduSessionRequirement
        {
            OsiSessionSpduParameterHdr param_hdr;
            uint16_t flags; // cppcheck-suppress unusedStructMember
        };

        // overlay the appropriate struct
        const OsiSessionSpduSessionRequirement* param = (const
            OsiSessionSpduSessionRequirement*)tpkt_cur->start();

        bool checks_pass = false;

        // param length is expected to be 0x02
        // flags value is expected to be 0x02

        // make sure this is only occurring in a CONNECT or ACCEPT SPDU
        if (hdr->spdu_type == OSI_SESSION_SPDU__CN or hdr->spdu_type == OSI_SESSION_SPDU__AC)
        {
            if (tpkt_cur->add_pos(sizeof(OsiSessionSpduParameterHdr) + param->param_hdr.length))
            {
                checks_pass = true;
            }
        }

        if (!checks_pass)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;
    }

    case OSI_SESSION_SPDU_PARAM__CALLING_SESSION_SELECTOR:
    {
        struct OsiSessionSpduCallingSessionSelector
        {
            OsiSessionSpduParameterHdr param_hdr;
            uint16_t calling_session_selector;  // cppcheck-suppress unusedStructMember
        };

        // overlay the appropriate struct
        const OsiSessionSpduCallingSessionSelector* param = (const
            OsiSessionSpduCallingSessionSelector*)tpkt_cur->start();

        // param length is expected to be 0x02

        // make sure this is only occurring in a CONNECT
        if (hdr->spdu_type != OSI_SESSION_SPDU__CN)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        // update the cursor to include header and parameter
        if (!tpkt_cur->add_pos(sizeof(OsiSessionSpduParameterHdr) + param->param_hdr.length))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;
    }

    case OSI_SESSION_SPDU_PARAM__CALLED_SESSION_SELECTOR:
    {
        struct OsiSessionSpduCalledSessionSelector
        {
            OsiSessionSpduParameterHdr param_hdr;
            uint16_t called_session_selector;   // cppcheck-suppress unusedStructMember
        };

        // overlay the appropriate struct
        const OsiSessionSpduCalledSessionSelector* param = (const
            OsiSessionSpduCalledSessionSelector*)tpkt_cur->start();

        // param length is expected to be 0x02

        // make sure this is only occurring in a CONNECT
        if (hdr->spdu_type != OSI_SESSION_SPDU__CN)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        // update the cursor to include header and parameter
        if (!tpkt_cur->add_pos(sizeof(OsiSessionSpduParameterHdr) + param->param_hdr.length))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;
    }

    case OSI_SESSION_SPDU_PARAM__SESSION_USER_DATA:
    {
        struct OsiSessionSpduSessionUserData
        {
            OsiSessionSpduParameterHdr param_hdr;
        };

        // overlay the appropriate struct
        const OsiSessionSpduSessionUserData* param = (const
            OsiSessionSpduSessionUserData*)tpkt_cur->start();

        // param length must be less than the reported session layer length
        if (param->param_hdr.length >= hdr->length)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        TpktAppliSearchStateType res = TPKT_APPLI_SEARCH_STATE__EXIT;
        // increment the cursor to account for the header bytes
        if (tpkt_cur->add_pos(sizeof(OsiSessionSpduParameterHdr)))
        {
            // pass off to the presentation layer for additional parsing
            res = tpkt_search_from_osi_pres_layer(tpkt_cur);
        }
        return res;
    }
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

// process the data with the starting assumption of an OSI Session layer
// since the Give Tokens (GT) and Data Transfer (DT) layers have the same
// values, the `process_as_data_transfer` variable is included for use
// making that distinction. By default it is set to `false`
TpktAppliSearchStateType tpkt_internal_search_from_osi_session_layer(Cursor* tpkt_cur, bool
    process_as_data_transfer)
{
    // overlay the session header
    const OsiSessionHdr* hdr = (const OsiSessionHdr*)tpkt_cur->start();

    // get the flow data
    const Packet* p      = DetectionEngine::get_current_packet();
    TpktFlowData* tpktfd = (TpktFlowData*)p->flow->get_flow_data(TpktFlowData::inspector_id);

    bool checks_pass = false;

    // if flow data cannot be found something went wrong and we should just
    // exit. the flow data should not be initialized at this point
    if (tpktfd)
    {
        // track the SPDU type for when we get to the presentation layer
        // this is tracked in the session data so that the value can be
        // preserved even when a message is split at the start of the
        // presentation layer
        tpktfd->ssn_data.cur_spdu_type = (OsiSessionSpduType)hdr->spdu_type;

        // length must be smaller than or equal to the number of bytes remaining
        // this is the case because in the TPKT stage we will have waited to
        // start processing until all of the data for that layer was collected.
        if (hdr->length <= tpkt_cur->size())
        {
            // increase the `tpkt_cur` to point to the data following
            // the OSI Session Layer
            if (tpkt_cur->add_pos(sizeof(OsiSessionHdr)))
            {
                checks_pass = true;
            }
        }
    }

    if (!checks_pass)
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    // determine parsing from here on out based on the SPDU type
    switch (hdr->spdu_type)
    {
    // Give Tokens or Data Transfer
    case OSI_SESSION_SPDU__GT_DT:
        // bail when the length field of this SPDU is non-null
        if (hdr->length != 0x00)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        // Annoyingly the SPDU type for `Give Tokens` and
        // `Data Transfer` are the same. Fortunately the
        // `Data Transfer` seems to require a `Give Tokens`
        // layer to have appeared first
        if (process_as_data_transfer)
        {
            // treat this layer as a `Data Transfer` SPDU
            // since there is no data allowed with the `Data Transfer`
            //  SPDU there is no need to increment the cursor

            // session layer evaluation has passed and processing gets
            // handed off to the presentation layer
            const TpktAppliSearchStateType res = tpkt_search_from_osi_pres_layer(tpkt_cur);

            // return the result when a definitive answer has been found
            if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
            {
                return res;
            }
        }
        else
        {
            // treat this layer as a `Give Tokens` SPDU
            // since there is no data allowed with the `Give Tokens`
            // SPDU there is no need to increment the cursor

            // next session layer should be treated as a DT SPDU
            TpktAppliSearchStateType res = tpkt_search_from_osi_session_layer(tpkt_cur,
                OSI_SESSION_PROCESS_AS_DT__TRUE);

            // return the result when a definitive answer has been found
            if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
            {
                return res;
            }
        }

        break;

    // Connect
    case OSI_SESSION_SPDU__CN:
    {
        // bail when the length field of this SPDU is non-null
        if (hdr->length == 0x00)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        // save off the current index for loop comparison later
        uint32_t connect_spdu_data_idx = tpkt_cur->get_pos();

        // loop through the parameters
        // minus one is to account for the cursor being 0-indexed and
        //    the length being 1-indexed
        // set a maximum number of loops to the remaining number of
        //    bytes in the cursor divided by the smallest TLV (0x03)
        uint32_t max_loops      = get_max_loops(tpkt_cur);
        uint32_t max_pos        = get_max_pos(connect_spdu_data_idx, hdr->length);
        uint32_t loop_iteration = 0x00;
        while (tpkt_cur->get_pos() < max_pos and loop_iteration < max_loops)
        {
            TpktAppliSearchStateType res = resolve_spdu_parameter(tpkt_cur, hdr);
            if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
            {
                return res;
            }
            loop_iteration++;
        }

        break;
    }

    // Accept
    case OSI_SESSION_SPDU__AC:
    {
        // alert when the length field of this SPDU is null
        if (hdr->length == 0x00)
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        // save off the current index for loop comparison later
        uint32_t accept_spdu_data_idx = tpkt_cur->get_pos();

        // loop through the parameters
        // minus one is to account for the cursor being 0-indexed and
        //    the length being 1-indexed
        uint32_t max_loops      = get_max_loops(tpkt_cur);
        uint32_t max_pos        = get_max_pos(accept_spdu_data_idx, hdr->length);
        uint32_t loop_iteration = 0x00;
        while (tpkt_cur->get_pos() < max_pos and loop_iteration < max_loops)
        {
            TpktAppliSearchStateType res = resolve_spdu_parameter(tpkt_cur, hdr);
            if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
            {
                return res;
            }
            loop_iteration++;
        }

        break;
    }

    default:
        tpkt_cur->set_pos(tpkt_cur->size());
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

