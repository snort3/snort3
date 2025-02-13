//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// osi_pres_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "osi_pres_decode.h"

#include "service_inspectors/mms/mms_decode.h"

#include "osi_session_decode.h"

using namespace snort;

static OsiPresPpduModeSelectorType resolve_mode_selector(BerReader*, Cursor*, uint32_t);
static TpktAppliSearchStateType decode_osi_pres_context_list_item(BerReader*, Cursor*);
static TpktAppliSearchStateType decode_osi_pres_normal_mode_params(BerReader*, Cursor*);

bool process_next_ber_tag(BerReader* ber, BerElement* e, Cursor* tpkt_cur, BerTagProcessType
    process_type)
{
    if (e and ber->read(tpkt_cur->start(), *e))
    {
        // determine if the cursor needs to be incremented by only the header
        // length or both the header and payload length
        switch (process_type)
        {
        case BER_TAG__ADD_NONE:
            return true;

        case BER_TAG__ADD_HEADER_ONLY:
            return tpkt_cur->add_pos(e->header_length);

        case BER_TAG__ADD_HEADER_AND_PAYLOAD:
            return tpkt_cur->add_pos(e->header_length + e->length);
        }
    }
    return false;
}

static OsiPresPpduModeSelectorType resolve_mode_selector(BerReader* ber, Cursor* tpkt_cur, uint32_t
    spdu_type)
{
    // define types relevant for the mode selector
    enum
    {
        OSI_PRES_TYPE_SEQ          = 0x31,
        OSI_PRES_MODE_VALUE        = 0x80,
        OSI_PRES_MODE_SELECTOR_SEQ = 0xA0,
    };

    BerElement e;

    switch (spdu_type)
    {
    case OSI_SESSION_SPDU__CN:             // fallthrough
    case OSI_SESSION_SPDU__AC:
        // read the CP-type PDU
        if (process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
        {
            if (e.type == OSI_PRES_TYPE_SEQ)
            {
                // increment the cursor to point to the next tag
                if (tpkt_cur->add_pos(e.header_length))
                {
                    // read the mode selector value
                    if (process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
                    {
                        if (e.type == OSI_PRES_MODE_SELECTOR_SEQ)
                        {
                            // increment the cursor to point to the next tag
                            if (tpkt_cur->add_pos(e.header_length))
                            {
                                // read the mode selector value
                                if (process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
                                {
                                    if (e.type == OSI_PRES_MODE_VALUE)
                                    {
                                        if (!tpkt_cur->add_pos(e.header_length + e.length))
                                        {
                                            break;
                                        }
                                        if ((OsiPresPpduModeSelectorType) * e.data ==
                                            OSI_PRES_MODE__NORMAL)
                                        {
                                            return OSI_PRES_MODE__NORMAL;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        break;
    }

    tpkt_cur->set_pos(tpkt_cur->size());
    return OSI_PRES_MODE__INVALID;
}

static TpktAppliSearchStateType decode_osi_pres_context_list_item(BerReader* ber, Cursor* tpkt_cur)
{
    // define types relevant for the context definition result list
    enum OsiPresContextListItemType
    {
        OSI_PRES_CONTEXT_LIST_PRES_CONTEXT_ID           = 0x02,
        OSI_PRES_CONTEXT_LIST_ABSTRACT_SYNTAX_NAME      = 0x06,
        OSI_PRES_CONTEXT_LIST_TRANSFER_SYNTAX_NAME_LIST = 0x30,
        OSI_PRES_CONTEXT_LIST_RESULT                    = 0x80,
        OSI_PRES_CONTEXT_LIST_TRANSFER_SYNTAX_NAME      = 0x81,
        OSI_PRES_CONTEXT_LIST_PRES_DATA_VALUES          = 0xA0,
    };

    // save off the current index for loop comparison later
    uint32_t context_list_param_idx = tpkt_cur->get_pos();

    // null the context identifier
    uint8_t context_id = OSI_PRES_CONTEXT_ID__NULL;

    BerElement e;

    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    // context definition list length
    uint32_t context_list_length = e.length;

    // loop through the parameters
    // set a maximum number of loops to the remaining number of
    //    bytes in the cursor divided by the smallest TLV (0x03)
    uint32_t max_loops      = get_max_loops(tpkt_cur);
    uint32_t max_pos        = get_max_pos(context_list_param_idx, context_list_length);
    uint32_t loop_iteration = 0x00;
    while (tpkt_cur->get_pos() < max_pos and loop_iteration < max_loops)
    {
        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case OSI_PRES_CONTEXT_LIST_PRES_CONTEXT_ID:
        {
            struct OsiPresContextListPresContextId
            {
                uint8_t id;
            };

            const OsiPresContextListPresContextId* param = (const
                OsiPresContextListPresContextId*)e.data;

            switch (param->id)
            {
            case OSI_PRES_CONTEXT_ID__ACSE:
                context_id = OSI_PRES_CONTEXT_ID__ACSE;
                break;

            case OSI_PRES_CONTEXT_ID__MMS:
                context_id = OSI_PRES_CONTEXT_ID__MMS;
                break;

            default:
                tpkt_cur->set_pos(tpkt_cur->size());
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            // increment cursor to next group
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;
        }

        case OSI_PRES_CONTEXT_LIST_ABSTRACT_SYNTAX_NAME:
            // increment cursor to next group
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_CONTEXT_LIST_TRANSFER_SYNTAX_NAME_LIST:
            // increment cursor to next group
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_CONTEXT_LIST_RESULT:
            // increment cursor to next group
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_CONTEXT_LIST_TRANSFER_SYNTAX_NAME:
            // increment cursor to next group
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_CONTEXT_LIST_PRES_DATA_VALUES:
            enum OsiPresDataValuesType
            {
                OSI_PRES_SINGLE_ASN1_TYPE = 0xA0,
            };

            // get the data value type
            if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            // at this time only single asn1 type is expected
            switch (e.type)
            {
            case OSI_PRES_SINGLE_ASN1_TYPE:
                switch (context_id)
                {
                case OSI_PRES_CONTEXT_ID__ACSE:
                    return tpkt_search_from_osi_acse_layer(tpkt_cur);

                case OSI_PRES_CONTEXT_ID__MMS:
                    // read the next tag to get the MMS size
                    if (process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
                    {
                        if (tpkt_cur->get_pos() + e.length <= tpkt_cur->size())
                        {
                            // return true indicating that we have found MMS data
                            return TPKT_APPLI_SEARCH_STATE__MMS_FOUND;
                        }
                    }
                    return TPKT_APPLI_SEARCH_STATE__EXIT;

                default:
                    return TPKT_APPLI_SEARCH_STATE__EXIT;
                }
                break;

            default:
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }
            break;
        }

        loop_iteration++;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

static TpktAppliSearchStateType decode_osi_pres_normal_mode_params(BerReader* ber,
    Cursor* tpkt_cur)
{
    // define types relevant for the normal mode params
    enum OsiPresNormalModeParamsType
    {
        OSI_PRES_NORMAL_PARAM_PROTO_VERSION                       = 0x80,
        OSI_PRES_NORMAL_PARAM_CALLING_PRES_SELECTOR               = 0x81,
        OSI_PRES_NORMAL_PARAM_CALLED_PRES_SELECTOR                = 0x82,
        OSI_PRES_NORMAL_PARAM_RESPONDING_PRES_SELECTOR            = 0x83,
        OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_LIST        = 0xA4,
        OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_LIST_ITEM              = 0x30,
        OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_RESULT_LIST = 0xA5,
        OSI_PRES_NORMAL_PARAM_PRES_REQS                           = 0x88,
        OSI_PRES_NORMAL_PARAM_USER_DATA                           = 0x61,
    };

    BerElement e;

    // save off the current index for loop comparison later
    uint32_t normal_mode_param_idx = tpkt_cur->get_pos();

    // increment the cursor to point to the next tag
    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    // get the normal mode parameters length
    uint32_t normal_mode_param_length = e.total_length - e.header_length;

    // loop through the parameters
    // set a maximum number of loops to the remaining number of
    //    bytes in the cursor divided by the smallest TLV (0x03)
    uint32_t normal_mode_param_max_loops      = get_max_loops(tpkt_cur);
    uint32_t normal_mode_param_max_pos        = get_max_pos(normal_mode_param_idx,
        normal_mode_param_length);
    uint32_t normal_mode_param_loop_iteration = 0x00;
    while (tpkt_cur->get_pos() < normal_mode_param_max_pos and normal_mode_param_loop_iteration <
        normal_mode_param_max_loops)
    {
        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case OSI_PRES_NORMAL_PARAM_PROTO_VERSION:
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_NORMAL_PARAM_CALLING_PRES_SELECTOR:
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_NORMAL_PARAM_CALLED_PRES_SELECTOR:
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_NORMAL_PARAM_RESPONDING_PRES_SELECTOR:
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_LIST:
        {
            if (!tpkt_cur->add_pos(e.header_length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            // save off the current index for loop comparison later
            uint32_t context_definition_list_idx = tpkt_cur->get_pos();

            // context definition list length
            uint32_t context_definition_list_length = e.length;

            // loop through the parameters
            // set a maximum number of loops to the remaining number of
            //    bytes in the cursor divided by the smallest TLV (0x03)
            uint32_t context_list_item_max_loops = get_max_loops(tpkt_cur);
            uint32_t max_pos = get_max_pos(context_definition_list_idx,
                context_definition_list_length);
            uint32_t context_list_item_loop_iteration = 0x00;
            while (tpkt_cur->get_pos() < max_pos and context_list_item_loop_iteration <
                context_list_item_max_loops)
            {
                TpktAppliSearchStateType res = decode_osi_pres_context_list_item(ber, tpkt_cur);
                if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
                {
                    return res;
                }
                context_list_item_loop_iteration++;
            }

            break;
        }

        case OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_RESULT_LIST:
        {
            if (!tpkt_cur->add_pos(e.header_length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            // save off the current index for loop comparison later
            uint32_t context_definition_result_list_idx = tpkt_cur->get_pos();

            // context definition list length
            uint32_t context_definition_result_list_length = e.length;

            // loop through the parameters
            // set a maximum number of loops to the remaining number of
            //    bytes in the cursor divided by the smallest TLV (0x03)
            uint32_t context_list_item_max_loops      = get_max_loops(tpkt_cur);
            uint32_t context_list_item_max_pos        = get_max_pos(
                context_definition_result_list_idx, context_definition_result_list_length);
            uint32_t context_list_item_loop_iteration = 0x00;
            while (tpkt_cur->get_pos() < context_list_item_max_pos and
                context_list_item_loop_iteration < context_list_item_max_loops)
            {
                TpktAppliSearchStateType res = decode_osi_pres_context_list_item(ber, tpkt_cur);
                if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
                {
                    return res;
                }
                context_list_item_loop_iteration++;
            }

            break;
        }

        case OSI_PRES_NORMAL_PARAM_PRES_REQS:
            if (!tpkt_cur->add_pos(e.header_length + e.length))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;

        case OSI_PRES_NORMAL_PARAM_USER_DATA:
        {
            TpktAppliSearchStateType res = TPKT_APPLI_SEARCH_STATE__EXIT;
            if (tpkt_cur->add_pos(e.header_length))
            {
                // Decode the user data item
                // Returning directly here as this item is the determining factor
                // on whether or not a sub protocol is contained within the data
                // No need to loop here as the User Data item is not a list
                res = decode_osi_pres_context_list_item(ber, tpkt_cur);
            }

            return res;
        }

        default:
            tpkt_cur->set_pos(tpkt_cur->size());
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        normal_mode_param_loop_iteration++;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

// process the data with the starting assumption of an OSI Presentation layer
TpktAppliSearchStateType tpkt_internal_search_from_osi_pres_layer(Cursor* tpkt_cur)
{
    // get the flow data
    Packet* p      = DetectionEngine::get_current_packet();
    TpktFlowData* tpktfd = (TpktFlowData*)p->flow->get_flow_data(TpktFlowData::inspector_id);

    // if flow data cannot be found something went wrong and we should just
    // exit. the flow data should not be initialized at this point
    if (tpktfd)
    {
        // retrieve the SPDU type in our flow data
        OsiSessionSpduType spdu_type = tpktfd->ssn_data.cur_spdu_type;

        // prepare to read the BER data
        BerReader ber(*tpkt_cur);
        BerElement e;

        // change parsing based on what SPDU type we noticed in the Session layer
        switch (spdu_type)
        {
        // Give Tokens or Data Transfer
        case OSI_SESSION_SPDU__GT_DT:
            // get the normal mode parameters length
            if (process_next_ber_tag(&ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
            {
                return decode_osi_pres_context_list_item(&ber, tpkt_cur);
            }
            break;

        // Connect
        case OSI_SESSION_SPDU__CN:
        {
            // determine the mode
            uint32_t mode = resolve_mode_selector(&ber, tpkt_cur, spdu_type);

            switch (mode)
            {
            case OSI_PRES_MODE__NORMAL:
                return decode_osi_pres_normal_mode_params(&ber, tpkt_cur);

            default:
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;
        }

        // Accept
        case OSI_SESSION_SPDU__AC:
        {
            // determine the mode
            uint32_t mode = resolve_mode_selector(&ber, tpkt_cur, spdu_type);

            switch (mode)
            {
            case OSI_PRES_MODE__NORMAL:
                return decode_osi_pres_normal_mode_params(&ber, tpkt_cur);

            default:
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            break;
        }

        default:
            break;
        }
    }

    return TPKT_APPLI_SEARCH_STATE__EXIT;
}

