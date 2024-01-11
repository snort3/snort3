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

// osi_acse_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "osi_acse_decode.h"

#include "osi_session_decode.h"
#include "osi_pres_decode.h"

using namespace snort;

static TpktAppliSearchStateType decode_osi_acse_proto_ver_param(const BerElement*, Cursor*);
static TpktAppliSearchStateType decode_osi_acse_context_name_param(BerReader*, Cursor*);
static TpktAppliSearchStateType decode_osi_acse_user_data_param(BerReader*, Cursor*);
static TpktAppliSearchStateType decode_osi_acse_aarq_param(BerReader*, Cursor*);
static TpktAppliSearchStateType decode_osi_acse_aare_param(BerReader*, Cursor*);

static TpktAppliSearchStateType decode_osi_acse_proto_ver_param(const BerElement* e,
    Cursor* tpkt_cur)
{
    if (!tpkt_cur->add_pos(e->length))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

static TpktAppliSearchStateType decode_osi_acse_context_name_param(BerReader* ber,
    Cursor* tpkt_cur)
{
    BerElement e;

    enum
    {
        ASO_CONTEXT_NAME_OID_TAG = 0x06,
    };

    // read message type tag
    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_AND_PAYLOAD))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    switch (e.type)
    {
    case ASO_CONTEXT_NAME_OID_TAG:
        break;

    default:
        tpkt_cur->set_pos(tpkt_cur->size());
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

static TpktAppliSearchStateType decode_osi_acse_user_data_param(BerReader* ber, Cursor* tpkt_cur)
{
    enum
    {
        USER_INFORMATION_ASSOCIATION_DATA_TAG = 0x28,
    };

    BerElement e;

    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    switch (e.type)
    {
    case USER_INFORMATION_ASSOCIATION_DATA_TAG:
    {
        // save off the current index for loop comparison later
        const uint32_t user_data_idx = tpkt_cur->get_pos();

        // context definition list length
        const uint32_t user_data_length = e.length;

        // loop through the parameters
        // minus one is to account for the cursor being 0-indexed and
        //    the length being 1-indexed
        // set a maximum number of loops to the remaining number of
        //    bytes in the cursor divided by the smallest TLV (0x03)
        const uint32_t max_loops      = get_max_loops(tpkt_cur);
        uint32_t loop_iteration = 0x00;
        while (tpkt_cur->get_pos() < (user_data_idx + user_data_length - 1) and loop_iteration <
            max_loops)
        {
            enum
            {
                ASSOCIATION_DATA_DIRECT_REFERENCE   = 0x06,
                ASSOCIATION_DATA_INDIRECT_REFERENCE = 0x02,
                ASSOCIATION_DATA_ENCODING_ASN1      = 0xA0,
            };

            if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
            {
                return TPKT_APPLI_SEARCH_STATE__EXIT;
            }

            switch (e.type)
            {
            case ASSOCIATION_DATA_DIRECT_REFERENCE:   // fallthrough
            case ASSOCIATION_DATA_INDIRECT_REFERENCE:
                if (!tpkt_cur->add_pos(e.length))
                {
                    return TPKT_APPLI_SEARCH_STATE__EXIT;
                }
                break;

            case ASSOCIATION_DATA_ENCODING_ASN1:
                // don't increment the cursor past these bytes as this
                // is actually the start of MMS

                // read the next tag to get the MMS size
                if (process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_NONE))
                {
                    // make sure the cursor has the byte to be requested
                    if (tpkt_cur->get_pos() + e.length <= tpkt_cur->size())
                    {
                        // return true indicating that we have found MMS data
                        return TPKT_APPLI_SEARCH_STATE__MMS_FOUND;
                    }
                }
                return TPKT_APPLI_SEARCH_STATE__EXIT;

            default:
                tpkt_cur->set_pos(tpkt_cur->size());
                return TPKT_APPLI_SEARCH_STATE__EXIT;
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

static TpktAppliSearchStateType decode_osi_acse_aarq_param(BerReader* ber, Cursor* tpkt_cur)
{
    // define types relevant
    enum
    {
        OSI_ACSE_AARQ_PROTO_VERSION        = 0x80,
        OSI_ACSE_AARQ_ASO_CONTEXT_NAME     = 0xA1,
        OSI_ACSE_AARQ_CALLED_AP_TITLE      = 0xA2,
        OSI_ACSE_AARQ_CALLED_AE_QUALIFIER  = 0xA3,
        OSI_ACSE_AARQ_CALLING_AP_TITLE     = 0xA6,
        OSI_ACSE_AARQ_CALLING_AE_QUALIFIER = 0xA7,
        OSI_ACSE_AARQ_USER_INFORMATION     = 0xBE,
    };

    BerElement e;

    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    switch (e.type)
    {
    case OSI_ACSE_AARQ_PROTO_VERSION:
        return decode_osi_acse_proto_ver_param(&e, tpkt_cur);

    case OSI_ACSE_AARQ_ASO_CONTEXT_NAME:
        return decode_osi_acse_context_name_param(ber, tpkt_cur);

    case OSI_ACSE_AARQ_CALLED_AP_TITLE:
        enum
        {
            CALLED_AP_TITLE_OID_TAG = 0x06,
        };

        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_AND_PAYLOAD))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case CALLED_AP_TITLE_OID_TAG:
            break;

        default:
            tpkt_cur->set_pos(tpkt_cur->size());
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;

    case OSI_ACSE_AARQ_CALLED_AE_QUALIFIER:
        enum
        {
            CALLED_AE_QUALIFIER_VALUE_TAG = 0x02,
        };

        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_AND_PAYLOAD))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case CALLED_AE_QUALIFIER_VALUE_TAG:
            break;

        default:
            tpkt_cur->set_pos(tpkt_cur->size());
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;

    case OSI_ACSE_AARQ_CALLING_AP_TITLE:
        enum
        {
            CALLING_AP_TITLE_OID_TAG = 0x06,
        };

        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_AND_PAYLOAD))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case CALLING_AP_TITLE_OID_TAG:
            break;

        default:
            tpkt_cur->set_pos(tpkt_cur->size());
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;

    case OSI_ACSE_AARQ_CALLING_AE_QUALIFIER:
        enum
        {
            CALLING_AE_QUALIFIER_VALUE_TAG = 0x02,
        };

        if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_AND_PAYLOAD))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        switch (e.type)
        {
        case CALLING_AE_QUALIFIER_VALUE_TAG:
            break;

        default:
            tpkt_cur->set_pos(tpkt_cur->size());
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }

        break;

    case OSI_ACSE_AARQ_USER_INFORMATION:
        return decode_osi_acse_user_data_param(ber, tpkt_cur);

    default:
        tpkt_cur->set_pos(tpkt_cur->size());
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

static TpktAppliSearchStateType decode_osi_acse_aare_param(BerReader* ber, Cursor* tpkt_cur)
{
    // define types relevant
    enum
    {
        OSI_ACSE_AARE_PROTO_VERSION            = 0x80,
        OSI_ACSE_AARE_ASO_CONTEXT_NAME         = 0xA1,
        OSI_ACSE_AARE_RESULT                   = 0xA2,
        OSI_ACSE_AARE_RESULT_SOURCE_DIAGNOSTIC = 0xA3,
        OSI_ACSE_AARE_RESPONDING_AP_TITLE      = 0xA4,
        OSI_ACSE_AARE_RESPONDING_AE_QUALIFIER  = 0xA5,
        OSI_ACSE_AARE_USER_INFORMATION         = 0xBE,
    };

    BerElement e;

    if (!process_next_ber_tag(ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    switch (e.type)
    {
    case OSI_ACSE_AARE_PROTO_VERSION:
        return decode_osi_acse_proto_ver_param(&e, tpkt_cur);

    case OSI_ACSE_AARE_ASO_CONTEXT_NAME:
        return decode_osi_acse_context_name_param(ber, tpkt_cur);

    case OSI_ACSE_AARE_RESULT:
        if (!tpkt_cur->add_pos(e.length))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }
        break;

    case OSI_ACSE_AARE_RESULT_SOURCE_DIAGNOSTIC:  // fallthrough
    case OSI_ACSE_AARE_RESPONDING_AP_TITLE:       // fallthrough
    case OSI_ACSE_AARE_RESPONDING_AE_QUALIFIER:
        if (!tpkt_cur->add_pos(e.length))
        {
            return TPKT_APPLI_SEARCH_STATE__EXIT;
        }
        break;

    case OSI_ACSE_AARE_USER_INFORMATION:
        return decode_osi_acse_user_data_param(ber, tpkt_cur);

    default:
        tpkt_cur->set_pos(tpkt_cur->size());
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    return TPKT_APPLI_SEARCH_STATE__SEARCH;
}

TpktAppliSearchStateType tpkt_internal_search_from_osi_acse_layer(Cursor* tpkt_cur)
{
    // initialize a BER reader
    BerReader ber(*tpkt_cur);
    BerElement e;

    // read message type tag
    if (!process_next_ber_tag(&ber, &e, tpkt_cur, BER_TAG__ADD_HEADER_ONLY))
    {
        return TPKT_APPLI_SEARCH_STATE__EXIT;
    }

    // determine message type
    switch (e.type)
    {
    case OSI_ACSE_AARQ:
    {
        const uint32_t aarq_idx    = tpkt_cur->get_pos();
        const uint32_t aarq_length = e.length;

        // loop through the parameters
        // minus one is to account for the cursor being 0-indexed and
        //    the length being 1-indexed
        // set a maximum number of loops to the remaining number of
        //    bytes in the cursor divided by the smallest TLV (0x03)
        const uint32_t max_loops      = get_max_loops(tpkt_cur);
        uint32_t loop_iteration = 0x00;
        while (tpkt_cur->get_pos() < (aarq_idx + aarq_length - 1) and loop_iteration < max_loops)
        {
            TpktAppliSearchStateType res = decode_osi_acse_aarq_param(&ber, tpkt_cur);
            if (res != TPKT_APPLI_SEARCH_STATE__SEARCH)
            {
                return res;
            }
            loop_iteration++;
        }
        break;
    }

    case OSI_ACSE_AARE:
    {
        const uint32_t aare_idx    = tpkt_cur->get_pos();
        const uint32_t aare_length = e.length;

        // loop through the parameters
        // minus one is to account for the cursor being 0-indexed and
        //    the length being 1-indexed
        // set a maximum number of loops to the remaining number of
        //    bytes in the cursor divided by the smallest TLV (0x03)
        const uint32_t max_loops      = get_max_loops(tpkt_cur);
        uint32_t loop_iteration = 0x00;
        while (tpkt_cur->get_pos() < (aare_idx + aare_length - 1) and loop_iteration < max_loops)
        {
            TpktAppliSearchStateType res = decode_osi_acse_aare_param(&ber, tpkt_cur);
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

