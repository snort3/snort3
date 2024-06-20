//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// mms_curses.cc author Jared Rittle <jared.rittle@cisco.com>
// Moved from curses.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mms_curse.h"
#include "curse_book.h"

#include <assert.h>

enum PresCtx
{
    PRES_CTX_ACSE = 1,
    PRES_CTX_MMS = 3,
};

static bool verify_search_depth_idx( unsigned len, uint32_t idx, uint32_t max_depth_idx )
{
    return idx + max_depth_idx < len;
}

static uint32_t search_for_osi_session_spdu( MmsTracker& mms, const uint8_t* data, uint32_t idx )
{
    switch ( data[idx] )
    {
    // check for a known MMS message tag in the event Session/Pres/ACSE aren't used
    case MMS_CONFIRMED_REQUEST_TAG:    // fallthrough intentional
    case MMS_CONFIRMED_RESPONSE_TAG:   // fallthrough intentional
    case MMS_CONFIRMED_ERROR_TAG:      // fallthrough intentional
    case MMS_UNCONFIRMED_TAG:          // fallthrough intentional
    case MMS_REJECT_TAG:               // fallthrough intentional
    case MMS_CANCEL_REQUEST_TAG:       // fallthrough intentional
    case MMS_CANCEL_RESPONSE_TAG:      // fallthrough intentional
    case MMS_CANCEL_ERROR_TAG:         // fallthrough intentional
    case MMS_INITIATE_REQUEST_TAG:     // fallthrough intentional
    case MMS_INITIATE_RESPONSE_TAG:    // fallthrough intentional
    case MMS_INITIATE_ERROR_TAG:       // fallthrough intentional
    case MMS_CONCLUDE_REQUEST_TAG:     // fallthrough intentional
    case MMS_CONCLUDE_RESPONSE_TAG:    // fallthrough intentional
    case MMS_CONCLUDE_ERROR_TAG:
    {
        // when it looks like MMS this early, drop the index back one and push processing down to the full MMS parsing
        // taking this approach as there are other paths into the MMS determination
        if ( idx > 0 )
        {
            idx--;
            mms.state = MMS_STATE__MMS;
            break;
        }

        // default to MMS not found
        mms.state = MMS_STATE__NOT_FOUND;
        break;
    }

    // if mms isn't found, search for a supported OSI Session layer

    // check for the Confirmed Request/Response path
    case MMS_OSI_SESSION_SPDU_GT_DT:
    {
        mms.state = MMS_STATE__OSI_SESSION_SPDU_GT_LEN;
        break;
    }

    // check for the Initiate Request path
    case MMS_OSI_SESSION_SPDU_CN:
    {
        mms.state = MMS_STATE__OSI_SESSION_SPDU_CN_LEN;
        break;
    }

    // check for the Initiate Response path
    case MMS_OSI_SESSION_SPDU_AC:
    {
        mms.state = MMS_STATE__OSI_SESSION_SPDU_AC_LEN;
        break;
    }

    // if neither are found, it is most likely not MMS
    default:
    {
        mms.state = MMS_STATE__NOT_FOUND;
        break;
    }
    }
    return idx;
}

static uint32_t search_for_pres_ctx( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    // define some constants for search windows
    constexpr uint32_t fully_encoded_data_window = 3;
    constexpr uint32_t pres_ctx_window = 3;
    constexpr uint32_t max_depth_idx = fully_encoded_data_window + pres_ctx_window;

    // try to determine if the ACSE layer exists
    // len reduction is to allow space for the forward looking checks
    bool ctx_likely = false;
    for ( uint32_t init_byte = idx; ( init_byte < len - max_depth_idx ) && !ctx_likely; init_byte++)
    {
        // require the user-data fully encoded data tag ( | 61 | )
        if ( data[init_byte] != 0x61 )
        {
            continue;
        }

        // make sure there is still enough space left in the buffer for the forward search
        // allow up to two bytes for the fully encoded data field
        if ( !verify_search_depth_idx( len, init_byte, max_depth_idx ) )
        {
            // not enough data to process
            assert( !ctx_likely );
            break;
        }

        for ( uint32_t encode_tag_shift = 1; ( encode_tag_shift < fully_encoded_data_window ) && !ctx_likely; encode_tag_shift++ )
        {
            uint32_t encode_tag_byte = init_byte + encode_tag_shift;
            // look for the ' fully encoded data ' user data tag ( | 30 | );
            if ( data[encode_tag_byte] != 0x30 )
            {
                continue;
            }

            for ( uint32_t pres_ctx_shift = 1; ( pres_ctx_shift < + pres_ctx_window ) && !ctx_likely; pres_ctx_shift++ )
            {
                // look for the presentation context tag and length ( | 02 01 | )
                bool ctx_b1 = data[encode_tag_byte + pres_ctx_shift] == 0x02;
                bool ctx_b2 = data[encode_tag_byte + pres_ctx_shift + 1] == 0x01;
                if ( ctx_b1 && ctx_b2 )
                {
                    switch ( data[encode_tag_byte + pres_ctx_shift + 2] )
                    {
                    // set the state accordingly when the OSI ACSE presentation context ( | 01 | ) has been found
                    case PresCtx::PRES_CTX_ACSE:
                    {
                        // place the index at the last byte of the presentation context
                        idx = init_byte + encode_tag_shift + pres_ctx_shift + 2;
                        mms.state = MMS_STATE__OSI_ACSE;
                        ctx_likely = true;
                        break;
                    }
                    // set the state accordingly when the MMS presentation context ( | 03 | ) has been found
                    case PresCtx::PRES_CTX_MMS:
                    {
                        // place the index at the last byte of the presentation context
                        idx = init_byte + encode_tag_shift + pres_ctx_shift + 2;
                        mms.state = MMS_STATE__MMS;
                        ctx_likely = true;
                        break;
                    }
                    // no default as we want to keep looking if an acceptable context is not found
                    }
                }
            }
        }
    }
    return idx;
}

static uint32_t search_for_osi_session_spdu_params( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    enum
    {
        CN_SPDU_PARAM__CONNECT_ACCEPT_ITEM = 0x05,
        CN_SPDU_PARAM__SESSION_REQUIREMENT = 0x14,
        CN_SPDU_PARAM__SESSION_USER_DATA = 0xC1,
    };

    // len reduction is to allow space for the forward looking checks
    while ( idx < len - 3 )
    {
        // check for the possibility of a connect accept item
        if ( data[idx] == CN_SPDU_PARAM__CONNECT_ACCEPT_ITEM )
        {
            // track that the item was found
            mms.connect_accept_item_likely = true;
        }
        // check for the possibility of a session requirement
        else if ( data[idx] == CN_SPDU_PARAM__SESSION_REQUIREMENT )
        {
            // track that the item was found
            mms.session_requirement_likely = true;
        }
        // check for the possibility of a session user data item
        else if ( data[idx] == CN_SPDU_PARAM__SESSION_USER_DATA )
        {
            // when this has been found and there is a good chance all of the other required items exist, move on to look for mms
            if ( mms.connect_accept_item_likely &&
                mms.session_requirement_likely )
            {
                mms.state = MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN;
                break;
            }
            // otherwise it is unlikely that this is mms
            else
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }
        }
        // no else case as we want to allow for the possibility of non-standard items

        // increment the index to look at the item length field
        idx++;
        // increment the index to the end of the item data
        idx += data[idx];
        // increment the index to the start of the next item
        idx++;

        // if the index has gotten larger than the available buffer, bail
        if ( idx >= len )
        {
            mms.state = MMS_STATE__NOT_FOUND;
            break;
        }
    }
    return idx;
}

static uint32_t search_for_osi_acse_type( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    enum
    {
        OSI_ACSE_AARQ = 0x60,
        OSI_ACSE_AARE = 0x61,
    };

    constexpr uint32_t max_search_depth_idx = 3;
    if ( verify_search_depth_idx( len, idx, max_search_depth_idx ) )
    {
        // when ACSE is likely found, do processing at that layer to determine if MMS is being transported
        // length field could be 1-2 bytes depending on encoding
        for ( uint32_t j = 0; j < max_search_depth_idx; j++ )
        {
            // look for either the AARQ ( | 60 | ) or AARE ( | 61 | ) tag
            if ( data[idx+j] == OSI_ACSE_AARQ || data[idx+j] == OSI_ACSE_AARE )
            {
                mms.state = MMS_STATE__OSI_ACSE_DATA;
                idx += j;
                break;
            }
        }
    }
    return idx;
}

static uint32_t search_for_osi_acse_data( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    // this will likely be a good distance from the current position
    // minus three is to give space for the forward checks for the direct and indirect reference
    for ( uint32_t k = 0; idx+k < len-3; k++ )
    {
        // look for the MMS presentation context ( | 02 01 03 | )
        if ( data[idx+k] == 0x02 && data[idx+k+1] == 0x01 && data[idx+k+2] == 0x03 )
        {
            mms.state = MMS_STATE__MMS;
            // increment the index to the end of the mms context id reference
            idx += k+2;
            break;
        }
    }
    return idx;
}

static uint32_t search_for_mms( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    constexpr uint32_t max_search_depth_idx = 2;
    if ( verify_search_depth_idx( len, idx, max_search_depth_idx ) )
    {
        // search within the next two bytes to determine if mms is likely
        for ( uint32_t j = 0; j < max_search_depth_idx; j++ )
        {
            // for each remaining byte check to see if it is in the known tag map
            switch ( data[idx+j] )
            {
            case MMS_CONFIRMED_REQUEST_TAG:
            {
                mms.state = MMS_STATE__MMS_CONFIRMED_REQUEST;
                idx += j;
                break;
            }
            case MMS_CONFIRMED_RESPONSE_TAG:   // fallthrough intentional
            case MMS_CONFIRMED_ERROR_TAG:      // fallthrough intentional
            case MMS_UNCONFIRMED_TAG:          // fallthrough intentional
            case MMS_REJECT_TAG:               // fallthrough intentional
            case MMS_CANCEL_REQUEST_TAG:       // fallthrough intentional
            case MMS_CANCEL_RESPONSE_TAG:      // fallthrough intentional
            case MMS_CANCEL_ERROR_TAG:         // fallthrough intentional
            case MMS_INITIATE_REQUEST_TAG:     // fallthrough intentional
            case MMS_INITIATE_RESPONSE_TAG:    // fallthrough intentional
            case MMS_INITIATE_ERROR_TAG:       // fallthrough intentional
            case MMS_CONCLUDE_REQUEST_TAG:     // fallthrough intentional
            case MMS_CONCLUDE_RESPONSE_TAG:    // fallthrough intentional
            case MMS_CONCLUDE_ERROR_TAG:
            {
                // if an MMS tag exists in the remaining data,
                // hand off to the MMS service inspector
                mms.state = MMS_STATE__FOUND;
                idx += j;
                break;
            }
            // no default as we want to keep searching if a result wasn't found in this loop
            }

            // move on to the next case when a state has been set
            if ( mms.state != MMS_STATE__NOT_FOUND )
            {
                break;
            }
        }
    }
    return idx;
}

static uint32_t search_for_mms_confirmed_request( MmsTracker& mms, const uint8_t* data, unsigned len, uint32_t idx )
{
    // default to MMS not found
    mms.state = MMS_STATE__NOT_FOUND;

    // confirmed service request types
    enum
    {
        DEFINE_NAMED_TYPE_MESSAGE = 0xAE,
        DEFINE_NAMED_VARIABLE_MESSAGE = 0xA7,
        DEFINE_NAMED_VARIABLE_LIST_MESSAGE = 0xAB,
        DEFINE_SCATTERED_ACCESS_MESSAGE = 0xA8,
        DEFINE_SEMAPHORE_MESSAGE = 0xB5,
        DELETE_NAMED_TYPE_MESSAGE = 0xB0,
        DELETE_NAMED_VARIABLE_LIST_MESSAGE = 0xAD,
        DELETE_SEMAPHORE_MESSAGE = 0xB6,
        DELETE_VARIABLE_ACCESS_MESSAGE = 0xAA,
        DOWNLOAD_SEGMENT_MESSAGE = 0x9B,
        GET_NAME_LIST_MESSAGE = 0xA1,
        GET_NAMED_TYPE_ATTRIBUTES_MESSAGE = 0xAF,
        GET_NAMED_VARIABLE_LIST_ATTRIBUTES_MESSAGE = 0xAC,
        GET_SCATTERED_ACCESS_ATTRIBUTES_MESSAGE = 0xA9,
        GET_VARIABLE_ACCESS_ATTRIBUTES_MESSAGE = 0xA6,
        IDENTIFY_MESSAGE = 0x82,
        INITIATE_DOWNLOAD_SEQUENCE_MESSAGE = 0xBA,
        INITIATE_UPLOAD_SEQUENCE_MESSAGE = 0x9D,
        INPUT_MESSAGE = 0xB1,
        OUTPUT_MESSAGE = 0xB2,
        READ_MESSAGE = 0xA4,
        RELINQUISH_CONTROL_MESSAGE = 0xB4,
        RENAME_MESSAGE = 0xA3,
        REPORT_POOL_SEMAPHORE_STATUS_MESSAGE = 0xB8,
        REPORT_SEMAPHORE_ENTRY_STATUS_MESSAGE = 0xB9,
        REPORT_SEMAPHORE_STATUS_MESSAGE = 0xB7,
        STATUS_MESSAGE = 0x80,
        TAKE_CONTROL_MESSAGE = 0xB3,
        TERMINATE_DOWNLOAD_SEQUENCE_MESSAGE = 0xBC,
        UPLOAD_SEGMENT_MESSAGE = 0x9E,
        WRITE_MESSAGE = 0xA5,
        EXPANSION_9F = 0x9F,
        EXPANSION_BF = 0xBF,
    };

    // look for a known Confirmed Service Request 4-6 bytes away
    constexpr uint32_t max_search_depth_idx = 6;
    if ( verify_search_depth_idx( len, idx, max_search_depth_idx ) )
    {
        for ( uint32_t j = 3; j <= max_search_depth_idx; j++ )
        {
            // check for any of the single byte service tags
            switch ( data[idx+j] )
            {
            case DEFINE_NAMED_TYPE_MESSAGE: // fallthrough intentional
            case DEFINE_NAMED_VARIABLE_MESSAGE: // fallthrough intentional
            case DEFINE_NAMED_VARIABLE_LIST_MESSAGE: // fallthrough intentional
            case DEFINE_SCATTERED_ACCESS_MESSAGE: // fallthrough intentional
            case DEFINE_SEMAPHORE_MESSAGE: // fallthrough intentional
            case DELETE_NAMED_TYPE_MESSAGE: // fallthrough intentional
            case DELETE_NAMED_VARIABLE_LIST_MESSAGE: // fallthrough intentional
            case DELETE_SEMAPHORE_MESSAGE: // fallthrough intentional
            case DELETE_VARIABLE_ACCESS_MESSAGE: // fallthrough intentional
            case DOWNLOAD_SEGMENT_MESSAGE: // fallthrough intentional
            case GET_NAME_LIST_MESSAGE: // fallthrough intentional
            case GET_NAMED_TYPE_ATTRIBUTES_MESSAGE: // fallthrough intentional
            case GET_NAMED_VARIABLE_LIST_ATTRIBUTES_MESSAGE: // fallthrough intentional
            case GET_SCATTERED_ACCESS_ATTRIBUTES_MESSAGE: // fallthrough intentional
            case GET_VARIABLE_ACCESS_ATTRIBUTES_MESSAGE: // fallthrough intentional
            case IDENTIFY_MESSAGE: // fallthrough intentional
            case INITIATE_DOWNLOAD_SEQUENCE_MESSAGE: // fallthrough intentional
            case INITIATE_UPLOAD_SEQUENCE_MESSAGE: // fallthrough intentional
            case INPUT_MESSAGE: // fallthrough intentional
            case OUTPUT_MESSAGE: // fallthrough intentional
            case READ_MESSAGE: // fallthrough intentional
            case RELINQUISH_CONTROL_MESSAGE: // fallthrough intentional
            case RENAME_MESSAGE: // fallthrough intentional
            case REPORT_POOL_SEMAPHORE_STATUS_MESSAGE: // fallthrough intentional
            case REPORT_SEMAPHORE_ENTRY_STATUS_MESSAGE: // fallthrough intentional
            case REPORT_SEMAPHORE_STATUS_MESSAGE: // fallthrough intentional
            case STATUS_MESSAGE: // fallthrough intentional
            case TAKE_CONTROL_MESSAGE: // fallthrough intentional
            case TERMINATE_DOWNLOAD_SEQUENCE_MESSAGE: // fallthrough intentional
            case UPLOAD_SEGMENT_MESSAGE: // fallthrough intentional
            case WRITE_MESSAGE: // fallthrough intentional
            case EXPANSION_9F: // fallthrough intentional
            case EXPANSION_BF:
            {
                idx += j;
                mms.state = MMS_STATE__FOUND;
                break;
            }
            // no default as we want to keep searching if a result wasn't found in this loop
            }

            // move on to the next case when a state has been set
            if ( mms.state != MMS_STATE__NOT_FOUND )
            {
                break;
            }
        }
    }

    return idx;
}

bool CurseBook::mms_curse( const uint8_t* data, unsigned len, CurseTracker* tracker )
{
    // peg the tracker to MMS
    MmsTracker& mms = tracker->mms;

    // if the state is set to MMS_STATE__SEARCH it means we most likely
    // have a split pipelined message coming through and will need to
    // reset the state
    if ( mms.state == MMS_STATE__SEARCH )
    {
        mms.state = mms.last_state;
    }

    uint32_t idx = 0;
    while ( idx < len )
    {
        switch ( mms.state )
        {
        case MMS_STATE__TPKT_VER:
        {
            // MMS is only known to run over version | 03 |
            if ( data[idx] != 0x03 )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__TPKT_RES;
            break;
        }

        case MMS_STATE__TPKT_RES:
        {
            mms.state = MMS_STATE__TPKT_LEN1;
            break;
        }

        case MMS_STATE__TPKT_LEN1:
        {
            mms.state = MMS_STATE__TPKT_LEN2;
            break;
        }

        case MMS_STATE__TPKT_LEN2:
        {
            mms.state = MMS_STATE__COTP_LEN;
            break;
        }

        case MMS_STATE__COTP_LEN:
        {
            mms.state = MMS_STATE__COTP_PDU;
            break;
        }

        case MMS_STATE__COTP_PDU:
        {
            // 7 6 5 4 3 2 1 0
            // ---------------
            // . . . . x x x x   Destination Reference
            // x x x x . . . .   PDU Type
            constexpr uint32_t MMS_COTP_PDU_DT_DATA = 0x0F;

            if ( data[idx] >> 0x04 != MMS_COTP_PDU_DT_DATA )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__COTP_TPDU_NUM;
            break;
        }

        case MMS_STATE__COTP_TPDU_NUM:
        {
            mms.state = MMS_STATE__OSI_SESSION_SPDU;
            break;
        }

        case MMS_STATE__OSI_SESSION_SPDU:
        {
            idx = search_for_osi_session_spdu(mms, data, idx);
            break;
        }


        //
        // State path for most MMS messages
        //

        // check the length field of a GT SPDU
        case MMS_STATE__OSI_SESSION_SPDU_GT_LEN:
        {
            // length should always be zero for MMS
            if ( data[idx] != 0x00 )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__OSI_SESSION_SPDU_DT;
            break;
        }

        // check for the tag of a DT SPDU
        case MMS_STATE__OSI_SESSION_SPDU_DT:
        {
            // tag should always be | 01 | for DT
            if ( data[idx] != MMS_OSI_SESSION_SPDU_GT_DT )
            {
                mms.state = MMS_STATE__NOT_FOUND;
            break;
            }

            mms.state = MMS_STATE__OSI_SESSION_SPDU_DT_LEN;
            break;
        }

        // check the length field of a DT SPDU
        case MMS_STATE__OSI_SESSION_SPDU_DT_LEN:
        {
            // length should always be zero for MMS
            if ( data[idx] != 0x00 )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__OSI_PRES_USER_DATA;
            break;
        }

        // process the User Data Presentation type
        case MMS_STATE__OSI_PRES_USER_DATA:
        {
            idx = search_for_pres_ctx(mms, data, len, idx);
            break;
        }


        //
        // State path for Initiate-Request and Initiate-Response
        //

        // skip the CN SPDU length field
        case MMS_STATE__OSI_SESSION_SPDU_CN_LEN:
        {
            mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAMS;
            break;
        }

        // skip the AC SPDU length field
        case MMS_STATE__OSI_SESSION_SPDU_AC_LEN:
        {
            mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAMS;
            break;
        }

        // check the parameters
        case MMS_STATE__OSI_SESSION_SPDU_PARAMS:
        {
            idx = search_for_osi_session_spdu_params(mms, data, len, idx);
            break;
        }

        // jump over the length field
        case MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN:
        {
            mms.state = MMS_STATE__OSI_PRES_CP_CPA;
            break;
        }

        // process a CP or CPA presentation type
        case MMS_STATE__OSI_PRES_CP_CPA:
        {
            // look for the ' CP ' or ' CPA ' presentation type tag ( | 31 | );
            if ( data[idx] != 0x31 )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__OSI_PRES_CP_CPA_USER_DATA_ACSE_LOCATE;
            break;
        }

        //
        case MMS_STATE__OSI_PRES_CP_CPA_USER_DATA_ACSE_LOCATE:
        {
            idx = search_for_pres_ctx(mms, data, len, idx);
            break;
        }

        // check for ACSE
        case MMS_STATE__OSI_ACSE:
        {
            // look for the presentation data values single ASN1 type ( | A0 | );
            if ( data[idx] != 0xA0 )
            {
                mms.state = MMS_STATE__NOT_FOUND;
                break;
            }

            mms.state = MMS_STATE__OSI_ACSE_TYPE;
            break;
        }

        // look for a supported ACSE type tag
        case MMS_STATE__OSI_ACSE_TYPE:
        {
            idx = search_for_osi_acse_type(mms, data, len, idx);
            break;
        }

        //
        case MMS_STATE__OSI_ACSE_DATA:
        {
            idx = search_for_osi_acse_data(mms, data, len, idx);
            break;
        }


        //
        // State path for MMS convergence
        //

        // Look for a byte known to represent a MMS tag
        case MMS_STATE__MMS:
        {
            idx = search_for_mms(mms, data, len, idx);
            break;
        }

        case MMS_STATE__MMS_CONFIRMED_REQUEST:
        {
            idx = search_for_mms_confirmed_request(mms, data, len, idx);
            break;
        }

        case MMS_STATE__FOUND:
        {
            mms.state = MMS_STATE__TPKT_VER;

            return true;
        }

        case MMS_STATE__NOT_FOUND:
        {
            mms.state = MMS_STATE__TPKT_VER;

            return false;
        }

        default:
        {
            mms.state = MMS_STATE__NOT_FOUND;
            assert( false );
            break;
        }
        }

        idx++;
    }

    mms.last_state = mms.state;
    mms.state = MMS_STATE__SEARCH;

    return false;
}
