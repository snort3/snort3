//--------------------------------------------------------------------------
// Copyright (C) 2023-2026 Cisco and/or its affiliates. All rights reserved.
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
    assert( data );

    // Maximum length bytes to skip before resetting pattern search
    constexpr uint32_t MAX_SKIP_BYTES = 2;

    enum
    {
        USER_DATA_TAG = 0x61,
        ENCODED_DATA_TAG = 0x30,
        PRES_CTX_TAG = 0x02,
        PRES_CTX_LEN = 0x01,
    };

    while ( idx < len )
    {
        switch ( mms.state )
        {
        case MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG:
            if ( data[idx] == USER_DATA_TAG )
            {
                mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN;
                mms.state_remain = 0;
            }
            break;

        case MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN:
            if ( data[idx] == ENCODED_DATA_TAG )
            {
                mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_ENCODED_DATA_LEN;
                mms.state_remain = 0;
            }
            else if ( data[idx] == USER_DATA_TAG )
            {
                mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN;
                mms.state_remain = 0;
            }
            else if ( ++mms.state_remain > MAX_SKIP_BYTES )
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            break;

        case MMS_STATE__OSI_PRES_CTX_SKIP_ENCODED_DATA_LEN:
            if ( data[idx] == PRES_CTX_TAG )
            {
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN;
                mms.state_remain = 0;
            }
            else if ( data[idx] == USER_DATA_TAG )
            {
                mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN;
                mms.state_remain = 0;
            }
            else if ( ++mms.state_remain > MAX_SKIP_BYTES )
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            break;

        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_TAG:
            if ( data[idx] == PRES_CTX_TAG )
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN;
            else
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            break;

        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN:
            if ( data[idx] == PRES_CTX_LEN )
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT;
            else
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            break;

        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT:
            switch ( data[idx] )
            {
            case PresCtx::PRES_CTX_ACSE:
                mms.state = MMS_STATE__OSI_ACSE;
                return idx;

            case PresCtx::PRES_CTX_MMS:
                mms.state = MMS_STATE__MMS;
                return idx;

            default:
                mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
                break;
            }
            break;

        default:
            assert( false );
            break;
        }

        idx++;
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

    assert( data );

    while ( idx < len )
    {
        switch ( mms.state )
        {
        case MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE:
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
                    mms.state_remain = 0;
                    return idx;
                }
                // otherwise it is unlikely that this is mms
                else
                {
                    mms.state = MMS_STATE__NOT_FOUND;
                    mms.state_remain = 0;
                    return idx;
                }
            }

            mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_LEN;
            mms.state_remain = 1;

            break;
        }

        case MMS_STATE__OSI_SESSION_SPDU_PARAM_LEN:
        {
            mms.state_remain = data[idx];

            if ( mms.state_remain > 0 )
                mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_DATA;
            else
            {
                // no data for this parameter; move on to the next parameter type.
                mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;
                mms.state_remain = 1;
            }

            break;
        }

        case MMS_STATE__OSI_SESSION_SPDU_PARAM_DATA:
        {
            uint32_t advance_len = std::min<uint32_t>(
                static_cast<uint32_t>( mms.state_remain ), len - idx );

            // move to the end of data, adjusting for the upcoming idx++ at the end of the loop
            idx += advance_len - 1;

            mms.state_remain -= advance_len;

            if ( mms.state_remain == 0 )
            {
                mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;
                mms.state_remain = 1;
            }

            break;
        }

        default:
            assert( false );
            break;
        }

        idx++;
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
    assert( data );

    enum
    {
        ACSE_CONTEXT_TAG = 0x02,
        ACSE_CONTEXT_LEN = 0x01,
        ACSE_MMS_CONTEXT = 0x03,
        ACSE_ACSE_CONTEXT = 0x01,
    };

    while ( idx < len )
    {
        switch ( mms.state )
        {
        case MMS_STATE__OSI_ACSE_DATA_FIND_TAG:
            if ( data[idx] == ACSE_CONTEXT_TAG )
                mms.state = MMS_STATE__OSI_ACSE_DATA_CHECK_LEN;
            break;

        case MMS_STATE__OSI_ACSE_DATA_CHECK_LEN:
            if ( data[idx] == ACSE_CONTEXT_LEN )
                mms.state = MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT;
            else
                mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
            break;

        case MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT:
            switch ( data[idx] )
            {
            case ACSE_MMS_CONTEXT:
                mms.state = MMS_STATE__MMS;
                return idx;

            case ACSE_ACSE_CONTEXT:
                mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
                break;

            default:
                mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
            }
            break;

        default:
            mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
            assert( false );
            break;
        }

        idx++;
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
            mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            // Avoid processing current byte twice
            continue;
        }


        //
        // State path for Initiate-Request and Initiate-Response
        //

        // skip the CN SPDU length field
        case MMS_STATE__OSI_SESSION_SPDU_CN_LEN:
        {
            mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;
            break;
        }

        // skip the AC SPDU length field
        case MMS_STATE__OSI_SESSION_SPDU_AC_LEN:
        {
            mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;
            break;
        }

        // check the parameters
        case MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE:    // fallthrough intentional
        case MMS_STATE__OSI_SESSION_SPDU_PARAM_LEN:     // fallthrough intentional
        case MMS_STATE__OSI_SESSION_SPDU_PARAM_DATA:
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

        // Initialize presentation context search
        case MMS_STATE__OSI_PRES_CP_CPA_USER_DATA_ACSE_LOCATE:
        {
            mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
            continue;
        }

        // Presentation context search states
        case MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG:      // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN:        // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SEARCH_ENCODED_DATA_TAG:   // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SKIP_ENCODED_DATA_LEN:     // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_TAG:       // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN:       // fallthrough intentional
        case MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT:
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
            mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
            continue;
        }

        // ACSE data search states
        case MMS_STATE__OSI_ACSE_DATA_FIND_TAG:
        case MMS_STATE__OSI_ACSE_DATA_CHECK_LEN:
        case MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT:
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


//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

TEST_CASE("search_for_osi_session_spdu_params user data success", "[mms]")
{
    const uint8_t data[] = { 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;
    mms.connect_accept_item_likely = true;
    mms.session_requirement_likely = true;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), 0);

    CHECK(r == 0);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.state_remain == 0);
}

TEST_CASE("search_for_osi_session_spdu_params user data missing prerequisite", "[mms]")
{
    const uint8_t data[] = { 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), 0);

    CHECK(r == 0);
    CHECK(mms.state == MMS_STATE__NOT_FOUND);
    CHECK(mms.state_remain == 0);
}

TEST_CASE("search_for_osi_session_spdu_params zero length parameters", "[mms]")
{
    const uint8_t data[] = {
        0x05, 0x00,
        0x14, 0x00,
        0xC1
    };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), 0);

    CHECK(r == 4);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.connect_accept_item_likely);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params data in same buffer", "[mms]")
{
    const uint8_t data[] = {
        0x05, 0x01, 0xAA,
        0x14, 0x01, 0xBB,
        0xC1
    };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), 0);

    CHECK(r == 6);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.connect_accept_item_likely);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params unknown tag skip", "[mms]")
{
    const uint8_t data[] = {
        0xEE, 0x02, 0xAA, 0xBB,
        0x05, 0x00,
        0x14, 0x00,
        0xC1
    };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), 0);

    CHECK(r == 8);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.connect_accept_item_likely);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params split type and len", "[mms]")
{
    const uint8_t data1[] = { 0x05 };
    const uint8_t data2[] = { 0x01, 0x00, 0x14, 0x01, 0x00, 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    uint32_t r = search_for_osi_session_spdu_params(mms, data1, sizeof(data1), 0);
    CHECK(r == 1);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_PARAM_LEN);
    CHECK(mms.state_remain == 1);
    CHECK(mms.connect_accept_item_likely);

    r = search_for_osi_session_spdu_params(mms, data2, sizeof(data2), 0);
    CHECK(r == 5);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params split len and data", "[mms]")
{
    const uint8_t data1[] = { 0x05, 0x02 };
    const uint8_t data2[] = { 0xAA, 0xBB, 0x14, 0x01, 0x00, 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    uint32_t r = search_for_osi_session_spdu_params(mms, data1, sizeof(data1), 0);
    CHECK(r == 2);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_PARAM_DATA);
    CHECK(mms.state_remain == 2);
    CHECK(mms.connect_accept_item_likely);

    r = search_for_osi_session_spdu_params(mms, data2, sizeof(data2), 0);
    CHECK(r == 5);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params split midway through data", "[mms]")
{
    const uint8_t data1[] = { 0x05, 0x03, 0xAA };
    const uint8_t data2[] = { 0xBB, 0xCC, 0x14, 0x01, 0x00, 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    uint32_t r = search_for_osi_session_spdu_params(mms, data1, sizeof(data1), 0);
    CHECK(r == 3);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_PARAM_DATA);
    CHECK(mms.state_remain == 2);
    CHECK(mms.connect_accept_item_likely);

    r = search_for_osi_session_spdu_params(mms, data2, sizeof(data2), 0);
    CHECK(r == 5);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params split at data end", "[mms]")
{
    const uint8_t data1[] = { 0x05, 0x01, 0xAA };
    const uint8_t data2[] = { 0x14, 0x01, 0x00, 0xC1 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    uint32_t r = search_for_osi_session_spdu_params(mms, data1, sizeof(data1), 0);
    CHECK(r == 3);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE);
    CHECK(mms.state_remain == 1);
    CHECK(mms.connect_accept_item_likely);

    r = search_for_osi_session_spdu_params(mms, data2, sizeof(data2), 0);
    CHECK(r == 3);
    CHECK(mms.state == MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN);
    CHECK(mms.session_requirement_likely);
}

TEST_CASE("search_for_osi_session_spdu_params OOB index", "[mms]")
{
    const uint8_t data[] = { 1, 2, 3, 4, 5, 6 };

    MmsTracker mms;
    mms.state = MMS_STATE__OSI_SESSION_SPDU_PARAM_TYPE;

    const uint32_t r = search_for_osi_session_spdu_params(mms, data, sizeof(data), UINT32_MAX);
    CHECK(r == UINT32_MAX);
}

TEST_CASE("search_for_osi_acse_data: pattern found", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 2);
}

TEST_CASE("search_for_osi_acse_data: pattern not found", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: pattern at offset", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0xFF, 0xAA, 0x02, 0x01, 0x03, 0x00 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 4);
}

TEST_CASE("search_for_osi_acse_data: wrong length byte", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x02, 0x03 }; // Wrong length (0x02 instead of 0x01)
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: ACSE context found continues search", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // First ACSE context (02 01 01), then MMS context (02 01 03)
    uint8_t data[] = { 0x02, 0x01, 0x01, 0xAA, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 6);
}

TEST_CASE("search_for_osi_acse_data: partial match at buffer end", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0xAA, 0xBB, 0x02 }; // Tag found at end
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    // Should be in CHECK_LEN state waiting for next byte
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_LEN);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: resume from CHECK_LEN state", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_CHECK_LEN;

    uint8_t data[] = { 0x01, 0x03 }; // Length and context
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 1);
}

TEST_CASE("search_for_osi_acse_data: resume from CHECK_CONTEXT state", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT;

    uint8_t data[] = { 0x03 }; // MMS context
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 0);
}

TEST_CASE("search_for_osi_acse_data: empty buffer", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[1] = { };
    unsigned len = 0;
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result == 0);
}

TEST_CASE("search_for_osi_acse_data: multiple patterns only first found", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x01, 0x03, 0xFF, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 2); // Stops at first match
}

TEST_CASE("search_for_osi_acse_data: unknown context resets", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x01, 0x05, 0xAA, 0x02, 0x01, 0x03 }; // Unknown context 0x05
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 6); // Found second pattern after reset
}

TEST_CASE("search_for_osi_acse_data: pattern at start of buffer", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x01, 0x03, 0xFF };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 2);
}

TEST_CASE("search_for_osi_acse_data: long search with pattern at end", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 8);
}

TEST_CASE("search_for_osi_acse_data: fragmented across packets", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // First packet: tag found
    uint8_t data1[] = { 0xAA, 0x02 };
    uint32_t result1 = search_for_osi_acse_data(mms, data1, sizeof(data1), 0);

    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_LEN);
    CHECK(result1 == sizeof(data1));

    // Second packet: length and context
    uint8_t data2[] = { 0x01, 0x03 };
    uint32_t result2 = search_for_osi_acse_data(mms, data2, sizeof(data2), 0);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result2 == 1);
}

TEST_CASE("search_for_osi_acse_data: wrong length resets and finds next", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    uint8_t data[] = { 0x02, 0x03, 0xAA, 0x02, 0x01, 0x03 }; // Wrong len, then correct
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 5);
}

TEST_CASE("search_for_osi_acse_data: buffer boundary tag and length only", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // Buffer ends after tag and length, no context byte
    uint8_t data[] = { 0x02, 0x01 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    // Should be waiting for context byte in next packet
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: buffer boundary tag only", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // Buffer ends after tag only
    uint8_t data[] = { 0x02 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    // Should be waiting for length byte in next packet
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_LEN);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: buffer boundary with junk then tag", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // Buffer with junk data, then tag at very end
    uint8_t data[] = { 0xFF, 0xAA, 0xBB, 0x02 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    // Should find tag at end and wait for length
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_LEN);
    CHECK(result == len);
}

TEST_CASE("search_for_osi_acse_data: buffer boundary complete pattern at end", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // Complete pattern exactly at buffer end
    uint8_t data[] = { 0xFF, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_osi_acse_data(mms, data, len, idx);

    // Should find complete pattern
    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result == 3); // Points to last byte of pattern
}

TEST_CASE("search_for_osi_acse_data: three packet fragmentation", "[mms][acse]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;

    // First packet: ends with tag
    uint8_t data1[] = { 0xFF, 0x02 };
    uint32_t result1 = search_for_osi_acse_data(mms, data1, sizeof(data1), 0);
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_LEN);
    CHECK(result1 == sizeof(data1));

    // Second packet: only length
    uint8_t data2[] = { 0x01 };
    uint32_t result2 = search_for_osi_acse_data(mms, data2, sizeof(data2), 0);
    CHECK(mms.state == MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT);
    CHECK(result2 == sizeof(data2));

    // Third packet: context
    uint8_t data3[] = { 0x03 };
    uint32_t result3 = search_for_osi_acse_data(mms, data3, sizeof(data3), 0);
    CHECK(mms.state == MMS_STATE__MMS);
    CHECK(result3 == 0);
}

TEST_CASE("search_for_osi_acse_data: single byte buffer at each state", "[mms][acse]")
{
    // Test each state with minimal single-byte buffers

    // State 1: FIND_TAG with single byte
    MmsTracker mms1;
    mms1.state = MMS_STATE__OSI_ACSE_DATA_FIND_TAG;
    uint8_t data1[] = { 0xFF };
    uint32_t result1 = search_for_osi_acse_data(mms1, data1, sizeof(data1), 0);
    CHECK(mms1.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result1 == 1);

    // State 2: CHECK_LEN with wrong byte
    MmsTracker mms2;
    mms2.state = MMS_STATE__OSI_ACSE_DATA_CHECK_LEN;
    uint8_t data2[] = { 0xFF };
    uint32_t result2 = search_for_osi_acse_data(mms2, data2, sizeof(data2), 0);
    CHECK(mms2.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result2 == 1);

    // State 3: CHECK_CONTEXT with unknown context
    MmsTracker mms3;
    mms3.state = MMS_STATE__OSI_ACSE_DATA_CHECK_CONTEXT;
    uint8_t data3[] = { 0xFF };
    uint32_t result3 = search_for_osi_acse_data(mms3, data3, sizeof(data3), 0);
    CHECK(mms3.state == MMS_STATE__OSI_ACSE_DATA_FIND_TAG);
    CHECK(result3 == 1);
}

TEST_CASE("search_for_pres_ctx: complete pattern found", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 4);
}

TEST_CASE("search_for_pres_ctx: ACSE context found", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0x01, 0x01 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_ACSE));
    CHECK(result == 4);
}

TEST_CASE("search_for_pres_ctx: small payload no pattern", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0xFF };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: small payload partial match", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: buffer without 0x61 byte", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: buffer boundary protection", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: pattern with offset", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0xFF, 0xAA, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 6);
}

TEST_CASE("search_for_pres_ctx: wrong encoded data tag resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 6);
}

TEST_CASE("search_for_pres_ctx: wrong pres_ctx tag resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 7);
}

TEST_CASE("search_for_pres_ctx: wrong length resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 8);
}

TEST_CASE("search_for_pres_ctx: unknown context value resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0x01, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 9);
}

TEST_CASE("search_for_pres_ctx: single byte at buffer end", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0xFF, 0xAA, 0x61 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: empty buffer", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[1] = { };
    unsigned len = 0;
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == 0);
}

TEST_CASE("search_for_pres_ctx: resume from skip_user_data_len state", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN;
    mms.state_remain = 0;

    uint8_t data[] = { 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 3);
}

TEST_CASE("search_for_pres_ctx: resume with wrong byte resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN;
    mms.state_remain = 0;

    uint8_t data[] = { 0xFF, 0xFF, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 7);
}

TEST_CASE("search_for_pres_ctx: pattern at exact buffer end", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 4);
}

TEST_CASE("search_for_pres_ctx: multiple false starts", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0xFF, 0x61, 0x30, 0xFF, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 9);
}

TEST_CASE("search_for_pres_ctx: fragmented across packets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data1[] = { 0x61, 0x30 };
    uint32_t result1 = search_for_pres_ctx(mms, data1, sizeof(data1), 0);
    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SKIP_ENCODED_DATA_LEN));
    CHECK(result1 == sizeof(data1));

    uint8_t data2[] = { 0x02, 0x01 };
    uint32_t result2 = search_for_pres_ctx(mms, data2, sizeof(data2), 0);
    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT));
    CHECK(result2 == sizeof(data2));

    uint8_t data3[] = { 0x03 };
    uint32_t result3 = search_for_pres_ctx(mms, data3, sizeof(data3), 0);
    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result3 == 0);
}

TEST_CASE("search_for_pres_ctx: OOB protection with partial match", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0x02, 0x01 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: ASN.1 with length bytes", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x14, 0x30, 0x12, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 6);
}

TEST_CASE("search_for_pres_ctx: max skip bytes boundary exactly 2 bytes", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0xFF, 0xAA, 0xBB, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: skip encoded data len exceeds max skip bytes", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x30, 0xFF, 0xAA, 0xBB, 0x61, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 9);
}

TEST_CASE("search_for_pres_ctx: fragmented in length field", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data1[] = { 0x61, 0x14 };
    uint32_t result1 = search_for_pres_ctx(mms, data1, sizeof(data1), 0);
    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SKIP_USER_DATA_LEN));
    CHECK(result1 == sizeof(data1));

    uint8_t data2[] = { 0x30, 0x12, 0x02, 0x01 };
    uint32_t result2 = search_for_pres_ctx(mms, data2, sizeof(data2), 0);
    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_CONTEXT));
    CHECK(result2 == sizeof(data2));

    uint8_t data3[] = { 0x03 };
    uint32_t result3 = search_for_pres_ctx(mms, data3, sizeof(data3), 0);
    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result3 == 0);
}

TEST_CASE("search_for_pres_ctx: 2-byte ASN.1 length encoding", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x82, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 5);
}

TEST_CASE("search_for_pres_ctx: state_remain resets correctly", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0x14, 0x30, 0x12, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__MMS));
    CHECK(result == 6);
}

TEST_CASE("search_for_pres_ctx: exactly at max skip bytes then tag found", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x61, 0xFF, 0xAA, 0xBB, 0x30, 0x02, 0x01, 0x03 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: OOB read protection small payload", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x62, 0x63 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: resume from pres_ctx state", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0x02 };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_LEN));
    CHECK(result == len);
}

TEST_CASE("search_for_pres_ctx: resume from pres_ctx wrong tag resets", "[mms][pres_ctx]")
{
    MmsTracker mms;
    mms.state = MMS_STATE__OSI_PRES_CTX_SEARCH_PRES_CTX_TAG;
    mms.state_remain = 0;

    uint8_t data[] = { 0xFF };
    unsigned len = sizeof(data);
    uint32_t idx = 0;

    uint32_t result = search_for_pres_ctx(mms, data, len, idx);

    CHECK((mms.state == MMS_STATE__OSI_PRES_CTX_SEARCH_USER_DATA_TAG));
    CHECK(result == len);
}

#endif
