//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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

bool CurseBook::mms_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
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

    // define all known MMS tags to check for
    enum
    {
        MMS_CONFIRMED_REQUEST_TAG    = 0xA0,
        MMS_CONFIRMED_RESPONSE_TAG   = 0xA1,
        MMS_CONFIRMED_ERROR_TAG      = 0xA2,
        MMS_UNCONFIRMED_TAG          = 0xA3,
        MMS_REJECT_TAG               = 0xA4,
        MMS_CANCEL_REQUEST_TAG       = 0x85,
        MMS_CANCEL_RESPONSE_TAG      = 0x86,
        MMS_CANCEL_ERROR_TAG         = 0xA7,
        MMS_INITIATE_REQUEST_TAG     = 0xA8,
        MMS_INITIATE_RESPONSE_TAG    = 0xA9,
        MMS_INITIATE_ERROR_TAG       = 0xAA,
        MMS_CONCLUDE_REQUEST_TAG     = 0x8B,
        MMS_CONCLUDE_RESPONSE_TAG    = 0x8C,
        MMS_CONCLUDE_ERROR_TAG       = 0xAD,
    };

    uint32_t idx = 0;
    while ( idx < len )
    {
        switch ( mms.state )
        {
            case MMS_STATE__TPKT_VER:
            {
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
                const uint32_t MMS_COTP_PDU_DT_DATA = 0x0F;

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
                // define all known OSI Session layer SPDU tags to check
                enum
                {
                    MMS_OSI_SESSION_SPDU_GT_DT = 0x01,
                    MMS_OSI_SESSION_SPDU_CN = 0x0D,
                    MMS_OSI_SESSION_SPDU_AC = 0x0E,
                };

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
                        // if an MMS tag exists in the remaining data,
                        // hand off to the MMS service inspector
                        mms.state = MMS_STATE__FOUND;
                        break;
                    }

                    // if mms isn't found, search for an OSI Session layer
                    case MMS_OSI_SESSION_SPDU_GT_DT: // fallthrough intentional
                    case MMS_OSI_SESSION_SPDU_CN:    // fallthrough intentional
                    case MMS_OSI_SESSION_SPDU_AC:
                    {
                        mms.state = MMS_STATE__MMS;
                        break;
                    }

                    // if neither are found, it is most likely not MMS
                    default:
                    {
                        mms.state = MMS_STATE__NOT_FOUND;
                    }
                }

                break;
            }

            case MMS_STATE__MMS:
            {
                // loop through the remaining bytes in the buffer checking for known MMS tags
                for ( uint32_t i=idx; i < len; i++ )
                {
                    // for each remaining byte check to see if it is in the known tag map
                    switch ( data[i] )
                    {
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
                            // if an MMS tag exists in the remaining data,
                            // hand off to the MMS service inspector
                            mms.state = MMS_STATE__FOUND;
                            break;
                        }
                        // no default here as it we don't know when we would hit
                        // the first MMS tag without doing full parsing
                    }

                    // exit the loop when a state has been determined
                    if ( mms.state == MMS_STATE__NOT_FOUND
                        or mms.state == MMS_STATE__SEARCH
                        or mms.state == MMS_STATE__FOUND )
                    {
                        break;
                    }
                }

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
                assert(false);
                break;
            }
        }

        idx++;
    }

    mms.last_state = mms.state;
    mms.state = MMS_STATE__SEARCH;

    return false;
}
