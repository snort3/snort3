//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// util_tpkt.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_tpkt.h"

#include "tpkt/cotp_decode.h"
#include "tpkt/osi_acse_decode.h"
#include "tpkt/osi_pres_decode.h"
#include "tpkt/osi_session_decode.h"
#include "tpkt/tpkt_decode.h"

using namespace snort;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned TpktFlowData::inspector_id = 0;

void TpktFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

TpktFlowData::TpktFlowData() :
    FlowData(inspector_id)
{
}

TpktFlowData::~TpktFlowData()
{
    delete [] ssn_data.server_packet_data;
    delete [] ssn_data.client_packet_data;
}

//-------------------------------------------------------------------------
// parsing stuff
//-------------------------------------------------------------------------

static TpktEncapLayerSearchStateType is_tpkt(Cursor*, TpktFlowData*, bool);
static bool is_cotp(Cursor*);
static bool is_osi_session(Cursor*);
static bool is_osi_pres(Cursor*);
static bool is_osi_acse(Cursor* c);
static bool is_mms(Cursor* c);

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid TPKT layer
TpktEncapLayerSearchStateType is_tpkt(Cursor* c, TpktFlowData* tpktfd, bool is_from_client)
{
    // not starting with a struct overlay approach here as we need to be
    // able to support any number of bytes coming in
    const uint32_t remaining_bytes = c->length();

    if (remaining_bytes == 0)
    {
        return TPKT_ENCAP_LAYER_SEARCH_STATE__EXIT;
    }

    // it is possible that we have a partial message if only the TPKT
    // version byte has come through so far
    // if it turns out not to be a partial it will get caught on the
    // next loop
    const uint8_t tpkt_version = *(c->start());
    if (tpkt_version == 0x03 and remaining_bytes > 0x00 and remaining_bytes < sizeof(TpktHdr))
    {
        return TPKT_ENCAP_LAYER_SEARCH_STATE__PARTIAL;
    }

    // overlay the TPKT header at the cursor start
    const TpktHdr* hdr = (const TpktHdr*)c->start();

    // check for the static parts of the expected header
    if (hdr->version == 0x03 and hdr->reserved == 0x00)
    {
        // check to see if the reported length fits within the given data
        // when it doesn't it most likely means that we have a split message
        // and need to process it differently
        if (htons(hdr->length) <= c->size())
        {
            // make sure the reported length is long enough to even potentially
            // contain a MMS message
            // otherwise flow through to TPKT_ENCAP_LAYER_SEARCH_STATE__EXIT
            if (htons(hdr->length) >= TPKT_MIN_LEN)
            {
                if (!c->add_pos(sizeof(TpktHdr)))
                {
                    return TPKT_ENCAP_LAYER_SEARCH_STATE__EXIT;
                }

                // before indicating that the layer is most likely TPKT,
                // update the appropriate exit offset tracker
                if (is_from_client)
                {
                    tpktfd->ssn_data.client_exit_offset = tpktfd->ssn_data.client_splitter_offset +
                        htons(hdr->length);
                }
                else
                {
                    tpktfd->ssn_data.server_exit_offset = tpktfd->ssn_data.server_splitter_offset +
                        htons(hdr->length);
                }
                return TPKT_ENCAP_LAYER_SEARCH_STATE__FOUND;
            }
        }
        else
        {
            return TPKT_ENCAP_LAYER_SEARCH_STATE__PARTIAL;
        }
    }
    return TPKT_ENCAP_LAYER_SEARCH_STATE__EXIT;
}

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid COTP layer
static bool is_cotp(Cursor* c)
{
    // make sure we have enough data in the cursor to overlay the struct
    if (c->length() >= sizeof(CotpHdr))
    {
        // overlay the struct
        const CotpHdr* hdr = (const CotpHdr*)c->start();

        if (hdr->length == 0x02 and hdr->pdu_type == COTP_PDU_TYPE_DT_DATA and
            hdr->last_data_unit == 0x01)
        {
            if (c->add_pos(sizeof(CotpHdr)))
            {
                return true;
            }
        }
    }
    return false;
}

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid OSI Session layer
static bool is_osi_session(Cursor* c)
{
    // make sure we have enough data in the cursor to overlay the struct
    if (c->length() >= sizeof(OsiSessionHdr))
    {
        // overlay the struct
        const OsiSessionHdr* hdr = (const OsiSessionHdr*)c->start();

        // check #1
        // look for Give Tokens (GT) followed by Data Transfer (DT)
        // this pattern will indicate that a Confirmed Request or Response
        // message may be present
        // both of these types are the same value and appear to be distinguished by
        // their location in the message
#define OSI_SESSION_SPDU_GT_DT_SIZE    0x02
        if (hdr->spdu_type == OSI_SESSION_SPDU__GT_DT and hdr->length == 0x00)
        {
            hdr += OSI_SESSION_SPDU_GT_DT_SIZE;
            if (hdr->spdu_type == OSI_SESSION_SPDU__GT_DT and hdr->length == 0x00)
            {
                bool res = false;
                if (c->add_pos(sizeof(OsiSessionHdr)))
                {
                    res = true;
                }
                return res;
            }
        }

        // check #2
        // look for a Connect (CN) or Accept (AC) SPDU
        // this pattern will indicate that an initiate Request or Response
        // message may be present
        if (hdr->spdu_type == OSI_SESSION_SPDU__CN or hdr->spdu_type == OSI_SESSION_SPDU__AC)
        {
            if (hdr->length < c->size())
            {
                return true;
            }
        }
    }

    return false;
}

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid OSI Presentation layer
static bool is_osi_pres(Cursor* c)
{
    BerReader ber(*c);
    BerElement e;

    // read the first BER tag and bail if anything goes wrong
    if (ber.read(c->start(), e))
    {
        enum OsiPresMsgType
        {
            OSI_PRES_MSG__CP_OR_CPA = 0x31,
            OSI_PRES_MSG__CPC       = 0x61,
        };

        // check the first BER tag for a known type that can be decoded
        // OSI_PRES_MSG__CP_OR_CPA indicates an potential initiate Request or Response
        // OSI_PRES_MSG__CPC indicates a potential confirmed Request or Response
        if (e.type == OSI_PRES_MSG__CP_OR_CPA or e.type == OSI_PRES_MSG__CPC)
        {
            if (e.length < c->size())
            {
                if (c->add_pos(e.header_length + e.length))
                {
                    return true;
                }
            }
        }
    }

    return false;
}

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid OSI ACSE layer
static bool is_osi_acse(Cursor* c)
{
    BerReader ber(*c);
    BerElement e;

    // read the first BER tag and bail if anything goes wrong
    if (ber.read(c->start(), e))
    {
        // check the first BER tag for a known type that can be decoded
        // OSI_ACSE_AARQ indicates a potential initiate Request
        // OSI_ACSE_AARE indicates a potential initiate Response
        if (e.type == OSI_ACSE_AARQ or e.type == OSI_ACSE_AARE)
        {
            if (e.length < c->size())
            {
                if (c->add_pos(e.header_length + e.length))
                {
                    return true;
                }
            }
        }
    }
    return false;
}

// internal function used by `get_next_tpkt_encap_layer` that checks the data at
// the current position for a pattern consistent with a valid MMS layer
static bool is_mms(Cursor* c)
{
    BerReader ber(*c);
    BerElement e;

    // read the first BER tag and bail if anything goes wrong
    if (ber.read(c->start(), e))
    {
        // check the first BER tag for a known MMS message type
        switch (e.type)
        {
        case MMS_MSG__CONFIRMED_REQUEST:           // fallthrough
        case MMS_MSG__CONFIRMED_RESPONSE:          // fallthrough
        case MMS_MSG__CONFIRMED_ERROR:             // fallthrough
        case MMS_MSG__UNCONFIRMED:                 // fallthrough
        case MMS_MSG__REJECT:                      // fallthrough
        case MMS_MSG__CANCEL_REQUEST:              // fallthrough
        case MMS_MSG__CANCEL_RESPONSE:             // fallthrough
        case MMS_MSG__CANCEL_ERROR:                // fallthrough
        case MMS_MSG__INITIATE_REQUEST:            // fallthrough
        case MMS_MSG__INITIATE_RESPONSE:           // fallthrough
        case MMS_MSG__INITIATE_ERROR:              // fallthrough
        case MMS_MSG__CONCLUDE_REQUEST:            // fallthrough
        case MMS_MSG__CONCLUDE_RESPONSE:           // fallthrough
        case MMS_MSG__CONCLUDE_ERROR:
            if (e.length < c->size())
            {
                if (c->add_pos(e.header_length + e.length))
                {
                    return true;
                }
            }
            break;

        default:
            // continue on if none of the known cases are found
            break;
        }
    }

    return false;
}

// function to run analysis on the data and return the best guess of which
// TPKT encapsulation layer is present starting from the current cursor pos
TpktEncapLayerType get_next_tpkt_encap_layer(Packet* p, Cursor* c)
{
    // create TPKT flow data and add it to the packet
    TpktFlowData* tpktfd = (TpktFlowData*)p->flow->get_flow_data(TpktFlowData::inspector_id);

    if (!tpktfd)
    {
        tpktfd = new TpktFlowData;
        p->flow->set_flow_data(tpktfd);
    }

    // check for the TPKT layer
    switch (is_tpkt(c, tpktfd, p->is_from_client()))
    {
    case TPKT_ENCAP_LAYER_SEARCH_STATE__FOUND:
        return TPKT_ENCAP_LAYER__TPKT;

    // for the TPKT layer specifically it is possible to have a partial
    // message in pipelined cases. When this happens we essentially add
    // in all of the data to the current cursor and move on to the next
    // loop for continued processing
    case TPKT_ENCAP_LAYER_SEARCH_STATE__PARTIAL:
        return TPKT_ENCAP_LAYER__PARTIAL;

    default:
        // assume not found when nothing explicit comes out
        break;
    }

    // check for the COTP layer
    if (is_cotp(c))
    {
        return TPKT_ENCAP_LAYER__COTP;
    }

    // check for the OSI Session layer
    if (is_osi_session(c))
    {
        return TPKT_ENCAP_LAYER__OSI_SESSION;
    }

    // check for the OSI Pres layer
    if (is_osi_pres(c))
    {
        return TPKT_ENCAP_LAYER__OSI_PRES;
    }

    // check for the OSI ACSE layer
    if (is_osi_acse(c))
    {
        return TPKT_ENCAP_LAYER__OSI_ACSE;
    }

    // check for the MMS layer
    if (is_mms(c))
    {
        return TPKT_ENCAP_LAYER__MMS;
    }

    // if a decision cannot be made on what layer is present, set the exit
    // offset to the end of the current data before returning no layer
    // found. in this case we are just moving on from the data and not
    // sending it to the service inspector
    if (p->is_from_client())
    {
        tpktfd->ssn_data.client_exit_offset = c->size();
    }
    else
    {
        tpktfd->ssn_data.server_exit_offset = c->size();
    }

    // no valid layer found
    return TPKT_ENCAP_LAYER__NONE;
}

// exposing the all of the layer search functions from a single location
TpktAppliSearchStateType tpkt_search_from_tpkt_layer(Cursor* c)
{
    return tpkt_internal_search_from_tpkt_layer(c);
}

// exposing the all of the layer search functions from a single location
TpktAppliSearchStateType tpkt_search_from_cotp_layer(Cursor* c)
{
    return tpkt_internal_search_from_cotp_layer(c);
}

// exposing the all of the layer search functions from a single location
TpktAppliSearchStateType tpkt_search_from_osi_session_layer(Cursor* c, bool
    process_as_data_transfer)
{
    return tpkt_internal_search_from_osi_session_layer(c, process_as_data_transfer);
}

// exposing the all of the layer search functions from a single location
TpktAppliSearchStateType tpkt_search_from_osi_pres_layer(Cursor* c)
{
    return tpkt_internal_search_from_osi_pres_layer(c);
}

// exposing the all of the layer search functions from a single location
TpktAppliSearchStateType tpkt_search_from_osi_acse_layer(Cursor* c)
{
    return tpkt_internal_search_from_osi_acse_layer(c);
}

