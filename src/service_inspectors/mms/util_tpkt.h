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

// util_tpkt.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef TPKT_H
#define TPKT_H

// The TPKT util provides an interface for processing the encapsulation
// layers associated with TPKT, COTP, OSI Session, OSI Pres, and OSI ACSE

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "framework/counts.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "service_inspectors/mms/mms.h"
#include "utils/util_ber.h"

namespace snort
{
struct Packet;
}

#define TPKT_PACKET_DATA_BUF_SIZE    0x10000
#define TPKT_SMALLEST_TLV_SIZE       0x03

//-------------------------------------------------------------------------
// type definitions
//-------------------------------------------------------------------------

enum OsiSessionSpduType
{
    OSI_SESSION_SPDU__GT_DT   = 0x01,
    OSI_SESSION_SPDU__CN      = 0x0D,
    OSI_SESSION_SPDU__AC      = 0x0E,
    OSI_SESSION_SPDU__NOT_SET = 0xFFFFFFFF,
};

enum ProcessAsDataTransferType
{
    OSI_SESSION_PROCESS_AS_DT__TRUE  = true,
    OSI_SESSION_PROCESS_AS_DT__FALSE = false,
};

enum TpktEncapLayerType
{
    TPKT_ENCAP_LAYER__NONE,
    TPKT_ENCAP_LAYER__TPKT,
    TPKT_ENCAP_LAYER__COTP,
    TPKT_ENCAP_LAYER__OSI_SESSION,
    TPKT_ENCAP_LAYER__OSI_PRES,
    TPKT_ENCAP_LAYER__OSI_ACSE,
    TPKT_ENCAP_LAYER__MMS,
    TPKT_ENCAP_LAYER__PARTIAL,
};

enum TpktEncapLayerSearchStateType
{
    TPKT_ENCAP_LAYER_SEARCH_STATE__EXIT,
    TPKT_ENCAP_LAYER_SEARCH_STATE__FOUND,
    TPKT_ENCAP_LAYER_SEARCH_STATE__PARTIAL,
};

enum TpktAppliSearchStateType
{
    TPKT_APPLI_SEARCH_STATE__MMS_FOUND,
    TPKT_APPLI_SEARCH_STATE__SEARCH,
    TPKT_APPLI_SEARCH_STATE__EXIT,
};

enum TpktPacketDataDirectionType
{
    TPKT_PACKET_DATA_DIRECTION__SERVER,
    TPKT_PACKET_DATA_DIRECTION__CLIENT,
};

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

class TpktSessionData
{
public:
    OsiSessionSpduType cur_spdu_type = OSI_SESSION_SPDU__NOT_SET;
    bool process_as_data_transfer    = OSI_SESSION_PROCESS_AS_DT__FALSE;
    uint8_t* server_packet_data      = nullptr;
    uint32_t server_packet_len       = 0;
    uint32_t server_start_offset     = 0;
    uint32_t server_splitter_offset  = 0;
    uint32_t server_exit_offset      = 0;
    uint8_t* client_packet_data      = nullptr;
    uint32_t client_packet_len       = 0;
    uint32_t client_start_offset     = 0;
    uint32_t client_splitter_offset  = 0;
    uint32_t client_exit_offset      = 0;

    void packet_data_reset(TpktPacketDataDirectionType direction)
    {
        if (direction == TPKT_PACKET_DATA_DIRECTION__SERVER)
        {
            delete [] server_packet_data;
            server_packet_data = new uint8_t[TPKT_PACKET_DATA_BUF_SIZE];
        }
        else if (direction == TPKT_PACKET_DATA_DIRECTION__CLIENT)
        {
            delete [] client_packet_data;
            client_packet_data = new uint8_t[TPKT_PACKET_DATA_BUF_SIZE];
        }
    }

    void session_data_reset()
    {
        cur_spdu_type            = OSI_SESSION_SPDU__NOT_SET;
        process_as_data_transfer = OSI_SESSION_PROCESS_AS_DT__FALSE;

        packet_data_reset(TPKT_PACKET_DATA_DIRECTION__SERVER);
        server_packet_len      = 0;
        server_start_offset    = 0;
        server_splitter_offset = 0;
        server_exit_offset     = 0;

        packet_data_reset(TPKT_PACKET_DATA_DIRECTION__CLIENT);
        client_packet_len      = 0;
        client_start_offset    = 0;
        client_splitter_offset = 0;
        client_exit_offset     = 0;
    }
};

class TpktFlowData : public snort::FlowData
{
public:
    TpktFlowData();
    ~TpktFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.session_data_reset();
    }

    void reset_packet_data(TpktPacketDataDirectionType direction)
    {
        ssn_data.packet_data_reset(direction);
    }

    size_t size_of() override
    {
        return sizeof(*this);
    }

public:
    static unsigned inspector_id;
    TpktSessionData ssn_data;
};

//-------------------------------------------------------------------------
// function definitions
//-------------------------------------------------------------------------

TpktEncapLayerType get_next_tpkt_encap_layer(snort::Packet*, Cursor*);
TpktAppliSearchStateType tpkt_search_from_tpkt_layer(Cursor*);
TpktAppliSearchStateType tpkt_search_from_cotp_layer(Cursor*);
TpktAppliSearchStateType tpkt_search_from_osi_session_layer(Cursor*, bool);
TpktAppliSearchStateType tpkt_search_from_osi_pres_layer(Cursor*);
TpktAppliSearchStateType tpkt_search_from_osi_acse_layer(Cursor*);

#endif

