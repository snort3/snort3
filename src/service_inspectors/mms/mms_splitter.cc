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

// mms_splitter.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mms_splitter.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "profiler/profiler.h"
#include "utils/util_ber.h"

#include "mms.h"
#include "mms_decode.h"
#include "mms_module.h"
#include "util_tpkt.h"

using namespace snort;

static void reset_packet_data(Packet*, TpktFlowData*, CurPacketContext*);
static void update_flow_data(Packet*, TpktFlowData*, CurPacketContext*);
static bool populate_cur_pkt_ctx(Packet*, TpktFlowData*, CurPacketContext*);
static void update_cur_pkt_ctx_exit_offset(Packet*, TpktFlowData*, CurPacketContext*);

static void process_mms_not_found_result(Packet*, TpktFlowData*, CurPacketContext*,
    TpktAppliSearchStateType, Packet*);

static void reset_packet_data(Packet* p, TpktFlowData* tpktfd, CurPacketContext* cur_pkt_ctx)
{
    assert(p->is_from_client() or p->is_from_server());
    if (p->is_from_client())
    {
        tpktfd->reset_packet_data(TPKT_PACKET_DATA_DIRECTION__CLIENT);
        cur_pkt_ctx->data = tpktfd->ssn_data.client_packet_data;
    }
    else if (p->is_from_server())
    {
        tpktfd->reset_packet_data(TPKT_PACKET_DATA_DIRECTION__SERVER);
        cur_pkt_ctx->data = tpktfd->ssn_data.server_packet_data;
    }
}

static void update_flow_data(Packet* p, TpktFlowData* tpktfd, CurPacketContext* cur_pkt_ctx)
{
    assert(p->is_from_client() or p->is_from_server());
    if (p->is_from_client())
    {
        // set new packet data buffer
        tpktfd->ssn_data.client_packet_len      = cur_pkt_ctx->len;
        tpktfd->ssn_data.client_start_offset    = cur_pkt_ctx->start_offset;
        tpktfd->ssn_data.client_splitter_offset = cur_pkt_ctx->splitter_offset;
        tpktfd->ssn_data.client_exit_offset     = cur_pkt_ctx->exit_offset;
    }
    else if (p->is_from_server())
    {
        // set new packet data buffer
        tpktfd->ssn_data.server_packet_len      = cur_pkt_ctx->len;
        tpktfd->ssn_data.server_start_offset    = cur_pkt_ctx->start_offset;
        tpktfd->ssn_data.server_splitter_offset = cur_pkt_ctx->splitter_offset;
        tpktfd->ssn_data.server_exit_offset     = cur_pkt_ctx->exit_offset;
    }
}

static bool populate_cur_pkt_ctx(Packet* p, TpktFlowData* tpktfd, CurPacketContext* cur_pkt_ctx)
{
    assert(p->is_from_client() or p->is_from_server());
    bool res = false;
    if (p->is_from_client())
    {
        cur_pkt_ctx->data            = tpktfd->ssn_data.client_packet_data;
        cur_pkt_ctx->len             = tpktfd->ssn_data.client_packet_len;
        cur_pkt_ctx->start_offset    = tpktfd->ssn_data.client_start_offset;
        cur_pkt_ctx->splitter_offset = tpktfd->ssn_data.client_splitter_offset;
        cur_pkt_ctx->exit_offset     = tpktfd->ssn_data.client_exit_offset;
        res = true;
    }
    else if (p->is_from_server())
    {
        cur_pkt_ctx->data            = tpktfd->ssn_data.server_packet_data;
        cur_pkt_ctx->len             = tpktfd->ssn_data.server_packet_len;
        cur_pkt_ctx->start_offset    = tpktfd->ssn_data.server_start_offset;
        cur_pkt_ctx->splitter_offset = tpktfd->ssn_data.server_splitter_offset;
        cur_pkt_ctx->exit_offset     = tpktfd->ssn_data.server_exit_offset;
        res = true;
    }

    return res;
}

static void update_cur_pkt_ctx_exit_offset(Packet* p, TpktFlowData* tpktfd,
    CurPacketContext* cur_pkt_ctx)
{
    assert(p->is_from_client() or p->is_from_server());
    if (p->is_from_client())
    {
        cur_pkt_ctx->exit_offset = tpktfd->ssn_data.client_exit_offset;
    }
    else if (p->is_from_server())
    {
        cur_pkt_ctx->exit_offset = tpktfd->ssn_data.server_exit_offset;
    }
}

static void process_mms_not_found_result(Packet* p, TpktFlowData* tpktfd,
    CurPacketContext* cur_pkt_ctx, TpktAppliSearchStateType res, Packet* tmp_pkt)
{
    if (res == TPKT_APPLI_SEARCH_STATE__EXIT)
    {
        cur_pkt_ctx->splitter_offset = cur_pkt_ctx->exit_offset;
    }
    else
    {
        // track how far into the full message we have processed
        // for the next loop
        cur_pkt_ctx->splitter_offset = cur_pkt_ctx->len;
    }
    cur_pkt_ctx->start_offset = cur_pkt_ctx->exit_offset;
    update_flow_data(p, tpktfd, cur_pkt_ctx);
    delete tmp_pkt;
}

MmsSplitter::MmsSplitter(bool b) :
    StreamSplitter(b)
{
}

// MMS Splitter:
// Statefully inspects MMS traffic from the start of a session,
// Reads up until the start of the MMS message and then sets a flush point
// at the end of that message
StreamSplitter::Status MmsSplitter::scan(Packet* p, const uint8_t* data, uint32_t len,
    uint32_t /*flags*/, uint32_t* fp)
{
    // create TPKT flow data and add it to the packet
    TpktFlowData* tpktfd = (TpktFlowData*)p->flow->get_flow_data(TpktFlowData::inspector_id);

    if (!tpktfd)
    {
        tpktfd = new TpktFlowData;
        p->flow->set_flow_data(tpktfd);
        tpktfd->reset_packet_data(TPKT_PACKET_DATA_DIRECTION__SERVER);
        tpktfd->reset_packet_data(TPKT_PACKET_DATA_DIRECTION__CLIENT);
    }

    CurPacketContext cur_pkt_ctx;
    if (!populate_cur_pkt_ctx(p, tpktfd, &cur_pkt_ctx))
    {
        tpktfd->reset();
        return StreamSplitter::ABORT;
    }

    // verify that there is enough space in the buffer for the new data
    if (cur_pkt_ctx.len + len >= TPKT_PACKET_DATA_BUF_SIZE)
    {
        tpktfd->reset();
        return StreamSplitter::ABORT;
    }

    // append the new data to the existing buffer
    memcpy(cur_pkt_ctx.data + cur_pkt_ctx.len, data, len);

    // increase the packet length to include both the prior and the existing data lengths
    cur_pkt_ctx.len += len;

    // create a cursor to keep track of position through later layers
    // can't use the packet provided at the beginning as it isn't populated yet
    Packet* tmp_pkt = new Packet(false);
    tmp_pkt->data  = cur_pkt_ctx.data;
    tmp_pkt->dsize = cur_pkt_ctx.len;
    tmp_pkt->context = nullptr;

    Cursor mms_cur = Cursor(tmp_pkt);

    mms_cur.set_pos(cur_pkt_ctx.start_offset);

    // make the best guess of what the starting layer
    TpktEncapLayerType layer = get_next_tpkt_encap_layer(p, &mms_cur);

    // set the exit offset
    update_cur_pkt_ctx_exit_offset(p, tpktfd, &cur_pkt_ctx);

    // reset the cursor position
    mms_cur.set_pos(cur_pkt_ctx.start_offset);

    // start the parsing based on the layer determination
    switch (layer)
    {
    case TPKT_ENCAP_LAYER__TPKT:
    {
        TpktAppliSearchStateType res = tpkt_search_from_tpkt_layer(&mms_cur);
        if (res != TPKT_APPLI_SEARCH_STATE__MMS_FOUND)
        {
            process_mms_not_found_result(p, tpktfd, &cur_pkt_ctx, res, tmp_pkt);
            return StreamSplitter::SEARCH;
        }
        break;
    }

    case TPKT_ENCAP_LAYER__COTP:
    {
        TpktAppliSearchStateType res = tpkt_search_from_cotp_layer(&mms_cur);
        if (res != TPKT_APPLI_SEARCH_STATE__MMS_FOUND)
        {
            process_mms_not_found_result(p, tpktfd, &cur_pkt_ctx, res, tmp_pkt);
            return StreamSplitter::SEARCH;
        }
        break;
    }

    case TPKT_ENCAP_LAYER__OSI_SESSION:
    {
        TpktAppliSearchStateType res = tpkt_search_from_osi_session_layer(&mms_cur,
            OSI_SESSION_PROCESS_AS_DT__FALSE);
        if (res != TPKT_APPLI_SEARCH_STATE__MMS_FOUND)
        {
            process_mms_not_found_result(p, tpktfd, &cur_pkt_ctx, res, tmp_pkt);
            return StreamSplitter::SEARCH;
        }
        break;
    }

    case TPKT_ENCAP_LAYER__OSI_PRES:
    {
        TpktAppliSearchStateType res = tpkt_search_from_osi_pres_layer(&mms_cur);
        if (res != TPKT_APPLI_SEARCH_STATE__MMS_FOUND)
        {
            process_mms_not_found_result(p, tpktfd, &cur_pkt_ctx, res, tmp_pkt);
            return StreamSplitter::SEARCH;
        }
        break;
    }

    case TPKT_ENCAP_LAYER__OSI_ACSE:
    {
        TpktAppliSearchStateType res = tpkt_search_from_osi_acse_layer(&mms_cur);
        if (res != TPKT_APPLI_SEARCH_STATE__MMS_FOUND)
        {
            process_mms_not_found_result(p, tpktfd, &cur_pkt_ctx, res, tmp_pkt);
            return StreamSplitter::SEARCH;
        }
        break;
    }

    case TPKT_ENCAP_LAYER__MMS:
        // no need to do anything since the cursor is sitting on MMS
        break;

    case TPKT_ENCAP_LAYER__PARTIAL:
        cur_pkt_ctx.splitter_offset = cur_pkt_ctx.len;
        update_flow_data(p, tpktfd, &cur_pkt_ctx);
        delete tmp_pkt;
        return StreamSplitter::SEARCH;

    // no valid layer found
    default:
        delete tmp_pkt;
        tpktfd->reset();
        return StreamSplitter::ABORT;
    }

    // save the MMS offset
    MmsFlowData* mmsfd = (MmsFlowData*)p->flow->get_flow_data(MmsFlowData::inspector_id);
    if (!mmsfd)
    {
        mmsfd = new MmsFlowData;
        p->flow->set_flow_data(mmsfd);
        mms_stats.sessions++;
    }

    // store the offset to the start of the MMS message
    mmsfd->set_mms_offset(mms_cur.get_pos());

    // build a ber element
    BerReader ber(mms_cur);
    BerElement e;

    // read the first TLV of the MMS message
    if (ber.read(mms_cur.start(), e))
    {
        // add the size of the MMS message to the cursor so our flush point
        // lands at the end of that message
        // e.header_length holds the length of the Type and Length fields
        // e.length holds the value of the Length field
        if (mms_cur.add_pos(e.header_length + e.length))
        {
            // make sure that the mms data fits within the reported packet length
            if (mms_cur.get_pos() <= cur_pkt_ctx.len)
            {
                // set the flush point
                // the fp is not necessarily just the current position when messages are pipelined
                *fp = mms_cur.get_pos() - cur_pkt_ctx.splitter_offset;

                // clean up tracking details when there is no more data to parse
                if (mms_cur.get_pos() < mms_cur.size())
                {
                    // calculate the new length by taking the full message length minus our current
                    // position
                    uint32_t new_len = cur_pkt_ctx.len - mms_cur.get_pos();

                    // create a buffer to hold the combined packet
                    uint8_t* new_data = new uint8_t[new_len];
                    memcpy(new_data, cur_pkt_ctx.data + mms_cur.get_pos(), new_len);

                    // clear the existing buffer
                    reset_packet_data(p, tpktfd, &cur_pkt_ctx);

                    // copy the new data into the flowdata buffer
                    memcpy(cur_pkt_ctx.data, new_data, new_len);

                    // deallocate the newdata
                    delete [] new_data;

                    // update the remaining flowdata
                    cur_pkt_ctx.splitter_offset = 0;
                    cur_pkt_ctx.len             = new_len;
                    cur_pkt_ctx.exit_offset     = 0;
                    update_flow_data(p, tpktfd, &cur_pkt_ctx);
                }
                else
                {
                    cur_pkt_ctx.len             = 0;
                    cur_pkt_ctx.start_offset    = 0;
                    cur_pkt_ctx.splitter_offset = 0;
                    cur_pkt_ctx.exit_offset     = 0;
                    update_flow_data(p, tpktfd, &cur_pkt_ctx);
                }

                // flush
                delete tmp_pkt;
                return StreamSplitter::FLUSH;
            }
        }
    }

    // if execution gets here the reported length doesn't match up with mms
    mmsfd->reset();

    delete tmp_pkt;
    tpktfd->reset();
    return StreamSplitter::ABORT;
}

