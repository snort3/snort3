//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembler_ips.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembler_ips.h"

#include <cassert>

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main/analyzer.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"
#include "tcp_stream_tracker.h"

using namespace snort;

// see scan_data_post_ack() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
int32_t TcpReassemblerIps::scan_data_pre_ack(uint32_t* flags, Packet* p)
{
    assert(seglist->session->flow == p->flow);

    int32_t ret_val = FINAL_FLUSH_HOLD;

    if ( SEQ_GT(seglist->head->scan_seq(), seglist->seglist_base_seq) )
        return ret_val;

    if ( !seglist->cur_rseg )
        seglist->cur_rseg = seglist->cur_sseg;

    if ( !is_q_sequenced() )
        return ret_val;

    TcpSegmentNode* tsn = seglist->cur_sseg;
    uint32_t total = tsn->scan_seq() - seglist->seglist_base_seq;

    ret_val = FINAL_FLUSH_OK;
    while ( tsn && *flags )
    {
        total += tsn->unscanned();

        uint32_t end = tsn->scan_seq() + tsn->unscanned();
        uint32_t pos = paf.paf_position();

        if ( paf.paf_initialized() && SEQ_LEQ(end, pos) )
        {
            if ( !tsn->next_no_gap() )
            {
                ret_val = FINAL_FLUSH_HOLD;
                break;
            }

            tsn = tsn->next;
            continue;
        }

        if ( tsn->next_no_gap() )
            *flags |= PKT_MORE_TO_FLUSH;
        else
            *flags &= ~PKT_MORE_TO_FLUSH;
        int32_t flush_pt = paf.paf_check(p, tsn->paf_data(), tsn->unscanned(),
            total, tsn->scan_seq(), flags);

        if (flush_pt >= 0)
        {
            seglist->cur_sseg = tsn;
            return flush_pt;
        }

        if (!tsn->next_no_gap() || (paf.state == StreamSplitter::STOP))
        {
            if ( !(tsn->next_no_gap() || fin_no_gap(*tsn)) )
                ret_val = FINAL_FLUSH_HOLD;
            break;
        }

        tsn = tsn->next;
    }

    seglist->cur_sseg = tsn;
    
    return ret_val;
}

int TcpReassemblerIps::eval_flush_policy_on_ack(Packet*)
{
    purge_flushed_ackd();

    return 0;
}

int TcpReassemblerIps::eval_flush_policy_on_data(Packet* p)
{
    if ( !seglist->head )
        return 0;

    last_pdu = nullptr;
    uint32_t flags;
    uint32_t flushed = 0;
    int32_t flush_amt;

    do
    {
        flags = packet_dir;
        flush_amt = scan_data_pre_ack(&flags, p);
        if ( flush_amt <= 0 )
            break;

        flushed += flush_to_seq(flush_amt, p, flags);
    } while ( seglist->head and !p->flow->is_inspection_disabled() );

    if ( (paf.state == StreamSplitter::ABORT) && is_splitter_paf() )
    {
        tracker->fallback();
        return eval_flush_policy_on_data(p);
    }
    else if ( final_flush_on_fin(flush_amt, p, FIN_WITH_SEQ_SEEN) )
        finish_and_final_flush(p->flow, true, p);

    if ( !seglist->head )
        return flushed;

    if ( tracker->is_retransmit_of_held_packet(p) )
        flushed += perform_partial_flush(p);

    if ( asymmetric_flow_flushed(flushed, p) )
    {
        purge_to_seq(seglist->head->start_seq() + flushed);
        tracker->r_win_base = seglist->seglist_base_seq;
        tcpStats.flush_on_asymmetric_flow++;
    }

    return flushed;
}

int TcpReassemblerIps::eval_asymmetric_flush(snort::Packet* p)
{
    return eval_flush_policy_on_data(p);
}

int TcpReassemblerIps::flush_stream(Packet* p, uint32_t dir, bool final_flush)
{
    if ( seglist->session->flow->two_way_traffic()
        or (tracker->get_tcp_state() == TcpStreamTracker::TCP_MID_STREAM_RECV) )
    {
        uint32_t bytes = get_q_sequenced();  // num bytes in pre-ack mode
        if ( bytes )
            return flush_to_seq(bytes, p, dir);
    }

    if ( final_flush )
        return do_zero_byte_flush(p, dir);

    return 0;
}

