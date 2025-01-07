//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembler.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H


#include <cstdint>

#include "flow/flow.h"
#include "protocols/packet.h"
#include "stream/pafng.h"
#include "stream/stream.h"

#include "tcp_reassembly_segments.h"

namespace snort
{
    class StreamSplitter;
}

class TcpSegmentDescriptor;
class TcpSegmentNode;
class TcpStreamTracker;
enum FinSeqNumStatus : uint8_t;

class TcpReassembler
{
public:

    // OK means FIN seen, data scanned, flush point not found, no gaps
    enum ScanStatus {
        FINAL_FLUSH_HOLD = -2,
        FINAL_FLUSH_OK = -1
    };

    TcpReassembler()
    { }

    virtual ~TcpReassembler()
    { }

    virtual void init(bool server, snort::StreamSplitter* ss) = 0;
    virtual int eval_flush_policy_on_ack(snort::Packet*) = 0;
    virtual int eval_flush_policy_on_data(snort::Packet*) = 0;
    virtual int eval_asymmetric_flush(snort::Packet*) = 0;
    virtual int flush_stream(snort::Packet*, uint32_t dir, bool final_flush = false) = 0;
    virtual void flush_queued_segments(snort::Flow* flow, bool clear, snort::Packet* = nullptr) = 0;
    virtual void finish_and_final_flush(snort::Flow* flow, bool clear, snort::Packet*) = 0;
    virtual uint32_t perform_partial_flush(snort::Flow*, snort::Packet*&) = 0;
    virtual void purge_flushed_ackd() = 0;
    virtual FlushPolicy get_flush_policy() const = 0;
    virtual void release_splitter() = 0;
    virtual bool is_splitter_paf() const = 0;
    virtual bool segment_already_scanned(uint32_t seq) = 0;
    virtual void initialize_paf() = 0;
    virtual void reset_paf() = 0;
    virtual void clear_paf() = 0;

    // static methods for TcpReassembler per thread initialization and termination
    static void tinit();
    static void tterm();

protected:
    uint8_t packet_dir = 0;
    bool server_side = true;
};

class TcpReassemblerIgnore : public TcpReassembler
{
public:
    TcpReassemblerIgnore(bool server);

    void init(bool, snort::StreamSplitter*) override
    { }

    int eval_flush_policy_on_ack(snort::Packet*) override
    { return 0; }

    int eval_flush_policy_on_data(snort::Packet*) override
    { return 0; }

    int eval_asymmetric_flush(snort::Packet*) override
    { return 0; }

    int flush_stream(snort::Packet*, uint32_t, bool) override
    { return 0; }

    void flush_queued_segments(snort::Flow*, bool, snort::Packet*) override
    { }

    void finish_and_final_flush(snort::Flow*, bool, snort::Packet*) override
    { }

    uint32_t perform_partial_flush(snort::Flow*, snort::Packet*&) override;

    void purge_flushed_ackd() override
    { }

    void release_splitter() override
    { }

    bool is_splitter_paf() const override
    { return false; }

    bool segment_already_scanned(uint32_t) override
    { return false; }

    void reset_paf() override
    { }

    void clear_paf() override
    { }

    void initialize_paf() override
    { }

    FlushPolicy get_flush_policy() const override
    { return STREAM_FLPOLICY_IGNORE; }

    static TcpReassemblerIgnore* get_instance(bool server_side);
};

class  TcpReassemblerBase : public TcpReassembler
{
public:

    // OK means FIN seen, data scanned, flush point not found, no gaps
    enum ScanStatus {
        FINAL_FLUSH_HOLD = -2,
        FINAL_FLUSH_OK = -1
    };

    TcpReassemblerBase(TcpStreamTracker& trk, TcpReassemblySegments& seglist)
        : tracker(trk), seglist(seglist)
    { }

    virtual ~TcpReassemblerBase() override
    { }

    virtual void init(bool server, snort::StreamSplitter* ss) override;
    virtual void flush_queued_segments(snort::Flow* flow, bool clear, snort::Packet* = nullptr) override;
    virtual void finish_and_final_flush(snort::Flow* flow, bool clear, snort::Packet*) override;
    virtual uint32_t perform_partial_flush(snort::Flow*, snort::Packet*&) override;
    virtual void purge_flushed_ackd() override;

    void release_splitter() override
    { splitter = nullptr; }

    bool is_splitter_paf() const override
    { return splitter && splitter->is_paf(); }

    bool segment_already_scanned(uint32_t seq) override
    {
        if ( paf.paf_initialized() and SEQ_GT(paf.pos, seq) )
            return true;
        else
            return false;
    }

    virtual void initialize_paf() override
    {
        // only initialize if we have a data segment queued
        if ( !seglist.head )
            return;

       if ( !paf.paf_initialized() or !SEQ_EQ(paf.seq_num, seglist.head->start_seq()) )
            paf.paf_initialize(seglist.head->start_seq());
    }

    void reset_paf() override
    { paf.paf_reset(); }

    void clear_paf() override
    { paf.paf_clear(); }

protected:
    void show_rebuilt_packet(snort::Packet*);
    int flush_data_segments(uint32_t flush_len, snort::Packet* pdu);
    void prep_pdu(snort::Flow*, snort::Packet*, uint32_t pkt_flags, snort::Packet*);
    snort::Packet* initialize_pdu(snort::Packet*, uint32_t pkt_flags, struct timeval);
    int flush_to_seq(uint32_t bytes, snort::Packet*, uint32_t pkt_flags);
    int do_zero_byte_flush(snort::Packet*, uint32_t pkt_flags);
    uint32_t get_q_footprint();
    uint32_t get_q_sequenced();
    bool is_q_sequenced();
    void final_flush(snort::Packet*, uint32_t dir);
    bool splitter_finish(snort::Flow* flow);
    void purge_to_seq(uint32_t flush_seq);

    bool fin_no_gap(const TcpSegmentNode&);
    bool fin_acked_no_gap(const TcpSegmentNode&);
    void update_skipped_bytes(uint32_t);
    void check_first_segment_hole();
    uint32_t perform_partial_flush(snort::Packet*);
    bool final_flush_on_fin(int32_t flush_amt, snort::Packet*, FinSeqNumStatus);
    bool asymmetric_flow_flushed(uint32_t flushed, snort::Packet *p);

    ProtocolAwareFlusher paf;
    TcpStreamTracker& tracker;
    TcpReassemblySegments& seglist;
    snort::StreamSplitter* splitter = nullptr;

    snort::Packet* last_pdu = nullptr;
    uint8_t ignore_dir = 0;
    bool splitter_finish_flag = false;
};

#endif

