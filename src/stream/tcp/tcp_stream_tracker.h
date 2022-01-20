//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_tracker.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jun 24, 2015

#ifndef TCP_STREAM_TRACKER_H
#define TCP_STREAM_TRACKER_H

#include <list>

#include "stream/paf.h"

#include "segment_overlap_editor.h"
#include "tcp_defs.h"
#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"
#include "tcp_segment_descriptor.h"

extern const char* tcp_state_names[];
extern const char* tcp_event_names[];

namespace snort
{
struct Packet;
}

class HeldPacket;
class TcpReassembler;
class TcpSession;

class TcpStreamTracker
{
public:
    enum TcpState : uint8_t
    {
        TCP_LISTEN,
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_ESTABLISHED,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_CLOSE_WAIT,
        TCP_CLOSING,
        TCP_LAST_ACK,
        TCP_TIME_WAIT,
        TCP_CLOSED,
        TCP_STATE_NONE,
        TCP_MAX_STATES
    };

    enum TcpEvent : uint8_t
    {
        TCP_SYN_SENT_EVENT,
        TCP_SYN_RECV_EVENT,
        TCP_SYN_ACK_SENT_EVENT,
        TCP_SYN_ACK_RECV_EVENT,
        TCP_ACK_SENT_EVENT,
        TCP_ACK_RECV_EVENT,
        TCP_DATA_SEG_SENT_EVENT,
        TCP_DATA_SEG_RECV_EVENT,
        TCP_FIN_SENT_EVENT,
        TCP_FIN_RECV_EVENT,
        TCP_RST_SENT_EVENT,
        TCP_RST_RECV_EVENT,
        TCP_NO_FLAGS_EVENT,
        TCP_MAX_EVENTS
    };

    enum FinSeqNumStatus : uint8_t { FIN_NOT_SEEN, FIN_WITH_SEQ_SEEN, FIN_WITH_SEQ_ACKED };

    TcpStreamTracker(bool client);
    virtual ~TcpStreamTracker();

    bool is_client_tracker() const
    { return client_tracker; }

    bool is_server_tracker() const
    { return !client_tracker; }

    TcpState get_tcp_state() const
    { return tcp_state; }

    void set_tcp_state(TcpState tcp_state)
    { this->tcp_state = tcp_state; }

    TcpEvent get_tcp_event() const
    { return tcp_event; }

    TcpEvent set_tcp_event(const TcpSegmentDescriptor&);

    void set_tcp_event(TcpEvent tcp_event)
    { this->tcp_event = tcp_event; }

    uint32_t get_rcv_nxt() const
    { return rcv_nxt; }

    void set_rcv_nxt(uint32_t rcv_nxt)
    { this->rcv_nxt = rcv_nxt; }

    uint32_t get_rcv_wnd() const
    { return rcv_wnd; }

    void set_rcv_wnd(uint32_t rcv_wnd)
    { this->rcv_wnd = rcv_wnd; }

    uint16_t get_rcv_up() const
    { return rcv_up; }

    void set_rcv_up(uint16_t rcv_up)
    { this->rcv_up = rcv_up; }

    uint32_t get_irs() const
    { return irs; }

    void set_irs(uint32_t irs)
    { this->irs = irs; }

    uint32_t get_snd_una() const
    { return snd_una; }

    void set_snd_una(uint32_t snd_una)
    { this->snd_una = snd_una; }

    uint32_t get_snd_nxt() const
    { return snd_nxt; }

    void set_snd_nxt(uint32_t snd_nxt)
    { this->snd_nxt = snd_nxt; }

    uint16_t get_snd_up() const
    { return snd_up; }

    void set_snd_up(uint16_t snd_up)
    { this->snd_up = snd_up; }

    uint32_t get_snd_wl1() const
    { return snd_wl1; }

    void set_snd_wl1(uint32_t snd_wl1)
    { this->snd_wl1 = snd_wl1; }

    uint32_t get_snd_wl2() const
    { return snd_wl2; }

    void set_snd_wl2(uint32_t snd_wl2)
    { this->snd_wl2 = snd_wl2; }

    uint32_t get_snd_wnd() const
    { return snd_wnd; }

    void set_snd_wnd(uint32_t snd_wnd)
    { this->snd_wnd = snd_wnd; }

    uint32_t get_iss() const
    { return iss; }

    void set_iss(uint32_t iss)
    { this->iss = iss; }

    uint32_t get_fin_final_seq() const
    { return fin_final_seq + fin_seq_adjust; }

    uint32_t get_fin_seq_adjust()
    { return fin_seq_adjust; }

    bool is_fin_seq_set() const
    { return fin_seq_set; }

    uint32_t get_ts_last_packet() const
    { return ts_last_packet; }

    void set_ts_last_packet(uint32_t ts_last_packet)
    { this->ts_last_packet = ts_last_packet; }

    bool is_ack_valid(uint32_t cur)
    {
        if ( ( snd_una == 0 ) && ( snd_nxt == 0 ) )
            return true;

        bool valid = SEQ_LEQ(cur, snd_nxt);
        if ( !valid )
            tcpStats.invalid_ack++;

        return valid;
    }

    // ack number must ack syn
    bool is_rst_valid_in_syn_sent(const TcpSegmentDescriptor& tsd) const
    { return tsd.get_ack() == snd_una; }

    uint32_t get_ts_last() const
    { return ts_last; }

    void set_ts_last(uint32_t ts_last)
    { this->ts_last = ts_last; }

    uint16_t get_tf_flags() const
    { return tf_flags; }

    void set_tf_flags(uint16_t flags)
    { this->tf_flags |= flags; }

    void clear_tf_flags(uint16_t flags)
    { this->tf_flags &= ~flags; }

    uint16_t get_wscale() const
    { return wscale; }

    void set_wscale(uint16_t wscale)
    { this->wscale = wscale; }

    uint16_t get_mss() const
    { return mss; }

    void set_mss(uint16_t mss)
    { this->mss = mss; }

    uint8_t get_tcp_options_len() const
    { return tcp_options_len; }

    void set_tcp_options_len(uint8_t tcp_options_len)
    { this->tcp_options_len = tcp_options_len; }

    void cache_mac_address(const TcpSegmentDescriptor&, uint8_t direction);
    bool compare_mac_addresses(const uint8_t eth_addr[]);

    bool is_rst_pkt_sent() const
    { return rst_pkt_sent; }

    void set_flush_policy(FlushPolicy policy)
    { flush_policy = policy; }

    FlushPolicy get_flush_policy() const
    { return flush_policy; }

    virtual void init_tcp_state();
    virtual void init_flush_policy();
    virtual void set_splitter(snort::StreamSplitter* ss);
    virtual void set_splitter(const snort::Flow* flow);

    snort::StreamSplitter* get_splitter()
    { return splitter; }

    bool is_splitter_paf() const
    { return splitter && splitter->is_paf(); }

    bool splitter_finish(snort::Flow* flow);

    bool is_reassembly_enabled() const
    { return  ( splitter and (flush_policy != STREAM_FLPOLICY_IGNORE) ); }

    virtual void init_on_syn_sent(TcpSegmentDescriptor&);
    virtual void init_on_syn_recv(TcpSegmentDescriptor&);
    virtual void init_on_synack_sent(TcpSegmentDescriptor&);
    virtual void init_on_synack_recv(TcpSegmentDescriptor&);
    virtual void init_on_3whs_ack_sent(TcpSegmentDescriptor&);
    virtual void init_on_3whs_ack_recv(TcpSegmentDescriptor&);
    virtual void init_on_data_seg_sent(TcpSegmentDescriptor&);
    virtual void init_on_data_seg_recv(TcpSegmentDescriptor&);
    virtual void finish_server_init(TcpSegmentDescriptor&);
    virtual void finish_client_init(TcpSegmentDescriptor&);

    virtual void update_tracker_ack_recv(TcpSegmentDescriptor&);
    virtual void update_tracker_ack_sent(TcpSegmentDescriptor&);
    virtual void update_tracker_no_ack_recv(TcpSegmentDescriptor&);
    virtual void update_tracker_no_ack_sent(TcpSegmentDescriptor&);
    virtual bool update_on_3whs_ack(TcpSegmentDescriptor&);
    virtual bool update_on_rst_recv(TcpSegmentDescriptor&);
    virtual void update_on_rst_sent();
    virtual bool update_on_fin_recv(TcpSegmentDescriptor&);
    virtual bool update_on_fin_sent(TcpSegmentDescriptor&);
    virtual bool is_segment_seq_valid(TcpSegmentDescriptor&);
    bool set_held_packet(snort::Packet*);
    bool is_retransmit_of_held_packet(snort::Packet*);
    void finalize_held_packet(snort::Packet*);
    void finalize_held_packet(snort::Flow*);
    void perform_fin_recv_flush(TcpSegmentDescriptor&);
    uint32_t perform_partial_flush();
    bool is_holding_packet() const { return held_packet != null_iterator; }

    // max_remove < 0 means time out all eligible packets.
    // Return whether there are more packets that need to be released.
    static bool release_held_packets(const timeval& cur_time, int max_remove);
    static void set_held_packet_timeout(const uint32_t ms);
    static bool adjust_expiration(uint32_t new_timeout_ms, const timeval& now);
    static void thread_init();
    static void thread_term();

public:
    uint32_t snd_una = 0; // SND.UNA - send unacknowledged
    uint32_t snd_nxt = 0; // SND.NXT - send next
    uint32_t snd_wnd = 0; // SND.WND - send window
    uint32_t snd_wl1 = 0; // SND.WL1 - segment sequence number used for last window update
    uint32_t snd_wl2 = 0; // SND.WL2 - segment acknowledgment number used for last window update
    uint32_t iss = 0;     // ISS     - initial send sequence number

    uint32_t rcv_nxt = 0; // RCV.NXT - receive next
    uint32_t rcv_wnd = 0; // RCV.WND - receive window
    uint32_t irs = 0;     // IRS     - initial receive sequence number

    uint16_t snd_up = 0;  // SND.UP  - send urgent pointer
    uint16_t rcv_up = 0;  // RCV.UP  - receive urgent pointer

    uint32_t held_pkt_seq = 0;
    TcpState tcp_state;
    TcpEvent tcp_event = TCP_MAX_EVENTS;

    bool client_tracker;
    bool require_3whs = false;
    bool rst_pkt_sent = false;

// FIXIT-L make these non-public
public:
    TcpNormalizerPolicy normalizer;
    TcpReassemblerPolicy reassembler;
    TcpSession* session = nullptr;

    uint32_t r_win_base = 0; // remote side window base sequence number (the last ack we got)
    uint32_t small_seg_count = 0;
    uint32_t max_queue_seq_nxt; // next expected sequence once queue limit is exceeded
    uint8_t max_queue_exceeded = MQ_NONE;
    uint8_t order = 0;
    FinSeqNumStatus fin_seq_status = TcpStreamTracker::FIN_NOT_SEEN;
    bool reinit_seg_base = false;

protected:
    static const std::list<HeldPacket>::iterator null_iterator;
    std::list<HeldPacket>::iterator held_packet;
    snort::StreamSplitter* splitter = nullptr;
    uint32_t ts_last_packet = 0;
    uint32_t ts_last = 0;       // last timestamp (for PAWS)
    uint32_t fin_final_seq = 0;
    uint32_t fin_seq_adjust = 0;
    uint16_t mss = 0;           // max segment size
    uint16_t wscale = 0;        // window scale setting
    uint16_t tf_flags = 0;
    uint8_t mac_addr[6] = { };
    uint8_t tcp_options_len = 0;
    FlushPolicy flush_policy = STREAM_FLPOLICY_IGNORE;
    bool mac_addr_valid = false;
    bool fin_seq_set = false;  // FIXIT-M should be obviated by tcp state
    bool splitter_finish_flag = false;
};

// <--- note -- the 'state' parameter must be a reference
inline TcpStreamTracker::TcpState& operator++(TcpStreamTracker::TcpState& state, int)
{
    if ( state < TcpStreamTracker::TCP_MAX_STATES )
        state = static_cast<TcpStreamTracker::TcpState>( static_cast<int>(state) + 1 );
    else
        state = TcpStreamTracker::TCP_MAX_STATES;

    return state;
}

#endif

