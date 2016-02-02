//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_tracker.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#ifndef TCP_STREAM_TRACKER_H
#define TCP_STREAM_TRACKER_H

#include "stdint.h"

#include "tcp_segment_descriptor.h"

extern const char* tcp_state_names[];
extern const char* tcp_event_names[];

class TcpStreamTracker
{
public:
    enum TcpStates
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

    enum TcpEvents
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
        TCP_MAX_EVENTS
    };

    TcpStreamTracker(bool);
    virtual ~TcpStreamTracker();

    bool is_client_tracker() const
    {
        return client_tracker;
    }

    bool is_3whs_required() const
    {
        return require_3whs;
    }

    void set_require_3whs(bool require3_whs)
    {
        this->require_3whs = require3_whs;
    }

    TcpStates get_tcp_state() const
    {
        return tcp_state;
    }

    void set_tcp_state(TcpStates tcp_state)
    {
        this->tcp_state = tcp_state;
    }

    TcpEvents get_tcp_event() const
    {
        return tcp_event;
    }

    void set_tcp_event(TcpSegmentDescriptor& tsd);

    void set_tcp_event(TcpEvents tcp_event)
    {
        this->tcp_event = tcp_event;
    }

    uint32_t get_rcv_nxt() const
    {
        return rcv_nxt;
    }

    void set_rcv_nxt(uint32_t rcv_nxt)
    {
        this->rcv_nxt = rcv_nxt;
    }

    uint32_t get_rcv_wnd() const
    {
        return rcv_wnd;
    }

    void set_rcv_wnd(uint32_t rcv_wnd)
    {
        this->rcv_wnd = rcv_wnd;
    }

    uint16_t get_rcv_up() const
    {
        return rcv_up;
    }

    void set_rcv_up(uint16_t rcv_up)
    {
        this->rcv_up = rcv_up;
    }

    uint32_t get_irs() const
    {
        return irs;
    }

    void set_irs(uint32_t irs)
    {
        this->irs = irs;
    }

    uint32_t get_snd_una() const
    {
        return snd_una;
    }

    void set_snd_una(uint32_t snd_una)
    {
        this->snd_una = snd_una;
    }

    uint32_t get_snd_nxt() const
    {
        return snd_nxt;
    }

    void set_snd_nxt(uint32_t snd_nxt)
    {
        this->snd_nxt = snd_nxt;
    }

    uint16_t get_snd_up() const
    {
        return snd_up;
    }

    void set_snd_up(uint16_t snd_up)
    {
        this->snd_up = snd_up;
    }

    uint32_t get_snd_wl1() const
    {
        return snd_wl1;
    }

    void set_snd_wl1(uint32_t snd_wl1)
    {
        this->snd_wl1 = snd_wl1;
    }

    uint32_t get_snd_wl2() const
    {
        return snd_wl2;
    }

    void set_snd_wl2(uint32_t snd_wl2)
    {
        this->snd_wl2 = snd_wl2;
    }

    uint32_t get_snd_wnd() const
    {
        return snd_wnd;
    }

    void set_snd_wnd(uint32_t snd_wnd)
    {
        this->snd_wnd = snd_wnd;
    }

    uint32_t get_iss() const
    {
        return iss;
    }

    void set_iss(uint32_t iss)
    {
        this->iss = iss;
    }

    uint32_t get_ts_last_packet() const
    {
        return ts_last_packet;
    }

    void set_ts_last_packet(uint32_t ts_last_packet)
    {
        this->ts_last_packet = ts_last_packet;
    }

    bool is_ack_valid(uint32_t cur)
    {
        /* If we haven't seen anything, ie, low & high are 0, return true */
        if ( ( snd_una == 0 ) && ( snd_una == snd_nxt ) )
            return 1;

        return ( SEQ_GEQ(cur, snd_una) && SEQ_LEQ(cur, snd_nxt) );
    }

    // ack number must ack syn
    bool is_rst_valid_in_syn_sent(TcpSegmentDescriptor& tsd)
    {
        return tsd.get_ack() == snd_una;
    }

    void cache_mac_address(TcpSegmentDescriptor& tsd, uint8_t direction);
    bool compare_mac_addresses(const uint8_t eth_addr[]);

protected:
    bool client_tracker;
    bool require_3whs;

    uint32_t snd_una; // SND.UNA - send unacknowledged
    uint32_t snd_nxt; // SND.NXT - send next
    uint32_t snd_wnd; // SND.WND - send window
    uint16_t snd_up;  // SND.UP  - send urgent pointer
    uint32_t snd_wl1; // SND.WL1 - segment sequence number used for last window update
    uint32_t snd_wl2; // SND.WL2 - segment acknowledgment number used for last window update
    uint32_t iss;     // ISS     - initial send sequence number

    uint32_t rcv_nxt; // RCV.NXT - receive next
    uint32_t rcv_wnd; // RCV.WND - receive window
    uint16_t rcv_up;  // RCV.UP  - receive urgent pointer
    uint32_t irs;     // IRS     - initial receive sequence number

    uint32_t ts_last_packet; // timestamp of last packet we got

    // FIXIT - make this protected

public:
    uint32_t ts_last; /* last timestamp (for PAWS) */
    uint16_t wscale; /* window scale setting */
    uint16_t mss; /* max segment size */

    uint8_t mac_addr[6];
    uint8_t flags; /* bitmap flags (TF_xxx) */

protected:
    TcpStates tcp_state;
    TcpEvents tcp_event;
};

inline TcpStreamTracker::TcpStates& operator++(TcpStreamTracker::TcpStates& state, int)  // <---
                                                                                         // note --
                                                                                         // must be
                                                                                         // a reference
{
    const int i = static_cast<int>(state);
    state = static_cast<TcpStreamTracker::TcpStates>((i + 1) % ( TcpStreamTracker::TCP_MAX_EVENTS +
        1 ) );
    return state;
}

#endif

