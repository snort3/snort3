//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
//
// held_packet_queue.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "held_packet_queue.h"

#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_stream_tracker.h"

using namespace snort;

void HeldPacket::adjust_expiration(const timeval& delta, bool up)
{
    timeval new_expiration;
    if ( up )
        timeradd(&expiration, &delta, &new_expiration);
    else
        timersub(&expiration, &delta, &new_expiration);
    expiration = new_expiration;
}

HeldPacket::HeldPacket(DAQ_Msg_h msg, uint32_t seq, const timeval& exp, TcpStreamTracker& trk)
    : daq_msg(msg), seq_num(seq), expiration(exp), tracker(trk), expired(false)
{ }

HeldPacketQueue::iter_t HeldPacketQueue::append(DAQ_Msg_h msg, uint32_t seq,
    TcpStreamTracker& trk)
{
    timeval now, expiration;
    packet_gettimeofday(&now);
    timeradd(&now, &timeout, &expiration);

    q.emplace_back(msg, seq, expiration, trk);
    return --q.end();
}

void HeldPacketQueue::erase(iter_t it)
{
    q.erase(it);
}

bool HeldPacketQueue::execute(const timeval& cur_time, int max_remove)
{
    while ( !q.empty() && (max_remove < 0 || max_remove--) )
    {
        auto held_packet = q.begin();
        if ( held_packet->has_expired(cur_time) )
        {
            held_packet->get_tracker().perform_partial_flush();
            tcpStats.held_packet_timeouts++;
        }
        else
            break;
    }

    return !q.empty() && q.front().has_expired(cur_time);
}

bool HeldPacketQueue::adjust_expiration(uint32_t new_timeout, const timeval& now)
{
    if ( q.empty() )
        return false;

    uint32_t ms;
    bool up;

    uint32_t old_timeout = get_timeout();
    set_timeout(new_timeout);

    if ( new_timeout < old_timeout )
    {
        ms = old_timeout - new_timeout;
        up = false;
    }
    else if ( new_timeout > old_timeout )
    {
        ms = new_timeout - old_timeout;
        up = true;
    }
    else
        return false;

    timeval delta = { static_cast<time_t>(ms) / 1000, static_cast<suseconds_t>((ms % 1000) * 1000) };

    for ( auto& hp : q )
        hp.adjust_expiration(delta, up);

    return q.front().has_expired(now);
}
