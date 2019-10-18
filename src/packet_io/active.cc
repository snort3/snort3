//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// active.c author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "active.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/action_manager.h"
#include "protocols/tcp.h"
#include "pub_sub/active_events.h"
#include "stream/stream.h"
#include "utils/dnet_header.h"

#include "sfdaq.h"
#include "sfdaq_instance.h"
#include "sfdaq_module.h"

using namespace snort;

#define MAX_ATTEMPTS 20

const char* Active::act_str[Active::ACT_MAX][Active::AST_MAX] =
{
    { "allow", "error", "error", "error" },
    { "hold", "error", "error", "error" },
    { "retry", "error", "error", "error" },
    { "drop", "cant_drop", "would_drop", "force_drop" },
    { "block", "cant_block", "would_block", "force_block" },
    { "reset", "cant_reset", "would_reset", "force_reset" },
};
bool Active::enabled = false;

THREAD_LOCAL uint8_t Active::s_attempts = 0;
THREAD_LOCAL bool Active::s_suspend = false;
THREAD_LOCAL Active::Counts snort::active_counts;

typedef int (* send_t) (
    DAQ_Msg_h msg, int rev, const uint8_t* buf, uint32_t len);

static THREAD_LOCAL eth_t* s_link = nullptr;
static THREAD_LOCAL ip_t* s_ipnet = nullptr;
static THREAD_LOCAL send_t s_send = SFDAQ::inject;

//--------------------------------------------------------------------
// helpers

int Active::send_eth(
    DAQ_Msg_h, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = eth_send(s_link, buf, len);
    active_counts.injects++;
    return ( (uint32_t)sent != len );
}

int Active::send_ip(
    DAQ_Msg_h, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = ip_send(s_ipnet, buf, len);
    active_counts.injects++;
    return ( (uint32_t)sent != len );
}

static inline EncodeFlags GetFlags()
{
    EncodeFlags flags = ENC_FLAG_ID;
    if ( SFDAQ::can_inject_raw() || s_ipnet )
        flags |= ENC_FLAG_RAW;
    return flags;
}

// TBD strafed sequence numbers could be divided by window
// scaling if present.

static uint32_t Strafe(int i, uint32_t flags, const Packet* p)
{
    flags &= ENC_FLAG_VAL;

    switch ( i )
    {
    case 0:
        flags |= ENC_FLAG_SEQ;
        break;

    case 1:
        flags = p->dsize;
        flags &= ENC_FLAG_VAL;
        flags |= ENC_FLAG_SEQ;
        break;

    case 2:
    case 3:
        flags += (p->dsize << 1);
        flags &= ENC_FLAG_VAL;
        flags |= ENC_FLAG_SEQ;
        break;

    case 4:
        flags += (p->dsize << 2);
        flags &= ENC_FLAG_VAL;
        flags |= ENC_FLAG_SEQ;
        break;

    default:
        flags += (ntohs(p->ptrs.tcph->th_win) >> 1);
        flags &= ENC_FLAG_VAL;
        flags |= ENC_FLAG_SEQ;
        break;
    }
    return flags;
}

//--------------------------------------------------------------------

void Active::kill_session(Packet* p, EncodeFlags flags)
{
    switch ( p->type() )
    {
    case PktType::NONE:
        // Can only occur if we have never seen IP
        return;

    case PktType::TCP:
        send_reset(p, 0);
        if ( flags & ENC_FLAG_FWD )
            send_reset(p, ENC_FLAG_FWD);
        break;

    default:
        if ( packet_force_dropped() )
            send_unreach(p, UnreachResponse::FWD);
        else
            send_unreach(p, UnreachResponse::PORT);
        break;
    }
}

//--------------------------------------------------------------------

void Active::init(SnortConfig* sc)
{
    if (sc->max_responses > 0)
        Active::set_enabled();
}

bool Active::thread_init(SnortConfig* sc)
{
    s_attempts = sc->respond_attempts;

    if ( s_attempts > MAX_ATTEMPTS )
        s_attempts = MAX_ATTEMPTS;

    if ( enabled && !s_attempts )
        s_attempts = 1;

    if ( enabled && (!SFDAQ::can_inject() || !sc->respond_device.empty()) )
    {
        if ( SnortConfig::read_mode() || !open(sc->respond_device.c_str()) )
        {
            ParseWarning(WARN_DAQ, "active responses disabled since DAQ "
                "can't inject packets.");
#ifndef REG_TEST
            s_attempts = 0;
#endif
        }
    }

    return true;
}

void Active::thread_term()
{
    Active::close();
}

//--------------------------------------------------------------------

void Active::send_reset(Packet* p, EncodeFlags ef)
{
    int i;
    EncodeFlags flags = (GetFlags() | ef) & ~ENC_FLAG_VAL;
    EncodeFlags value = ef & ENC_FLAG_VAL;

    for ( i = 0; i < s_attempts; i++ )
    {
        uint32_t len;
        const uint8_t* rej;

        value = Strafe(i, value, p);

        rej = PacketManager::encode_response(TcpResponse::RST, flags|value, p, len);
        if ( !rej )
            return;

        s_send(p->daq_msg, !(ef & ENC_FLAG_FWD), rej, len);
    }
}

void Active::send_unreach(Packet* p, UnreachResponse type)
{
    uint32_t len;
    const uint8_t* rej;
    EncodeFlags flags = GetFlags();

    if ( !s_attempts )
        return;

    rej = PacketManager::encode_reject(type, flags, p, len);
    if ( !rej )
        return;

    s_send(p->daq_msg, 1, rej, len);
}

bool Active::send_data(
    Packet* p, EncodeFlags flags, const uint8_t* buf, uint32_t blen)
{
    const uint8_t* seg;
    uint32_t plen;

    flags |= GetFlags();
    flags &= ~ENC_FLAG_VAL;

    if ( flags & ENC_FLAG_RST_SRVR )
    {
        plen = 0;
        EncodeFlags tmp_flags = flags ^ ENC_FLAG_FWD;
        seg = PacketManager::encode_response(TcpResponse::RST, tmp_flags, p, plen);

        if ( seg )
        {
            s_send(p->daq_msg, !(tmp_flags & ENC_FLAG_FWD), seg, plen);
            active_counts.injects++;
        }
    }
    flags |= ENC_FLAG_SEQ;

    uint32_t sent = 0;
    const uint16_t maxPayload = PacketManager::encode_get_max_payload(p);

    if (maxPayload)
    {
        uint16_t toSend;
        do
        {
            plen = 0;
            toSend = blen > maxPayload ? maxPayload : blen;
            flags = (flags & ~ENC_FLAG_VAL) | sent;
            seg = PacketManager::encode_response(TcpResponse::PUSH, flags, p, plen, buf, toSend);

            if ( !seg )
                return false;

            s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
            active_counts.injects++;

            buf += toSend;
            sent += toSend;
        }
        while (blen -= toSend);
    }

    plen = 0;
    flags = (flags & ~ENC_FLAG_VAL) | sent;
    seg = PacketManager::encode_response(TcpResponse::FIN, flags, p, plen, nullptr, 0);

    if ( !seg )
        return false;

    s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
    active_counts.injects++;

    if (flags & ENC_FLAG_RST_CLNT)
    {
        sent++;
        plen = 0;
        flags = (flags & ~ENC_FLAG_VAL) | sent;
        seg = PacketManager::encode_response(TcpResponse::RST, flags, p, plen);

        if ( seg )
        {
            s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
            active_counts.injects++;
        }
    }

    return true;
}

void Active::inject_data(
    Packet* p, EncodeFlags flags, const uint8_t* buf, uint32_t blen)
{
    uint32_t plen;
    const uint8_t* seg;

    if ( !s_attempts )
        return;

    flags |= GetFlags();
    flags &= ~ENC_FLAG_VAL;

    seg = PacketManager::encode_response(TcpResponse::PUSH, flags, p, plen, buf, blen);
    if ( !seg )
        return;

    s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
}

//--------------------------------------------------------------------

bool Active::is_reset_candidate(const Packet* p)
{
    if ( !p->is_tcp() or !p->ptrs.tcph )
        return false;

    /*
    **  This ensures that we don't reset packets that we just
    **  spoofed ourselves, thus inflicting a self-induced DOS
    **  attack.
    */
    return ( !(p->ptrs.tcph->th_flags & TH_RST) );
}

bool Active::is_unreachable_candidate(const Packet* p)
{
    // FIXIT-L allow unr to tcp/udp/icmp4/icmp6 only or for all
    switch ( p->type() )
    {
    case PktType::TCP:
    case PktType::UDP:
        return true;

    case PktType::ICMP:
        // FIXIT-L return false for icmp unreachables
        return true;

    default:
        break;
    }

    return false;
}

void Active::cant_drop()
{
    if ( active_status < AST_CANT )
        active_status = AST_CANT;

    else if ( active_status < AST_WOULD )
        active_status = AST_WOULD;
}

void Active::update_status(const Packet* p, bool force)
{
    if ( s_suspend )
        cant_drop();

    else if ( force )
        active_status = AST_FORCE;

    else if ( active_status != AST_FORCE)
    {
        if ( SnortConfig::inline_mode() )
        {
            if ( !SFDAQ::forwarding_packet(p->pkth) )
                active_status = AST_WOULD;
        }
        else if ( SnortConfig::inline_test_mode() )
        {
            active_status = AST_WOULD;
        }
    }
}

void Active::daq_update_status(const Packet* p)
{
    if ( s_suspend )
    {
        cant_drop();
    }
    else if ( active_status != AST_FORCE )
    {
        if ( !SFDAQ::forwarding_packet(p->pkth) )
            active_status = AST_WOULD;
    }
}

void Active::drop_packet(const Packet* p, bool force)
{
    if ( active_action < ACT_DROP )
        active_action = ACT_DROP;

    update_status(p, force);
}

void Active::daq_drop_packet(const Packet* p)
{
    if ( active_action < ACT_DROP )
        active_action = ACT_DROP;

    daq_update_status(p);
}

bool Active::retry_packet(const Packet* p)
{
    if (active_action != ACT_PASS || !SFDAQ::forwarding_packet(p->pkth))
        return false;

    // FIXIT-L semi-arbitrary heuristic for preventing retry queue saturation - reevaluate later
    if (!p->daq_instance || p->daq_instance->get_pool_available() < p->daq_instance->get_batch_size())
    {
        // Fall back on dropping the packet and relying on the host to retransmit
        active_action = ACT_DROP;
        daq_stats.retries_dropped++;
        return false;
    }

    // If a retransmit would be added to the retry queue, drop it instead.
    // FIXIT-L this behavior needs to be reevaluated and probably moved somewhere else
    if (p->packet_flags & PKT_RETRANSMIT)
        active_action = ACT_DROP;
    else
        active_action = ACT_RETRY;

    return true;
}

bool Active::hold_packet(const Packet*)
{
    if ( active_action < ACT_HOLD )
    {
        active_action = ACT_HOLD;
        return true;
    }

    return false;
}

void Active::allow_session(Packet* p)
{
    active_action = ACT_PASS;

    if ( p->flow )
    {
        p->flow->set_state(Flow::FlowState::ALLOW);
        p->flow->disable_inspection();
    }

    p->disable_inspect = true;
}

void Active::block_session(Packet* p, bool force)
{
    active_action = ACT_BLOCK;
    update_status(p, force);

    if ( force or SnortConfig::inline_mode() or SnortConfig::treat_drop_as_ignore() )
        Stream::block_flow(p);

    p->disable_inspect = true;
}

void Active::reset_session(Packet* p, bool force)
{
    update_status(p, force);
    active_action = ACT_RESET;

    if ( force or SnortConfig::inline_mode() or SnortConfig::treat_drop_as_ignore() )
        Stream::drop_flow(p);

    if ( enabled )
    {
        ActionManager::queue_reject(SnortConfig::get_conf(), p);

        if ( p->flow )
        {
            Stream::init_active_response(p, p->flow);
            p->flow->set_state(Flow::FlowState::RESET);
        }
    }

    p->disable_inspect = true;
}

void Active::set_delayed_action(ActiveAction action, bool force)
{
    delayed_active_action = action;

    if ( force )
        active_status = AST_FORCE;
}

void Active::apply_delayed_action(Packet* p)
{
    bool force = (active_status == AST_FORCE);

    switch ( delayed_active_action )
    {
    case ACT_PASS:
        break;
    case ACT_DROP:
        drop_packet(p, force);
        break;
    case ACT_BLOCK:
        block_session(p, force);
        break;
    case ACT_RESET:
        reset_session(p, force);
        break;
    case ACT_RETRY:
        if(!retry_packet(p))
            drop_packet(p, force);
        break;
    default:
        break;
    }

    delayed_active_action = ACT_PASS;
}

//--------------------------------------------------------------------

bool Active::open(const char* dev)
{
    if ( dev && strcasecmp(dev, "ip") )
    {
        s_link = eth_open(dev);

        if ( !s_link )
            FatalError("%s: can't open %s\n", "Active response", dev);

        s_send = send_eth;
    }
    else
    {
        s_ipnet = ip_open();

        if ( !s_ipnet )
            FatalError("%s: can't open ip\n", "Active response");

        s_send = send_ip;
    }
    return ( s_link or s_ipnet );
}

void Active::close()
{
    if ( s_link )
        eth_close(s_link);

    if ( s_ipnet )
        ip_close(s_ipnet);

    s_link = nullptr;
    s_ipnet = nullptr;
}

void Active::reset()
{
    active_tunnel_bypass = 0;
    active_status = AST_ALLOW;
    active_action = ACT_PASS;
    delayed_active_action = ACT_PASS;
}
