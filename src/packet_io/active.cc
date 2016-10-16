//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "stream/stream.h"
#include "utils/dnet_header.h"

#include "sfdaq.h"

#define MAX_ATTEMPTS 20

// these can't be pkt flags because we do the handling
// of these flags following all processing and the drop
// or response may have been produced by a pseudopacket.
THREAD_LOCAL Active::ActiveStatus Active::active_status = Active::AST_ALLOW;
THREAD_LOCAL Active::ActiveAction Active::active_action = Active::ACT_PASS;
THREAD_LOCAL Active::ActiveAction Active::delayed_active_action = Active::ACT_PASS;

THREAD_LOCAL int Active::active_tunnel_bypass = 0;
THREAD_LOCAL bool Active::active_suspend = false;

THREAD_LOCAL uint8_t Active::s_attempts = 0;
THREAD_LOCAL uint64_t Active::s_injects = 0;

bool Active::s_enabled = false;

typedef int (* send_t) (
    const DAQ_PktHdr_t* h, int rev, const uint8_t* buf, uint32_t len);

static THREAD_LOCAL eth_t* s_link = NULL;
static THREAD_LOCAL ip_t* s_ipnet = NULL;
static THREAD_LOCAL send_t s_send = SFDAQ::inject;

//--------------------------------------------------------------------
// helpers

int Active::send_eth(
    const DAQ_PktHdr_t*, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = eth_send(s_link, buf, len);
    s_injects++;
    return ( (uint32_t)sent != len );
}

int Active::send_ip(
    const DAQ_PktHdr_t*, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = ip_send(s_ipnet, buf, len);
    s_injects++;
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
        Active::send_reset(p, 0);
        if ( flags & ENC_FLAG_FWD )
            Active::send_reset(p, ENC_FLAG_FWD);
        break;

    default:
        if ( Active::packet_force_dropped() )
            Active::send_unreach(p, UnreachResponse::FWD);
        else
            Active::send_unreach(p, UnreachResponse::PORT);
        break;
    }
}

//--------------------------------------------------------------------

bool Active::init(SnortConfig* sc)
{
    s_attempts = sc->respond_attempts;

    if ( s_attempts > MAX_ATTEMPTS )
        s_attempts = MAX_ATTEMPTS;

    if ( s_enabled && !s_attempts )
        s_attempts = 1;

    if ( s_enabled && (!SFDAQ::can_inject() || !sc->respond_device.empty()) )
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

void Active::term()
{
    Active::close();
}

bool Active::is_enabled()
{ return s_enabled and s_attempts; }

void Active::set_enabled(bool on_off)
{
    s_enabled = on_off;
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

        s_send(p->pkth, !(ef & ENC_FLAG_FWD), rej, len);
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

    s_send(p->pkth, 1, rej, len);
}

bool Active::send_data(
    Packet* p, EncodeFlags flags, const uint8_t* buf, uint32_t blen)
{
    uint16_t toSend;
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
            s_send(p->pkth, !(tmp_flags & ENC_FLAG_FWD), seg, plen);
    }
    flags |= ENC_FLAG_SEQ;

    uint32_t sent = 0;
    const uint16_t maxPayload = PacketManager::encode_get_max_payload(p);

    if (maxPayload)
    {
        do
        {
            plen = 0;
            toSend = blen > maxPayload ? maxPayload : blen;
            flags = (flags & ~ENC_FLAG_VAL) | sent;
            seg = PacketManager::encode_response(TcpResponse::PUSH, flags, p, plen, buf, toSend);

            if ( !seg )
                return false;

            s_send(p->pkth, !(flags & ENC_FLAG_FWD), seg, plen);

            buf += toSend;
            sent += toSend;
        }
        while (blen -= toSend);
    }

    plen = 0;
    flags = (flags & ~ENC_FLAG_VAL) | sent;
    seg = PacketManager::encode_response(TcpResponse::FIN, flags, p, plen, NULL, 0);

    if ( !seg )
        return false;

    s_send(p->pkth, !(flags & ENC_FLAG_FWD), seg, plen);

    if (flags & ENC_FLAG_RST_CLNT)
    {
        sent++;
        plen = 0;
        flags = (flags & ~ENC_FLAG_VAL) | sent;
        seg = PacketManager::encode_response(TcpResponse::RST, flags, p, plen);

        if ( seg )
            s_send(p->pkth, !(flags & ENC_FLAG_FWD), seg, plen);
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

    s_send(p->pkth, !(flags & ENC_FLAG_FWD), seg, plen);
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
        return 1;

    case PktType::ICMP:
        // FIXIT-L return false for icmp unreachables
        return 1;

    default:
        break;
    }

    return 0;
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
    if ( suspended() )
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
    if ( suspended() )
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

void Active::block_session(const Packet* p, bool force)
{
    update_status(p, force);
    active_action = ACT_BLOCK;

    if ( force or SnortConfig::inline_mode() or SnortConfig::treat_drop_as_ignore() )
        Stream::block_flow(p);
}

void Active::reset_session(const Packet* p, bool force)
{
    update_status(p, force);
    active_action = ACT_RESET;

    if ( force or SnortConfig::inline_mode() or SnortConfig::treat_drop_as_ignore() )
        Stream::drop_flow(p);

    if ( s_enabled and snort_conf->max_responses )
    {
        ActionManager::queue_reject(p);

        if ( p->flow )
        {
            Stream::init_active_response(p, p->flow);
            p->flow->set_state(Flow::FlowState::RESET);
        }
    }
}

void Active::set_delayed_action(ActiveAction action, bool force)
{
    delayed_active_action = action;

    if (force)
        active_status = AST_FORCE;
}

void Active::apply_delayed_action(const Packet* p)
{
    bool force = (active_status == AST_FORCE);

    switch (delayed_active_action)
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

    s_link = NULL;
    s_ipnet = NULL;
}

static const char* act_str[Active::ACT_MAX][Active::AST_MAX] =
{
    { "allow", "error", "error", "error" },
    { "drop", "cant_drop", "would_drop", "force_drop" },
    { "block", "cant_block", "would_block", "force_block" },
    { "reset", "cant_reset", "would_reset", "force_reset" },
};

const char* Active::get_action_string()
{
    return act_str[active_action][active_status];
}

