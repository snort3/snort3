//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/action_manager.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "pub_sub/active_events.h"
#include "stream/stream.h"
#include "utils/dnet_header.h"

#include "active_action.h"
#include "active_counts.h"
#include "sfdaq.h"
#include "sfdaq_instance.h"
#include "sfdaq_module.h"

using namespace snort;

#define MAX_ATTEMPTS 20

class ResetAction : public snort::ActiveAction
{
public:
    ResetAction() : ActiveAction(ActionPriority::AP_RESET) { }

    void delayed_exec(snort::Packet* p) override
    {
        p->active->kill_session(p, ENC_FLAG_FWD);
    }
};

const char* Active::act_str[Active::ACT_MAX][Active::AST_MAX] =
{
    { "trust", "error", "error", "error" },
    { "allow", "error", "error", "error" },
    { "hold", "error", "error", "error" },
    { "retry", "error", "error", "error" },
    { "rewrite", "cant_rewrite", "would_rewrite", "force_rewrite" },
    { "drop", "cant_drop", "would_drop", "force_drop" },
    { "block", "cant_block", "would_block", "force_block" },
    { "reset", "cant_reset", "would_reset", "force_reset" },
};

static THREAD_LOCAL uint8_t s_attempts = 0;
static THREAD_LOCAL bool s_suspend = false;
static THREAD_LOCAL Active::ActiveSuspendReason s_suspend_reason = Active::ASP_NONE;

static THREAD_LOCAL Active::Counts active_counts;

typedef int (* send_t) (
    DAQ_Msg_h msg, int rev, const uint8_t* buf, uint32_t len);

static THREAD_LOCAL eth_t* s_link = nullptr;
static THREAD_LOCAL ip_t* s_ipnet = nullptr;
static THREAD_LOCAL send_t s_send = SFDAQ::inject;

static ResetAction default_reset;
static int default_drop_reason_id = -1;

static std::unordered_map<std::string, uint8_t> drop_reason_id_map;

PegCount* get_active_counts()
{ return (PegCount*)&active_counts; }

//--------------------------------------------------------------------
// helpers

int Active::send_eth(
    DAQ_Msg_h, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = eth_send(s_link, buf, len);
    return ( (uint32_t)sent != len );
}

int Active::send_ip(
    DAQ_Msg_h, int, const uint8_t* buf, uint32_t len)
{
    ssize_t sent = ip_send(s_ipnet, buf, len);
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

static uint64_t Strafe(int i, uint64_t flags, const Packet* p)
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
        if (is_unreachable_candidate(p))
        {
            if ( packet_force_dropped() )
                send_unreach(p, UnreachResponse::FWD);
            else
                send_unreach(p, UnreachResponse::PORT);
        }
        break;
    }
}

//--------------------------------------------------------------------

bool Active::thread_init(const SnortConfig* sc)
{
    s_attempts = sc->respond_attempts;

    if ( s_attempts > MAX_ATTEMPTS )
        s_attempts = MAX_ATTEMPTS;

    if ( !s_attempts )
        s_attempts = 1;

    if ( !SFDAQ::can_inject() || !sc->respond_device.empty() )
    {
        if ( sc->read_mode() ||
            !open(sc->respond_device.empty() ? nullptr : sc->respond_device.c_str()) )
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
        if ( (p->packet_flags & PKT_USE_DIRECT_INJECT) or
            (p->flow and p->flow->flags.use_direct_inject) )
        {
            DIOCTL_DirectInjectReset msg =
                { p->daq_msg, (uint8_t)((ef & ENC_FLAG_FWD) ? DAQ_DIR_FORWARD : DAQ_DIR_REVERSE) };
            int ret = p->daq_instance->ioctl(DIOCTL_DIRECT_INJECT_RESET,
                &msg, sizeof(msg));
            if ( ret != DAQ_SUCCESS )
            {
                active_counts.failed_direct_injects++;
                return;
            }

            active_counts.direct_injects++;
        }
        else
        {
            uint32_t len;
            const uint8_t* rej;

            value = Strafe(i, value, p);

            rej = PacketManager::encode_response(TcpResponse::RST, flags|value, p, len);
            if ( !rej )
            {
                active_counts.failed_injects++;
                return;
            }

            int ret = s_send(p->daq_msg, !(ef & ENC_FLAG_FWD), rej, len);
            if ( ret )
                active_counts.failed_injects++;
            else
                active_counts.injects++;
        }
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
    {
        active_counts.failed_injects++;
        return;
    }

    int ret = s_send(p->daq_msg, 1, rej, len);
    if ( ret )
        active_counts.failed_injects++;
    else
        active_counts.injects++;
}

uint32_t Active::send_data(
    Packet* p, EncodeFlags flags, const uint8_t* buf, uint32_t blen)
{
    int ret;
    const uint8_t* seg;
    uint32_t plen;
    bool use_direct_inject = (p->packet_flags & PKT_USE_DIRECT_INJECT) or
        (p->flow and p->flow->flags.use_direct_inject);

    flags |= GetFlags();
    flags &= ~ENC_FLAG_VAL;

    // Send RST to the originator of the data.
    if ( flags & ENC_FLAG_RST_SRVR )
    {
        EncodeFlags tmp_flags = flags ^ ENC_FLAG_FWD;
        if ( use_direct_inject )
        {
            DIOCTL_DirectInjectReset msg =
                { p->daq_msg, (uint8_t)((tmp_flags & ENC_FLAG_FWD) ? DAQ_DIR_FORWARD :
                DAQ_DIR_REVERSE) };
            ret = p->daq_instance->ioctl(DIOCTL_DIRECT_INJECT_RESET,
                &msg, sizeof(msg));
            if ( ret != DAQ_SUCCESS )
            {
                active_counts.failed_direct_injects++;
                return 0;
            }

            active_counts.direct_injects++;
        }
        else
        {
            plen = 0;
            seg = PacketManager::encode_response(TcpResponse::RST, tmp_flags, p, plen);

            if ( seg )
            {
                ret = s_send(p->daq_msg, !(tmp_flags & ENC_FLAG_FWD), seg, plen);
                if ( ret )
                    active_counts.failed_injects++;
                else
                    active_counts.injects++;
            }
            else
                active_counts.failed_injects++;
        }
    }
    flags |= ENC_FLAG_SEQ;

    uint32_t sent = 0;

    if (buf != nullptr)
    {
        // Inject the payload.
        if ( use_direct_inject )
        {
            flags = (flags & ~ENC_FLAG_VAL);
            const DAQ_DIPayloadSegment segments[] = {
                { buf, blen }
            };
            const DAQ_DIPayloadSegment* payload[] = { &segments[0] };
            DIOCTL_DirectInjectPayload msg = { p->daq_msg,  payload, 1,
                                               (uint8_t)((flags & ENC_FLAG_FWD) ? DAQ_DIR_FORWARD :
                                               DAQ_DIR_REVERSE) };
            ret = p->daq_instance->ioctl(DIOCTL_DIRECT_INJECT_PAYLOAD,
                &msg, sizeof(msg));
            if ( ret != DAQ_SUCCESS )
            {
                active_counts.failed_direct_injects++;
                return 0;
            }

            sent = blen;
            active_counts.direct_injects++;
        }
        else
        {
            const uint16_t maxPayload = PacketManager::encode_get_max_payload(p);

            if (maxPayload)
            {
                uint32_t toSend;
                do
                {
                    plen = 0;
                    flags = (flags & ~ENC_FLAG_VAL) | sent;
                    toSend = blen > maxPayload ? maxPayload : blen;
                    seg = PacketManager::encode_response(TcpResponse::PUSH, flags, p, plen, buf,
                        toSend);

                    if ( !seg )
                    {
                        active_counts.failed_injects++;
                        return sent;
                    }

                    ret = s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
                    if ( ret )
                        active_counts.failed_injects++;
                    else
                        active_counts.injects++;

                    sent += toSend;
                    buf += toSend;
                }
                while (blen -= toSend);
            }
        }
    }

    // FIXIT-L: Currently there is no support for injecting a FIN via
    // direct injection.
    if ( !use_direct_inject )
    {
        plen = 0;
        flags = (flags & ~ENC_FLAG_VAL) | sent;
        seg = PacketManager::encode_response(TcpResponse::FIN, flags, p, plen, nullptr, 0);

        if ( !seg )
        {
            active_counts.failed_injects++;
            return sent;
        }

        ret = s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
        if ( ret )
            active_counts.failed_injects++;
        else
            active_counts.injects++;

        // Sending a FIN requires that we bump the seq by 1.
        sent++;
    }

    //  Send RST to the receiver of the data.
    if (flags & ENC_FLAG_RST_CLNT)
    {
        flags = (flags & ~ENC_FLAG_VAL) | sent;
        if ( use_direct_inject )
        {
            DIOCTL_DirectInjectReset msg =
                { p->daq_msg, (uint8_t)((flags & ENC_FLAG_FWD) ? DAQ_DIR_FORWARD : DAQ_DIR_REVERSE) };
            ret = p->daq_instance->ioctl(DIOCTL_DIRECT_INJECT_RESET,
                &msg, sizeof(msg));
            if ( ret != DAQ_SUCCESS )
            {
                active_counts.failed_direct_injects++;
                return sent;
            }

            active_counts.direct_injects++;
        }
        else
        {
            plen = 0;
            seg = PacketManager::encode_response(TcpResponse::RST, flags, p, plen);

            if ( seg )
            {
                ret = s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
                if ( ret )
                    active_counts.failed_injects++;
                else
                    active_counts.injects++;
            }
            else
                active_counts.failed_injects++;
        }
    }

    return sent;
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
    {
        active_counts.failed_injects++;
        return;
    }

    int ret = s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen);
    if ( ret )
        active_counts.failed_injects++;
    else
        active_counts.injects++;
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
    if ( p->type() == PktType::TCP || p->type() == PktType::UDP)
        return true;

    return false;
}

void Active::cant_drop()
{
    if ( active_status < AST_CANT )
    {
        active_status = AST_CANT;
        active_would_reason = get_whd_reason_from_suspend_reason();
    }
    else if ( active_status < AST_WOULD )
    {
        active_status = AST_WOULD;
        active_would_reason = get_whd_reason_from_suspend_reason();
    }
}

void Active::update_status_actionable(const Packet* p)
{
    if ( p->context->conf->ips_inline_mode() )
    {
        if ( !SFDAQ::forwarding_packet(p->pkth) )
        {
            active_status = AST_WOULD;
            active_would_reason = WHD_INTERFACE_IDS;
        }
        else if ( active_action == ACT_REWRITE and !SFDAQ::can_replace() )
        {
            active_status = AST_WOULD;
            active_would_reason = WHD_INTERFACE_IDS;
        }
    }
    else if ( p->context->conf->ips_inline_test_mode() )
    {
        active_status = AST_WOULD;
        active_would_reason = WHD_IPS_INLINE_TEST;
    }
    else if ( p->context->conf->ips_passive_mode() )
    {
        active_status = AST_WOULD;
        active_would_reason = WHD_INTERFACE_IDS;
    }
}

void Active::suspend(ActiveSuspendReason suspend_reason)
{
    s_suspend = true;
    s_suspend_reason = suspend_reason;
}

bool Active::is_suspended()
{ return s_suspend; }

void Active::resume()
{
    s_suspend = false;
    s_suspend_reason = ASP_NONE;
}

bool Active::can_partial_block_session() const
{ return active_status == AST_CANT and s_suspend_reason > ASP_NONE and s_suspend_reason != ASP_TIMEOUT; }

bool Active::keep_pruned_flow() const
{ return ( s_suspend_reason == ASP_PRUNE ) or ( s_suspend_reason == ASP_RELOAD ); }

bool Active::keep_timedout_flow() const
{ return ( s_suspend_reason == ASP_TIMEOUT ); }

Active::ActiveWouldReason Active::get_whd_reason_from_suspend_reason()
{
    switch ( s_suspend_reason )
    {
    case ASP_NONE: return WHD_NONE;
    case ASP_PRUNE: return WHD_PRUNE;
    case ASP_TIMEOUT: return WHD_TIMEOUT;
    case ASP_RELOAD: return WHD_RELOAD;
    case ASP_EXIT: return WHD_EXIT;
    }
    return WHD_NONE;
}

void Active::update_status(const Packet* p, bool force)
{
    if ( s_suspend )
    {
        update_status_actionable(p);

        if ( !active_status )
            cant_drop();
    }
    else if ( force )
        active_status = AST_FORCE;
    else if ( active_status != AST_FORCE )
        update_status_actionable(p);
}

void Active::daq_update_status(const Packet* p)
{
    if ( s_suspend )
    {
        update_status_actionable(p);

        if ( !active_status )
            cant_drop();
    }
    else if ( active_status != AST_FORCE )
    {
        update_status_actionable(p);
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

void Active::rewrite_packet(const Packet* p, bool force)
{
    if ( active_action < ACT_REWRITE )
        active_action = ACT_REWRITE;

    update_status(p, force);
}

bool Active::retry_packet(const Packet* p)
{
    if (ACT_RETRY == active_action)
        return true;

    if (ACT_RETRY < active_action || !SFDAQ::forwarding_packet(p->pkth))
        return false;

    // FIXIT-L semi-arbitrary heuristic for preventing retry queue saturation - reevaluate later
    SFDAQInstance* daq_instance = p->daq_instance ? p->daq_instance : SFDAQ::get_local_instance();
    if (!daq_instance || daq_instance->get_pool_available() < daq_instance->get_batch_size())
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

bool Active::hold_packet(const Packet* p)
{
    if (active_action >= ACT_HOLD)
        return false;

    // FIXIT-L same semi-arbitrary heuristic as the retry queue logic - reevaluate later
    if (!p->daq_instance || p->daq_instance->get_pool_available() <
        p->daq_instance->get_batch_size())
    {
        active_counts.holds_denied++;
        return false;
    }

    active_action = ACT_HOLD;
    active_counts.holds_allowed++;

    return true;
}

void Active::cancel_packet_hold()
{
    assert(active_action == ACT_HOLD);
    active_counts.holds_canceled++;
    active_action = ACT_ALLOW;
}

void Active::trust_session(Packet* p, bool force)
{
    if (ACT_ALLOW < active_action)
        return;

    DetectionEngine::disable_all(p);

    if (force)
    {
        p->packet_flags |= PKT_IGNORE;
        if ( p->flow )
        {
            p->flow->trust();
            p->flow->stop_deferring_trust();
        }
        p->disable_inspect = true;
    }
    else if (p->flow && p->flow->try_trust())
        active_action = ACT_TRUST;
}

void Active::block_session(Packet* p, bool force)
{
    active_action = ACT_BLOCK;
    update_status(p, force);

    if ( force or (p->context->conf->ips_inline_mode() and SFDAQ::forwarding_packet(p->pkth)))
        Stream::block_flow(p);

    if ( force and p->flow )
        p->flow->set_state(Flow::FlowState::BLOCK);

    p->disable_inspect = true;
}

void Active::reset_session(Packet* p, bool force)
{
    reset_session(p, &default_reset, force);
}

void Active::reset_session(Packet* p, ActiveAction* reject, bool force)
{
    active_action = ACT_RESET;
    update_status(p, force);

    if ( force or (p->context->conf->ips_inline_mode() and SFDAQ::forwarding_packet(p->pkth)) )
        Stream::drop_flow(p);

    if (reject)
        Active::queue(reject, p);

    if ( p->flow )
    {
        Stream::init_active_response(p, p->flow);
        p->flow->set_state(Flow::FlowState::RESET);
    }

    p->disable_inspect = true;
}

void Active::queue(ActiveAction* a, Packet* p)
{
    if ( !(*p->action) || a->get_action() > (*p->action)->get_action() )
        *p->action = a;
}

void Active::set_delayed_action(ActiveActionType action, bool force)
{
    set_delayed_action(action, action == ACT_RESET ? &default_reset : nullptr, force);
}

void Active::set_delayed_action(ActiveActionType action, ActiveAction* act, bool force)
{
    // Don't update the delayed active action to a less strict one, with
    // the exception of going from allow to trust.
    if(delayed_active_action >= action and delayed_active_action > ACT_ALLOW)
        return;

    delayed_active_action = action;

    if (delayed_reject == nullptr)
        delayed_reject = act;

    if ( force )
        active_status = AST_FORCE;
}

void Active::apply_delayed_action(Packet* p)
{
    bool force = (active_status == AST_FORCE);

    switch ( delayed_active_action )
    {
    case ACT_ALLOW:
        break;
    case ACT_DROP:
        drop_packet(p, force);
        break;
    case ACT_BLOCK:
        block_session(p, force);
        break;
    case ACT_RESET:
        assert(delayed_reject);   // resets must have been told which reject to use
        reset_session(p, delayed_reject, force);
        break;
    case ACT_RETRY:
        if (!retry_packet(p))
            drop_packet(p, force);
        break;
    case ACT_TRUST:
        trust_session(p, force);
        break;
    default:
        break;
    }

    delayed_active_action = ACT_ALLOW;
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
    active_would_reason = WHD_NONE;
    active_action = ACT_ALLOW;
    delayed_active_action = ACT_ALLOW;
    delayed_reject = nullptr;
    drop_reason = nullptr;
}

void Active::clear_queue(Packet* p)
{
    *p->action = nullptr;
    DetectionEngine::clear_replacement();
}

void Active::execute(Packet* p)
{
    if ( *p->action )
    {
        (*p->action)->delayed_exec(p);
        *p->action = nullptr;
    }

    if (p->flow)
    {
        p->flow->finalize_trust(*p->active);
        if (p->active->session_was_trusted())
            p->flow->trust();
    }
}

void Active::set_default_drop_reason(uint8_t reason_id)
{
    default_drop_reason_id = reason_id;
}

void Active::map_drop_reason_id(const char* verdict_reason, uint8_t id)
{
    drop_reason_id_map[verdict_reason] = id;
}

void Active::set_drop_reason(const char* reason)
{
    if ( !drop_reason and !is_suspended() )
        drop_reason = reason;
}

int Active::get_drop_reason_id()
{
    const auto iter = drop_reason_id_map.find(drop_reason);
    if ( iter != drop_reason_id_map.end() )
        return iter->second;

    return default_drop_reason_id;
}

void Active::send_reason_to_daq(Packet& p)
{
    if ( !drop_reason )
        return;

    int reason = get_drop_reason_id();
    if ( reason != -1 )
        p.daq_instance->set_packet_verdict_reason(p.daq_msg, reason);
}
