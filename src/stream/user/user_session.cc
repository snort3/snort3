//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// user_session.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "user_session.h"

#include "detection/detection_engine.h"
#include "detection/rules.h"
#include "main/snort.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "stream_user.h"
#include "user_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats user_perf_stats;

// we always get exactly one copy of user data in order
// maintain "seg"list of user data stream
// allocate bucket size to substantially improve performance
// run user data through paf

//-------------------------------------------------------------------------
// segment stuff
//-------------------------------------------------------------------------

#define OVERHEAD   32
#define PAGE_SZ    4096
#define BUCKET     (PAGE_SZ - OVERHEAD)

UserSegment* UserSegment::init(const uint8_t* p, unsigned n)
{
    unsigned bucket = (n > BUCKET) ? n : BUCKET;
    UserSegment* us = (UserSegment*)snort_alloc(sizeof(*us)+bucket-1);

    us->len = 0;
    us->offset = 0;
    us->used = 0;
    us->copy(p, n);

    return us;
}

void UserSegment::term(UserSegment* us)
{
    snort_free(us);
}

unsigned UserSegment::avail()
{
    unsigned size = offset + len;
    return (BUCKET > size) ? BUCKET - size : 0;
}

void UserSegment::copy(const uint8_t* p, unsigned n)
{
    memcpy(data+offset+len, p, n);
    len += n;
}

void UserSegment::shift(unsigned n)
{
    assert(len >= n);
    offset += n;
    len -= n;
}

unsigned UserSegment::get_len()
{ return len; }

uint8_t* UserSegment::get_data()
{ return data + offset; }

bool UserSegment::unused()
{ return used < offset + len; }

void UserSegment::use(unsigned n)
{
    used += n;
    if ( used > offset + len )
        used = offset + len;
}

void UserSegment::reset()
{ used = offset; }

unsigned UserSegment::get_unused_len()
{ return (offset + len > used) ? offset + len - used : 0; }

uint8_t* UserSegment::get_unused_data()
{ return data + used; }

//-------------------------------------------------------------------------
// tracker stuff
//-------------------------------------------------------------------------

UserTracker::UserTracker()
{ init(); }

UserTracker::~UserTracker()
{ term(); }

void UserTracker::init()
{
    paf_clear(&paf_state);
    splitter = nullptr;
    total = 0;
}

void UserTracker::term()
{
    if ( splitter )
    {
        delete splitter;
        splitter = nullptr;
    }

    for ( auto* p : seg_list )
        snort_free(p);

    seg_list.clear();
}

void UserTracker::detect(
    const Packet* p, const StreamBuffer& sb, uint32_t flags, Packet* up)
{
    up->pkth = p->pkth;
    up->ptrs = p->ptrs;
    up->flow = p->flow;
    up->data = sb.data;
    up->dsize = sb.length;

    up->proto_bits = p->proto_bits;
    up->pseudo_type = PSEUDO_PKT_USER;

    up->packet_flags = flags | PKT_REBUILT_STREAM | PKT_PSEUDO;
    up->packet_flags |= (p->packet_flags & (PKT_FROM_CLIENT|PKT_FROM_SERVER));
    up->packet_flags |= (p->packet_flags & (PKT_STREAM_EST|PKT_STREAM_UNEST_UNI));

    trace_logf(stream_user, "detect[%d]\n", up->dsize);
    snort::Snort::inspect(up);
}

int UserTracker::scan(Packet* p, uint32_t& flags)
{
    if ( seg_list.empty() )
        return -1;

    DetectionEngine::onload(p->flow);
    std::list<UserSegment*>::iterator it;

    for ( it = seg_list.begin(); it != seg_list.end(); ++it)
    {
        UserSegment* us = *it;

        if ( !us->unused() )
            continue;

        flags = p->packet_flags & (PKT_FROM_CLIENT|PKT_FROM_SERVER);
        unsigned len = us->get_unused_len();
        trace_logf(stream_user, "scan[%d]\n", len);

        int32_t flush_amt = paf_check(
            splitter, &paf_state, p->flow, us->get_unused_data(), len,
            total, paf_state.seq, &flags);

        if ( flush_amt >= 0 )
        {
            us->use(flush_amt);

            if ( !splitter->is_paf() && total > (unsigned)flush_amt )
            {
                paf_jump(&paf_state, total - flush_amt);
                return total;
            }
            return flush_amt;
        }
        us->use(len);
    }
    return -1;
}

void UserTracker::flush(Packet* p, unsigned flush_amt, uint32_t flags)
{
    unsigned bytes_flushed = 0;
    StreamBuffer sb = { nullptr, 0 };
    trace_logf(stream_user, "flush[%d]\n", flush_amt);
    uint32_t rflags = flags & ~PKT_PDU_TAIL;
    Packet* up = DetectionEngine::set_next_packet(p);

    while ( !seg_list.empty() and bytes_flushed < flush_amt )
    {
        UserSegment* us = seg_list.front();
        const uint8_t* data = us->get_data();
        unsigned len = us->get_len();
        unsigned bytes_copied = 0;

        if ( len + bytes_flushed > flush_amt )
            len = flush_amt - bytes_flushed;

        if ( len + bytes_flushed == flush_amt )
        {
            rflags |= (flags & PKT_PDU_TAIL);
            len = flush_amt;
        }

        trace_logf(stream_user, "reassemble[%d]\n", len);
        sb = splitter->reassemble(
            p->flow, flush_amt, bytes_flushed, data, len, rflags, bytes_copied);

        bytes_flushed += bytes_copied;
        total -= bytes_copied;

        rflags &= ~PKT_PDU_HEAD;

        if ( sb.data )
            detect(p, sb, flags, up);

        if ( bytes_copied == us->get_len() )
        {
            seg_list.pop_front();
            UserSegment::term(us);
        }
        else
        {
            us->shift(bytes_copied);
        }
    }
}

void UserTracker::process(Packet* p)
{
    DetectionEngine::onload(p->flow);

    uint32_t flags = 0;
    int flush_amt = scan(p, flags);

    while ( flush_amt >= 0 )
    {
        unsigned amt = (unsigned)flush_amt;
        assert(total >= amt);

        flush(p, amt, flags);

        if ( total )
            flush_amt = scan(p, flags);
        else
            break;
    }
}

void UserTracker::add_data(Packet* p)
{
    trace_logf(stream_user, "add[%d]\n", p->dsize);
    unsigned avail = 0;

    if ( !seg_list.empty() )
    {
        UserSegment* us = seg_list.back();
        avail = us->avail();

        if ( avail )
        {
            if ( avail > p->dsize )
                avail = p->dsize;
            us->copy(p->data, avail);
        }
    }

    if ( avail < p->dsize )
    {
        UserSegment* us = UserSegment::init(p->data+avail, p->dsize-avail);
        seg_list.push_back(us);
    }
    total += p->dsize;
    process(p);
}

//-------------------------------------------------------------------------
// private user session methods
// may need additional refactoring
//-------------------------------------------------------------------------

void UserSession::start(Packet* p, Flow* flow)
{
    Inspector* ins = flow->gadget;

    if ( !ins )
        ins = flow->clouseau;

    if ( ins )
    {
        set_splitter(true, ins->get_splitter(true));
        set_splitter(false, ins->get_splitter(false));
    }
    else
    {
        set_splitter(true, new AtomSplitter(true));
        set_splitter(false, new AtomSplitter(false));
    }

    {
        flow->pkt_type = p->type();
        flow->ip_proto = (uint8_t)p->get_ip_proto_next();

        if (flow->ssn_state.session_flags & SSNFLAG_RESET)
            flow->ssn_state.session_flags &= ~SSNFLAG_RESET;

        if ( (flow->ssn_state.session_flags & SSNFLAG_CLIENT_SWAP) &&
            !(flow->ssn_state.session_flags & SSNFLAG_CLIENT_SWAPPED) )
        {
            SfIp ip = flow->client_ip;
            uint16_t port = flow->client_port;

            flow->client_ip = flow->server_ip;
            flow->server_ip = ip;

            flow->client_port = flow->server_port;
            flow->server_port = port;

            if ( !flow->two_way_traffic() )
            {
                if ( flow->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT )
                {
                    flow->ssn_state.session_flags ^= SSNFLAG_SEEN_CLIENT;
                    flow->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;
                }
                else if ( flow->ssn_state.session_flags & SSNFLAG_SEEN_SERVER )
                {
                    flow->ssn_state.session_flags ^= SSNFLAG_SEEN_SERVER;
                    flow->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
                }
            }
            flow->ssn_state.session_flags |= SSNFLAG_CLIENT_SWAPPED;
        }
#if 0
        // FIXIT-M implement stream_user perf stats
        //flow->set_expire(p, dstPolicy->session_timeout);

        // add user flavor to perf stats?
        AddStreamSession(
            &sfBase, flow->session_state & STREAM_STATE_MIDSTREAM ? SSNFLAG_MIDSTREAM : 0);

        StreamUpdatePerfBaseState(&sfBase, tmp->flow, TCP_STATE_SYN_SENT);

        EventInternal(SESSION_EVENT_SETUP);
#endif
    }
}

void UserSession::end(Packet*, Flow*)
{
    delete client.splitter;
    delete server.splitter;

    client.splitter = nullptr;
    server.splitter = nullptr;
}

void UserSession::update(Packet* p, Flow* flow)
{
    if ( p->ptrs.sp and p->ptrs.dp )
        p->packet_flags |= PKT_STREAM_EST;
    else
        p->packet_flags |= PKT_STREAM_UNEST_UNI;

    if ( !(flow->ssn_state.session_flags & SSNFLAG_ESTABLISHED) )
    {
        if ( p->is_from_client() )
            flow->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        else
            flow->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;

        if ( (flow->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
            (flow->ssn_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            flow->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;

            flow->set_ttl(p, false);
        }
    }

    StreamUserConfig* pc = get_user_cfg(flow->ssn_server);
    flow->set_expire(p, pc->session_timeout);
}

void UserSession::restart(Packet* p)
{
    bool c2s = p->is_from_client();
    UserTracker& ut = c2s ? server : client;
    std::list<UserSegment*>::iterator it;
    ut.total = 0;

    for ( it = ut.seg_list.begin(); it != ut.seg_list.end(); ++it)
    {
        (*it)->reset();
        ut.total += (*it)->get_len();
    }

    paf_reset(&ut.paf_state);
    ut.process(p);
}

//-------------------------------------------------------------------------
// UserSession methods
//-------------------------------------------------------------------------

UserSession::UserSession(Flow* flow) : Session(flow) { }


bool UserSession::setup(Packet*)
{
    client.init();
    server.init();

#ifdef ENABLE_EXPECTED_USER
    if ( Stream::expected_flow(flow, p) )
        return false;
#endif
    return true;
}

void UserSession::clear()
{
    client.term();
    server.term();
    flow->restart();
}

void UserSession::set_splitter(bool c2s, StreamSplitter* ss)
{
    UserTracker& ut = c2s ? server : client;

    if ( ut.splitter )
        delete ut.splitter;

    ut.splitter = ss;

    if ( ss )
        paf_setup(&ut.paf_state);
}

StreamSplitter* UserSession::get_splitter(bool c2s)
{
    UserTracker& ut = c2s ? server : client;
    return ut.splitter;
}

int UserSession::process(Packet* p)
{
    Profile profile(user_perf_stats);

    if ( Stream::expired_flow(flow, p) )
    {
        flow->restart();
        // FIXIT-M count user session timeouts here

#ifdef ENABLE_EXPECTED_USER
        if ( Stream::expected_flow(flow, p))
            return 0;
#endif
    }

    flow->set_direction(p);

    if ( Stream::blocked_flow(flow, p) || Stream::ignored_flow(flow, p) )
        return 0;

    update(p, flow);

    UserTracker& ut = p->is_from_client() ? server : client;

    if ( p->ptrs.decode_flags & DECODE_SOF or !ut.splitter )
        start(p, flow);

    if ( p->data && p->dsize )
        ut.add_data(p);

    if ( p->ptrs.decode_flags & DECODE_EOF )
        end(p, flow);

    return 0;
}

//-------------------------------------------------------------------------
// UserSession methods
// FIXIT-M these are TBD after tcp is updated
// some will be deleted, some refactored, some implemented
//-------------------------------------------------------------------------

void UserSession::update_direction(char /*dir*/, const SfIp*, uint16_t /*port*/) { }

bool UserSession::add_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return true; }
bool UserSession::check_alerted(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }

int UserSession::update_alert(
    Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
    uint32_t /*event_id*/, uint32_t /*event_second*/)
{ return 0; }

uint8_t UserSession::get_reassembly_direction()
{ return SSN_DIR_NONE; }

