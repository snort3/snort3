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

// dnp3.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnp3.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "protocols/packet.h"

#include "dnp3_paf.h"
#include "dnp3_reassembly.h"

using namespace snort;

THREAD_LOCAL Dnp3Stats dnp3_stats;
THREAD_LOCAL ProfileStats dnp3_perf_stats;

Dnp3FlowData::Dnp3FlowData() : FlowData(inspector_id)
{
    dnp3_stats.concurrent_sessions++;
    if(dnp3_stats.max_concurrent_sessions < dnp3_stats.concurrent_sessions)
        dnp3_stats.max_concurrent_sessions = dnp3_stats.concurrent_sessions;
}

Dnp3FlowData::~Dnp3FlowData()
{
    assert(dnp3_stats.concurrent_sessions > 0);
    dnp3_stats.concurrent_sessions--;
}

unsigned Dnp3FlowData::inspector_id = 0;

static dnp3_session_data_t* get_session_data(Flow* flow)
{
    Dnp3FlowData* fd = (Dnp3FlowData*)flow->get_flow_data(Dnp3FlowData::inspector_id);
    return fd ? &fd->dnp3_session : nullptr;
}

static dnp3_session_data_t* set_new_dnp3_session(Packet* p)
{
    Dnp3FlowData* fd = new Dnp3FlowData;
    p->flow->set_flow_data(fd);
    return(&fd->dnp3_session);
}

static const uint8_t* dnp3_get_alt_buffer(Packet* p, unsigned& len)
{
    dnp3_session_data_t* dnp3_sess = get_session_data(p->flow);
    len = 0;

    if (dnp3_sess)
    {
        dnp3_reassembly_data_t* rdata;
        /* rdata->buffer will be the alt decode buffer.
           This will be returned via the get_buf inspector API*/

        if (dnp3_sess->direction == DNP3_CLIENT)
            rdata = &(dnp3_sess->client_rdata);
        else
            rdata = &(dnp3_sess->server_rdata);
        if (rdata->state == DNP3_REASSEMBLY_STATE__DONE)
        {
            len = rdata->buflen;
            return (const uint8_t*)rdata->buffer;
        }
    }
    return nullptr;
}

static void dnp3_reset_alt_buffer(const Packet* p)
{
    dnp3_session_data_t* dnp3_sess = get_session_data(p->flow);

    if (dnp3_sess)
    {
        dnp3_reassembly_data_t* rdata;

        if (dnp3_sess->direction == DNP3_CLIENT)
            rdata = &(dnp3_sess->client_rdata);
        else
            rdata = &(dnp3_sess->server_rdata);
        if (rdata->state == DNP3_REASSEMBLY_STATE__DONE)
            dnp3_reassembly_reset(rdata);
    }
}

static bool dnp3_process_udp(dnp3ProtoConf& config, dnp3_session_data_t* dnp3_sess, Packet* p)
{
    /* Possibly multiple PDUs in this UDP payload.
       Split up and process individually. */

    uint16_t bytes_processed = 0;
    bool truncated_pdu = false;

    while (bytes_processed < p->dsize)
    {
        const uint8_t* pdu_start;
        uint16_t user_data, num_crcs, pdu_length;
        const dnp3_link_header_t* link;

        pdu_start = (const uint8_t*)(p->data + bytes_processed);
        link = (const dnp3_link_header_t*)pdu_start;

        /*Stop if the start bytes are not 0x0564 */
        if ((p->dsize < bytes_processed + 2)
            || (link->start != DNP3_START_BYTES))
            break;

        /* Alert and stop if there's not enough data to read a length */
        if ((p->dsize - bytes_processed < (int)sizeof(dnp3_link_header_t)) ||
            (link->len < DNP3_HEADER_REMAINDER_LEN))
        {
            truncated_pdu = true;
            break;
        }

        /* Calculate the actual length of data to inspect */
        user_data = link->len - DNP3_HEADER_REMAINDER_LEN;
        num_crcs = 1 + (user_data/DNP3_CHUNK_SIZE) + ((user_data % DNP3_CHUNK_SIZE) ? 1 : 0);
        pdu_length = DNP3_MIN_LEN + link->len + (DNP3_CRC_SIZE*num_crcs);

        if (bytes_processed + pdu_length > p->dsize)
        {
            truncated_pdu = true;
            break;
        }

        dnp3_full_reassembly(config, dnp3_sess, p, pdu_start, pdu_length);
        bytes_processed += pdu_length;
    }

    if (truncated_pdu)
    {
        DetectionEngine::queue_event(GID_DNP3, DNP3_DROPPED_FRAME);
    }

    return true;
}

/* Main runtime entry point */

static void process_dnp3(dnp3ProtoConf& config, Packet* p)
{
    if ( p->has_tcp_data() && !p->is_full_pdu() )
    {
        return;
    }

    /* Attempt to get a previously allocated DNP3 block. */
    dnp3_session_data_t* dnp3_sess = get_session_data(p->flow);

    if (dnp3_sess == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our DNP3 data-block attached, create one.
         */
        dnp3_sess = set_new_dnp3_session(p);

        if ( !dnp3_sess )
        {
            return;
        }
    }

    /* When pipelined DNP3 PDUs appear in a single TCP segment or UDP packet,
       the detection engine caches the results of the rule options after
       evaluating on the first PDU. Setting this flag stops the caching. */
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    /* Set reassembly direction */
    if (p->is_from_client())
        dnp3_sess->direction = DNP3_CLIENT;
    else
        dnp3_sess->direction = DNP3_SERVER;

    /* Do preprocessor-specific detection stuff here */
    if (p->has_tcp_data())
    {
        ++dnp3_stats.tcp_pdus;
        /* Single PDU. PAF already split them up into separate pseudo-packets. */
        dnp3_full_reassembly(config, dnp3_sess, p,(const uint8_t*)p->data,p->dsize);
    }
    else if (p->has_udp_data())
    {
        ++dnp3_stats.udp_packets;
        dnp3_process_udp(config, dnp3_sess, p);
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dnp3 : public Inspector
{
public:
    Dnp3(dnp3ProtoConf&);

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;
    void clear(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    {
        return new Dnp3Splitter(c2s);
    }

private:
    dnp3ProtoConf config;
};

Dnp3::Dnp3(dnp3ProtoConf& pc)
{
    config.check_crc = pc.check_crc;
}


void Dnp3::show(SnortConfig*)
{
    print_dnp3_conf(config);
}

void Dnp3::eval(Packet* p)
{
    Profile profile(dnp3_perf_stats);

    assert (p->has_tcp_data() || p->has_udp_data());
    assert(p->flow);

    ++dnp3_stats.total_packets;

    process_dnp3(config, p);
}

bool Dnp3::get_buf(
    InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    if ( ibt != InspectionBuffer::IBT_ALT )
        return false;

    b.data = dnp3_get_alt_buffer(p,b.len);

    return (b.data != nullptr);
}

void Dnp3::clear(Packet* p)
{
    dnp3_reset_alt_buffer(p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dnp3Module;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void dnp3_init()
{
    Dnp3FlowData::init();
}

static Inspector* dnp3_ctor(Module* m)
{
    Dnp3Module* mod = (Dnp3Module*)m;
    dnp3ProtoConf config;
    mod->get_data(config);
    return new Dnp3(config);
}

static void dnp3_dtor(Inspector* p)
{
    delete p;
}

const InspectApi dnp3_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DNP3_NAME,
        DNP3_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__UDP | PROTO_BIT__PDU,
    nullptr,  // buffers
    "dnp3",
    dnp3_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dnp3_ctor,
    dnp3_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_dnp3_func;
extern const BaseApi* ips_dnp3_ind;
extern const BaseApi* ips_dnp3_obj;
extern const BaseApi* ips_dnp3_data;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_dnp3[] =
#endif
{
    &dnp3_api.base,
    ips_dnp3_func,
    ips_dnp3_ind,
    ips_dnp3_obj,
    ips_dnp3_data,
    nullptr
};

