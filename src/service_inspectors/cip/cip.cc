//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// cip.cc author Jian Wu <jiawu2@cisco.com>

/* Description: service inspector for the CIP protocol. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/cip_events.h"
#include "stream/stream_splitter.h"
#include "utils/util.h"              // for snort_calloc

#include "cip_module.h"
#include "cip_paf.h"
#include "cip_parsing.h"

using namespace snort;

THREAD_LOCAL ProfileStats cip_perf_stats;

unsigned CipFlowData::inspector_id = 0;
unsigned CipEventData::pub_id = 0;

static void free_cip_data(void* data);

CipFlowData::CipFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    cip_stats.sessions++;
    cip_stats.concurrent_sessions++;
    if (cip_stats.max_concurrent_sessions < cip_stats.concurrent_sessions)
        cip_stats.max_concurrent_sessions = cip_stats.concurrent_sessions;
}

CipFlowData::~CipFlowData()
{
    free_cip_data(&session);
    assert(cip_stats.concurrent_sessions > 0);
    cip_stats.concurrent_sessions--;
}

CipSessionData* get_cip_session_data(const Flow* flow)
{
    CipFlowData* fd = static_cast<CipFlowData*>(flow->get_flow_data(CipFlowData::inspector_id));
    return fd ? &fd->session : nullptr;
}

static CipSessionData* set_new_cip_session_data(CipProtoConf* config, Packet* p)
{
    CipFlowData* fd = new CipFlowData;
    CipSessionData* css = &fd->session;

    p->flow->set_flow_data(fd);

    /* Only allocate global state data for TCP connections. */
    if (p->has_tcp_data())
    {
        css->global_data.connection_list.list_size = config->max_cip_connections;
        css->global_data.connection_list.list
            = static_cast<CipConnection*>(snort_calloc(config->max_cip_connections,
            sizeof(CipConnection)));

        css->global_data.unconnected_list.list_size = config->max_unconnected_messages;
        css->global_data.unconnected_list.list
            = static_cast<CipUnconnectedMessage*>(snort_calloc(config->max_unconnected_messages,
            sizeof(CipUnconnectedMessage)));
    }

    return &fd->session;
}

static void free_cip_data(void* data)
{
    CipSessionData* css = static_cast<CipSessionData*>(data);

    if ( css->global_data.connection_list.list )
    {
        snort_free(css->global_data.connection_list.list);
        css->global_data.connection_list.list = nullptr;
    }

    if ( css->global_data.unconnected_list.list )
    {
        snort_free(css->global_data.unconnected_list.list);
        css->global_data.unconnected_list.list = nullptr;
    }
}

static CipPacketDirection get_packet_direction(Packet* p)
{
    if (!p->has_tcp_data())
    {
        return CIP_FROM_UNKNOWN;
    }
    if (p->packet_flags & PKT_FROM_CLIENT)
    {
        return CIP_FROM_CLIENT;
    }
    return CIP_FROM_SERVER;
}

static void publish_data_to_appId(Packet* packet, CipCurrentData& current_data)
{
    CipEventData cip_event_data;
    CipEvent cip_event(packet, &cip_event_data);

    bool publish_appid = true;

    // Set one specific matching type for this PDU, in order of priority.
    if (current_data.invalid_fatal)
    {
        cip_event_data.type = CIP_DATA_TYPE_MALFORMED;
    }
    else if (current_data.cip_message_type == CipMessageTypeExplicit)
    {
        if (current_data.cip_msg.is_cip_request)
        {
            /* Just Cip implement this function in parsing.cc  */
            pack_cip_request_event(&current_data.cip_msg.request, &cip_event_data);
        }
        else
        {
            // Do not attempt to set applications for CIP responses.
            publish_appid = false;
        }
    }
    else if (current_data.cip_message_type == CipMessageTypeImplicit)
    {
        cip_event_data.type = CIP_DATA_TYPE_IMPLICIT;
        cip_event_data.class_id = current_data.enip_data.connection_class_id;
    }
    else if (current_data.enip_data.enip_decoded)
    {
        cip_event_data.type = CIP_DATA_TYPE_ENIP_COMMAND;
        cip_event_data.enip_command_id = current_data.enip_data.enip_header.command;
    }
    else
    {
        cip_event_data.type = CIP_DATA_TYPE_OTHER;
    }

    if (publish_appid)
    {
        DataBus::publish(CipEventData::pub_id, CipEventIds::DATA, cip_event, packet->flow);
    }
}

static void log_cip_validity_errors(const CipCurrentData& current_data,
    CipGlobalSessionData& global_data)
{
    if (current_data.invalid_fatal)
    {
        /* what is engine  */
        DetectionEngine::queue_event(GID_CIP, CIP_MALFORMED);
    }
    else if (current_data.enip_data.enip_invalid_nonfatal != 0
        || current_data.cip_msg.request.cip_req_invalid_nonfatal != 0)
    {
        DetectionEngine::queue_event(GID_CIP, CIP_NON_CONFORMING);
    }

    if (global_data.connection_list.connection_pruned)
    {
        DetectionEngine::queue_event(GID_CIP, CIP_CONNECTION_LIMIT);
        global_data.connection_list.connection_pruned = false;
    }

    if (global_data.unconnected_list.request_pruned)
    {
        DetectionEngine::queue_event(GID_CIP, CIP_REQUEST_LIMIT);
        global_data.unconnected_list.request_pruned = false;
    }
}

static void cip_current_data_process(CipSessionData* css, CipCurrentData& current_data,
    CipProtoConf* config, Packet* p)
{
    /* Current Data should be implemented as the same with c files  */
    memset(&current_data, 0, sizeof(CipCurrentData));
    current_data.direction = get_packet_direction(p);

    css->global_data.config = config;
    css->global_data.snort_packet = p;

    /* parse_enip_layer should be implemented specifically  */
    current_data.invalid_fatal = !parse_enip_layer(p->data,
        p->dsize,
        p->has_tcp_data(),
        &current_data,
        &css->global_data);

    if (!current_data.invalid_fatal
        && (p->dsize != current_data.enip_data.enip_header.length + ENIP_HEADER_SIZE))
    {
        current_data.enip_data.enip_invalid_nonfatal |= ENIP_INVALID_PAYLOAD_SIZE;
    }
}

static void snort_cip(CipProtoConf* config, Packet* p)
{
    Profile profile(cip_perf_stats);

    if (p->has_tcp_data() && !p->is_full_pdu())
        return;

    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    CipSessionData* css = get_cip_session_data(p->flow);

    if (css == nullptr)
    {
        css = set_new_cip_session_data(config, p);
    }

    CipCurrentData& current_data = css->current_data;
    cip_current_data_process(css, current_data, config, p);
    publish_data_to_appId(p, current_data);
    log_cip_validity_errors(current_data, css->global_data);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Cip : public Inspector
{
public:
    Cip(CipProtoConf*);
    ~Cip() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;

    class StreamSplitter* get_splitter(bool c2s) override
    { return new CipSplitter(c2s); }

    bool is_control_channel() const override
    { return true; }

private:
    CipProtoConf* config;
};

Cip::Cip(CipProtoConf* pc)
{
    config = pc;
}

Cip::~Cip()
{
    if (config)
    {
        delete config;
    }
}

bool Cip::configure(SnortConfig*)
{
    CipEventData::pub_id = DataBus::get_id(cip_pub_key);
    return true;
}

void Cip::show(const SnortConfig*) const
{
    if (!config)
        return;

    if (config->embedded_cip_enabled)
    {
        std::string cip_path = std::to_string(config->embedded_cip_class_id);
        cip_path += " ";
        cip_path += std::to_string(config->embedded_cip_service_id);
        ConfigLogger::log_value("embedded_cip_path", cip_path.c_str());
    }

    ConfigLogger::log_value("unconnected_timeout", config->unconnected_timeout);
    ConfigLogger::log_value("max_cip_connections", config->max_cip_connections);
    ConfigLogger::log_value("max_unconnected_messages", config->max_unconnected_messages);
}

void Cip::eval(Packet* p)
{
    assert(p->has_tcp_data() || p->has_udp_data());
    assert(p->flow);
    cip_stats.packets++;
    snort_cip(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new CipModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void cip_init()
{
    CipFlowData::init();
}

static Inspector* cip_ctor(Module* m)
{
    CipModule* mod = static_cast<CipModule*>(m);
    return new Cip(mod->get_data());
}

static void cip_dtor(Inspector* p)
{
    delete p;
}

const InspectApi cip_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CIP_NAME,
        CIP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr,  // buffers
    "cip",
    cip_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    cip_ctor,
    cip_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_cip_attribute;
extern const BaseApi* ips_cip_class;
extern const BaseApi* ips_cip_connpathclass;
extern const BaseApi* ips_cip_enipcommand;
extern const BaseApi* ips_cip_enipreq;
extern const BaseApi* ips_cip_eniprsp;
extern const BaseApi* ips_cip_instance;
extern const BaseApi* ips_cip_req;
extern const BaseApi* ips_cip_rsp;
extern const BaseApi* ips_cip_service;
extern const BaseApi* ips_cip_status;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_cip[] =
#endif
{
    &cip_api.base,
    ips_cip_attribute,
    ips_cip_class,
    ips_cip_connpathclass,
    ips_cip_enipcommand,
    ips_cip_enipreq,
    ips_cip_eniprsp,
    ips_cip_instance,
    ips_cip_req,
    ips_cip_rsp,
    ips_cip_service,
    ips_cip_status,
    nullptr
};

