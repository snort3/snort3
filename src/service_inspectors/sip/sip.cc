//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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
// sip.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/sip_events.h"
#include "stream/stream_splitter.h"

#include "sip_module.h"
#include "sip_splitter.h"
#include "sip_utils.h"

using namespace snort;

THREAD_LOCAL ProfileStats sipPerfStats;

static void snort_sip(SIP_PROTO_CONF* GlobalConf, Packet* p);
static void FreeSipData(void*);

unsigned SipFlowData::inspector_id = 0;
unsigned SIPData::pub_id = 0;

bool get_buf_sip(unsigned id, snort::Packet* p, snort::InspectionBuffer& b)
{
    if (id != SIP_HEADER_ID and id != SIP_BODY_ID)
        return false;

    if ((!p->has_tcp_data() and !p->is_udp()) or !p->flow or !p->dsize)
        return false;

    if (p->has_tcp_data() and !p->is_full_pdu())
        return false;

    SIPData* sd = get_sip_session_data(p->flow);
    if (!sd)
        return false;

    const SIP_Roptions& ropts = sd->ropts;
    const uint8_t* data = (id == SIP_HEADER_ID) ? ropts.header_data : ropts.body_data;
    unsigned len = (id == SIP_HEADER_ID) ? ropts.header_len : ropts.body_len;
    if (!data or !len)
        return false;

    b.data = data;
    b.len = len;
    b.is_accumulated = false;
    return true;
}

SipFlowData::SipFlowData() : FlowData(inspector_id)
{
    sip_stats.sessions++;
    sip_stats.concurrent_sessions++;
    if(sip_stats.max_concurrent_sessions < sip_stats.concurrent_sessions)
        sip_stats.max_concurrent_sessions = sip_stats.concurrent_sessions;
}

SipFlowData::~SipFlowData()
{
    FreeSipData(&session);
    assert(sip_stats.concurrent_sessions > 0);
    sip_stats.concurrent_sessions--;
}

static SIPData* SetNewSIPData(Packet* p)
{
    SipFlowData* fd = new SipFlowData;
    p->flow->set_flow_data(fd);
    return &fd->session;
}

SIPData* get_sip_session_data(const Flow* flow)
{
    SipFlowData* fd = (SipFlowData*)flow->get_flow_data(SipFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static void FreeSipData(void* data)
{
    SIPData* ssn = (SIPData*)data;

    /*Free all the dialog data*/
    sip_freeDialogs(&ssn->dialogs);
}

static std::string GetSIPMethods(SIPMethodNode* method)
{
    std::string cmds;

    for (; method; method = method->nextm)
    {
        cmds += method->methodName;
        cmds += " ";
    }

    if ( !cmds.empty() )
        cmds.pop_back();
    else
        cmds += "none";

    return cmds;
}

/*********************************************************************
 * Main entry point for SIP processing.
 *
 * Arguments:
 *  Packet * - pointer to packet structure
 *
 * Returns:
 *  int -   true
 *          false
 *
 *********************************************************************/
static inline int SIP_Process(Packet* p, SIPData* sessp, SIP_PROTO_CONF* config)
{
    bool status;
    const char* sip_buff = (const char*)p->data;
    const char* end;
    SIP_Roptions* pRopts = &(sessp->ropts);
    SIPMsg sipMsg;

    memset(&sipMsg, 0, SIPMSG_ZERO_LEN);

    /*Input parameters*/
    sipMsg.isTcp = p->has_tcp_data();

    end =  sip_buff + p->dsize;

    status = sip_parse(&sipMsg, sip_buff, end, config);

    memset(pRopts, 0, sizeof(*pRopts));
    if (true == status)
    {
        /*Update the dialog state*/
        SIP_updateDialog(sipMsg, &(sessp->dialogs), p, config);
    }
    /*Update the session data*/
    pRopts->method_data = sipMsg.method;
    pRopts->method_len = sipMsg.methodLen;
    pRopts->header_data = sipMsg.header;
    pRopts->header_len = sipMsg.headerLen;
    pRopts->body_len = sipMsg.bodyLen;
    pRopts->body_data = sipMsg.body_data;
    pRopts->status_code = sipMsg.status_code;

    sip_freeMsg(&sipMsg);
    return status;
}

// Main runtime entry point for SIP inspector.

static void snort_sip(SIP_PROTO_CONF* config, Packet* p)
{
    Profile profile(sipPerfStats);  // cppcheck-suppress unreadVariable

    /* Attempt to get a previously allocated SIP block. */
    SIPData* sessp = get_sip_session_data(p->flow);

    if (sessp == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our SIP data-block attached, create one.
         */
        sessp = SetNewSIPData(p);

        if ( !sessp )
            // Could not get/create the session data for this packet.
            return;
    }

    /* Don't process if we've missed packets */
    if (sessp->state_flags & SIP_FLG_MISSED_PACKETS)
        return;

    if (!SIP_Process(p,sessp, config))
        sessp->sip_aborted = true;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Sip : public Inspector
{
public:
    Sip(SIP_PROTO_CONF*);
    ~Sip() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;

    class StreamSplitter* get_splitter(bool to_server) override
    { return new SipSplitter(to_server); }

    bool is_control_channel() const override
    { return true; }

    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override
    { return get_buf_sip(id, p, b); }

private:
    SIP_PROTO_CONF* config;
};

Sip::Sip(SIP_PROTO_CONF* pc)
{
    config = pc;
}

Sip::~Sip()
{
    if ( config )
    {
        SIP_DeleteMethods(config->methods);
        delete config;
    }
}

bool Sip::configure(SnortConfig*)
{
    if ( !SIPData::pub_id )
        SIPData::pub_id = DataBus::get_id(sip_pub_key);

    return true;
}

void Sip::show(const SnortConfig*) const
{
    if ( !config )
        return;

    auto methods = GetSIPMethods(config->methods);

    ConfigLogger::log_flag("ignore_call_channel", config->ignoreChannel);
    ConfigLogger::log_value("max_call_id_len", config->maxCallIdLen);
    ConfigLogger::log_value("max_contact_len", config->maxContactLen);
    ConfigLogger::log_value("max_content_len", config->maxContentLen);
    ConfigLogger::log_value("max_dialogs", config->maxNumDialogsInSession);
    ConfigLogger::log_value("max_from_len", config->maxFromLen);
    ConfigLogger::log_value("max_request_name_len", config->maxRequestNameLen);
    ConfigLogger::log_value("max_to_len", config->maxToLen);
    ConfigLogger::log_value("max_uri_len", config->maxUriLen);
    ConfigLogger::log_value("max_via_len", config->maxViaLen);
    ConfigLogger::log_list("methods", methods.c_str());
    ConfigLogger::log_value("sip_timeout", config->sip_timeout);
    ConfigLogger::log_value("sip_media_timeout", config->sip_media_timeout);
    ConfigLogger::log_value("sip_invite_timeout", config->sip_invite_timeout);
    ConfigLogger::log_value("sip_disconnect_timeout", config->sip_disconnect_timeout);
}

void Sip::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data());
    assert(p->flow);

    sip_stats.packets++;
    snort_sip(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SipModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void sip_init()
{
    SipFlowData::init();
}

static Inspector* sip_ctor(Module* m)
{
    SipModule* mod = (SipModule*)m;
    return new Sip(mod->get_data());
}

static void sip_dtor(Inspector* p)
{
    delete p;
}

static const char* sip_bufs[] =
{
    "sip_header",
    "sip_body",
    nullptr
};

const InspectApi sip_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SIP_NAME,
        SIP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__UDP | PROTO_BIT__PDU,
    sip_bufs,
    "sip",
    sip_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sip_ctor,
    sip_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_sip_header;
extern const BaseApi* ips_sip_body;
extern const BaseApi* ips_sip_method;
extern const BaseApi* ips_sip_stat_code;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_sip[] =
#endif
{
    &sip_api.base,
    ips_sip_header,
    ips_sip_body,
    ips_sip_method,
    ips_sip_stat_code,
    nullptr
};

