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
// sip.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream_splitter.h"

#include "sip_module.h"
#include "sip_splitter.h"
#include "sip_utils.h"

using namespace snort;

THREAD_LOCAL ProfileStats sipPerfStats;

static void snort_sip(SIP_PROTO_CONF* GlobalConf, Packet* p);
static void FreeSipData(void*);

unsigned SipFlowData::inspector_id = 0;

SipFlowData::SipFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
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

static void PrintSipConf(SIP_PROTO_CONF* config)
{
    SIPMethodNode* method;
    if (config == nullptr)
        return;
    LogMessage("SIP config: \n");
    LogMessage("    Max number of dialogs in a session: %d %s \n",
        config->maxNumDialogsInSession,
        config->maxNumDialogsInSession
        == SIP_DEFAULT_MAX_DIALOGS_IN_SESSION ?
        "(Default)" : "");

    LogMessage("    Ignore media channel: %s\n",
        config->ignoreChannel ?
        "ENABLED" : "DISABLED");
    LogMessage("    Max URI length: %d %s \n",
        config->maxUriLen,
        config->maxUriLen
        == SIP_DEFAULT_MAX_URI_LEN ?
        "(Default)" : "");
    LogMessage("    Max Call ID length: %d %s \n",
        config->maxCallIdLen,
        config->maxCallIdLen
        == SIP_DEFAULT_MAX_CALL_ID_LEN ?
        "(Default)" : "");
    LogMessage("    Max Request name length: %d %s \n",
        config->maxRequestNameLen,
        config->maxRequestNameLen
        == SIP_DEFAULT_MAX_REQUEST_NAME_LEN ?
        "(Default)" : "");
    LogMessage("    Max From length: %d %s \n",
        config->maxFromLen,
        config->maxFromLen
        == SIP_DEFAULT_MAX_FROM_LEN ?
        "(Default)" : "");
    LogMessage("    Max To length: %d %s \n",
        config->maxToLen,
        config->maxToLen
        == SIP_DEFAULT_MAX_TO_LEN ?
        "(Default)" : "");
    LogMessage("    Max Via length: %d %s \n",
        config->maxViaLen,
        config->maxViaLen
        == SIP_DEFAULT_MAX_VIA_LEN ?
        "(Default)" : "");
    LogMessage("    Max Contact length: %d %s \n",
        config->maxContactLen,
        config->maxContactLen
        == SIP_DEFAULT_MAX_CONTACT_LEN ?
        "(Default)" : "");
    LogMessage("    Max Content length: %d %s \n",
        config->maxContentLen,
        config->maxContentLen
        == SIP_DEFAULT_MAX_CONTENT_LEN ?
        "(Default)" : "");
    LogMessage("\n");
    LogMessage("    Methods:\n");
    LogMessage("\t%s ",
        config->methodsConfig
        == SIP_METHOD_DEFAULT ?
        "(Default)" : "");
    method = config->methods;
    while (nullptr != method)
    {
        LogMessage(" %s", method->methodName);
        method = method->nextm;
    }

    LogMessage("\n");
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
    SIP_Roptions* pRopts;
    SIPMsg sipMsg;

    memset(&sipMsg, 0, SIPMSG_ZERO_LEN);

    /*Input parameters*/
    sipMsg.isTcp = p->has_tcp_data();

    end =  sip_buff + p->dsize;

    status = sip_parse(&sipMsg, sip_buff, end, config);

    if (true == status)
    {
        /*Update the dialog state*/
        SIP_updateDialog(&sipMsg, &(sessp->dialogs), p, config);
    }
    /*Update the session data*/
    pRopts = &(sessp->ropts);
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

/* Main runtime entry point for SIP preprocessor.
 * Analyzes SIP packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_sip(SIP_PROTO_CONF* config, Packet* p)
{
    Profile profile(sipPerfStats);

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

    SIP_Process(p,sessp, config);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Sip : public Inspector
{
public:
    Sip(SIP_PROTO_CONF*);
    ~Sip() override;

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;

    class StreamSplitter* get_splitter(bool to_server) override
    { return new SipSplitter(to_server); }

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

void Sip::show(SnortConfig*)
{
    PrintSipConf(config);
}

void Sip::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data());
    assert(p->flow);

    sip_stats.packets++;
    snort_sip(config, p);
}

bool Sip::get_buf(
    InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    SIPData* sd;
    SIP_Roptions* ropts;
    const uint8_t* data = nullptr;
    unsigned len = 0;

    sd = get_sip_session_data(p->flow);
    if (!sd)
        return false;

    ropts = &sd->ropts;

    switch ( ibt )
    {
    case InspectionBuffer::IBT_HEADER:
        data = ropts->header_data;
        len = ropts->header_len;
        break;

    case InspectionBuffer::IBT_BODY:
        data = ropts->body_data;
        len = ropts->body_len;
        break;

    default:
        break;
    }

    if (!len)
        return false;

    assert(data);

    b.data = data;
    b.len = len;

    return true;
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
    nullptr, // buffers
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

