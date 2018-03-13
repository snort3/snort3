//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

/* alert_fast
 *
 * Purpose:  output plugin for fast alerting
 *
 * Arguments:  alert file
 *
 * Effect:
 *
 * Alerts are written to a file in the snort fast alert format
 *
 * Comments:   Allows use of fast alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vector>

#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "log/obfuscator.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "packet_io/intf.h"
#include "packet_io/sfdaq.h"
#include "service_inspectors/http_inspect/http_enum.h"

using namespace snort;
using namespace std;

/* full buf was chosen to allow printing max size packets
 * in hex/ascii mode:
 * each byte => 2 nibbles + space + ascii + overhead
 */
#define FULL_BUF (4*IP_MAXPACKET)
#define FAST_BUF (4*K_BYTES)

static THREAD_LOCAL TextLog* fast_log = nullptr;

#define S_NAME "alert_fast"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "packet", Parameter::PT_BOOL, nullptr, "false",
      "output packet dump with alert" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event with brief text format"

class FastModule : public Module
{
public:
    FastModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file;
    unsigned long limit;
    bool packet;
};

bool FastModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("packet") )
        packet = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else
        return false;

    return true;
}

bool FastModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    packet = false;
    return true;
}

//-------------------------------------------------------------------------
// helper

static void load_buf_ids(
    Inspector* ins, std::vector<const char*>& keys, std::vector<unsigned>& ids)
{
    for ( auto key : keys )
    {
        unsigned id = ins->get_buf_id(key);
        assert(id);
        ids.push_back(id);
    }
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class FastLogger : public Logger
{
public:
    FastLogger(FastModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

private:
    string file;
    unsigned long limit;
    bool packet;

    std::vector<unsigned> req_ids;
    std::vector<unsigned> rsp_ids;
};

FastLogger::FastLogger(FastModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    packet = m->packet;

    //-----------------------------------------------------------------
    // FIXIT-L generalize buffer sets when other inspectors get smarter
    // this is only applicable to http_inspect
    // could be configurable; and should be should be shared with u2

    Inspector* ins = InspectorManager::get_inspector("http_inspect");
    
    if ( !ins )
        return;

    std::vector<const char*> req
    { "http_method", "http_version", "http_uri", "http_header", "http_cookie",
      "http_client_body" };

    std::vector<const char*> rsp
    { "http_version", "http_stat_code", "http_stat_msg", "http_uri", "http_header",
      "http_cookie" };
    //-----------------------------------------------------------------

    load_buf_ids(ins, req, req_ids);
    load_buf_ids(ins, rsp, rsp_ids);
}

void FastLogger::open()
{
    unsigned sz = packet ? FULL_BUF : FAST_BUF;
    fast_log = TextLog_Init(file.c_str(), sz, limit);
}

void FastLogger::close()
{
    if ( fast_log )
        TextLog_Term(fast_log);
}

void FastLogger::alert(Packet* p, const char* msg, const Event& event)
{
    LogTimeStamp(fast_log, p);

    if ( Active::get_action() > Active::ACT_PASS )
        TextLog_Print(fast_log, " [%s]", Active::get_action_string());

    TextLog_Puts(fast_log, " [**] ");

    TextLog_Print(fast_log, "[%u:%u:%u] ",
        event.sig_info->gid, event.sig_info->sid, event.sig_info->rev);

    if (SnortConfig::alert_interface())
        TextLog_Print(fast_log, " <%s> ", PRINT_INTERFACE(SFDAQ::get_interface_spec()));

    if ( msg )
        TextLog_Puts(fast_log, msg);

    TextLog_Puts(fast_log, " [**] ");

    // print the packet header to the alert file
    LogPriorityData(fast_log, event);
    LogAppID(fast_log, p);
    TextLog_Print(fast_log, "{%s} ", p->get_type());
    LogIpAddrs(fast_log, p);

    // log packet (p) if this is not an http request with one or more buffers
    // because in that case packet data is also in http_headers or http_client_body
    // only http provides buffers at present; http_raw_status is always
    // available if a response was processed by http_inspect
    bool log_pkt = true;

    if ( packet || SnortConfig::output_app_data() )
    {
        TextLog_NewLine(fast_log);
        Inspector* gadget = p->flow ? p->flow->gadget : nullptr;
        const char** buffers = gadget ? gadget->get_api()->buffers : nullptr;

        if ( buffers )
        {
            InspectionBuffer buf;
            const std::vector<unsigned>& idv = gadget->get_buf(HttpEnums::HTTP_BUFFER_RAW_STATUS,
                p, buf) ? rsp_ids : req_ids;
            bool rsp = (idv == rsp_ids);

            for ( auto id : idv )
            {

                if ( gadget->get_buf(id, p, buf) )
                    LogNetData(fast_log, buf.data, buf.len, p, buffers[id-1]);

                log_pkt = rsp;
            }
        }
        else if ( gadget )
        {
            InspectionBuffer buf;

            if ( gadget->get_buf(InspectionBuffer::IBT_KEY, p, buf) )
                LogNetData(fast_log, buf.data, buf.len, p);

            if ( gadget->get_buf(InspectionBuffer::IBT_HEADER, p, buf) )
                LogNetData(fast_log, buf.data, buf.len, p);

            if ( gadget->get_buf(InspectionBuffer::IBT_BODY, p, buf) )
                LogNetData(fast_log, buf.data, buf.len, p);
        }
        if (p->has_ip())
            LogIPPkt(fast_log, p);

        else if ( log_pkt and p->obfuscator )
        {
            // FIXIT-P avoid string copy
            std::string buf((const char*)p->data, p->dsize);

            for ( const auto& b : *p->obfuscator )
                buf.replace(b.offset, b.length, b.length, p->obfuscator->get_mask_char());

            LogNetData(fast_log, (const uint8_t*)buf.c_str(), p->dsize, p);
        }
        else if ( log_pkt )
            LogNetData(fast_log, p->data, p->dsize, p);

        DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

        if ( buf.len and event.sig_info->gid != 116 )
            LogNetData(fast_log, buf.data, buf.len, p, "alt");
    }
    TextLog_NewLine(fast_log);
    TextLog_Flush(fast_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FastModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* fast_ctor(SnortConfig*, Module* mod)
{ return new FastLogger((FastModule*)mod); }

static void fast_dtor(Logger* p)
{ delete p; }

static LogApi fast_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    fast_ctor,
    fast_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_fast[] =
#endif
{
    &fast_api.base,
    nullptr
};

