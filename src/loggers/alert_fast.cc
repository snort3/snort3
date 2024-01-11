//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mutex>
#include <vector>

#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "log/obfuscator.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "stream/stream_splitter.h"

using namespace snort;
using namespace std;

/* full buf was chosen to allow printing max size packets
 * in hex/ascii mode:
 * each byte => 2 nibbles + space + ascii + overhead
 */
#define FULL_BUF (4*IP_MAXPACKET)
#define FAST_BUF (4*K_BYTES)

static THREAD_LOCAL TextLog* fast_log = nullptr;
static once_flag init_flag;

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

    { "buffers", Parameter::PT_BOOL, nullptr, "false",
      "output IPS buffer dump" },

    { "buffers_depth", Parameter::PT_INT, "0:maxSZ", "0",
      "number of IPS buffer bytes to dump per buffer (0 is unlimited)" },

    { "limit", Parameter::PT_INT, "0:maxSZ", "0",
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
    { return GLOBAL; }

public:
    size_t limit = 0;
    size_t buffers_depth = 0;
    bool file = false;
    bool packet = false;
    bool buffers = false;
};

bool FastModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("packet") )
        packet = v.get_bool();

    else if ( v.is("buffers") )
        buffers = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_size() * 1024 * 1024;

    else if ( v.is("buffers_depth") )
        buffers_depth = v.get_size();

    return true;
}

bool FastModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    packet = false;
    buffers = false;
    buffers_depth = 0;
    return true;
}

//-------------------------------------------------------------------------
// helper
//-------------------------------------------------------------------------

static void load_buf_ids(
    Inspector* ins, const std::vector<const char*>& keys, std::vector<unsigned>& ids)
{
    for ( auto key : keys )
    {
        unsigned id = ins->get_buf_id(key);
        assert(id);
        ids.emplace_back(id);
    }
}

static void ObfuscateLogNetData(TextLog* log, const uint8_t* data, const int len,
    Packet* p, const char* buf_name, const char* buf_key, const char* ins_name)
{
    // FIXIT-P avoid string copy
    std::string buf((const char*)data, len);
    auto obf = p->obfuscator;

    if ( obf and obf->select_buffer(buf_key) )
        for ( const auto& b : *obf )
            buf.replace(b.offset, b.length, b.length, obf->get_mask_char());

    LogNetData(log, (const uint8_t*)buf.c_str(), len, p, buf_name, ins_name);
}

static bool should_dump_buffer(const char* buf_name, const char** buffs_to_dump)
{
    if ( !buf_name )
        return false;

    size_t cmp_idx = 0;

    while ( buffs_to_dump[cmp_idx] )
        if ( !strcmp(buf_name, buffs_to_dump[cmp_idx++]) )
            return true;

    return false;
}

static void log_ips_buffers(Packet* p, const char** buffs_to_dump, unsigned long depth)
{
    if ( !buffs_to_dump or !buffs_to_dump[0] )
        return;

    auto& all_buffs = p->context->matched_buffers;
    std::vector<MatchedBuffer*> to_dump;

    for ( auto& b : all_buffs )
        if ( should_dump_buffer(b.name, buffs_to_dump) and to_dump.cend() ==
            find_if(to_dump.begin(), to_dump.end(), [b](MatchedBuffer*& cmp_b)
            {
                bool same_buffers = cmp_b->name == b.name and cmp_b->data == b.data;
                if ( same_buffers and cmp_b->size < b.size )
                {
                    cmp_b->size = b.size;
                    return true;
                }

                return same_buffers;
            }) )
            to_dump.push_back(&b);

    for ( auto b : to_dump )
    {
        const char* buf_name = b->name;

        if ( !buf_name )
            continue;

        int log_depth = depth && depth < b->size ? depth : b->size;
        ObfuscateLogNetData(fast_log, b->data, log_depth, p, buf_name, buf_name, "detection");
    }
}

using BufferIds = std::vector<unsigned>;

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
    void log_data(Packet*, const Event&);

    static void set_buffer_ids(Inspector*);
    const BufferIds& get_buffer_ids(Inspector*, Packet*);

private:
    string file;
    unsigned long limit;
    unsigned long buffers_depth;
    bool packet;
    bool log_buffers;

    static std::vector<unsigned> req_ids;
    static std::vector<unsigned> rsp_ids;
};

std::vector<unsigned> FastLogger::req_ids;
std::vector<unsigned> FastLogger::rsp_ids;

FastLogger::FastLogger(FastModule* m) : file(m->file ? F_NAME : "stdout"), limit(m->limit),
    buffers_depth(m->buffers_depth), packet(m->packet), log_buffers(m->buffers)
{ }

//-----------------------------------------------------------------
// FIXIT-L generalize buffer sets when other inspectors get smarter
// this is only applicable to http_inspect
// could be configurable; and should be should be shared with u2
//-----------------------------------------------------------------
void FastLogger::set_buffer_ids(Inspector* gadget)
{
    std::vector<const char*> req
    { "http_method", "http_version", "http_uri", "http_header", "http_cookie", "http_client_body" };

    std::vector<const char*> rsp
    { "http_version", "http_stat_code", "http_stat_msg", "http_uri", "http_header", "http_cookie" };

    load_buf_ids(gadget, req, req_ids);
    load_buf_ids(gadget, rsp, rsp_ids);
}

const BufferIds& FastLogger::get_buffer_ids(Inspector* gadget, Packet* p)
{
    // lazy init required because loggers don't have a configure (yet)
    call_once(init_flag, set_buffer_ids, gadget);

    InspectionBuffer buf;
    const std::vector<unsigned>& idv =
            gadget->get_buf(HttpEnums::HTTP_BUFFER_RAW_STATUS, p, buf) ? rsp_ids : req_ids;

    return idv;
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

    if ( p->active->packet_was_dropped() )
        TextLog_Print(fast_log, " [%s]", p->active->get_action_string());

    TextLog_Puts(fast_log, " [**] ");

    TextLog_Print(fast_log, "[%u:%u:%u] ",
        event.sig_info->gid, event.sig_info->sid, event.sig_info->rev);

    if (p->context->conf->alert_interface())
        TextLog_Print(fast_log, " <%s> ", SFDAQ::get_input_spec());

    if ( msg )
        TextLog_Puts(fast_log, msg);

    TextLog_Puts(fast_log, " [**] ");

    // print the packet header to the alert file
    LogPriorityData(fast_log, event);
    LogAppID(fast_log, p);
    TextLog_Print(fast_log, "{%s} ", p->get_type());
    LogIpAddrs(fast_log, p);

    if ( packet || p->context->conf->output_app_data() )
    {
        log_data(p, event);
    }
    TextLog_NewLine(fast_log);
    TextLog_Flush(fast_log);
}

// log packet (p) if this is not an http request with one or more buffers
// because in that case packet data is also in http_headers or http_client_body
// only http provides buffers at present; http_raw_status is always
// available if a response was processed by http_inspect
void FastLogger::log_data(Packet* p, const Event& event)
{
    TextLog_NewLine(fast_log);

    bool log_pkt = true;
    const char* ins_name = "snort";
    Inspector* gadget = nullptr;

    if ( p->flow and p->flow->session )
    {
        snort::StreamSplitter* ss = p->flow->session->get_splitter(p->is_from_client());
        if ( ss and ss->is_paf() )
        {
            gadget = p->flow->gadget;
            if ( gadget )
                ins_name = gadget->get_name();
        }
    }
    const char** buffers = (gadget and !strcmp(ins_name, "http_inspect")) ? gadget->get_api()->buffers : nullptr;

    if ( buffers )
    {
        const BufferIds& idv = get_buffer_ids(gadget, p);

        for ( auto id : idv )
        {
            InspectionBuffer buf;

            if ( gadget->get_buf(id, p, buf) )
                ObfuscateLogNetData(fast_log, buf.data, buf.len, p, buffers[id-1], buffers[id-1], ins_name);

            log_pkt = (idv == rsp_ids);
        }
    }
    else if ( gadget )
    {
        InspectionBuffer buf;

        if ( gadget->get_buf(InspectionBuffer::IBT_KEY, p, buf) )
            LogNetData(fast_log, buf.data, buf.len, p, nullptr, ins_name);

        if ( gadget->get_buf(InspectionBuffer::IBT_HEADER, p, buf) )
            LogNetData(fast_log, buf.data, buf.len, p, nullptr, ins_name);

        if ( gadget->get_buf(InspectionBuffer::IBT_BODY, p, buf) )
            LogNetData(fast_log, buf.data, buf.len, p, nullptr, ins_name);
    }
    if (p->has_ip())
        LogIPPkt(fast_log, p);
    else if ( log_pkt )
        ObfuscateLogNetData(fast_log, p->data, p->dsize, p, nullptr, "pkt_data", ins_name);

    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

    if ( buf.len and event.sig_info->gid != 116 )
        LogNetData(fast_log, buf.data, buf.len, p, "alt");

    if ( log_buffers )
        log_ips_buffers(p, event.buffs_to_dump, buffers_depth);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FastModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* fast_ctor(Module* mod)
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

