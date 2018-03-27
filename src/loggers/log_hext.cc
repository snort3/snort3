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

// log_hext.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/data_bus.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/text_log.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

#define S_NAME "log_hext"
#define F_NAME S_NAME ".txt"

static const char* s_help = "output payload suitable for daq hext";

static THREAD_LOCAL TextLog* hext_log = nullptr;
static THREAD_LOCAL unsigned s_pkt_num = 0;


class DaqMetaEventHandler : public DataHandler
{
public:
    DaqMetaEventHandler() = default;
    void handle(DataEvent&, Flow*) override;
};

void DaqMetaEventHandler::handle(DataEvent& event, Flow*)
{
    if (!hext_log) return;

    DaqMetaEvent* ev = (DaqMetaEvent*)&event;

    const char* cmd;
    switch (ev->get_type()) {
        case DAQ_METAHDR_TYPE_SOF: cmd = "sof"; break;
        case DAQ_METAHDR_TYPE_EOF: cmd = "eof"; break;
        default: return;
    }

    const Flow_Stats_t* fs = (const Flow_Stats_t*)ev->get_data();

    SfIp src, dst;
    char shost[INET6_ADDRSTRLEN];
    char dhost[INET6_ADDRSTRLEN];

    src.set(fs->initiatorIp);
    dst.set(fs->responderIp);

    src.ntop(shost, sizeof(shost));
    dst.ntop(dhost, sizeof(dhost));

    int vlan_tag = fs->vlan_tag == 0xfff ?  0 : fs->vlan_tag;

    TextLog_Print(hext_log,
        "\n$%s %d %d %d %d %s %d %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
        cmd,
        fs->ingressZone,
        fs->egressZone,
        fs->ingressIntf,
        fs->egressIntf,
        shost, ntohs(fs->initiatorPort),
        dhost, ntohs(fs->responderPort),
        fs->opaque,
        fs->initiatorPkts,
        fs->responderPkts,
        fs->initiatorPktsDropped,
        fs->responderPktsDropped,
        fs->initiatorBytesDropped,
        fs->responderBytesDropped,
        fs->isQoSAppliedOnSrcIntf,
        fs->sof_timestamp.tv_sec,
        fs->eof_timestamp.tv_sec,
        vlan_tag,
        fs->address_space_id,
        fs->protocol);
}


//-------------------------------------------------------------------------
// impl stuff
//-------------------------------------------------------------------------

static void log_raw(const Packet* p)
{
    TextLog_Print(hext_log, "\n# %u [%u]\n",
        s_pkt_num++, p->pkth->caplen);
}

static void log_header(const Packet* p)
{
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    const SfIp* addr = p->ptrs.ip_api.get_src();
    sfip_ntop(addr, src, sizeof(src));

    addr = p->ptrs.ip_api.get_dst();
    sfip_ntop(addr, dst, sizeof(dst));

    TextLog_Print(hext_log, "\n$packet %s %d -> %s %d\n",
        src, p->ptrs.sp, dst, p->ptrs.dp);
}

static void log_data(const uint8_t* p, unsigned n, unsigned width)
{
    string txt;
    unsigned odx = 0, idx = 0;

    TextLog_NewLine(hext_log);

    for ( idx = 0; idx < n; idx++)
    {
        if ( !odx )
            TextLog_Putc(hext_log, 'x');

        uint8_t byte = p[idx];
        TextLog_Print(hext_log, "%2.02X ", byte);
        txt += isprint(byte) ? byte : '.';

        if ( ++odx == width )
        {
            TextLog_Print(hext_log, " # %s\n", txt.c_str());
            txt.clear();
            odx = 0;
        }
    }
    if ( odx )
    {
        while ( odx++ < width )
            TextLog_Print(hext_log, "   ");

        TextLog_Print(hext_log, " # %s\n", txt.c_str());
    }
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "raw", Parameter::PT_BOOL, nullptr, "false",
      "output all full packets if true, else just TCP payload" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "width", Parameter::PT_INT, "0:", "20",
      "set line width (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class HextModule : public Module
{
public:
    HextModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file;
    bool raw;
    unsigned long limit;
    unsigned width;
};

bool HextModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("raw") )
        raw = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else if ( v.is("width") )
        width = v.get_long();

    else
        return false;

    return true;
}

bool HextModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    raw = false;
    limit = 0;
    width = 20;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class HextLogger : public Logger
{
public:
    HextLogger(HextModule*);

    void open() override;
    void close() override;

    void log(Packet*, const char* msg, Event*) override;

private:
    string file;
    unsigned long limit;
    unsigned width;
    bool raw;
};

HextLogger::HextLogger(HextModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    width = m->width;
    raw = m->raw;
    DataBus::subscribe(DAQ_META_EVENT, new DaqMetaEventHandler());
}

void HextLogger::open()
{
    const unsigned buf_sz = 65536;
    hext_log = TextLog_Init(file.c_str(), buf_sz, limit);
}

void HextLogger::close()
{
    if ( hext_log )
        TextLog_Term(hext_log);
}

void HextLogger::log(Packet* p, const char*, Event*)
{
    if ( raw )
    {
        log_raw(p);
        log_data(p->pkt, p->pkth->caplen, width);
    }
    else if ( p->has_tcp_data() )
    {
        log_header(p);
        log_data(p->data, p->dsize, width);
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new HextModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* hext_ctor(SnortConfig*, Module* mod)
{
    return new HextLogger((HextModule*)mod);
}

static void hext_dtor(Logger* p)
{ delete p; }

static const LogApi hext_api =
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
    hext_ctor,
    hext_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* log_hext[] =
#endif
{
    &hext_api.base,
    nullptr
};

