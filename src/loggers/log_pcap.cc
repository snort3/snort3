//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include <pcap.h>

#include "framework/logger.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "packet_io/sfdaq.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

/*
 * <pcap file> ::= <pcap file hdr> [<pcap pkt hdr> <packet>]*
 * on 64 bit systems, some fields in the <pcap * hdr> are 8 bytes
 * but still stored on disk as 4 bytes.
 * eg: (sizeof(*pkth) = 24) > (dumped size = 16)
 * so we use PCAP_*_HDR_SZ defines in lieu of sizeof().
 */

#define PCAP_FILE_HDR_SZ (24)
#define PCAP_PKT_HDR_SZ  (16)

struct LtdConfig
{
    string file;
    size_t limit;
};

struct LtdContext
{
    char* file;
    pcap_dumper_t* dumpd;
    time_t lastTime;
    size_t size;
    int log_cnt;
};

static THREAD_LOCAL LtdContext context;

static void TcpdumpRollLogFile(LtdConfig*);

#define S_NAME "log_pcap"
#define F_NAME "log.pcap"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "log packet in pcap format"

class TcpdumpModule : public Module
{
public:
    TcpdumpModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    unsigned long limit;
};

bool TcpdumpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else
        return false;

    return true;
}

bool TcpdumpModule::begin(const char*, int, SnortConfig*)
{
    limit = 0;
    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static inline size_t SizeOf(const DAQ_PktHdr_t* pkth)
{
    return PCAP_PKT_HDR_SZ + pkth->caplen;
}

static void LogTcpdumpSingle(
    LtdConfig* data, Packet* p, const char*, Event*)
{
    size_t dumpSize = SizeOf(p->pkth);

    if ( data->limit && (context.size + dumpSize > data->limit) )
        TcpdumpRollLogFile(data);

    pcap_dump((uint8_t*)context.dumpd, reinterpret_cast<const struct pcap_pkthdr*>(p->pkth), p->pkt);
    context.size += dumpSize;

    if (!SnortConfig::line_buffered_logging())  // FIXIT-L misnomer
    {
        fflush( (FILE*)context.dumpd);
    }
}

static void LogTcpdumpStream(
    LtdConfig*, Packet*, const char*, Event*)
{
// FIXIT-L log reassembled stream data with original packet?
// (take original packet headers and append reassembled data)
}

static void TcpdumpInitLogFile(LtdConfig*, bool no_timestamp)
{
    string file;
    string filename = F_NAME;

    context.lastTime = time(nullptr);
    context.log_cnt = 0;

    if(!no_timestamp)
    {
        char timestamp[16];
        snprintf(timestamp, sizeof(timestamp), ".%lu", context.lastTime);
        filename += timestamp;
    }

    get_instance_file(file, filename.c_str());

    int dlt = SFDAQ::get_base_protocol();

    // convert these flavors of raw to the generic
    // for compatibility with libpcap 1.0.0
    if ( dlt == DLT_IPV4 || dlt == DLT_IPV6 )
        dlt = DLT_RAW;

    pcap_t* pcap;
    pcap = pcap_open_dead(dlt, SFDAQ::get_snap_len());

    if ( !pcap )
        FatalError("%s: can't get pcap context\n", S_NAME);

    context.dumpd = pcap ? pcap_dump_open(pcap, file.c_str()) : nullptr;

    if (context.dumpd == nullptr)
    {
        FatalError("%s: can't open %s: %s\n",
            S_NAME, file.c_str(), pcap_geterr(pcap));
    }
    pcap_close(pcap);

    context.file = snort_strdup(file.c_str());
    context.size = PCAP_FILE_HDR_SZ;
}

static void TcpdumpRollLogFile(LtdConfig* data)
{
    time_t now = time(nullptr);

    /* don't roll over any sooner than resolution
     * of filename discriminator
     */
    if ( now <= context.lastTime )
        return;

    /* close the output file */
    if ( context.dumpd != nullptr )
    {
        pcap_dump_close(context.dumpd);
        context.dumpd = nullptr;
        context.size = 0;
        snort_free(context.file);
        context.file = nullptr;
    }

    /* Have to add stamps now to distinguish files */
    TcpdumpInitLogFile(data, false);
}

static void SpoLogTcpdumpCleanup(LtdConfig*)
{
    /*
     * if we haven't written any data, dump the output file so there aren't
     * fragments all over the disk
     */
    if (context.file && !context.log_cnt)
    {
        int ret = unlink(context.file);

        if ( ret )
            ErrorMessage("Could not remove tcpdump output file %s: %s\n",
                context.file, get_error(errno));

        snort_free(context.file);
        context.file = nullptr;
    }
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class PcapLogger : public Logger
{
public:
    PcapLogger(TcpdumpModule*);
    ~PcapLogger() override;

    void open() override;
    void close() override;
    void reset() override;

    void log(Packet*, const char* msg, Event*) override;

private:
    LtdConfig* config;
};

PcapLogger::PcapLogger(TcpdumpModule* m)
{
    config = new LtdConfig;
    config->limit = m->limit;
}

PcapLogger::~PcapLogger()
{
    delete config;
}

void PcapLogger::open()
{
    TcpdumpInitLogFile(config, SnortConfig::output_no_timestamp());
}

void PcapLogger::close()
{
    SpoLogTcpdumpCleanup(nullptr);

    if ( context.dumpd )
    {
        pcap_dump_close(context.dumpd);
        context.dumpd = nullptr;
    }
    if ( context.file )
        snort_free(context.file);
}

void PcapLogger::log(Packet* p, const char* msg, Event* event)
{
    if(!context.dumpd)
        open();

    context.log_cnt++;
    if (p->packet_flags & PKT_REBUILT_STREAM)
        LogTcpdumpStream(config, p, msg, event);
    else
        LogTcpdumpSingle(config, p, msg, event);
}

void PcapLogger::reset()
{
    if(!context.dumpd)
        open();
    else
        TcpdumpRollLogFile(config);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TcpdumpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* tcpdump_ctor(SnortConfig*, Module* mod)
{ return new PcapLogger((TcpdumpModule*)mod); }

static void tcpdump_dtor(Logger* p)
{ delete p; }

static LogApi tcpdump_api
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
    OUTPUT_TYPE_FLAG__LOG,
    tcpdump_ctor,
    tcpdump_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* log_pcap[] =
#endif
{
    &tcpdump_api.base,
    nullptr
};

