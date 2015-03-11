//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2001 Brian Caswell <bmc@mitre.org>
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>

#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "snort.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/eth.h"

#define LOG_BUFFER (4*K_BYTES)

static THREAD_LOCAL TextLog* csv_log;

#define S_NAME "alert_csv"
#define F_NAME S_NAME ".txt"

using namespace std;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

#define csv_range \
    "timestamp | gid | sid | rev | msg | proto | " \
    "src_addr | dst_addr | src_port | dst_port | " \
    "eth_src | eth_dst | eth_type | eth_len | " \
    "ttl | tos | id | ip_len | dgm_len | " \
    "icmp_type | icmp_code | icmp_id | icmp_seq | " \
    "tcp_flags | tcp_seq | tcp_ack | tcp_len | tcp_win | " \
    "udp_len"

#define csv_deflt \
    "timestamp gid sid rev src_addr src_port dst_addr dst_port"

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "csv", Parameter::PT_MULTI, csv_range, csv_deflt,
      "selected fields will be output in given order left to right" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    // FIXIT-M provide PT_UNITS that converts to multiplier automatically
    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "bytes | KB | MB | GB" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event in csv format"

class CsvModule : public Module
{
public:
    CsvModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    bool file;
    string csvargs;
    unsigned long limit;
    unsigned units;
};

bool CsvModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("csv") )
        csvargs = SnortStrdup(v.get_string());

    else if ( v.is("limit") )
        limit = v.get_long();

    else if ( v.is("units") )
        units = v.get_long();

    else
        return false;

    return true;
}

bool CsvModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    units = 0;
    csvargs = csv_deflt;
    return true;
}

bool CsvModule::end(const char*, int, SnortConfig*)
{
    while ( units-- )
        limit *= 1024;

    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class CsvLogger : public Logger
{
public:
    CsvLogger(CsvModule*);
    ~CsvLogger();

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;

public:
    string file;
    unsigned long limit;
    char** args;
    int numargs;
};

CsvLogger::CsvLogger(CsvModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    args = mSplit(m->csvargs.c_str(), " \n\t", 0, &numargs, 0);
}

CsvLogger::~CsvLogger()
{
    mSplitFree(&args, numargs);
}

void CsvLogger::open()
{
    csv_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
}

void CsvLogger::close()
{
    if ( csv_log )
        TextLog_Term(csv_log);
}

void CsvLogger::alert(Packet* p, const char* msg, Event* event)
{
    int num;
    char* type;
    char tcpFlags[9];
    const eth::EtherHdr* eh = nullptr;

    assert(p);

    if (p->proto_bits & PROTO_BIT__ETH)
        eh = layer::get_eth_layer(p);

    // TBD an enum would be an improvement here
    for (num = 0; num < numargs; num++)
    {
        type = args[num];

        if (!strcasecmp("timestamp", type))
        {
            LogTimeStamp(csv_log, p);
        }
        else if (!strcasecmp("gid", type))
        {
            if (event != NULL)
                TextLog_Print(csv_log, "%lu",  (unsigned long)event->sig_info->generator);
        }
        else if (!strcasecmp("sid", type))
        {
            if (event != NULL)
                TextLog_Print(csv_log, "%lu",  (unsigned long)event->sig_info->id);
        }
        else if (!strcasecmp("rev", type))
        {
            if (event != NULL)
                TextLog_Print(csv_log, "%lu",  (unsigned long)event->sig_info->rev);
        }
        else if (!strcasecmp("msg", type))
        {
            TextLog_Quote(csv_log, msg);  /* Don't fatal */
        }
        else if (!strcasecmp("proto", type))
        {
            // api returns zero if invalid
            switch (p->type())
            {
            case PktType::UDP:
                TextLog_Puts(csv_log, "UDP");
                break;
            case PktType::TCP:
                TextLog_Puts(csv_log, "TCP");
                break;
            case PktType::ICMP:
                TextLog_Puts(csv_log, "ICMP");
                break;
            default:
                break;
            }
        }
        else if (!strcasecmp("eth_src", type))
        {
            if (eh)
            {
                TextLog_Print(csv_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_src[0],
                    eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
                    eh->ether_src[4], eh->ether_src[5]);
            }
        }
        else if (!strcasecmp("eth_dst", type))
        {
            if (eh)
            {
                TextLog_Print(csv_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
                    eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
                    eh->ether_dst[4], eh->ether_dst[5]);
            }
        }
        else if (!strcasecmp("eth_type", type))
        {
            if (eh != NULL)
                TextLog_Print(csv_log, "0x%X", ntohs(eh->ether_type));
        }
        else if (!strcasecmp("eth_len", type))
        {
            if (eh != NULL)
                TextLog_Print(csv_log, "0x%X", p->pkth->pktlen);
        }
        else if (!strcasecmp("udp_len", type))
        {
            if (p->ptrs.udph != NULL)
                TextLog_Print(csv_log, "%d", ntohs(p->ptrs.udph->uh_len));
        }
        else if (!strcasecmp("src_port", type))
        {
            // api return 0 if invalid
            switch (p->type())
            {
            case PktType::UDP:
            case PktType::TCP:
                TextLog_Print(csv_log, "%d", p->ptrs.sp);
                break;
            default:
                break;
            }
        }
        else if (!strcasecmp("dst_port", type))
        {
            switch (p->type())
            {
            case PktType::UDP:
            case PktType::TCP:
                TextLog_Print(csv_log, "%d", p->ptrs.dp);
                break;
            default:
                break;
            }
        }
        else if (!strcasecmp("src_addr", type))
        {
            if (p->has_ip())
                TextLog_Puts(csv_log, inet_ntoa(p->ptrs.ip_api.get_src()));
        }
        else if (!strcasecmp("dst_addr", type))
        {
            if (p->has_ip())
                TextLog_Puts(csv_log, inet_ntoa(p->ptrs.ip_api.get_dst()));
        }
        else if (!strcasecmp("icmp_type", type))
        {
            if (p->ptrs.icmph != NULL)
                TextLog_Print(csv_log, "%d", p->ptrs.icmph->type);
        }
        else if (!strcasecmp("icmp_code", type))
        {
            if (p->ptrs.icmph != NULL)
                TextLog_Print(csv_log, "%d", p->ptrs.icmph->code);
        }
        else if (!strcasecmp("icmp_id", type))
        {
            if (p->ptrs.icmph != NULL)
                TextLog_Print(csv_log, "%d", ntohs(p->ptrs.icmph->s_icmp_id));
        }
        else if (!strcasecmp("icmp_seq", type))
        {
            if (p->ptrs.icmph != NULL)
                TextLog_Print(csv_log, "%d", ntohs(p->ptrs.icmph->s_icmp_seq));
        }
        else if (!strcasecmp("ttl", type))
        {
            if (p->has_ip())
                TextLog_Print(csv_log, "%d",p->ptrs.ip_api.ttl());
        }
        else if (!strcasecmp("tos", type))
        {
            if (p->has_ip())
                TextLog_Print(csv_log, "%d", p->ptrs.ip_api.tos());
        }
        else if (!strcasecmp("id", type))
        {
            if (p->has_ip())
                TextLog_Print(csv_log, "%u", p->ptrs.ip_api.id());
        }
        else if (!strcasecmp("ip_len", type))
        {
            if (p->has_ip())
                TextLog_Print(csv_log, "%d", p->ptrs.ip_api.pay_len());
        }
        else if (!strcasecmp("dgm_len", type))
        {
            if (p->has_ip())
            {
                // XXX might cause a bug when IPv6 is printed?
                TextLog_Print(csv_log, "%d", p->ptrs.ip_api.dgram_len());
            }
        }
        else if (!strcasecmp("tcp_seq", type))
        {
            if (p->ptrs.tcph != NULL)
                TextLog_Print(csv_log, "0x%lX", (u_long)ntohl(p->ptrs.tcph->th_seq));
        }
        else if (!strcasecmp("tcp_ack", type))
        {
            if (p->ptrs.tcph != NULL)
                TextLog_Print(csv_log, "0x%lX", (u_long)ntohl(p->ptrs.tcph->th_ack));
        }
        else if (!strcasecmp("tcp_len", type))
        {
            if (p->ptrs.tcph != NULL)
                TextLog_Print(csv_log, "%d", (p->ptrs.tcph->off()));
        }
        else if (!strcasecmp("tcp_win", type))
        {
            if (p->ptrs.tcph != NULL)
                TextLog_Print(csv_log, "0x%X", ntohs(p->ptrs.tcph->th_win));
        }
        else if (!strcasecmp("tcp_flags",type))
        {
            if (p->ptrs.tcph != NULL)
            {
                CreateTCPFlagString(p->ptrs.tcph, tcpFlags);
                TextLog_Print(csv_log, "%s", tcpFlags);
            }
        }

        if (num < numargs - 1)
            TextLog_Putc(csv_log, ',');
    }

    TextLog_NewLine(csv_log);
    TextLog_Flush(csv_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CsvModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* csv_ctor(SnortConfig*, Module* mod)
{ return new CsvLogger((CsvModule*)mod); }

static void csv_dtor(Logger* p)
{ delete p; }

static LogApi csv_api
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
    csv_ctor,
    csv_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &csv_api.base,
    nullptr
};
#else
const BaseApi* alert_csv = &csv_api.base;
#endif

