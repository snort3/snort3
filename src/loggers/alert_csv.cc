//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// alert_csv.cc author Russ Combs <rucombs@cisco.com>
//
// this a complete rewrite of the work originally done by:
//
//     1998-2002 Martin Roesch <roesch@sourcefire.com>
//     2001-2001 Brian Caswell <bmc@mitre.org>
//     2002-2013 Sourcefire, Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "detection/signature.h"
#include "events/event.h"
#include "flow/flow_key.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/base64_encoder.h"
#include "log/log.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "utils/stats.h"

using namespace snort;
using namespace std;

#define LOG_BUFFER (4*K_BYTES)

static THREAD_LOCAL TextLog* csv_log;

#define S_NAME "alert_csv"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

struct Args
{
    Packet* pkt;
    const char* msg;
    const Event& event;
};

static void ff_action(Args&)
{
    TextLog_Puts(csv_log, Active::get_action_string());
}

static void ff_class(Args& a)
{
    const char* cls = "none";
    if ( a.event.sig_info->class_type and a.event.sig_info->class_type->name )
        cls = a.event.sig_info->class_type->name;
    TextLog_Puts(csv_log, cls);
}

static void ff_b64_data(Args& a)
{
    const unsigned block_size = 2048;
    char out[2*block_size];
    const uint8_t* in = a.pkt->data;

    unsigned nin = 0;
    Base64Encoder b64;

    TextLog_Putc(csv_log, '"');

    while ( nin < a.pkt->dsize )
    {
        unsigned kin = min(a.pkt->dsize-nin, block_size);
        unsigned kout = b64.encode(in+nin, kin, out);
        TextLog_Write(csv_log, out, kout);
        nin += kin;
    }

    if ( unsigned kout = b64.finish(out) )
        TextLog_Write(csv_log, out, kout);

    TextLog_Putc(csv_log, '"');
}

static void ff_dir(Args& a)
{
    const char* dir;

    if ( a.pkt->is_from_client() )
        dir = "C2S";
    else if ( a.pkt->is_from_server() )
        dir = "S2C";
    else
        dir = "UNK";

    TextLog_Puts(csv_log, dir);
}

static void ff_dst_addr(Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        TextLog_Puts(csv_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
    }
}

static void ff_dst_ap(Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.dp;

    TextLog_Print(csv_log, "%s:%u", addr, port);
}

static void ff_dst_port(Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.dp);
}

static void ff_eth_dst(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(csv_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);
}

static void ff_eth_len(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return;

    TextLog_Print(csv_log, "%u", a.pkt->pkth->pktlen);
}

static void ff_eth_src(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(csv_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);
}

static void ff_eth_type(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);
    TextLog_Print(csv_log, "0x%X", ntohs(eh->ether_type));
}

static void ff_gid(Args& a)
{
    TextLog_Print(csv_log, "%u",  a.event.sig_info->gid);
}

static void ff_icmp_code(Args& a)
{
    if (a.pkt->ptrs.icmph )
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.icmph->code);
}

static void ff_icmp_id(Args& a)
{
    if (a.pkt->ptrs.icmph )
        TextLog_Print(csv_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_id));
}

static void ff_icmp_seq(Args& a)
{
    if (a.pkt->ptrs.icmph )
        TextLog_Print(csv_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_seq));
}

static void ff_icmp_type(Args& a)
{
    if (a.pkt->ptrs.icmph )
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.icmph->type);
}

static void ff_iface(Args&)
{
    TextLog_Print(csv_log, "%s", SFDAQ::get_interface_spec());
}

static void ff_ip_id(Args& a)
{
    if (a.pkt->has_ip())
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.ip_api.id());
}

static void ff_ip_len(Args& a)
{
    if (a.pkt->has_ip())
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.ip_api.pay_len());
}

static void ff_msg(Args& a)
{
    TextLog_Puts(csv_log, a.msg);
}

static void ff_mpls(Args& a)
{
    uint32_t mpls;

    if (a.pkt->flow)
        mpls = a.pkt->flow->key->mplsLabel;

    else if ( a.pkt->proto_bits & PROTO_BIT__MPLS )
        mpls = a.pkt->ptrs.mplsHdr.label;

    else
        return;

    TextLog_Print(csv_log, "%u", ntohl(mpls));
}

static void ff_pkt_gen(Args& a)
{
    TextLog_Puts(csv_log, a.pkt->get_pseudo_type());
}

static void ff_pkt_len(Args& a)
{
    if (a.pkt->has_ip())
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.ip_api.dgram_len());
    else
        TextLog_Print(csv_log, "%u", a.pkt->dsize);
}

static void ff_pkt_num(Args& a)
{
    TextLog_Print(csv_log, STDu64, a.pkt->context->packet_number);
}

static void ff_priority(Args& a)
{
    TextLog_Print(csv_log, "%u", a.event.sig_info->priority);
}

static void ff_proto(Args& a)
{
    TextLog_Puts(csv_log, a.pkt->get_type());
}

static void ff_rev(Args& a)
{
    TextLog_Print(csv_log, "%u",  a.event.sig_info->rev);
}

static void ff_rule(Args& a)
{
    TextLog_Print(csv_log, "%u:%u:%u",
        a.event.sig_info->gid, a.event.sig_info->sid, a.event.sig_info->rev);
}

static void ff_seconds(Args& a)
{
    TextLog_Print(csv_log, "%u",  a.pkt->pkth->ts.tv_sec);
}

static void ff_service(Args& a)
{
    const char* svc = "unknown";
    if ( a.pkt->flow and a.pkt->flow->service )
        svc = a.pkt->flow->service;
    TextLog_Puts(csv_log, svc);
}

static void ff_sid(Args& a)
{
    TextLog_Print(csv_log, "%u",  a.event.sig_info->sid);
}

static void ff_src_addr(Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        TextLog_Puts(csv_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
    }
}

static void ff_src_ap(Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.sp;

    TextLog_Print(csv_log, "%s:%u", addr, port);
}

static void ff_src_port(Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.sp);
}

static void ff_target(Args& a)
{
    SfIpString addr = "";

    if ( a.event.sig_info->target == TARGET_SRC )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else if ( a.event.sig_info->target == TARGET_DST )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    else
        return;

    TextLog_Print(csv_log, "%s", addr);
}

static void ff_tcp_ack(Args& a)
{
    if (a.pkt->ptrs.tcph )
        TextLog_Print(csv_log, "0x%lX", (u_long)ntohl(a.pkt->ptrs.tcph->th_ack));
}

static void ff_tcp_flags(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        char tcpFlags[9];
        CreateTCPFlagString(a.pkt->ptrs.tcph, tcpFlags);
        TextLog_Print(csv_log, "%s", tcpFlags);
    }
}

static void ff_tcp_len(Args& a)
{
    if (a.pkt->ptrs.tcph )
        TextLog_Print(csv_log, "%u", (a.pkt->ptrs.tcph->off()));
}

static void ff_tcp_seq(Args& a)
{
    if (a.pkt->ptrs.tcph )
        TextLog_Print(csv_log, "0x%lX", (u_long)ntohl(a.pkt->ptrs.tcph->th_seq));
}

static void ff_tcp_win(Args& a)
{
    if (a.pkt->ptrs.tcph )
        TextLog_Print(csv_log, "0x%X", ntohs(a.pkt->ptrs.tcph->th_win));
}

static void ff_timestamp(Args& a)
{
    LogTimeStamp(csv_log, a.pkt);
}

static void ff_tos(Args& a)
{
    if (a.pkt->has_ip())
        TextLog_Print(csv_log, "%u", a.pkt->ptrs.ip_api.tos());
}

static void ff_ttl(Args& a)
{
    if (a.pkt->has_ip())
        TextLog_Print(csv_log, "%u",a.pkt->ptrs.ip_api.ttl());
}

static void ff_udp_len(Args& a)
{
    if (a.pkt->ptrs.udph )
        TextLog_Print(csv_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
}

static void ff_vlan(Args& a)
{
    uint16_t vid;

    if (a.pkt->flow)
        vid = a.pkt->flow->key->vlan_tag;

    else if ( a.pkt->proto_bits & PROTO_BIT__VLAN )
        vid = layer::get_vlan_layer(a.pkt)->vid();

    else
        return;

    TextLog_Print(csv_log, "%hu", vid);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

typedef void (*CsvFunc)(Args&);

static const CsvFunc csv_func[] =
{
    ff_action, ff_class, ff_b64_data, ff_dir, ff_dst_addr, ff_dst_ap,
    ff_dst_port, ff_eth_dst, ff_eth_len, ff_eth_src, ff_eth_type, ff_gid,
    ff_icmp_code, ff_icmp_id, ff_icmp_seq, ff_icmp_type, ff_iface, ff_ip_id,
    ff_ip_len, ff_msg, ff_mpls, ff_pkt_gen, ff_pkt_len, ff_pkt_num, ff_priority,
    ff_proto, ff_rev, ff_rule, ff_seconds, ff_service, ff_sid, ff_src_addr, ff_src_ap,
    ff_src_port, ff_target, ff_tcp_ack, ff_tcp_flags, ff_tcp_len, ff_tcp_seq,
    ff_tcp_win, ff_timestamp, ff_tos, ff_ttl, ff_udp_len, ff_vlan
};

#define csv_range \
    "action | class | b64_data | dir | dst_addr | dst_ap | " \
    "dst_port | eth_dst | eth_len | eth_src | eth_type | gid | " \
    "icmp_code | icmp_id | icmp_seq | icmp_type | iface | ip_id | " \
    "ip_len | msg | mpls | pkt_gen | pkt_len | pkt_num | priority | " \
    "proto | rev | rule | seconds | service | sid | src_addr | src_ap | " \
    "src_port | target | tcp_ack | tcp_flags | tcp_len | tcp_seq | " \
    "tcp_win | timestamp | tos | ttl | udp_len | vlan"

#define csv_deflt \
    "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action"

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "fields", Parameter::PT_MULTI, csv_range, csv_deflt,
      "selected fields will be output in given order left to right" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "separator", Parameter::PT_STRING, nullptr, ", ",
      "separate fields with this character sequence" },

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

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file;
    string sep;
    unsigned long limit;
    vector<CsvFunc> fields;
};

bool CsvModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("fields") )
    {
        string tok;
        v.set_first_token();
        fields.clear();

        while ( v.get_next_token(tok) )
            fields.push_back(csv_func[Parameter::index(csv_range, tok.c_str())]);
    }

    else if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else if ( v.is("separator") )
        sep = v.get_string();

    else
        return false;

    return true;
}

bool CsvModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    sep = ", ";

    if ( fields.empty() )
    {
        Value v(csv_deflt);
        string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
            fields.push_back(csv_func[Parameter::index(csv_range, tok.c_str())]);
    }
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class CsvLogger : public Logger
{
public:
    CsvLogger(CsvModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

public:
    string file;
    unsigned long limit;
    vector<CsvFunc> fields;
    string sep;
};

CsvLogger::CsvLogger(CsvModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    sep = m->sep;
    fields = std::move(m->fields);
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

void CsvLogger::alert(Packet* p, const char* msg, const Event& event)
{
    Args a = { p, msg, event };
    bool first = true;

    for ( CsvFunc f : fields )
    {
        if ( first )
            first = false;
        else
            // FIXIT-M need to check csv_log for nullptr
            TextLog_Puts(csv_log, sep.c_str());

        f(a);
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
#else
const BaseApi* alert_csv[] =
#endif
{
    &csv_api.base,
    nullptr
};

