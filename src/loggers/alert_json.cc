//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// alert_json.cc author Russ Combs <rucombs@cisco.com>
//

// preliminary version based on hacking up alert_csv.cc.  should probably
// share a common implementation class.

// if a more sophisticated solution is needed, for example to escape \ or
// whatever, look at this from Joel: https://github.com/jncornett/alert_json,
// which is also more OO implemented.  should pull in that at some point.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
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

static THREAD_LOCAL TextLog* json_log;

#define S_NAME "alert_json"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

struct Args
{
    Packet* pkt;
    const char* msg;
    const Event& event;
    bool comma;
};

static void print_label(Args& a, const char* label)
{
    if ( a.comma )
        TextLog_Print(json_log, ",");

    TextLog_Print(json_log, " \"%s\" : ", label);
}

static bool ff_action(Args& a)
{
    print_label(a, "action");
    TextLog_Quote(json_log, Active::get_action_string());
    return true;
}

static bool ff_class(Args& a)
{
    const char* cls = "none";

    if ( a.event.sig_info->class_type and a.event.sig_info->class_type->name )
        cls = a.event.sig_info->class_type->name;

    print_label(a, "class");
    TextLog_Quote(json_log, cls);
    return true;
}

static bool ff_b64_data(Args& a)
{
    if ( !a.pkt->dsize )
        return false;

    const unsigned block_size = 2048;
    char out[2*block_size];
    const uint8_t* in = a.pkt->data;

    unsigned nin = 0;
    Base64Encoder b64;

    print_label(a, "b64_data");
    TextLog_Putc(json_log, '"');

    while ( nin < a.pkt->dsize )
    {
        unsigned kin = min(a.pkt->dsize-nin, block_size);
        unsigned kout = b64.encode(in+nin, kin, out);
        TextLog_Write(json_log, out, kout);
        nin += kin;
    }

    if ( unsigned kout = b64.finish(out) )
        TextLog_Write(json_log, out, kout);

    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_dir(Args& a)
{
    const char* dir;

    if ( a.pkt->is_from_client() )
        dir = "C2S";
    else if ( a.pkt->is_from_server() )
        dir = "S2C";
    else
        dir = "UNK";

    print_label(a, "dir");
    TextLog_Quote(json_log, dir);
    return true;
}

static bool ff_dst_addr(Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "dst_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_dst_ap(Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.dp;

    print_label(a, "dst_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_dst_port(Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "dst_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.dp);
        return true;
    }
    return false;
}

static bool ff_eth_dst(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_dst");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    return true;
}

static bool ff_eth_len(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_len");
    TextLog_Print(json_log, "%u", a.pkt->pkth->pktlen);
    return true;
}

static bool ff_eth_src(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_src");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);
    return true;
}

static bool ff_eth_type(Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    print_label(a, "eth_type");
    TextLog_Print(json_log, "\"0x%X\"", ntohs(eh->ether_type));
    return true;
}

static bool ff_gid(Args& a)
{
    print_label(a, "gid");
    TextLog_Print(json_log, "%u",  a.event.sig_info->gid);
    return true;
}

static bool ff_icmp_code(Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_code");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->code);
        return true;
    }
    return false;
}

static bool ff_icmp_id(Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_id");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_id));
        return true;
    }
    return false;
}

static bool ff_icmp_seq(Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_seq");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_seq));
        return true;
    }
    return false;
}

static bool ff_icmp_type(Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_type");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->type);
        return true;
    }
    return false;
}

static bool ff_iface(Args& a)
{
    print_label(a, "iface");
    TextLog_Quote(json_log, SFDAQ::get_interface_spec());
    return true;
}

static bool ff_ip_id(Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_id");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.id());
        return true;
    }
    return false;
}

static bool ff_ip_len(Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_len");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.pay_len());
        return true;
    }
    return false;
}

static bool ff_msg(Args& a)
{
    print_label(a, "msg");
    TextLog_Puts(json_log, a.msg);
    return true;
}

static bool ff_mpls(Args& a)
{
    uint32_t mpls;

    if (a.pkt->flow)
        mpls = a.pkt->flow->key->mplsLabel;

    else if ( a.pkt->proto_bits & PROTO_BIT__MPLS )
        mpls = a.pkt->ptrs.mplsHdr.label;

    else
        return false;

    print_label(a, "mpls");
    TextLog_Print(json_log, "%u", ntohl(mpls));
    return true;
}

static bool ff_pkt_gen(Args& a)
{
    print_label(a, "pkt_gen");
    TextLog_Quote(json_log, a.pkt->get_pseudo_type());
    return true;
}

static bool ff_pkt_len(Args& a)
{
    print_label(a, "pkt_len");

    if (a.pkt->has_ip())
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.dgram_len());
    else
        TextLog_Print(json_log, "%u", a.pkt->dsize);

    return true;
}

static bool ff_pkt_num(Args& a)
{
    print_label(a, "pkt_num");
    TextLog_Print(json_log, STDu64, a.pkt->context->packet_number);
    return true;
}

static bool ff_priority(Args& a)
{
    print_label(a, "priority");
    TextLog_Print(json_log, "%u", a.event.sig_info->priority);
    return true;
}

static bool ff_proto(Args& a)
{
    print_label(a, "proto");
    TextLog_Quote(json_log, a.pkt->get_type());
    return true;
}

static bool ff_rev(Args& a)
{
    print_label(a, "rev");
    TextLog_Print(json_log, "%u",  a.event.sig_info->rev);
    return true;
}

static bool ff_rule(Args& a)
{
    print_label(a, "rule");

    TextLog_Print(json_log, "\"%u:%u:%u\"",
        a.event.sig_info->gid, a.event.sig_info->sid, a.event.sig_info->rev);

    return true;
}

static bool ff_seconds(Args& a)
{
    print_label(a, "seconds");
    TextLog_Print(json_log, "%u",  a.pkt->pkth->ts.tv_sec);
    return true;
}

static bool ff_service(Args& a)
{
    const char* svc = "unknown";

    if ( a.pkt->flow and a.pkt->flow->service )
        svc = a.pkt->flow->service;

    print_label(a, "service");
    TextLog_Quote(json_log, svc);
    return true;
}

static bool ff_sid(Args& a)
{
    print_label(a, "sid");
    TextLog_Print(json_log, "%u",  a.event.sig_info->sid);
    return true;
}

static bool ff_src_addr(Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "src_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_src_ap(Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.sp;

    print_label(a, "src_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_src_port(Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "src_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.sp);
        return true;
    }
    return false;
}

static bool ff_target(Args& a)
{
    SfIpString addr = "";

    if ( a.event.sig_info->target == TARGET_SRC )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else if ( a.event.sig_info->target == TARGET_DST )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    else
        return false;

    print_label(a, "target");
    TextLog_Quote(json_log, addr);
    return true;
}

static bool ff_tcp_ack(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_ack");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_ack));
        return true;
    }
    return false;
}

static bool ff_tcp_flags(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        char tcpFlags[9];
        CreateTCPFlagString(a.pkt->ptrs.tcph, tcpFlags);

        print_label(a, "tcp_flags");
        TextLog_Quote(json_log, tcpFlags);
        return true;
    }
    return false;
}

static bool ff_tcp_len(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_len");
        TextLog_Print(json_log, "%u", (a.pkt->ptrs.tcph->off()));
        return true;
    }
    return false;
}

static bool ff_tcp_seq(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_seq");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_seq));
        return true;
    }
    return false;
}

static bool ff_tcp_win(Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_win");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.tcph->th_win));
        return true;
    }
    return false;
}

static bool ff_timestamp(Args& a)
{
    print_label(a, "timestamp");
    TextLog_Putc(json_log, '"');
    LogTimeStamp(json_log, a.pkt);
    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_tos(Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "tos");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.tos());
        return true;
    }
    return false;
}

static bool ff_ttl(Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ttl");
        TextLog_Print(json_log, "%u",a.pkt->ptrs.ip_api.ttl());
        return true;
    }
    return false;
}

static bool ff_udp_len(Args& a)
{
    if (a.pkt->ptrs.udph )
    {
        print_label(a, "udp_len");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
        return true;
    }
    return false;
}

static bool ff_vlan(Args& a)
{
    uint16_t vid;

    if (a.pkt->flow)
        vid = a.pkt->flow->key->vlan_tag;

    else if ( a.pkt->proto_bits & PROTO_BIT__VLAN )
        vid = layer::get_vlan_layer(a.pkt)->vid();

    else
        return false;

    print_label(a, "vlan");
    TextLog_Print(json_log, "%hu", vid);
    return true;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

typedef bool (*JsonFunc)(Args&);

static const JsonFunc json_func[] =
{
    ff_action, ff_class, ff_b64_data, ff_dir, ff_dst_addr, ff_dst_ap,
    ff_dst_port, ff_eth_dst, ff_eth_len, ff_eth_src, ff_eth_type, ff_gid,
    ff_icmp_code, ff_icmp_id, ff_icmp_seq, ff_icmp_type, ff_iface, ff_ip_id,
    ff_ip_len, ff_msg, ff_mpls, ff_pkt_gen, ff_pkt_len, ff_pkt_num, ff_priority,
    ff_proto, ff_rev, ff_rule, ff_seconds, ff_service, ff_sid, ff_src_addr, ff_src_ap,
    ff_src_port, ff_target, ff_tcp_ack, ff_tcp_flags, ff_tcp_len, ff_tcp_seq,
    ff_tcp_win, ff_timestamp, ff_tos, ff_ttl, ff_udp_len, ff_vlan
};

#define json_range \
    "action | class | b64_data | dir | dst_addr | dst_ap | " \
    "dst_port | eth_dst | eth_len | eth_src | eth_type | gid | " \
    "icmp_code | icmp_id | icmp_seq | icmp_type | iface | ip_id | " \
    "ip_len | msg | mpls | pkt_gen | pkt_len | pkt_num | priority | " \
    "proto | rev | rule | seconds | service | sid | src_addr | src_ap | " \
    "src_port | target | tcp_ack | tcp_flags | tcp_len | tcp_seq | " \
    "tcp_win | timestamp | tos | ttl | udp_len | vlan"

#define json_deflt \
    "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action"

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "fields", Parameter::PT_MULTI, json_range, json_deflt,
      "selected fields will be output in given order left to right" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "separator", Parameter::PT_STRING, nullptr, ", ",
      "separate fields with this character sequence" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event in json format"

class JsonModule : public Module
{
public:
    JsonModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file;
    string sep;
    unsigned long limit;
    vector<JsonFunc> fields;
};

bool JsonModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("fields") )
    {
        string tok;
        v.set_first_token();
        fields.clear();

        while ( v.get_next_token(tok) )
            fields.push_back(json_func[Parameter::index(json_range, tok.c_str())]);
    }

    else if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else if ( v.is("separator") )
        sep = v.get_string();

    else
        return false;

    return true;
}

bool JsonModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    sep = ", ";

    if ( fields.empty() )
    {
        Value v(json_deflt);
        string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
            fields.push_back(json_func[Parameter::index(json_range, tok.c_str())]);
    }
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class JsonLogger : public Logger
{
public:
    JsonLogger(JsonModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

public:
    string file;
    unsigned long limit;
    vector<JsonFunc> fields;
    string sep;
};

JsonLogger::JsonLogger(JsonModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    sep = m->sep;
    fields = std::move(m->fields);
}

void JsonLogger::open()
{
    json_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
}

void JsonLogger::close()
{
    if ( json_log )
        TextLog_Term(json_log);
}

void JsonLogger::alert(Packet* p, const char* msg, const Event& event)
{
    Args a = { p, msg, event, false };
    TextLog_Putc(json_log, '{');

    for ( JsonFunc f : fields )
    {
        f(a);
        a.comma = true;
    }

    TextLog_Print(json_log, " }\n");
    TextLog_Flush(json_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new JsonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* json_ctor(SnortConfig*, Module* mod)
{ return new JsonLogger((JsonModule*)mod); }

static void json_dtor(Logger* p)
{ delete p; }

static LogApi json_api
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
    json_ctor,
    json_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_json[] =
#endif
{
    &json_api.base,
    nullptr
};

