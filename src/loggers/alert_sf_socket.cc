//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/* We use some Linux only socket capabilities */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>

#include "detection/treenodes.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "hash/ghash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/event_manager.h"
#include "parser/parser.h"
#include "protocols/packet.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

struct SfSock
{
    int connected;
    int sock;
    struct sockaddr_un addr;
};

struct RuleId
{
    unsigned gid;
    unsigned sid;
};

static THREAD_LOCAL SfSock context;

typedef vector<RuleId> RuleVector;

#define s_name "alert_sfsocket"

//-------------------------------------------------------------------------
// alert_sfsocket module
//-------------------------------------------------------------------------

static const Parameter rule_params[] =
{
    { "gid", Parameter::PT_INT, "1:", "1",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "1:", "1",
      "rule signature ID" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "name of unix socket file" },

    { "rules", Parameter::PT_LIST, rule_params, nullptr,
      "name of unix socket file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event over socket"

class SfSocketModule : public Module
{
public:
    SfSocketModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    string file;
    RuleVector rulez;
    RuleId rule;
};

bool SfSocketModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_string();

    else if ( v.is("gid") )
        rule.gid = v.get_long();

    else if ( v.is("sid") )
        rule.sid = v.get_long();

    return true;
}

bool SfSocketModule::begin(const char*, int, SnortConfig*)
{
    file.erase();
    rule.gid = rule.sid = 1;
    return true;
}

bool SfSocketModule::end(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "alert_sfsocket.rules") )
        rulez.push_back(rule);

    return true;
}

//-------------------------------------------------------------------------
// socket stuff

static int AlertSFSocket_Connect()
{
    /* check sock value */
    if (context.sock == -1)
        FatalError("AlertSFSocket: Invalid socket\n");

    if (connect(context.sock, (sockaddr*)&context.addr, sizeof(context.addr)) == -1)
    {
        if (errno == ECONNREFUSED || errno == ENOENT)
        {
            LogMessage("WARNING: AlertSFSocket: Unable to connect to socket: "
                "%s.\n", get_error(errno));
            return 1;
        }
        else
        {
            FatalError("AlertSFSocket: Unable to connect to socket "
                "(%i): %s\n", errno, get_error(errno));
        }
    }
    return 0;
}

static void sock_init(const char* args)
{
    if ( (context.sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0 )
        FatalError("Unable to create socket: %s\n", get_error(errno));

    std::string name;
    get_instance_file(name, args);

    memset(&context.addr, 0, sizeof(context.addr));
    context.addr.sun_family = AF_UNIX;
    memcpy(context.addr.sun_path + 1, name.c_str(), strlen(name.c_str()));

    if (AlertSFSocket_Connect() == 0)
        context.connected = 1;
}

static void send_sar(uint8_t* data, unsigned len)
{
    int tries = 0;

    do
    {
        tries++;
        /* connect as needed */
        if (!context.connected)
        {
            if (AlertSFSocket_Connect() != 0)
                break;
            context.connected = 1;
        }

        /* send request */
        if (send(context.sock, data, len, 0) == len)
        {
            /* success */
            return;
        }
        /* send failed */
        if (errno == ENOBUFS)
        {
            LogMessage("ERROR: AlertSFSocket: out of buffer space\n");
            break;
        }
        else if (errno == ECONNRESET)
        {
            context.connected = 0;
            LogMessage("WARNING: AlertSFSocket: connection reset, will attempt "
                "to reconnect.\n");
        }
        else if (errno == ECONNREFUSED)
        {
            LogMessage("WARNING: AlertSFSocket: connection refused, "
                "will attempt to reconnect.\n");
            context.connected = 0;
        }
        else if (errno == ENOTCONN)
        {
            LogMessage("WARNING: AlertSFSocket: not connected, "
                "will attempt to reconnect.\n");
            context.connected = 0;
        }
        else
        {
            LogMessage("ERROR: AlertSFSocket: unhandled error '%i' in send(): "
                "%s\n", errno, get_error(errno));
            context.connected = 0;
        }
    }
    while (tries <= 1);
    LogMessage("ERROR: AlertSFSocket: Alert not sent\n");
}

//-------------------------------------------------------------------------
// sig stuff

/* search for an OptTreeNode by sid in specific policy*/
// FIXIT-L wow - OptTreeNode_Search should be encapsulated somewhere ...
// (actually, the whole reason for doing this needs to be rethought)
static OptTreeNode* OptTreeNode_Search(uint32_t, uint32_t sid)
{
    GHashNode* hashNode;

    if (sid == 0)
        return nullptr;

    for (hashNode = ghash_findfirst(SnortConfig::get_conf()->otn_map);
        hashNode;
        hashNode = ghash_findnext(SnortConfig::get_conf()->otn_map))
    {
        OptTreeNode* otn = (OptTreeNode*)hashNode->data;
        RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);

        if ( rtn and is_network_protocol(rtn->snort_protocol_id) )
        {
            if (otn->sigInfo.sid == sid)
                return otn;
        }
    }

    return nullptr;
}

//-------------------------------------------------------------------------
// sar stuff

struct SnortActionRequest
{
    uint32_t event_id;
    uint32_t tv_sec;
    uint32_t gid;
    uint32_t sid;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t sport;
    uint16_t dport;
    IpProtocol ip_proto;
};

static void load_sar(Packet* packet, const Event& event, SnortActionRequest& sar)
{
    if ( !packet || !packet->ptrs.ip_api.is_ip() )
        return;

    // for now, only support ip4
    if ( !packet->ptrs.ip_api.is_ip4() )
        return;

    /* construct the action request */
    sar.event_id = event.event_id;
    sar.tv_sec = packet->pkth->ts.tv_sec;
    sar.gid = event.sig_info->gid;
    sar.sid = event.sig_info->sid;

    // when ip6 is supported:
    // * suggest TLV format where T == family, L is implied by
    //   T (and not sent), and V is just the address octets in
    //   network order
    // * if T is made the 1st octet of struct, bytes to read
    //   can be determined by reading 1 byte
    // * addresses could be moved to end of struct in uint8_t[32]
    //   and only 1st 8 used for ip4
    sar.src_ip =  ntohl(packet->ptrs.ip_api.get_src()->get_ip4_value());
    sar.dest_ip = ntohl(packet->ptrs.ip_api.get_dst()->get_ip4_value());
    sar.ip_proto = packet->get_ip_proto_next();

    if (packet->is_tcp() || packet->is_udp())
    {
        sar.sport = packet->ptrs.sp;
        sar.dport = packet->ptrs.dp;
    }
    else
    {
        sar.sport = 0;
        sar.dport = 0;
    }
}

//-------------------------------------------------------------------------

class SfSocketLogger : public Logger
{
public:
    SfSocketLogger(SfSocketModule*);

    void configure(RuleId&);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

private:
    string file;
};

SfSocketLogger::SfSocketLogger(SfSocketModule* m)
{
    file = m->file;

    for ( auto r : m->rulez )
        configure(r);
}

void SfSocketLogger::configure(RuleId& r)
{
    OptTreeNode* otn = OptTreeNode_Search(r.gid, r.sid);

    if ( !otn )
        ParseError("Unable to find OptTreeNode for %u:%u", r.gid, r.sid);

    else
        EventManager::add_output(&otn->outputFuncs, this);
}

void SfSocketLogger::open()
{
    sock_init(file.c_str());
}

void SfSocketLogger::close()
{
    ::close(context.sock);
    context.sock = -1;
}

void SfSocketLogger::alert(Packet* packet, const char*, const Event& event)
{
    SnortActionRequest sar;
    load_sar(packet, event, sar);
    send_sar((uint8_t*)&sar, sizeof(sar));
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SfSocketModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* sf_sock_ctor(SnortConfig*, Module* mod)
{ return new SfSocketLogger((SfSocketModule*)mod); }

static void sf_sock_dtor(Logger* p)
{ delete p; }

static LogApi sf_sock_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__NONE,
    sf_sock_ctor,
    sf_sock_dtor
};

const BaseApi* alert_sf_socket[] =
{
    &sf_sock_api.base,
    nullptr
};

