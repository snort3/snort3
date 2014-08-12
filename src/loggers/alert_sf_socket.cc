/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2003-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* We use some Linux only socket capabilities */

#include <errno.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <sys/un.h>

#include <string>

#include "snort_types.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "managers/event_manager.h"
#include "detection/generators.h"

#include "event.h"
#include "rules.h"
#include "treenodes.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "parser.h"

struct SfSock
{
    int connected;
    int sock;
    struct sockaddr_un addr;
};

static THREAD_LOCAL SfSock context;

using namespace std;

//-------------------------------------------------------------------------
// alert_sfsocket module
//-------------------------------------------------------------------------

// FIXIT this file will probably fail to compile on Linux

static const Parameter sfsocket_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "name of unix socket file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SfSocketModule : public Module
{
public:
    SfSocketModule() : Module("alert_sfsocket", sfsocket_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

public:
    string file;
};

bool SfSocketModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_string();

    else
        return false;

    return true;
}

bool SfSocketModule::begin(const char*, int, SnortConfig*)
{
    file.erase();
    return true;
}

//-------------------------------------------------------------------------
// parsing stuff

int String2ULong(char *string, unsigned long *result)
{
    unsigned long value;
    char *endptr;
    if(!string)
        return -1;

    value = strtoul(string, &endptr, 10);
    if(*endptr != '\0')
        return -1;

    *result = value;

    return 0;
}

/*
 * Parse 'sidValue' or 'gidValue:sidValue'
 */
int GidSid2UInt(char * args, uint32_t * sidValue, uint32_t * gidValue)
{
    char gbuff[80];
    char sbuff[80];
    int  i;
    unsigned long glong,slong;

    *gidValue=GENERATOR_SNORT_ENGINE;
    *sidValue=0;

    i=0;
    while( args && *args && (i < 20) )
    {
        sbuff[i]=*args;
        if( sbuff[i]==':' ) break;
        args++;
        i++;
    }
    sbuff[i]=0;

    if( i >= 20 )
    {
       return -1;
    }

    if( *args == ':' )
    {
        memcpy(gbuff,sbuff,i);
        gbuff[i]=0;

        if(String2ULong(gbuff,&glong))
        {
            return -1;
        }
        *gidValue = (uint32_t)glong;

        args++;
        i=0;
        while( args && *args && i < 20 )
        {
          sbuff[i]=*args;
          args++;
          i++;
        }
        sbuff[i]=0;

        if( i >= 20 )
        {
          return -1;
        }

        if(String2ULong(sbuff,&slong))
        {
            return -1;
        }
        *sidValue = (uint32_t)slong;
    }
    else
    {
        if(String2ULong(sbuff,&slong))
        {
            return -1;
        }
        *sidValue=(uint32_t)slong;
    }

    return 0;
}

//-------------------------------------------------------------------------
// socket stuff

static int AlertSFSocket_Connect(void)
{
    /* check sock value */
    if(context.sock == -1)
        FatalError("AlertSFSocket: Invalid socket\n");

    if(connect(context.sock, (sockaddr*)&context.addr, sizeof(context.addr)) == -1)
    {
        if(errno == ECONNREFUSED || errno == ENOENT)
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

static void sock_init(const char *args)
{
    if ( (context.sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0 )
        FatalError("Unable to create socket: %s\n", get_error(errno));

    std::string name;
    get_instance_file(name, args);

    memset(&context.addr, 0, sizeof(context.addr));
    context.addr.sun_family = AF_UNIX;
    memcpy(context.addr.sun_path + 1, name.c_str(), strlen(name.c_str()));

    if(AlertSFSocket_Connect() == 0)
        context.connected = 1;
}

void send_sar(uint8_t* data, unsigned len)
{
    int tries = 0;

    do
    {
        tries++;
        /* connect as needed */
        if(!context.connected)
        {
            if(AlertSFSocket_Connect() != 0)
                break;
            context.connected = 1;
        }

        /* send request */
        if(send(context.sock, data, len, 0) == len)
        {
            /* success */
            return;
        }
        /* send failed */
        if(errno == ENOBUFS)
        {
            LogMessage("ERROR: AlertSFSocket: out of buffer space\n");
            break;
        }
        else if(errno == ECONNRESET)
        {
            context.connected = 0;
            LogMessage("WARNING: AlertSFSocket: connection reset, will attempt "
                    "to reconnect.\n");
        }
        else if(errno == ECONNREFUSED)
        {
            LogMessage("WARNING: AlertSFSocket: connection refused, "
                    "will attempt to reconnect.\n");
            context.connected = 0;
        }
        else if(errno == ENOTCONN)
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
    } while(tries <= 1);
    LogMessage("ERROR: AlertSFSocket: Alert not sent\n");
    return;
}

//-------------------------------------------------------------------------
// sig stuff

/* search for an OptTreeNode by sid in specific policy*/
static OptTreeNode *OptTreeNode_Search(uint32_t, uint32_t sid)
{
    SFGHASH_NODE *hashNode;
    OptTreeNode *otn = NULL;
    RuleTreeNode *rtn = NULL;

    if(sid == 0)
        return NULL;

    // FIXIT wow - this should be encapsulated somewhere ...
    for (hashNode = sfghash_findfirst(snort_conf->otn_map);
            hashNode;
            hashNode = sfghash_findnext(snort_conf->otn_map))
    {
        otn = (OptTreeNode *)hashNode->data;
        rtn = getRuntimeRtnFromOtn(otn);
        if (rtn)
        {
            if ((rtn->proto == IPPROTO_TCP) || (rtn->proto == IPPROTO_UDP)
                    || (rtn->proto == IPPROTO_ICMP) || (rtn->proto == ETHERNET_TYPE_IP))
            {
                if (otn->sigInfo.id == sid)
                {
                    return otn;
                }
            }
        }
    }

    return NULL;
}

//-------------------------------------------------------------------------
// sar stuff

typedef struct _SnortActionRequest
{
    uint32_t event_id;
    uint32_t tv_sec;
    uint32_t generator;
    uint32_t sid;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t sport;
    uint16_t dport;
    uint8_t  protocol;
} SnortActionRequest;

void load_sar(Packet *packet, Event *event, SnortActionRequest& sar)

{
    if(!event || !packet || !packet->ip_api.is_valid())
        return;

    // for now, only support ip4
    if ( !packet->ip_api.is_ip4() )
        return;

    /* construct the action request */
    sar.event_id = event->event_id;
    sar.tv_sec = packet->pkth->ts.tv_sec;
    sar.generator = event->sig_info->generator;
    sar.sid = event->sig_info->id;

    // when ip6 is supported:
    // * suggest TLV format where T == family, L is implied by
    //   T (and not sent), and V is just the address octets in
    //   network order
    // * if T is made the 1st octet of struct, bytes to read
    //   can be determined by reading 1 byte
    // * addresses could be moved to end of struct in uint8_t[32]
    //   and only 1st 8 used for ip4
    sar.src_ip =  ntohl(packet->ip_api.get_src()->ip32[0]);
    sar.dest_ip = ntohl(packet->ip_api.get_dst()->ip32[0]);
    sar.protocol = packet->ip_api.proto();

    if(sar.protocol == IPPROTO_UDP || sar.protocol == IPPROTO_TCP)
    {
        sar.sport = packet->sp;
        sar.dport = packet->dp;
    }
    else
    {
        sar.sport = 0;
        sar.dport = 0;
    }
}

//-------------------------------------------------------------------------

class SfSocketLogger : public Logger {
public:
    SfSocketLogger(SfSocketModule*);

    void configure(SnortConfig*, char*);

    void open();
    void close();

    void alert(Packet*, const char* msg, Event*);

private:
    string file;
};

SfSocketLogger::SfSocketLogger(SfSocketModule* m)
{
    file = m->file;
}

void SfSocketLogger::configure(SnortConfig*, char *args)
{
    uint32_t gid, sid;

    if ( GidSid2UInt((char*)args, &sid, &gid) )
        FatalError("Invalid argument '%s' to alert_sf_socket_sid\n", args);

    OptTreeNode* otn = OptTreeNode_Search(gid,sid);

    if ( !otn )
        LogMessage("Unable to find OptTreeNode for SID %u\n", sid);

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

void SfSocketLogger::alert(Packet *packet, const char*, Event *event)
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
        "alert_sfsocket",
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__NONE,
    sf_sock_ctor,
    sf_sock_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sf_sock_api.base,
    nullptr
};
#else
const BaseApi* alert_sf_socket = &sf_sock_api.base;
#endif

#endif   /* LINUX */

