//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_rpc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rpc.h"

#include <netdb.h>
#include <sstream>
#include <string>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(USE_TIRPC)
#include <rpc/rpc.h>
#elif defined(__sun)
#include <rpc/rpcent.h>
#endif

#include "detection/ips_context.h"
#include "log/messages.h"
#include "protocols/packet.h"

#include "appid_inspector.h"
#include "app_info_table.h"

using namespace snort;
using namespace std;

enum RPCState
{
    RPC_STATE_CALL,
    RPC_STATE_REPLY,
    RPC_STATE_DONE
};

enum RPCTCPState
{
    RPC_TCP_STATE_FRAG,
    RPC_TCP_STATE_HEADER,
    RPC_TCP_STATE_CRED,
    RPC_TCP_STATE_CRED_DATA,
    RPC_TCP_STATE_VERIFY,
    RPC_TCP_STATE_VERIFY_DATA,
    RPC_TCP_STATE_REPLY_HEADER,
    RPC_TCP_STATE_PARTIAL,
    RPC_TCP_STATE_DONE
};

enum RPCReplyState
{
    RPC_REPLY_BEGIN,
    RPC_REPLY_MULTI,
    RPC_REPLY_MID
};

#define min(x,y) ((x)<(y) ? (x) : (y))

#define RPC_TYPE_CALL  0
#define RPC_TYPE_REPLY 1

#define RPC_PROGRAM_PORTMAP     100000
#define RPC_PORTMAP_GETPORT     3

#define RPC_BIND_PORTMAP_GETADDR 3

#define RPC_REPLY_ACCEPTED 0
#define RPC_REPLY_DENIED   1

#define RPC_MAX_ACCEPTED 4
#define RPC_MAX_DENIED   5

#define RPC_TCP_FRAG_MASK   0x80000000

/* sizeof(ServiceRPCCall)+sizeof(_SERVICE_RPC_PORTMAP)==56 */
#define RPC_MAX_TCP_PACKET_SIZE  56

#define PROGRAM_LENGTH 4
#define VERSION_LENGTH 4

#define RPCB_UNIVERSAL_ADDR_LENGTH 6

#pragma pack(1)

struct ServiceRPCFragment
{
    uint32_t length;
};

struct ServiceRPCAuth
{
    uint32_t flavor;
    uint32_t length;
};

struct ServiceRPCPortmap
{
    uint32_t program;
    uint32_t version;
    uint32_t proto;
    uint32_t port;
};

struct ServiceRPCPortmapReply
{
    uint32_t port;
};

struct NetId
{
    uint32_t length;
    // protocol string follows
};

struct UniversalAddress
{
    uint32_t length;
    // universal address follows
};

struct ServiceRPC
{
    uint32_t xid;
    uint32_t type;
};

struct ServiceRPCCall
{
    ServiceRPC header;
    uint32_t version;
    uint32_t program;
    uint32_t program_version;
    uint32_t procedure;
    ServiceRPCAuth cred;
    ServiceRPCAuth verify;
};

struct ServiceRPCReply
{
    ServiceRPC header;
    uint32_t reply_state;
    ServiceRPCAuth verify;
    uint32_t state;
};

#pragma pack()

struct ServiceRPCData
{
    RPCState state;
    RPCTCPState tcpstate[APP_ID_APPID_SESSION_DIRECTION_MAX];
    RPCTCPState tcpfragstate[APP_ID_APPID_SESSION_DIRECTION_MAX];
    uint32_t program;
    uint32_t program_version;
    uint32_t procedure;
    uint32_t xid;
    IpProtocol proto;
    uint32_t tcpsize[APP_ID_APPID_SESSION_DIRECTION_MAX];
    uint32_t tcpfragpos[APP_ID_APPID_SESSION_DIRECTION_MAX];
    uint32_t tcpauthsize[APP_ID_APPID_SESSION_DIRECTION_MAX];
    uint32_t tcppos[APP_ID_APPID_SESSION_DIRECTION_MAX];
    uint8_t tcpdata[APP_ID_APPID_SESSION_DIRECTION_MAX][RPC_MAX_TCP_PACKET_SIZE];
    int once;
};

#define RPC_PORT_PORTMAPPER 111
#define RPC_PORT_NFS        2049
#define RPC_PORT_MOUNTD     4046
#define RPC_PORT_NLOCKMGR   4045

struct RPCProgram
{
    RPCProgram* next;
    uint32_t program;
    char* name;
};

static THREAD_LOCAL RPCProgram* rpc_programs;

static uint8_t rpc_reply_accepted_pattern[8] = { 0,0,0,1,0,0,0,0 };
static uint8_t rpc_reply_denied_pattern[8] = { 0,0,0,1,0,0,0,1 };

RpcServiceDetector::RpcServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rpc";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    struct rpcent* rpc;
    RPCProgram* prog;

    if (!rpc_programs)
    {
        while ((rpc = getrpcent()))
        {
            if (rpc->r_name)
            {
                // FIXIT-RC - the memory allocated here may not be freed...
                prog = (RPCProgram*)snort_calloc(sizeof(RPCProgram));
                prog->program = rpc->r_number;
                prog->next = rpc_programs;
                rpc_programs = prog;
                prog->name = snort_strdup(rpc->r_name);
            }
        }
        endrpcent();
    }

    tcp_patterns =
    {
        { rpc_reply_accepted_pattern, sizeof(rpc_reply_accepted_pattern), 8, 0, 0 },
        { rpc_reply_denied_pattern, sizeof(rpc_reply_denied_pattern), 8, 0, 0 }
    };

    udp_patterns =
    {
        { rpc_reply_accepted_pattern, sizeof(rpc_reply_accepted_pattern), 4, 0, 0 },
        { rpc_reply_denied_pattern, sizeof(rpc_reply_denied_pattern), 4, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_SUN_RPC, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED }
    };

    service_ports =
    {
        { RPC_PORT_PORTMAPPER, IpProtocol::UDP, false },
        { RPC_PORT_PORTMAPPER, IpProtocol::UDP, true },
        { RPC_PORT_PORTMAPPER, IpProtocol::TCP, false },
        { RPC_PORT_NFS, IpProtocol::UDP, false },
        { RPC_PORT_NFS, IpProtocol::UDP, true },
        { RPC_PORT_NFS, IpProtocol::TCP, false },
        { RPC_PORT_MOUNTD, IpProtocol::UDP, false },
        { RPC_PORT_MOUNTD, IpProtocol::UDP, true },
        { RPC_PORT_MOUNTD, IpProtocol::TCP, false },
        { RPC_PORT_NLOCKMGR, IpProtocol::UDP, false },
        { RPC_PORT_NLOCKMGR, IpProtocol::UDP, true },
        { RPC_PORT_NLOCKMGR, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}

RpcServiceDetector::~RpcServiceDetector()
{
    RPCProgram* rpc = rpc_programs;

    while ( rpc )
    {
        RPCProgram* toast = rpc;
        rpc = rpc->next;

        if (toast->name)
            snort_free(toast->name);
        snort_free(toast);
    }
    rpc_programs = nullptr;
}

int RpcServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    if (args.asd.protocol == IpProtocol::UDP)
        return rpc_udp_validate(args);
    else
        return rpc_tcp_validate(args);
}

static const RPCProgram* FindRPCProgram(uint32_t program)
{
    RPCProgram* rpc;

    for (rpc = rpc_programs; rpc; rpc = rpc->next)
    {
        if (program == rpc->program)
            break;
    }
    return rpc;
}

static IpProtocol get_protocol_from_netid(const string& proto)
{
    if (proto == "tcp")
        return IpProtocol::TCP;
    else if (proto == "udp")
        return IpProtocol::UDP;
    else if (proto == "icmp")
        return IpProtocol::ICMPV4;
    else if (proto == "ip")
        return IpProtocol::IP;
    else
        return IpProtocol::PROTO_NOT_SET;
}

/*
 * Universal addresses take the form h1.h2.h3.h4.p1.p2 ; where h1, h2, h3 and h4 are respectively,
 * the first through fourth octets of the IP address each converted to ASCII-decimal. p1 and p2 are
 * respectively, the first and second octets of the service port, each converted to ASCII-decimal.
 */
static bool  validate_and_parse_universal_address(string& data, uint32_t &address,
    uint16_t &port)
{
    int i = 0;
    istringstream tokenizer(data);
    string tok;
    while (getline(tokenizer, tok, '.'))
    {
        if (!all_of(tok.begin(), tok.end(), ::isdigit))
            return false;
        int tmp = stoi(tok);
        if (tmp > 255)
            return false;
        if (i < 4)
        {
            address <<= 8u;
            address += tmp;
        }
        else
        {
            port <<= 8u;
            port += tmp;
        }
        i++;
    }
    if (i != 6)
        return false;
    return true;
}

int RpcServiceDetector::validate_packet(const uint8_t* data, uint16_t size, AppidSessionDirection dir,
    AppIdSession& asd, Packet* pkt, ServiceRPCData* rd, const char** pname, uint32_t* program)
{
    const ServiceRPCCall* call = nullptr;
    const ServiceRPCReply* reply = nullptr;
    const ServiceRPCPortmap* pm = nullptr;
    const ServiceRPCAuth* a = nullptr;
    uint32_t tmp = 0;
    uint32_t val = 0;
    const uint8_t* end = nullptr;
    const RPCProgram* rprog = nullptr;

    if (!size)
        return APPID_INPROCESS;

    end = data + size;

    if (asd.protocol == IpProtocol::UDP)
    {
        if (!rd->once)
        {
            rd->once = 1;
            if (size < sizeof(ServiceRPC))
                return APPID_NOMATCH;

            const ServiceRPC* rpc = (const ServiceRPC*)data;

            if (ntohl(rpc->type) == RPC_TYPE_REPLY)
            {
                asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
                rd->state = RPC_STATE_REPLY;
                dir = APP_ID_FROM_RESPONDER;
            }
        }
        else if (asd.get_session_flags(APPID_SESSION_UDP_REVERSED))
        {
            dir = (dir == APP_ID_FROM_RESPONDER) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        }
    }

    switch (rd->state)
    {
    case RPC_STATE_CALL:
        if (dir != APP_ID_FROM_INITIATOR)
            return APPID_INPROCESS;
        rd->state = RPC_STATE_DONE;
        if (size < sizeof(ServiceRPCCall))
            return APPID_NOT_COMPATIBLE;
        call = (const ServiceRPCCall*)data;
        if (ntohl(call->header.type) != RPC_TYPE_CALL)
            return APPID_NOT_COMPATIBLE;
        if (ntohl(call->version) != 2)
            return APPID_NOT_COMPATIBLE;
        rd->program = ntohl(call->program);
        rd->program_version = ntohl(call->program_version);
        rd->procedure = ntohl(call->procedure);
        tmp = ntohl(call->cred.length);
        if (sizeof(ServiceRPCCall)+tmp > size)
            return APPID_NOT_COMPATIBLE;
        data += (sizeof(ServiceRPCCall) - sizeof(ServiceRPCAuth)) + tmp;
        a = (const ServiceRPCAuth*)data;
        tmp = ntohl(a->length);
        if (tmp+sizeof(ServiceRPCAuth) > (unsigned)(end-data))
            return APPID_NOT_COMPATIBLE;
        data += sizeof(ServiceRPCAuth) + tmp;
        if (rd->program >= 0x60000000)
            return APPID_NOT_COMPATIBLE;
        switch (rd->program)
        {
        case RPC_PROGRAM_PORTMAP:
            if (rd->program_version == 3 and rd->procedure == RPC_BIND_PORTMAP_GETADDR)
            {
                if (sizeof(ServiceRPCCall) + PROGRAM_LENGTH + VERSION_LENGTH + sizeof(NetId) > size)
                    return APPID_NOT_COMPATIBLE;
                data += (PROGRAM_LENGTH + VERSION_LENGTH);
                const NetId* net_id = (const NetId*) data;
                tmp = ntohl(net_id->length);
                if (tmp == 0 or (sizeof(ServiceRPCCall) + PROGRAM_LENGTH + VERSION_LENGTH +
                    sizeof(NetId) + tmp > size))
                    return APPID_NOT_COMPATIBLE;

                data += sizeof(NetId);
                string netid_proto(data, data + tmp);
                rd->proto = get_protocol_from_netid(netid_proto);
            }
            else if (rd->program_version == 2 and rd->procedure == RPC_PORTMAP_GETPORT)
            {
                if (end-data < (int)sizeof(ServiceRPCPortmap))
                    return APPID_NOT_COMPATIBLE;
                pm = (const ServiceRPCPortmap*)data;
                rd->proto = (IpProtocol)ntohl(pm->proto);
            }
            break;
        default:
            break;
        }
        rd->xid = call->header.xid;
        rd->state = RPC_STATE_REPLY;
        break;
    case RPC_STATE_REPLY:
        if (dir != APP_ID_FROM_RESPONDER)
            return APPID_INPROCESS;
        rd->state = RPC_STATE_DONE;
        if (size < sizeof(ServiceRPCReply))
            return APPID_NOMATCH;
        reply = (const ServiceRPCReply*)data;
        if (ntohl(reply->header.type) != RPC_TYPE_REPLY)
            return APPID_NOMATCH;
        if (rd->xid != reply->header.xid && rd->xid != 0xFFFFFFFF)
            return APPID_NOMATCH;
        tmp = ntohl(reply->verify.length);
        if (sizeof(ServiceRPCReply)+tmp > size)
            return APPID_NOMATCH;
        data += sizeof(ServiceRPCReply) + tmp;
        tmp = ntohl(reply->reply_state);
        val = ntohl(reply->state);
        if (tmp == RPC_REPLY_ACCEPTED)
        {
            if (val > RPC_MAX_ACCEPTED)
                return APPID_NOMATCH;
            if (rd->xid == 0xFFFFFFFF && reply->header.xid != 0xFFFFFFFF)
            {
                rd->state = RPC_STATE_CALL;
                return APPID_INPROCESS;
            }
            *program = rd->program;

            switch (rd->program)
            {
            case RPC_PROGRAM_PORTMAP:
                if (rd->program_version == 3 and rd->procedure == RPC_BIND_PORTMAP_GETADDR)
                {
                    if ((sizeof(ServiceRPCReply) + sizeof(UniversalAddress)) > size)
                        return APPID_NOMATCH;
                    const UniversalAddress* u_addr = (const UniversalAddress*) data;
                    tmp = ntohl(u_addr->length);
                    if (tmp == 0 or
                        ((sizeof(ServiceRPCReply) + sizeof(UniversalAddress) + tmp) > size))
                        return APPID_NOMATCH;
                    uint32_t address = 0;
                    uint16_t port = 0;
                    data += sizeof(UniversalAddress);
                    string uaddr(data, data + tmp);
                    if ((count(uaddr.begin(), uaddr.end(), '.') == (RPCB_UNIVERSAL_ADDR_LENGTH - 1)) and
                        validate_and_parse_universal_address(uaddr, address, port))
                    {
                        SfIp sip;
                        uint32_t addr = htonl(address);
                        sip.set(&addr, AF_INET);
                        const SfIp* dip = pkt->ptrs.ip_api.get_dst();
                        AppIdSession* fsession = AppIdSession::create_future_session(pkt, dip, 0, &sip,
                            port, rd->proto, asd.config.snort_proto_ids[PROTO_INDEX_SUNRPC],
                            asd.get_odp_ctxt(), false, false, true);

                        if (fsession)
                        {
                            fsession->add_flow_data_id(port, this);
                            fsession->service_disco_state = APPID_DISCO_STATE_STATEFUL;
                            fsession->set_session_flags(asd.get_session_flags(
                                APPID_SESSION_SPECIAL_MONITORED |
                                APPID_SESSION_DISCOVER_APP |
                                APPID_SESSION_DISCOVER_USER));
                        }
                    }
                }
                else if (rd->program_version == 2 and rd->procedure == RPC_PORTMAP_GETPORT)
                {
                    const ServiceRPCPortmapReply* pmr = nullptr;
                    if (end-data < (int)sizeof(ServiceRPCPortmapReply))
                        return APPID_NOMATCH;
                    pmr = (const ServiceRPCPortmapReply*)data;
                    if (pmr->port)
                    {
                        const SfIp* dip = pkt->ptrs.ip_api.get_dst();
                        const SfIp* sip = pkt->ptrs.ip_api.get_src();
                        tmp = ntohl(pmr->port);

                        AppIdSession* pf = AppIdSession::create_future_session(pkt, dip, 0, sip,
                            (uint16_t)tmp, rd->proto, asd.config.snort_proto_ids[PROTO_INDEX_SUNRPC],
                            asd.get_odp_ctxt(), false, false, true);

                        if (pf)
                        {
                            pf->add_flow_data_id((uint16_t)tmp, this);
                            pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
                            pf->set_session_flags(asd.get_session_flags(
                                APPID_SESSION_SPECIAL_MONITORED |
                                APPID_SESSION_DISCOVER_APP |
                                APPID_SESSION_DISCOVER_USER));
                        }
                    }
                }
                *pname = "portmap";
                break;
            default:
                rprog = FindRPCProgram(rd->program);
                if (rprog && rprog->name)
                    *pname = rprog->name;
                break;
            }
        }
        else if (tmp == RPC_REPLY_DENIED)
        {
            if (val > RPC_MAX_DENIED)
                return APPID_NOMATCH;
        }
        else
            return APPID_NOMATCH;
        rd->state = RPC_STATE_CALL;
        return APPID_SUCCESS;
    default:
        return APPID_NOMATCH;
    }
    return APPID_INPROCESS;
}

int RpcServiceDetector::rpc_udp_validate(AppIdDiscoveryArgs& args)
{
    ServiceRPCData* rd;
    AppIdServiceSubtype sub;
    AppIdServiceSubtype* subtype;
    uint32_t program = 0;
    const char* pname = nullptr;
    int rval;
    const uint8_t* data = args.data;
    Packet* pkt = args.pkt;
    const AppidSessionDirection dir = args.dir;
    uint16_t size = args.size;

    if (!size)
    {
        rval = APPID_INPROCESS;
        goto done;
    }

    rd = (ServiceRPCData*)data_get(args.asd);
    if (!rd)
    {
        rd = (ServiceRPCData*)snort_calloc(sizeof(ServiceRPCData));
        data_add(args.asd, rd, &snort_free);
        rd->state = (dir == APP_ID_FROM_INITIATOR) ? RPC_STATE_CALL : RPC_STATE_REPLY;
        rd->xid = 0xFFFFFFFF;
    }

    rval = validate_packet(data, size, dir, args.asd, pkt, rd, &pname, &program);

done:
    switch (rval)
    {
    case APPID_INPROCESS:
        if (!args.asd.is_service_detected())
            service_inprocess(args.asd, pkt, dir);
        return APPID_INPROCESS;

    case APPID_SUCCESS:
        if (!args.asd.is_service_detected())
        {
            if (pname && *pname)
            {
                sub.service = pname;
                subtype = &sub;
            }
            else if (program)
            {
                char subname[64];
                snprintf(subname, sizeof(subname), "(%u)", program);
                sub.service = subname;
                subtype = &sub;
            }
            else
                subtype = nullptr;

            add_service(args.change_bits, args.asd, pkt, dir, APP_ID_SUN_RPC,
                nullptr, nullptr, subtype);
        }
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        return APPID_SUCCESS;

    case APPID_NOT_COMPATIBLE:
        if (!args.asd.is_service_detected())
        {
            incompatible_data(args.asd, pkt, dir);
        }
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_NOT_COMPATIBLE;

    case APPID_NOMATCH:
        if (!args.asd.is_service_detected())
        {
            fail_service(args.asd, pkt, dir);
        }
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_NOMATCH;
    default:
        return rval;
    }
}

int RpcServiceDetector::rpc_tcp_validate(AppIdDiscoveryArgs& args)
{
    ServiceRPCData* rd;
    const ServiceRPCFragment* frag;
    uint32_t length;
    uint32_t fragsize;
    int ret;
    int retval = -1;
    const ServiceRPCCall* call;
    const ServiceRPCReply* reply;

    AppIdServiceSubtype sub;
    AppIdServiceSubtype* subtype;
    uint32_t program = 0;
    const char* pname = nullptr;
    const uint8_t* data = args.data;
    Packet* pkt = args.pkt;
    const AppidSessionDirection dir = args.dir;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;

    rd = (ServiceRPCData*)data_get(args.asd);
    if (!rd)
    {
        rd = (ServiceRPCData*)snort_calloc(sizeof(ServiceRPCData));
        data_add(args.asd, rd, &snort_free);
        rd->state = RPC_STATE_CALL;
        for (ret=0; ret<APP_ID_APPID_SESSION_DIRECTION_MAX; ret++)
        {
            rd->tcpstate[ret] = RPC_TCP_STATE_FRAG;
            rd->tcpfragstate[ret] = RPC_TCP_STATE_HEADER;
        }
    }

    while (size)
    {
        fragsize = min(size, (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK) -
            rd->tcpfragpos[dir]);

        switch (rd->tcpstate[dir])
        {
        case RPC_TCP_STATE_FRAG:
            if (size < sizeof(ServiceRPCFragment))
                goto bail;
            frag = (const ServiceRPCFragment*)data;
            data += sizeof(ServiceRPCFragment);
            size -= sizeof(ServiceRPCFragment);

            rd->tcpsize[dir] = ntohl(frag->length);
            rd->tcpfragpos[dir] = 0;
            rd->tcpstate[dir] = rd->tcpfragstate[dir];
            break;
        case RPC_TCP_STATE_HEADER:
            if (dir == APP_ID_FROM_INITIATOR)
            {
                length = min(fragsize, offsetof(ServiceRPCCall, cred) -
                    rd->tcppos[dir]);
                memcpy(&rd->tcpdata[dir][rd->tcppos[dir]], data, length);
                rd->tcppos[dir] += length;
                rd->tcpfragpos[dir] += length;
                data += length;
                size -= length;
                if (rd->tcppos[dir] >= offsetof(ServiceRPCCall, cred))
                {
                    call = (ServiceRPCCall*)rd->tcpdata[dir];
                    if (ntohl(call->header.type) != RPC_TYPE_CALL)
                        goto bail;
                    if (ntohl(call->version) != 2)
                        goto bail;
                    rd->tcpstate[dir] = RPC_TCP_STATE_CRED;
                    rd->tcppos[dir] = 0;
                }
            }
            else
            {
                length = min(fragsize, offsetof(ServiceRPCReply, verify) -
                    rd->tcppos[dir]);
                memcpy(&rd->tcpdata[dir][rd->tcppos[dir]], data, length);
                rd->tcppos[dir] += length;
                rd->tcpfragpos[dir] += length;
                data += length;
                size -= length;
                if (rd->tcppos[dir] >= offsetof(ServiceRPCReply, verify))
                {
                    reply = (ServiceRPCReply*)rd->tcpdata[dir];
                    if (ntohl(reply->header.type) != RPC_TYPE_REPLY)
                        goto fail;
                    rd->tcpstate[dir] = RPC_TCP_STATE_VERIFY;
                    rd->tcppos[dir] = 0;
                }
            }
            break;
        case RPC_TCP_STATE_CRED:
            if (dir != APP_ID_FROM_INITIATOR)
                goto bail;
            length = min(fragsize, sizeof(ServiceRPCAuth) - rd->tcppos[dir]);
            memcpy(&rd->tcpdata[dir][offsetof(ServiceRPCCall, cred)+rd->tcppos[dir]],
                data, length);
            rd->tcppos[dir] += length;
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;
            if (rd->tcppos[dir] >= sizeof(ServiceRPCAuth))
            {
                // FIXIT-M the typecast for all the rd->tcpdata[dir] refs in this function cause
                // this warning:
                //     dereferencing type-punned pointer will break strict-aliasing rules
                // investigate recoding to eliminate this and improve readability
                length = ntohl(((ServiceRPCCall*)rd->tcpdata[dir])->cred.length);
                if (length > (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK) ||
                    rd->tcpfragpos[dir]+length > (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
                    goto bail;
                rd->tcpauthsize[dir] = length;
                rd->tcpstate[dir] = RPC_TCP_STATE_CRED_DATA;
                rd->tcppos[dir] = 0;
            }
            break;
        case RPC_TCP_STATE_CRED_DATA:
            if (dir != APP_ID_FROM_INITIATOR)
                goto bail;
            length = min(fragsize, rd->tcpauthsize[dir] - rd->tcppos[dir]);
            rd->tcppos[dir] += length;
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;
            if (rd->tcppos[dir] >= rd->tcpauthsize[dir])
            {
                ((ServiceRPCCall*)rd->tcpdata[dir])->cred.flavor = 0;
                ((ServiceRPCCall*)rd->tcpdata[dir])->cred.length = 0;
                rd->tcpstate[dir] = RPC_TCP_STATE_VERIFY;
                rd->tcppos[dir] = 0;
            }
            break;
        case RPC_TCP_STATE_VERIFY:
            length = min(fragsize, sizeof(ServiceRPCAuth) - rd->tcppos[dir]);
            if (dir == APP_ID_FROM_INITIATOR)
                memcpy(&rd->tcpdata[dir][offsetof(ServiceRPCCall, verify)+rd->tcppos[dir]],
                    data, length);
            else
                memcpy(&rd->tcpdata[dir][offsetof(ServiceRPCReply, verify)+rd->tcppos[dir]],
                    data, length);
            rd->tcppos[dir] += length;
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;
            fragsize -= length;
            if (rd->tcppos[dir] >= sizeof(ServiceRPCAuth))
            {
                if (dir == APP_ID_FROM_INITIATOR)
                    length = ntohl(((ServiceRPCCall*)rd->tcpdata[dir])->verify.length);
                else
                    length = ntohl(((ServiceRPCReply*)rd->tcpdata[dir])->verify.length);
                if (length > (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK) ||
                    rd->tcpfragpos[dir]+length > (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
                    goto bail;
                rd->tcpauthsize[dir] = length;
                rd->tcpstate[dir] = RPC_TCP_STATE_VERIFY_DATA;
                rd->tcppos[dir] = 0;
            }
            else
            {
                break;
            }
            // fallthrough
        case RPC_TCP_STATE_VERIFY_DATA:
            length = min(fragsize, rd->tcpauthsize[dir] - rd->tcppos[dir]);
            rd->tcppos[dir] += length;
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;
            if (rd->tcppos[dir] >= rd->tcpauthsize[dir])
            {
                if (dir == APP_ID_FROM_INITIATOR)
                {
                    ((ServiceRPCCall*)rd->tcpdata[dir])->verify.flavor = 0;
                    ((ServiceRPCCall*)rd->tcpdata[dir])->verify.length = 0;
                    rd->tcpstate[dir] = RPC_TCP_STATE_PARTIAL;
                    rd->tcppos[dir] = sizeof(ServiceRPCCall);
                    if (rd->tcpfragpos[dir] >= (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
                    {
                        if (rd->tcpsize[dir] & RPC_TCP_FRAG_MASK)
                        {

                            ret = validate_packet(rd->tcpdata[dir], rd->tcppos[dir], dir, args.asd,
                                pkt, rd, &pname, &program);


                            if (retval == -1)
                                retval = ret;
                            rd->tcpfragstate[dir] = RPC_TCP_STATE_HEADER;
                            rd->tcppos[dir] = 0;
                        }
                        else
                            rd->tcpfragstate[dir] = rd->tcpstate[dir];
                        rd->tcpstate[dir] = RPC_TCP_STATE_FRAG;
                    }
                }
                else
                {
                    ((ServiceRPCReply*)rd->tcpdata[dir])->verify.flavor = 0;
                    ((ServiceRPCReply*)rd->tcpdata[dir])->verify.length = 0;
                    rd->tcpstate[dir] = RPC_TCP_STATE_REPLY_HEADER;
                    if (rd->tcpfragpos[dir]+sizeof(uint32_t) > (rd->tcpsize[dir] &
                        ~RPC_TCP_FRAG_MASK))
                        goto bail;
                    rd->tcppos[dir] = 0;
                }
            }
            break;
        case RPC_TCP_STATE_REPLY_HEADER:
            if (dir != APP_ID_FROM_RESPONDER)
                goto bail;
            length = min(fragsize, sizeof(uint32_t) - rd->tcppos[dir]);
            memcpy(&rd->tcpdata[dir][offsetof(ServiceRPCReply, state)+rd->tcppos[dir]],
                data, length);
            rd->tcppos[dir] += length;
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;

            if (rd->tcppos[dir] >= sizeof(uint32_t))
            {
                rd->tcpstate[dir] = RPC_TCP_STATE_PARTIAL;
                rd->tcppos[dir] = sizeof(ServiceRPCReply);
            }
            if (rd->tcpfragpos[dir] >= (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
            {
                fragsize = 0;
            }
            else
            {
                break;
            }
            // fallthrough

        case RPC_TCP_STATE_PARTIAL:
            if (rd->tcppos[dir] < RPC_MAX_TCP_PACKET_SIZE && fragsize)
            {
                length = min(fragsize, RPC_MAX_TCP_PACKET_SIZE - rd->tcppos[dir]);
                memcpy(&rd->tcpdata[dir][rd->tcppos[dir]], data, length);
                rd->tcppos[dir] += length;
            }
            else
            {
                length = fragsize;
            }
            rd->tcpfragpos[dir] += length;
            data += length;
            size -= length;
            if (rd->tcpfragpos[dir] >= (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
            {
                if (rd->tcpsize[dir] & RPC_TCP_FRAG_MASK)
                {

                    ret = validate_packet(rd->tcpdata[dir], rd->tcppos[dir], dir, args.asd, pkt,
                        rd, &pname, &program);


                    if (retval == -1)
                        retval = ret;
                    rd->tcpfragstate[dir] = RPC_TCP_STATE_HEADER;
                    rd->tcppos[dir] = 0;
                }
                else
                    rd->tcpfragstate[dir] = rd->tcpstate[dir];
                rd->tcpstate[dir] = RPC_TCP_STATE_FRAG;
            }
            break;
        default:
            if (retval == -1)
                goto fail;
            else
            {
                args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
                goto done;
            }
        }
        if (rd->tcpstate[dir] != RPC_TCP_STATE_FRAG &&
            rd->tcpstate[dir] != RPC_TCP_STATE_PARTIAL &&
            rd->tcpfragpos[dir] >= (rd->tcpsize[dir] & ~RPC_TCP_FRAG_MASK))
        {
            if (rd->tcpsize[dir] & RPC_TCP_FRAG_MASK)
                goto bail;
            rd->tcpfragstate[dir] = rd->tcpstate[dir];
            rd->tcpstate[dir] = RPC_TCP_STATE_FRAG;
        }
    }
    if (retval == -1)
        retval = APPID_INPROCESS;

done:
    switch (retval)
    {
    case APPID_INPROCESS:
inprocess:
        if (!args.asd.is_service_detected())
            service_inprocess(args.asd, pkt, dir);
        else
            return APPID_SUCCESS;
        return APPID_INPROCESS;

    case APPID_SUCCESS:
        if (!args.asd.is_service_detected())
        {
            if (pname && *pname)
            {
                sub.service = pname;
                subtype = &sub;
            }
            else if (program)
            {
                char subname[64];
                snprintf(subname, sizeof(subname), "(%u)", program);
                sub.service = subname;
                subtype = &sub;
            }
            else
                subtype = nullptr;
            add_service(args.change_bits, args.asd, pkt, dir, APP_ID_SUN_RPC,
                nullptr, nullptr, subtype);
        }
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        return APPID_SUCCESS;

    case APPID_NOT_COMPATIBLE:
        if (!args.asd.is_service_detected())
            incompatible_data(args.asd, pkt, dir);
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_NOT_COMPATIBLE;

    case APPID_NOMATCH:
fail:
        if (args.asd.is_service_detected())
        {
            args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
            return APPID_SUCCESS;
        }
        fail_service(args.asd, pkt, dir);
        return APPID_NOMATCH;
    default:
        return retval;
    }

bail:
    args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
    rd->tcpstate[APP_ID_FROM_INITIATOR] = RPC_TCP_STATE_DONE;
    rd->tcpstate[APP_ID_FROM_RESPONDER] = RPC_TCP_STATE_DONE;
    if (dir == APP_ID_FROM_INITIATOR)
    {
        if (retval == -1)
            retval = APPID_NOT_COMPATIBLE;
    }
    else
    {
        if (retval == -1)
            retval = APPID_NOMATCH;
    }
    goto done;
}

