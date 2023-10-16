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

// service_rexec.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rexec.h"

#include "detection/ips_context.h"

#include "appid_debug.h"
#include "appid_inspector.h"
#include "app_info_table.h"
#include "protocols/packet.h"

using namespace snort;

#define REXEC_PORT  512
#define REXEC_MAX_PORT_PACKET 6

enum REXECState
{
    REXEC_STATE_PORT,
    REXEC_STATE_SERVER_CONNECT,
    REXEC_STATE_USERNAME,
    REXEC_STATE_PASSWORD,
    REXEC_STATE_COMMAND,
    REXEC_STATE_REPLY,
    REXEC_STATE_DONE,
    REXEC_STATE_BAIL,
    REXEC_STATE_STDERR_CONNECT_SYN,
    REXEC_STATE_STDERR_CONNECT_SYN_ACK,
    REXEC_STATE_STDERR_WAIT,
    REXEC_STATE_STDERR_DONE
};

struct ServiceREXECData
{
    REXECState state;
    struct ServiceREXECData* parent;
    struct ServiceREXECData* child;
};

static const uint64_t REXEC_EXPECTED_SESSION_FLAGS = APPID_SESSION_CONTINUE |
    APPID_SESSION_REXEC_STDERR | APPID_SESSION_NO_TPI | APPID_SESSION_NOT_A_SERVICE |
    APPID_SESSION_PORT_SERVICE_DONE;

RexecServiceDetector::RexecServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rexec";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_EXEC, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { REXEC_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static void rexec_free_state(void* data)
{
    ServiceREXECData* rd = (ServiceREXECData*)data;

    if (rd)
    {
        if (rd->parent)
        {
            rd->parent->child = nullptr;
            rd->parent->parent = nullptr;
        }
        if (rd->child)
        {
            rd->child->parent = nullptr;
            rd->child->child = nullptr;
        }
        snort_free(rd);
    }
}

void RexecServiceDetector::rexec_bail(ServiceREXECData* rd)
{
    if (!rd)
        return;
    rd->state = REXEC_STATE_BAIL;
    if(rd->child)
        rd->child->state = REXEC_STATE_BAIL;

    if(rd->parent)
        rd->parent->state = REXEC_STATE_BAIL;
}

int RexecServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int i = 0;
    uint32_t port = 0;
    const uint8_t* data = args.data;
    uint16_t size = args.size;

    ServiceREXECData* rd = (ServiceREXECData*)data_get(args.asd);
    if (!rd)
    {
        if (!size)
            goto inprocess;
        rd = (ServiceREXECData*)snort_calloc(sizeof(ServiceREXECData));
        data_add(args.asd, rd, &rexec_free_state);
        rd->state = REXEC_STATE_PORT;
    }
    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s rexec state %d\n", appidDebug->get_debug_session(), rd->state);

    switch (rd->state)
    {
    case REXEC_STATE_PORT:
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto bail;
        if (size > REXEC_MAX_PORT_PACKET)
            goto bail;
        if (data[size-1])
            goto bail;
        port = 0;
        for (i=0; i<size-1; i++)
        {
            if (!isdigit(data[i]))
                goto bail;
            port *= 10;
            port += data[i] - '0';
        }
        if (port > 65535)
            goto bail;
        if (port && args.pkt)
        {
            const SfIp* sip;
            const SfIp* dip;

            dip = args.pkt->ptrs.ip_api.get_dst();
            sip = args.pkt->ptrs.ip_api.get_src();
            AppIdSession* pf = AppIdSession::create_future_session(args.pkt,
                dip, 0, sip,(uint16_t)port, IpProtocol::TCP,
                args.asd.config.snort_proto_ids[PROTO_INDEX_REXEC], args.asd.get_odp_ctxt());

            if (pf)
            {
                ServiceREXECData* tmp_rd = (ServiceREXECData*)snort_calloc(
                    sizeof(ServiceREXECData));
                tmp_rd->state = REXEC_STATE_STDERR_CONNECT_SYN;
                tmp_rd->parent = rd;

                data_add(*pf, tmp_rd, &rexec_free_state);
                if (pf->add_flow_data_id((uint16_t)port, this))
                {
                    pf->service_disco_state = APPID_DISCO_STATE_FINISHED;
                    tmp_rd->state = REXEC_STATE_DONE;
                    tmp_rd->parent = nullptr;
                    return APPID_ENULL;
                }
                pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
                pf->scan_flags |= SCAN_HOST_PORT_FLAG;
                args.asd.initialize_future_session(*pf, REXEC_EXPECTED_SESSION_FLAGS);
                pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
                rd->child = tmp_rd;
                rd->state = REXEC_STATE_SERVER_CONNECT;
                args.asd.set_session_flags(APPID_SESSION_CONTINUE);
                goto success;
            }
            else
                rd->state = REXEC_STATE_USERNAME;
        }
        else
            rd->state = REXEC_STATE_USERNAME;
        break;
    case REXEC_STATE_SERVER_CONNECT:
        if (!size)
            break;
        /* The only valid way out of this state is for the child flow to change it. */
        goto fail;
    case REXEC_STATE_USERNAME:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = REXEC_STATE_PASSWORD;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case REXEC_STATE_PASSWORD:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = REXEC_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case REXEC_STATE_COMMAND:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto bail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = REXEC_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
        if (!size)
        {
            rd->state = REXEC_STATE_REPLY;
            break;
        }
        if (data[size-1])
            goto bail;
        /* stdin */
        for (i=0; i<size && data[i]; i++)
        {
            if (!isprint(data[i]))
                goto bail;
        }
        i++;
        if (i != size)
            goto bail;
        rd->state = REXEC_STATE_REPLY;
        break;
    case REXEC_STATE_REPLY:
        if (!size)
            goto inprocess;
        if (args.dir != APP_ID_FROM_RESPONDER)
            goto fail;
        if (size != 1)
            goto fail;
        if (rd->child)
        {
            if(rd->child->state == REXEC_STATE_STDERR_WAIT)
                rd->child->state = REXEC_STATE_STDERR_DONE;
            else
                goto fail;
        }
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        goto success;
    case REXEC_STATE_STDERR_CONNECT_SYN:
        rd->state = REXEC_STATE_STDERR_CONNECT_SYN_ACK;
        break;
    case REXEC_STATE_STDERR_CONNECT_SYN_ACK:
        if (rd->parent && rd->parent->state == REXEC_STATE_SERVER_CONNECT)
        {
            rd->parent->state = REXEC_STATE_USERNAME;
            rd->state = REXEC_STATE_STDERR_WAIT;
            break;
        }
        goto bail;
    case REXEC_STATE_STDERR_WAIT:
        if(!size)
            break;
        goto bail;
    case REXEC_STATE_STDERR_DONE:
        args.asd.clear_session_flags(APPID_SESSION_REXEC_STDERR | APPID_SESSION_CONTINUE);
        goto success;
    case REXEC_STATE_BAIL:
    default:
        goto bail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_EXEC);

bail:
    args.asd.clear_session_flags(APPID_SESSION_REXEC_STDERR);
    rexec_bail(rd);
    incompatible_data(args.asd, args.pkt, args.dir);
    args.asd.clear_session_flags(APPID_SESSION_REXEC_STDERR);
    return APPID_NOT_COMPATIBLE;

fail:
    args.asd.clear_session_flags(APPID_SESSION_REXEC_STDERR);
    rexec_bail(rd);
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

