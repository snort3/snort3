//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_inspector.h"
#include "appid_module.h"
#include "app_info_table.h"
#include "protocols/packet.h"

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
    REXEC_STATE_STDERR_CONNECT_SYN,
    REXEC_STATE_STDERR_CONNECT_SYN_ACK
};

struct ServiceREXECData
{
    REXECState state;
    struct ServiceREXECData* parent;
    struct ServiceREXECData* child;
};

RexecServiceDetector::RexecServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rexec";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    app_id = AppIdInspector::get_inspector()->add_appid_protocol_reference("rexec");

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

RexecServiceDetector::~RexecServiceDetector()
{
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

int RexecServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int i = 0;
    uint32_t port = 0;
    AppIdSession* pf = nullptr;
    AppIdSession* asd = args.asd;
    const uint8_t* data = args.data;
    Packet* pkt = args.pkt;
    const int dir = args.dir;
    uint16_t size = args.size;

    ServiceREXECData* rd = (ServiceREXECData*)data_get(asd);
    if (!rd)
    {
        if (!size)
            goto inprocess;
        rd = (ServiceREXECData*)snort_calloc(sizeof(ServiceREXECData));
        data_add(asd, rd, &rexec_free_state);
        rd->state = REXEC_STATE_PORT;
    }

    switch (rd->state)
    {
    case REXEC_STATE_PORT:
        if (dir != APP_ID_FROM_INITIATOR)
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
        if (port && pkt)
        {
            const SfIp* sip;
            const SfIp* dip;

            dip = pkt->ptrs.ip_api.get_dst();
            sip = pkt->ptrs.ip_api.get_src();
            pf = AppIdSession::create_future_session(pkt, dip, 0, sip, (uint16_t)port,
                IpProtocol::TCP, app_id, APPID_EARLY_SESSION_FLAG_FW_RULE);
            if (pf)
            {
                ServiceREXECData* tmp_rd = (ServiceREXECData*)snort_calloc(
                    sizeof(ServiceREXECData));
                tmp_rd->state = REXEC_STATE_STDERR_CONNECT_SYN;
                tmp_rd->parent = rd;

                data_add(pf, tmp_rd, &rexec_free_state);
                if (pf->add_flow_data_id((uint16_t)port, this))
                {
                    pf->service_disco_state = APPID_DISCO_STATE_FINISHED;
                    tmp_rd->state = REXEC_STATE_DONE;
                    tmp_rd->parent = nullptr;
                    return APPID_ENULL;
                }
                rd->child = tmp_rd;
                rd->state = REXEC_STATE_SERVER_CONNECT;
                pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
                pf->scan_flags |= SCAN_HOST_PORT_FLAG;
                initialize_expected_session(asd, pf,
                    APPID_SESSION_CONTINUE |
                    APPID_SESSION_REXEC_STDERR |
                    APPID_SESSION_NO_TPI |
                    APPID_SESSION_SERVICE_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE |
                    APPID_SESSION_PORT_SERVICE_DONE);
                pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
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
        if (dir != APP_ID_FROM_INITIATOR)
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
        if (dir != APP_ID_FROM_INITIATOR)
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
        if (dir != APP_ID_FROM_INITIATOR)
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
        if (dir != APP_ID_FROM_RESPONDER)
            goto fail;
        if (size != 1)
            goto fail;
        goto success;
        break;
    case REXEC_STATE_STDERR_CONNECT_SYN:
        rd->state = REXEC_STATE_STDERR_CONNECT_SYN_ACK;
        break;
    case REXEC_STATE_STDERR_CONNECT_SYN_ACK:
        if (rd->parent && rd->parent->state == REXEC_STATE_SERVER_CONNECT)
        {
            rd->parent->state = REXEC_STATE_USERNAME;
            asd->clear_session_flags(APPID_SESSION_REXEC_STDERR);
        }
        goto bail;
    default:
        goto bail;
    }

inprocess:
    if (!asd->is_service_detected())
        service_inprocess(asd, pkt, dir);
    return APPID_INPROCESS;

success:
    if (!asd->is_service_detected())
    {
        add_service(asd, pkt, dir, APP_ID_EXEC, nullptr, nullptr, nullptr);
        appid_stats.rexec_flows++;
    }
    return APPID_SUCCESS;

bail:
    if (!asd->is_service_detected())
    {
        incompatible_data(asd, pkt, dir);
    }
    asd->clear_session_flags(APPID_SESSION_CONTINUE);
    return APPID_NOT_COMPATIBLE;

fail:
    if (!asd->is_service_detected())
    {
        fail_service(asd, pkt, dir);
    }
    asd->clear_session_flags(APPID_SESSION_CONTINUE);
    return APPID_NOMATCH;
}

