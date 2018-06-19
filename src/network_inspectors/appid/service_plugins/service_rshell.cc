//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// service_rshell.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_rshell.h"

#include "protocols/packet.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_inspector.h"

#define RSHELL_PORT  514
#define RSHELL_MAX_PORT_PACKET 6

enum RSHELLState
{
    RSHELL_STATE_PORT,
    RSHELL_STATE_SERVER_CONNECT,
    RSHELL_STATE_USERNAME,
    RSHELL_STATE_USERNAME2,
    RSHELL_STATE_COMMAND,
    RSHELL_STATE_REPLY,
    RSHELL_STATE_DONE,
    RSHELL_STATE_STDERR_CONNECT_SYN,
    RSHELL_STATE_STDERR_CONNECT_SYN_ACK
};

struct ServiceRSHELLData
{
    RSHELLState state;
    ServiceRSHELLData* parent;
    ServiceRSHELLData* child;
};

RshellServiceDetector::RshellServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "rshell";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_SHELL, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { RSHELL_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static void rshell_free_state(void* data)
{
    ServiceRSHELLData* rd = (ServiceRSHELLData*)data;

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

int RshellServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    int i = 0;
    uint32_t port = 0;
    const uint8_t* data = args.data;
    uint16_t size = args.size;
    //FIXIT-M - Avoid thread locals
    static THREAD_LOCAL SnortProtocolId rsh_error_snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    ServiceRSHELLData* rd = (ServiceRSHELLData*)data_get(args.asd);
    if (!rd)
    {
        if (!size)
            goto inprocess;
        rd = (ServiceRSHELLData*)snort_calloc(sizeof(ServiceRSHELLData));
        data_add(args.asd, rd, &rshell_free_state);
        rd->state = RSHELL_STATE_PORT;
    }

    if (appidDebug->is_active())
        snort::LogMessage("AppIdDbg %s RSHELL state %d\n", appidDebug->get_debug_session(), rd->state);

    switch (rd->state)
    {
    case RSHELL_STATE_PORT:
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto fail;
        if (size > RSHELL_MAX_PORT_PACKET)
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
        if (port)
        {
            if(rsh_error_snort_protocol_id == UNKNOWN_PROTOCOL_ID)
                rsh_error_snort_protocol_id = snort::SnortConfig::get_conf()->proto_ref->find("rsh-error");

            ServiceRSHELLData* tmp_rd = (ServiceRSHELLData*)snort_calloc(
                sizeof(ServiceRSHELLData));
            tmp_rd->state = RSHELL_STATE_STDERR_CONNECT_SYN;
            tmp_rd->parent = rd;
            const snort::SfIp* dip = args.pkt->ptrs.ip_api.get_dst();
            const snort::SfIp* sip = args.pkt->ptrs.ip_api.get_src();
            AppIdSession* pf = AppIdSession::create_future_session(args.pkt, dip, 0, sip,
                (uint16_t)port, IpProtocol::TCP, rsh_error_snort_protocol_id, APPID_EARLY_SESSION_FLAG_FW_RULE,
                handler->get_inspector());
            if (pf)
            {
                pf->client_disco_state = APPID_DISCO_STATE_FINISHED;
                data_add(*pf, tmp_rd, &rshell_free_state);
                if (pf->add_flow_data_id((uint16_t)port, this))
                {
                    pf->service_disco_state = APPID_DISCO_STATE_FINISHED;
                    tmp_rd->state = RSHELL_STATE_DONE;
                    tmp_rd->parent = nullptr;
                    return APPID_ENOMEM;
                }
                pf->scan_flags |= SCAN_HOST_PORT_FLAG;
                initialize_expected_session(args.asd, *pf,
                    APPID_SESSION_CONTINUE | APPID_SESSION_REXEC_STDERR | APPID_SESSION_NO_TPI |
                    APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE |
                    APPID_SESSION_PORT_SERVICE_DONE, APP_ID_FROM_RESPONDER);
                pf->service_disco_state = APPID_DISCO_STATE_STATEFUL;
            }
            else
            {
                snort_free(tmp_rd);
                return APPID_ENOMEM;
            }
            rd->child = tmp_rd;
            rd->state = RSHELL_STATE_SERVER_CONNECT;
        }
        else
            rd->state = RSHELL_STATE_USERNAME;
        break;
    case RSHELL_STATE_SERVER_CONNECT:
        if (!size)
            break;
        /* The only valid way out of this state is for the child flow to change it. */
        goto fail;
    case RSHELL_STATE_USERNAME:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_USERNAME2;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case RSHELL_STATE_USERNAME2:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]) || isspace(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
    /* Fall through */
    case RSHELL_STATE_COMMAND:
        if (!size)
            break;
        if (args.dir != APP_ID_FROM_INITIATOR)
            goto fail;
        for (i=0; i<size && data[i]; i++)
            if (!isprint(data[i]))
                goto bail;
        rd->state = RSHELL_STATE_COMMAND;
        if (i >= size)
            goto bail;
        i++;
        data += i;
        size -= i;
        if (!size)
        {
            rd->state = RSHELL_STATE_REPLY;
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
        rd->state = RSHELL_STATE_REPLY;
        break;
    case RSHELL_STATE_REPLY:
        if (!size)
            goto inprocess;
        if (args.dir != APP_ID_FROM_RESPONDER)
            goto fail;
        if (size == 1)
            goto success;
        if (*data == 0x01)
        {
            data++;
            size--;
            for (i=0; i<size && data[i]; i++)
            {
                if (!isprint(data[i]) && data[i] != 0x0A && data[i] != 0x0D && data[i] != 0x09)
                    goto fail;
            }
            goto success;
        }
        goto fail;
        break;
    case RSHELL_STATE_STDERR_CONNECT_SYN:
        rd->state = RSHELL_STATE_STDERR_CONNECT_SYN_ACK;
        break;
    case RSHELL_STATE_STDERR_CONNECT_SYN_ACK:
        if (rd->parent && rd->parent->state == RSHELL_STATE_SERVER_CONNECT)
            rd->parent->state = RSHELL_STATE_USERNAME;
        args.asd.set_service_detected();    // FIXIT-M why is this set here and not when add_service is called?
        return APPID_SUCCESS;
    default:
        goto bail;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.asd, args.pkt, args.dir, APP_ID_SHELL);

bail:
    incompatible_data(args.asd, args.pkt, args.dir);
    return APPID_NOT_COMPATIBLE;

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

