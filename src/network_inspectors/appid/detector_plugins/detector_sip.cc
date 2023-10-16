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

// detector_sip.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_sip.h"

#include "appid_debug.h"
#include "appid_inspector.h"
#include "app_info_table.h"
#include "protocols/packet.h"

using namespace snort;

static const char SIP_REGISTER_BANNER[] = "REGISTER ";
static const char SIP_INVITE_BANNER[] = "INVITE ";
static const char SIP_CANCEL_BANNER[] = "CANCEL ";
static const char SIP_ACK_BANNER[] = "ACK ";
static const char SIP_BYE_BANNER[] = "BYE ";
static const char SIP_OPTIONS_BANNER[] = "OPTIONS ";
static const char SIP_BANNER[] = "SIP/2.0 ";
static const char SIP_BANNER_END[] = "SIP/2.0\x00d\x00a";
#define SIP_REGISTER_BANNER_LEN (sizeof(SIP_REGISTER_BANNER)-1)
#define SIP_INVITE_BANNER_LEN (sizeof(SIP_INVITE_BANNER)-1)
#define SIP_CANCEL_BANNER_LEN (sizeof(SIP_CANCEL_BANNER)-1)
#define SIP_ACK_BANNER_LEN (sizeof(SIP_ACK_BANNER)-1)
#define SIP_BYE_BANNER_LEN (sizeof(SIP_BYE_BANNER)-1)
#define SIP_OPTIONS_BANNER_LEN (sizeof(SIP_OPTIONS_BANNER)-1)
#define SIP_BANNER_LEN (sizeof(SIP_BANNER)-1)
#define SIP_BANNER_END_LEN (sizeof(SIP_BANNER_END)-1)
#define SIP_BANNER_LEN    (sizeof(SIP_BANNER)-1)

#define USER_STRING "from: "
#define MAX_USER_POS ((int)sizeof(USER_STRING) - 2)

static const unsigned SIP_PORT = 5060;
static const unsigned MAX_VENDOR_SIZE = 64;

enum SIPState
{
    SIP_STATE_INIT = 0,
    SIP_STATE_REGISTER,
    SIP_STATE_CALL
};

enum tSIP_FLAGS
{
    SIP_FLAG_SERVER_CHECKED = (1<< 0)
};

struct ClientSIPData
{
    void* owner = nullptr;
    SIPState state = SIP_STATE_INIT;
    uint32_t flags = 0;
    std::string user_name;
    std::string user_agent;
    std::string from;
};

static void clientDataFree(void* data)
{
    delete (ClientSIPData*)data;
}

SipUdpClientDetector::SipUdpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SIP";
    proto = IpProtocol::UDP;
    minimum_matches = 2;
    provides_user = true;

    udp_patterns =
    {
        { (const uint8_t*)SIP_REGISTER_BANNER, sizeof(SIP_REGISTER_BANNER) - 1, 0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_INVITE_BANNER, sizeof(SIP_INVITE_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_CANCEL_BANNER, sizeof(SIP_CANCEL_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_ACK_BANNER, sizeof(SIP_ACK_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BYE_BANNER, sizeof(SIP_BYE_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_OPTIONS_BANNER, sizeof(SIP_OPTIONS_BANNER) - 1,  -1, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER, sizeof(SIP_BANNER) - 1,                   0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER_END, sizeof(SIP_BANNER_END) - 1,          -1, 0, APP_ID_SIP },
    };

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    };

    handler->register_detector(name, this, proto);
}

int SipUdpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientSIPData* fd = (ClientSIPData*)data_get(args.asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        data_add(args.asd, fd, &clientDataFree);
        fd->owner = this;
        args.asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return APPID_INPROCESS;
}

#ifndef SIP_UNIT_TEST
SipTcpClientDetector::SipTcpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SIP";
    proto = IpProtocol::TCP;
    minimum_matches = 2;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)SIP_REGISTER_BANNER, sizeof(SIP_REGISTER_BANNER) - 1, 0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_INVITE_BANNER, sizeof(SIP_INVITE_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_CANCEL_BANNER, sizeof(SIP_CANCEL_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_ACK_BANNER, sizeof(SIP_ACK_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BYE_BANNER, sizeof(SIP_BYE_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_OPTIONS_BANNER, sizeof(SIP_OPTIONS_BANNER) - 1,  -1, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER, sizeof(SIP_BANNER) - 1,                   0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER_END, sizeof(SIP_BANNER_END) - 1,          -1, 0, APP_ID_SIP },
    };

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    };

    handler->register_detector(name, this, proto);
}


int SipTcpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientSIPData* fd = (ClientSIPData*)data_get(args.asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        data_add(args.asd, fd, &clientDataFree);
        fd->owner = this;
        args.asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return APPID_INPROCESS;
}

struct ServiceSIPData
{
    uint8_t serverPkt;
    char vendor[MAX_VENDOR_SIZE];
};

void SipServiceDetector::createRtpFlow(AppIdSession& asd, const Packet* pkt, const SfIp* cliIp,
    uint16_t cliPort, const SfIp* srvIp, uint16_t srvPort, IpProtocol protocol)
{
    OdpContext& odp_ctxt = asd.get_odp_ctxt();
    AppIdSession* fp = AppIdSession::create_future_session(pkt, cliIp, cliPort, srvIp, srvPort, protocol,
        asd.config.snort_proto_ids[PROTO_INDEX_SIP], odp_ctxt, false, true);

    if ( fp )
    {
        fp->set_client_id(asd.get_client_id());
        fp->set_payload_id(asd.get_payload_id());
        fp->set_service_id(APP_ID_RTP, odp_ctxt);

        // FIXIT-M : snort 2.9.x updated the flag to APPID_SESSION_EXPECTED_EVALUATE.
        // Check if it is needed here as well.
        // asd.initialize_future_session(*fp, APPID_SESSION_EXPECTED_EVALUATE);

        asd.initialize_future_session(*fp, APPID_SESSION_IGNORE_ID_FLAGS);
    }

    // create an RTCP flow as well

    AppIdSession* fp2 = AppIdSession::create_future_session(pkt, cliIp, cliPort + 1, srvIp, srvPort + 1, protocol,
        asd.config.snort_proto_ids[PROTO_INDEX_SIP], odp_ctxt, false, true);

    if ( fp2 )
    {
        fp2->set_client_id(asd.get_client_id());
        fp2->set_payload_id(asd.get_payload_id());
        fp2->set_service_id(APP_ID_RTCP, odp_ctxt);

        // FIXIT-M : same comment as above
        // asd.initialize_future_session(*fp2, APPID_SESSION_EXPECTED_EVALUATE);

        asd.initialize_future_session(*fp2, APPID_SESSION_IGNORE_ID_FLAGS);
    }
}

void SipServiceDetector::addFutureRtpFlows(SipEvent& event, AppIdSession& asd)
{
    event.begin_media_sessions();

    auto session_a = event.next_media_session();
    auto session_b = event.next_media_session();

    if ( !session_a || !session_b )
        return;

    session_a->begin_media_data();
    session_b->begin_media_data();

    auto media_a = session_a->next_media_data();
    auto media_b = session_b->next_media_data();

    while ( media_a && media_b )
    {
        createRtpFlow(asd, event.get_packet(), media_a->get_address(), media_a->get_port(),
            media_b->get_address(), media_b->get_port(), IpProtocol::UDP);

        media_a = session_a->next_media_data();
        media_b = session_b->next_media_data();
    }
}

SipServiceDetector::SipServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "sip";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)SIP_BANNER, SIP_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_INVITE_BANNER, SIP_INVITE_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_ACK_BANNER, SIP_ACK_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_REGISTER_BANNER, SIP_REGISTER_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_CANCEL_BANNER, SIP_CANCEL_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_BYE_BANNER, SIP_BYE_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_OPTIONS_BANNER, SIP_OPTIONS_BANNER_LEN, 0, 0, 0 },
    };

    udp_patterns = tcp_patterns;

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
        { APP_ID_RTP, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { SIP_PORT, IpProtocol::UDP, false },
        { SIP_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}

int SipServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceSIPData* ss = (ServiceSIPData*)data_get(args.asd);
    if (!ss)
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        data_add(args.asd, ss, &snort_free);
    }

    if (args.size && args.dir == APP_ID_FROM_RESPONDER)
        ss->serverPkt++;

    if (ss->serverPkt > 10)
    {
        if (!args.asd.is_service_detected())
        {
            fail_service(args.asd, args.pkt, args.dir);
        }
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_NOMATCH;
    }

    if (!args.asd.is_service_detected())
        service_inprocess(args.asd, args.pkt, args.dir);

    return APPID_INPROCESS;
}

#endif

void SipEventHandler::handle(DataEvent& event, Flow* flow)
{
    if (!flow)
        return;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    // Skip for sessions using old odp context after odp reload
    if (asd and (!pkt_thread_odp_ctxt or
        (asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version())))
        return;

    SipEvent& sip_event = (SipEvent&)event;
    const Packet* p = sip_event.get_packet();
    assert(p);

    if ( !asd )
    {
        IpProtocol protocol = p->is_tcp() ? IpProtocol::TCP : IpProtocol::UDP;
        AppidSessionDirection direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        asd = AppIdSession::allocate_session(p, protocol, direction, inspector,
            *pkt_thread_odp_ctxt);
    }
    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    AppidChangeBits change_bits;
    client_handler(sip_event, *asd, change_bits);
    service_handler(sip_event, *asd, change_bits);
    asd->publish_appid_event(change_bits, *p);
}

void SipEventHandler::client_handler(SipEvent& sip_event, AppIdSession& asd,
    AppidChangeBits& change_bits)
{
    AppId client_id = APP_ID_SIP;
    char* client_version = nullptr;

    SipUdpClientDetector* client = pkt_thread_odp_ctxt->get_sip_client_detector();
    if (!client)
        return;

    ClientSIPData* fd = (ClientSIPData*)client->data_get(asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        client->data_add(asd, fd, &clientDataFree);
        fd->owner = client;
        asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    AppidSessionDirection direction = (sip_event.get_packet()->is_from_client()) ?
        APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if ( sip_event.is_invite() && direction == APP_ID_FROM_INITIATOR )
    {
        size_t len;
        len = sip_event.get_from_len();
        if (len > 0)
            fd->from.assign(sip_event.get_from(), len);
        len = sip_event.get_user_name_len();
        if (len > 0)
            fd->user_name.assign(sip_event.get_user_name(), len);
        len = sip_event.get_user_agent_len();
        if (len > 0)
            fd->user_agent.assign(sip_event.get_user_agent(), len);
    }

    if ( !fd->user_agent.empty() )
    {
        if ( asd.get_odp_ctxt().get_sip_matchers().get_client_from_ua(
            fd->user_agent.c_str(), fd->user_agent.size(), client_id, client_version) )
            goto success;
    }

    if ( !fd->from.empty() && !(fd->flags & SIP_FLAG_SERVER_CHECKED) )
    {
        fd->flags |= SIP_FLAG_SERVER_CHECKED;

        if ( asd.get_odp_ctxt().get_sip_matchers().get_client_from_server(
            fd->from.c_str(), fd->from.size(), client_id, client_version) )
            goto success;
    }

    if ( !sip_event.is_dialog_established() )
        return;

success:
    if( !asd.is_client_detected() )
        client->add_app(asd, APP_ID_SIP, client_id, client_version, change_bits);

    if ( !fd->user_name.empty() )
        client->add_user(asd, fd->user_name.c_str(), APP_ID_SIP, true, change_bits);
}

#ifndef SIP_UNIT_TEST
void SipEventHandler::service_handler(SipEvent& sip_event, AppIdSession& asd,
    AppidChangeBits& change_bits)
{
    SipServiceDetector* service = pkt_thread_odp_ctxt->get_sip_service_detector();
    if (!service)
        return;

    ServiceSIPData* ss = (ServiceSIPData*)service->data_get(asd);
    if ( !ss )
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        service->data_add(asd, ss, &snort_free);
    }

    ss->serverPkt = 0;
    AppidSessionDirection direction = sip_event.get_packet()->is_from_client() ? APP_ID_FROM_INITIATOR :
        APP_ID_FROM_RESPONDER;

    if ( direction == APP_ID_FROM_RESPONDER )
    {
        if ( sip_event.get_user_agent_len() )
        {
            memcpy(ss->vendor, sip_event.get_user_agent(),
                sip_event.get_user_agent_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                sip_event.get_user_agent_len());
        }
        else if ( sip_event.get_server_len() )
        {
            memcpy(ss->vendor, sip_event.get_server(),
                sip_event.get_server_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                sip_event.get_server_len());
        }
    }

    if ( !sip_event.has_dialog() )
        return;

    if ( sip_event.is_media_updated() )
        service->addFutureRtpFlows(sip_event, asd);

    if ( sip_event.is_dialog_established() )
    {
        if ( !asd.is_service_detected() )
        {
            asd.set_session_flags(APPID_SESSION_CONTINUE);
            service->add_service(change_bits, asd, sip_event.get_packet(), direction, APP_ID_SIP,
                ss->vendor[0] ? ss->vendor : nullptr);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Sip service detected. Setting APPID_SESSION_CONTINUE flag\n",
                            appidDebug->get_debug_session());
        }
    }
}
#endif

