//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "detector_sip.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "pub_sub/sip_events.h"

#include "service_inspectors/sip/sip_common.h"
#include "appid_module.h"
#include "app_info_table.h"
#include "client_plugins/client_app_api.h"
#include "service_plugins/service_base.h"
#include "http_url_patterns.h"
#include "appid_utils/sf_mlmp.h"

using namespace std;

#include "app_info_table.h"
#include "client_plugins/client_app_api.h"
#include "service_plugins/service_base.h"
#include "http_url_patterns.h"
#include "appid_utils/sf_mlmp.h"

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

static const char svc_name[] = "sip";
static const unsigned SIP_PORT = 5060;

// static const unsigned MAX_ADDRESS_SIZE = 16;
// static const unsigned MAX_CALLID_SIZE = 64;
static const unsigned MAX_VENDOR_SIZE = 64;
// static const unsigned MAX_PORT_SIZE = 6;

enum SIPState
{
    SIP_STATE_INIT = 0,
    SIP_STATE_REGISTER,
    SIP_STATE_CALL
};

// static const unsigned SIP_STATUS_OK = 200;

// static const unsigned SIP_MAX_INFO_SIZE = 63;

enum tSIP_FLAGS
{
    SIP_FLAG_SERVER_CHECKED = (1<< 0)
};

struct ClientSIPData
{
    void* owner = nullptr;
    SIPState state = SIP_STATE_INIT;
    uint32_t flags = 0;
    string user_name;
    string user_agent;
    string from;
};

struct DetectorSipConfig
{
    bool enabled;
    void* sip_ua_matcher;
    DetectorAppSipPattern* sip_ua_list;
    void* sip_server_matcher;
    DetectorAppSipPattern* sip_server_list;
};

static THREAD_LOCAL DetectorSipConfig detector_sip_config;

static CLIENT_APP_RETCODE sip_client_init(const InitClientAppAPI* const init_api, SF_LIST* config);
static void sip_clean();
static CLIENT_APP_RETCODE sip_client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector* userData);
static CLIENT_APP_RETCODE sip_tcp_client_init(const InitClientAppAPI* const init_api,
    SF_LIST* config);
static CLIENT_APP_RETCODE sip_tcp_client_validate(const uint8_t* data, uint16_t size,
    const int dir, AppIdSession* asd, Packet* pkt, Detector* userData);
static int get_sip_client_app(void* patternMatcher, const char* pattern, uint32_t patternLen,
    AppId* ClientAppId, char** clientVersion);
static void clean_sip_ua();
static void clean_sip_server();

RNAClientAppModule sip_udp_client_mod =
{
    "SIP",
    IpProtocol::UDP,
    &sip_client_init,
    &sip_clean,
    &sip_client_validate,
    2,
    nullptr,
    nullptr,
    0,
    nullptr,
    1,
    0
};
RNAClientAppModule sip_tcp_client_mod =
{
    "SIP",
    IpProtocol::TCP,
    &sip_tcp_client_init,
    nullptr,
    &sip_tcp_client_validate,
    2,
    nullptr,
    nullptr,
    0,
    nullptr,
    1,
    0
};

struct Client_App_Pattern
{
    const uint8_t* pattern;
    unsigned length;
    int index;
    unsigned appId;
};

static Client_App_Pattern patterns[] =
{
    { (const uint8_t*)SIP_REGISTER_BANNER, sizeof(SIP_REGISTER_BANNER)-1, 0, APP_ID_SIP },
    { (const uint8_t*)SIP_INVITE_BANNER, sizeof(SIP_INVITE_BANNER)-1,     0, APP_ID_SIP },
    { (const uint8_t*)SIP_CANCEL_BANNER, sizeof(SIP_CANCEL_BANNER)-1,     0, APP_ID_SIP },
    { (const uint8_t*)SIP_ACK_BANNER, sizeof(SIP_ACK_BANNER)-1,           0, APP_ID_SIP },
    { (const uint8_t*)SIP_BYE_BANNER, sizeof(SIP_BYE_BANNER)-1,           0, APP_ID_SIP },
    { (const uint8_t*)SIP_OPTIONS_BANNER, sizeof(SIP_OPTIONS_BANNER)-1,   0, APP_ID_SIP },
    { (const uint8_t*)SIP_BANNER, sizeof(SIP_BANNER)-1,                   0, APP_ID_SIP },
    { (const uint8_t*)SIP_BANNER_END, sizeof(SIP_BANNER_END)-1,          -1, APP_ID_SIP },
};

static AppRegistryEntry appIdClientRegistry[] =
{
    { APP_ID_SIP, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
};

static AppRegistryEntry appIdServiceRegistry[] =
{
    { APP_ID_SIP, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    { APP_ID_RTP, APPINFO_FLAG_SERVICE_ADDITIONAL }
};

//service side
struct ServiceSIPData
{
    uint8_t serverPkt;
    char vendor[MAX_VENDOR_SIZE];
};

static int sip_service_init(const InitServiceAPI* const init_api);
static int sip_service_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &sip_service_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "sip"
};

static const RNAServiceValidationPort pp[] =
{
    { &sip_service_validate, SIP_PORT, IpProtocol::TCP, 0 },
    { &sip_service_validate, SIP_PORT, IpProtocol::UDP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

SO_PUBLIC RNAServiceValidationModule sip_service_mod =
{
    svc_name,
    &sip_service_init,
    pp,
    nullptr,
    nullptr,
    1,
    nullptr,
    0
};

static CLIENT_APP_RETCODE sip_client_init(const InitClientAppAPI* const init_api, SF_LIST*)
{
    unsigned i;

    /*configuration is read by sip_tcp_init(), which is called first */

    if (detector_sip_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering patterns: %s: %d\n",
            		(const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&sip_client_validate, IpProtocol::UDP, patterns[i].pattern,
                patterns[i].length, patterns[i].index);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdClientRegistry)/sizeof(*appIdClientRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdClientRegistry[j].appId);
        init_api->RegisterAppId(&sip_client_validate, appIdClientRegistry[j].appId,
            appIdClientRegistry[j].additionalInfo);
    }

    if (detector_sip_config.sip_ua_matcher)
        clean_sip_ua();

    if (detector_sip_config.sip_server_matcher)
        clean_sip_server();

    return CLIENT_APP_SUCCESS;
}

static void sip_clean()
{
    if (detector_sip_config.sip_ua_matcher)
        clean_sip_ua();

    if (detector_sip_config.sip_server_matcher)
        clean_sip_server();
}

static CLIENT_APP_RETCODE sip_tcp_client_init(const InitClientAppAPI* const init_api,
        SF_LIST* config)
{
    unsigned i;
    RNAClientAppModuleConfigItem* item;

    detector_sip_config.enabled = true;

    if (config)
    {
        SF_LNODE* next;
        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &next); item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&next))
        {
            DebugFormat(DEBUG_LOG,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
                detector_sip_config.enabled = atoi(item->value) ? true : false;
        }
    }

    if (detector_sip_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering patterns: %s: %d\n",
            		(const char*)patterns[i].pattern, patterns[i].index);
            init_api->RegisterPattern(&sip_tcp_client_validate, IpProtocol::TCP,
                patterns[i].pattern, patterns[i].length,
                patterns[i].index);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdClientRegistry)/sizeof(*appIdClientRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdClientRegistry[j].appId);
        init_api->RegisterAppId(&sip_tcp_client_validate, appIdClientRegistry[j].appId,
            appIdClientRegistry[j].additionalInfo);
    }

    return CLIENT_APP_SUCCESS;
}

static void clientDataFree(void* data)
{ delete (ClientSIPData*)data; }

// static const char* const SIP_USRNAME_BEGIN_MARKER = "<sip:";
static CLIENT_APP_RETCODE sip_client_validate(const uint8_t*, uint16_t, const int,
    AppIdSession* asd, Packet*, Detector*)
{
    ClientSIPData* fd = (ClientSIPData*)sip_udp_client_mod.api->data_get(asd,
        sip_udp_client_mod.flow_data_index);

    if( !fd )
    {
        fd = new ClientSIPData();
        sip_udp_client_mod.api->data_add(asd, fd,
            sip_udp_client_mod.flow_data_index, &clientDataFree);
        fd->owner = &sip_udp_client_mod;
        asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return CLIENT_APP_INPROCESS;
}

static CLIENT_APP_RETCODE sip_tcp_client_validate(const uint8_t* data, uint16_t size, const int
    dir, AppIdSession* asd, Packet* pkt, Detector* userData)
{
    return sip_client_validate(data, size, dir, asd, pkt, userData);
}

static int sipAppAddPattern(DetectorAppSipPattern** patternList, AppId ClientAppId,
    const char* clientVersion, const char* serverPattern)
{
    /* Allocate memory for data structures */
    DetectorAppSipPattern* pattern = (DetectorAppSipPattern*)snort_calloc(
        sizeof(DetectorAppSipPattern));
    pattern->userData.ClientAppId = ClientAppId;
    pattern->userData.clientVersion = snort_strdup(clientVersion);
    pattern->pattern.pattern = (uint8_t*)snort_strdup(serverPattern);
    pattern->pattern.patternSize = (int)strlen(serverPattern);
    pattern->next = *patternList;
    *patternList = pattern;

    return 0;
}

int sipUaPatternAdd(AppId ClientAppId, const char* clientVersion, const char* pattern)
{
    return sipAppAddPattern(&detector_sip_config.sip_ua_list, ClientAppId, clientVersion, pattern);
}

int sipServerPatternAdd(AppId ClientAppId, const char* clientVersion, const char* pattern)
{
    return sipAppAddPattern(&detector_sip_config.sip_server_list, ClientAppId, clientVersion, pattern);
}

int finalize_sip_ua()
{
    const int PATTERN_PART_MAX = 10;
    static THREAD_LOCAL tMlmpPattern patterns[PATTERN_PART_MAX];
    int num_patterns;
    DetectorAppSipPattern* patternNode;

    detector_sip_config.sip_ua_matcher = mlmpCreate();
    if( !detector_sip_config.sip_ua_matcher )
        return -1;

    detector_sip_config.sip_server_matcher = mlmpCreate();
    if( !detector_sip_config.sip_server_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_ua_matcher);
        detector_sip_config.sip_ua_matcher = nullptr;
        return -1;
    }

    for( patternNode = detector_sip_config.sip_ua_list; patternNode; patternNode = patternNode->next )
    {
        num_patterns = parseMultipleHTTPPatterns((const char*)patternNode->pattern.pattern,
            patterns,  PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern((tMlmpTree*)detector_sip_config.sip_ua_matcher, patterns, patternNode);
    }

    for( patternNode = detector_sip_config.sip_server_list; patternNode; patternNode = patternNode->next )
    {
        num_patterns = parseMultipleHTTPPatterns((const char*)patternNode->pattern.pattern,
            patterns,  PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern((tMlmpTree*)detector_sip_config.sip_server_matcher, patterns, patternNode);
    }

    mlmpProcessPatterns((tMlmpTree*)detector_sip_config.sip_ua_matcher);
    mlmpProcessPatterns((tMlmpTree*)detector_sip_config.sip_server_matcher);
    return 0;
}

static void clean_sip_ua()
{
    DetectorAppSipPattern* node;

    if( detector_sip_config.sip_ua_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_ua_matcher);
        detector_sip_config.sip_ua_matcher = nullptr;
    }

    for( node = detector_sip_config.sip_ua_list; node; node = detector_sip_config.sip_ua_list )
    {
        detector_sip_config.sip_ua_list = node->next;
        snort_free((void*)node->pattern.pattern);
        snort_free(node->userData.clientVersion);
        snort_free(node);
    }
}

static void clean_sip_server()
{
    DetectorAppSipPattern* node;

    if( detector_sip_config.sip_server_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_server_matcher);
        detector_sip_config.sip_server_matcher = nullptr;
    }

    for( node = detector_sip_config.sip_server_list; node; node = detector_sip_config.sip_server_list )
    {
        detector_sip_config.sip_server_list = node->next;
        snort_free((void*)node->pattern.pattern);
        snort_free(node->userData.clientVersion);
        snort_free(node);
    }
}

static int get_sip_client_app(void* patternMatcher, const char* pattern, uint32_t patternLen,
    AppId* ClientAppId, char** clientVersion)
{
    tMlmpPattern patterns[3];
    DetectorAppSipPattern* data;

    if( !pattern )
        return 0;

    patterns[0].pattern = (uint8_t*)pattern;
    patterns[0].patternSize = patternLen;
    patterns[1].pattern = nullptr;

    data = (DetectorAppSipPattern*)mlmpMatchPatternGeneric((tMlmpTree*)patternMatcher, patterns);

    if( !data )
        return 0;

    *ClientAppId = data->userData.ClientAppId;
    *clientVersion = data->userData.clientVersion;

    return 1;
}

static void createRtpFlow(AppIdSession* asd, const Packet* pkt, const SfIp* cliIp,
        uint16_t cliPort, const SfIp* srvIp, uint16_t srvPort, IpProtocol proto, int16_t app_id)
{
    AppIdSession* fp, * fp2;

    fp = AppIdSession::create_future_session(pkt, cliIp, cliPort, srvIp, srvPort, proto, app_id,
            APPID_EARLY_SESSION_FLAG_FW_RULE);
    if( fp )
    {
        fp->client_app_id = asd->client_app_id;
        fp->payload_app_id = asd->payload_app_id;
        fp->serviceAppId = APP_ID_RTP;
        PopulateExpectedFlow(asd, fp, APPID_SESSION_IGNORE_ID_FLAGS);
    }

    // create an RTCP flow as well
    fp2 = AppIdSession::create_future_session(pkt, cliIp, cliPort + 1, srvIp, srvPort + 1, proto, app_id,
            APPID_EARLY_SESSION_FLAG_FW_RULE);
    if( fp2 )
    {
        fp2->client_app_id = asd->client_app_id;
        fp2->payload_app_id = asd->payload_app_id;
        fp2->serviceAppId = APP_ID_RTCP;
        PopulateExpectedFlow(asd, fp2, APPID_SESSION_IGNORE_ID_FLAGS);
    }
}

static void addFutureRtpFlows(SipEvent& event, AppIdSession* asd)
{
    event.begin_media_sessions();

    auto session_a = event.next_media_session();
    auto session_b= event.next_media_session();

    if( !session_a || !session_b )
        return;

    DebugFormat(DEBUG_SIP, "Adding future media sessions ID: %u and %u\n",
        session_b->get_id(), session_b->get_id());

    session_a->begin_media_data();
    session_b->begin_media_data();

    auto media_a = session_a->next_media_data();
    auto media_b = session_b->next_media_data();

    while( media_a && media_b )
    {
        DebugFormat(DEBUG_SIP, "Adding future channels Source IP: %s Port: %hu\n",
            media_a->get_address()->ntoa(), media_a->get_port());
        DebugFormat(DEBUG_SIP, "Adding future channels Destine IP: %s Port: %hu\n",
            media_b->get_address()->ntoa(), media_b->get_port());

        createRtpFlow(asd, event.get_packet(), media_a->get_address(), media_a->get_port(),
            media_b->get_address(), media_b->get_port(), IpProtocol::UDP, APP_ID_RTP);
        createRtpFlow(asd, event.get_packet(), media_b->get_address(), media_b->get_port(),
            media_a->get_address(), media_b->get_port(), IpProtocol::UDP, APP_ID_RTP);

        media_a = session_a->next_media_data();
        media_b = session_b->next_media_data();
    }
}

static void SipSessionCbClientProcess(SipEvent& event, AppIdSession* asd)
{
    ClientSIPData* fd;
    AppId ClientAppId = APP_ID_SIP;
    char* clientVersion = nullptr;
    int direction;

    fd = (ClientSIPData*)sip_udp_client_mod.api->data_get(asd,
        sip_udp_client_mod.flow_data_index);
    if( !fd )
    {
        fd = new ClientSIPData();
        sip_udp_client_mod.api->data_add(asd, fd,
            sip_udp_client_mod.flow_data_index, &clientDataFree);
        fd->owner = &sip_udp_client_mod;
        asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    if( fd->owner != &sip_udp_client_mod && fd->owner != &sip_tcp_client_mod )
        return;

    direction = (event.get_packet()->is_from_client()) ?
        APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if( event.is_invite() && direction == APP_ID_FROM_INITIATOR )
    {
        fd->from = string(event.get_from(), event.get_from_len());
        fd->user_name = string(event.get_user_name(), event.get_user_name_len());
        fd->user_agent = string(event.get_user_agent(), event.get_user_agent_len());
    }

    if( fd->user_agent.size() )
    {
        if( get_sip_client_app(detector_sip_config.sip_ua_matcher,
            fd->user_agent.c_str(), fd->user_agent.size(), &ClientAppId, &clientVersion) )
            goto success;
    }

    if( fd->from.size() && !(fd->flags & SIP_FLAG_SERVER_CHECKED) )
    {
        fd->flags |= SIP_FLAG_SERVER_CHECKED;

        if( get_sip_client_app(detector_sip_config.sip_server_matcher,
            fd->from.c_str(), fd->from.size(), &ClientAppId, &clientVersion) )
            goto success;
    }

    if( !event.is_dialog_established() )
        return;

success:
    //client detection successful
    sip_udp_client_mod.api->add_app(asd, APP_ID_SIP, ClientAppId, clientVersion);
    appid_stats.sip_clients++;

    if( fd->user_name.size() )
        sip_udp_client_mod.api->add_user(asd, fd->user_name.c_str(), APP_ID_SIP, 1);

    asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
}

static void SipSessionCbServiceProcess(SipEvent& event, AppIdSession* asd)
{
    ServiceSIPData* ss;
    int direction;

    ss = (ServiceSIPData*)sip_service_mod.api->data_get(asd, sip_service_mod.flow_data_index);
    if( !ss )
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        sip_service_mod.api->data_add(asd, ss, sip_service_mod.flow_data_index, &snort_free);
    }

    ss->serverPkt = 0;

    direction = event.get_packet()->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if( direction == APP_ID_FROM_RESPONDER )
    {
        if( event.get_user_agent() )
        {
            memcpy(ss->vendor, event.get_user_agent(),
                event.get_user_agent_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                event.get_user_agent_len());
        }
        else if( event.get_server() )
        {
            memcpy(ss->vendor, event.get_server(),
                event.get_server_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                event.get_server_len());
        }
    }

    if( !event.has_dialog() )
        return;

    if( event.is_media_updated() )
        addFutureRtpFlows(event, asd);

    if( event.is_dialog_established() )
    {
        if( !asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED) )
        {
            asd->set_session_flags(APPID_SESSION_CONTINUE);
            sip_service_mod.api->add_service(asd, event.get_packet(), direction, &svc_element,
                APP_ID_SIP, ss->vendor[0] ? ss->vendor : nullptr, nullptr, nullptr);
            appid_stats.sip_flows++;
        }
    }
}

static int sip_service_init(const InitServiceAPI* const init_api)
{
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_BANNER, SIP_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_BANNER, SIP_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_INVITE_BANNER, SIP_INVITE_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_INVITE_BANNER, SIP_INVITE_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_ACK_BANNER, SIP_ACK_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_ACK_BANNER, SIP_ACK_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_REGISTER_BANNER, SIP_REGISTER_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_REGISTER_BANNER, SIP_REGISTER_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_CANCEL_BANNER, SIP_CANCEL_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_CANCEL_BANNER, SIP_CANCEL_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_BYE_BANNER, SIP_BYE_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const uint8_t*)SIP_BYE_BANNER, SIP_BYE_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::UDP,
            (const uint8_t*)SIP_OPTIONS_BANNER, SIP_OPTIONS_BANNER_LEN, 0, svc_name);
    init_api->RegisterPattern(&sip_service_validate, IpProtocol::TCP,
            (const  uint8_t*)SIP_OPTIONS_BANNER, SIP_OPTIONS_BANNER_LEN, 0, svc_name);

    unsigned i;
    for (i=0; i < sizeof(appIdServiceRegistry)/sizeof(*appIdServiceRegistry); i++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdServiceRegistry[i].appId);
        init_api->RegisterAppId(&sip_service_validate, appIdServiceRegistry[i].appId,
            appIdServiceRegistry[i].additionalInfo);
    }

    return 0;
}

static int sip_service_validate(ServiceValidationArgs* args)
{
    ServiceSIPData* ss;
    AppIdSession* asd = args->asd;

    ss = (ServiceSIPData*)sip_service_mod.api->data_get(asd, sip_service_mod.flow_data_index);
    if (!ss)
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        sip_service_mod.api->data_add(asd, ss, sip_service_mod.flow_data_index, &snort_free);
    }

    if (args->size && args->dir == APP_ID_FROM_RESPONDER)
    {
        ss->serverPkt++;
    }

    if (ss->serverPkt > 10)
    {
        if (!asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
        {
            sip_service_mod.api->fail_service(asd, args->pkt, args->dir, &svc_element,
                sip_service_mod.flow_data_index);
        }
        asd->clear_session_flags(APPID_SESSION_CONTINUE);
        return SERVICE_NOMATCH;
    }

    if (!asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
    {
        sip_service_mod.api->service_inprocess(asd, args->pkt, args->dir, &svc_element);
    }

    return SERVICE_INPROCESS;
}

void SipEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppIdSession* asd = nullptr;

#ifdef DEBUG_APP_ID_SESSIONS
    {
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        const SfIp* ip;

        src_ip[0] = 0;
        ip = p->ptrs.ip_api.get_src();
        sfip_ntop(ip, src_ip, sizeof(src_ip));
        dst_ip[0] = 0;
        ip = p->ptrs.ip_api.get_dst();
        sfip_ntop(ip, dst_ip, sizeof(dst_ip));
        fprintf(SF_DEBUG_FILE, "AppId Sip Snort Callback Session %s-%u -> %s-%u %d\n", src_ip,
            (unsigned)p->src_port, dst_ip, (unsigned)p->dst_port, IsTCP(p) ? IpProtocol::TCP :
            IpProtocol::UDP);
    }
#endif
    if( flow )
    	asd = appid_api.get_appid_data(flow);

    if( !asd )
    	return;

    SipSessionCbClientProcess((SipEvent&)event, asd);
    SipSessionCbServiceProcess((SipEvent&)event, asd);
}


