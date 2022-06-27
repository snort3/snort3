//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_utils.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <dlfcn.h>

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "trace/trace_api.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "detector_plugins/http_url_patterns.h"
#include "service_plugins/service_ssl.h"
#include "tp_appid_utils.h"
#include "tp_lib_handler.h"

using namespace std;
using namespace snort;

typedef AppIdHttpSession::pair_t pair_t;

static inline bool contains(const vector<AppId>& vec, const AppId val)
{
    for (const auto& elem : vec)
        if (elem == val)
            return true;
    return false;
}

static inline bool check_reinspect(const Packet* p, const AppIdSession& asd)
{
    return asd.get_session_flags(APPID_SESSION_HTTP_SESSION) and
           !asd.get_session_flags(APPID_SESSION_NO_TPI) and asd.is_tp_appid_done() and p->dsize;
}

static inline int check_ssl_appid_for_reinspect(AppId app_id, OdpContext& odp_ctxt)
{
    if (app_id <= SF_APPID_MAX &&
        (app_id == APP_ID_SSL ||
        odp_ctxt.get_app_info_mgr().get_app_info_flags(app_id,
            APPINFO_FLAG_SSL_INSPECT)))
        return 1;
    else
        return 0;
}

// FIXIT-M: All the AppIdHttpSession::set/update functions make an
// internal copy. That needs to change, as that's already the 2nd copy - the
// first copy happens when third party calls ThirdPartyAppIDAttributeData::set
// functions and that's unavoidable.
// Consider passing all the metadata pointers (e.g. host, url, etc.)
// to AppIdHttpSession directly from the thirdparty.so callbacks.
//
// Or, register observers with ThirdPartyAppIDAttributeData and modify the
// set functions to copy the tp buffers directly into the appropriate observer.
//
// Or, replace ThirdParty with 1st Party http_inspect.
static inline void process_http_session(const Packet& p, AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, AppidChangeBits& change_bits)
{
    AppIdHttpSession* hsession = asd.get_http_session(0);
    if (!hsession)
        hsession = asd.create_http_session();
    string* field=nullptr;
    bool own=true;

    hsession->reset_ptype_scan_counts();

    if (asd.get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        const string* spdyRequestScheme=attribute_data.spdy_request_scheme(false);
        const string* spdyRequestHost=attribute_data.spdy_request_host(own);
        const string* spdyRequestPath=attribute_data.spdy_request_path(own);

        if (spdyRequestScheme && spdyRequestHost && spdyRequestPath )
        {
            string* url;
            if (asd.get_session_flags(APPID_SESSION_DECRYPTED)
                && *spdyRequestScheme == "http")
            {
                url = new string("http://" + *spdyRequestHost + *spdyRequestPath);
            }
            else
            {
                url = new string("https://" + *spdyRequestHost + *spdyRequestPath);
            }

            if ( hsession->get_field(MISC_URL_FID) )
                hsession->set_chp_finished(false);

            hsession->set_field(MISC_URL_FID, url, change_bits);
        }

        if (spdyRequestHost)
        {
            if (hsession->get_field(REQ_HOST_FID))
                hsession->set_chp_finished(false);

            hsession->set_field(REQ_HOST_FID, spdyRequestHost, change_bits);
        }

        if (spdyRequestPath)
        {
            if ( hsession->get_field(REQ_URI_FID) )
                hsession->set_chp_finished(false);

            hsession->set_field(REQ_URI_FID, spdyRequestPath, change_bits);
        }
    }
    else
    {
        if ( (field=attribute_data.http_request_host(own)) != nullptr )
        {
            if ( hsession->get_field(REQ_HOST_FID) )
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->set_field(REQ_HOST_FID, field, change_bits);
        }

        if ( (field=attribute_data.http_request_url(own)) != nullptr )
        {
            static const char httpScheme[] = "http://";

            if (hsession->get_field(MISC_URL_FID) and !asd.get_session_flags(
                APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

            // Change http to https if session was decrypted.
            if (asd.get_session_flags(APPID_SESSION_DECRYPTED) and
                memcmp(field->c_str(), httpScheme, sizeof(httpScheme)-1) == 0)
            {
                // This is the only instance that requires that field be
                // non const and the reason TPAD_GET in tp_appid_types.h
                // returns string* rather than const string*.
                // In all other cases field can be const string*.
                field->insert(4, 1, 's');
            }
            hsession->set_field(MISC_URL_FID, field, change_bits);
        }

        if ( (field=attribute_data.http_request_uri(own)) != nullptr)
        {
            if ( hsession->get_field(REQ_URI_FID) )
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->set_field(REQ_URI_FID, field, change_bits);
        }
    }

    // FIXIT-M: except for request/response, these cases are duplicate.
    if ( (field=attribute_data.http_request_via(own)) != nullptr )
    {
        if ( hsession->get_field(MISC_VIA_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_VIA_FID, field, change_bits);
    }
    else if ( (field=attribute_data.http_response_via(own)) != nullptr )
    {
        if ( hsession->get_field(MISC_VIA_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_VIA_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_request_user_agent(own)) != nullptr )
    {
        if (hsession->get_field(REQ_AGENT_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_AGENT_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_response_code(own)) != nullptr )
    {
        if ( hsession->get_field(MISC_RESP_CODE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_RESP_CODE_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_request_referer(own)) != nullptr )
    {
        if ( hsession->get_field(REQ_REFERER_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_REFERER_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_request_cookie(own)) != nullptr )
    {
        if ( hsession->get_field(REQ_COOKIE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_COOKIE_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_response_content(own)) != nullptr )
    {
        if ( hsession->get_field(RSP_CONTENT_TYPE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(RSP_CONTENT_TYPE_FID, field, change_bits);
    }

    if (hsession->get_ptype_scan_count(RSP_LOCATION_FID) &&
        (field=attribute_data.http_response_location(own)) != nullptr)
    {
        if ( hsession->get_field(RSP_LOCATION_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(RSP_LOCATION_FID, field, change_bits);
    }

    if ( (field=attribute_data.http_request_body(own)) != nullptr )
    {
        if ( hsession->get_field(REQ_BODY_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(REQ_BODY_FID, field, change_bits);
    }

    if (hsession->get_ptype_scan_count(RSP_BODY_FID) &&
        (field=attribute_data.http_response_body(own)) != nullptr)
    {
        if (hsession->get_field(RSP_BODY_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(RSP_BODY_FID, field, change_bits);
    }

    if (!hsession->is_chp_finished() || hsession->is_chp_hold_flow())
    {
        asd.set_session_flags(APPID_SESSION_CHP_INSPECTING);
        asd.tpsession->set_attr(TP_ATTR_CONTINUE_MONITORING);
    }

    if ( (field=attribute_data.http_response_server(own)) != nullptr)
        hsession->set_field(MISC_SERVER_FID, field, change_bits);

    if ( (field=attribute_data.http_request_x_working_with(own)) != nullptr )
        hsession->set_field(MISC_XWW_FID, field, change_bits);

    if (SnortConfig::get_conf()->aux_ip_is_enabled())
    {
        const string* uri = hsession->get_field(REQ_URI_FID);

        if (uri and uri->size())
        {
            SfIp aux_ip;
            if (parse_ip_from_uri(*uri, aux_ip))
                p.flow->stash->store(aux_ip);
        }
    }
}

static inline void process_rtmp(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, int confidence, AppidChangeBits& change_bits)
{
    AppIdHttpSession* hsession = asd.get_http_session();
    if (!hsession)
        hsession = asd.create_http_session();
    bool own = true;
    const string* field = nullptr;

    if (!hsession->get_field(MISC_URL_FID) and
        ((field = attribute_data.http_request_url(own)) != nullptr))
        hsession->set_field(MISC_URL_FID, field, change_bits);

    if (!asd.get_odp_ctxt().referred_appId_disabled and
        !hsession->get_field(REQ_REFERER_FID) and
        ((field = attribute_data.http_request_referer(own)) != nullptr))
        hsession->set_field(REQ_REFERER_FID, field, change_bits);

    if (!hsession->get_field(REQ_AGENT_FID) and
        ((field = attribute_data.http_request_user_agent(own)) != nullptr))
        hsession->set_field(REQ_AGENT_FID, field, change_bits);

    asd.examine_rtmp_metadata(change_bits);

    if ( hsession->get_field(MISC_URL_FID) || (confidence == 100 &&
        asd.session_packet_count > asd.get_odp_ctxt().rtmp_max_packets) )
    {
        asd.tpsession->disable_flags(
            TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
            TP_SESSION_FLAG_FUTUREFLOW);
        asd.tpsession->reset();
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
    }
}

static inline void process_ssl(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, AppidChangeBits& change_bits)
{
    AppId tmpAppId = APP_ID_NONE;
    int tmpConfidence = 0;
    const string* field = nullptr;
    int reinspect_ssl_appid = 0;

    if (asd.get_session_flags(APPID_SESSION_HTTP_TUNNEL))
    {
        if (!asd.service_detector)
        {
            AppInfoTableEntry* entry = asd.get_odp_ctxt().
                get_app_info_mgr().get_app_info_entry(APP_ID_SSL);

            if (entry)
                asd.service_detector = entry->service_detector;
        }

        if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION))
            asd.clear_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    tmpAppId = asd.tpsession->get_appid(tmpConfidence);

    asd.set_session_flags(APPID_SESSION_SSL_SESSION);

    if (!asd.tsession)
        asd.tsession = new TlsSession();

    if (!asd.get_client_id())
        asd.set_client_appid_data(APP_ID_SSL_CLIENT, change_bits);

    reinspect_ssl_appid = check_ssl_appid_for_reinspect(tmpAppId, asd.get_odp_ctxt());

    if (!(asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
        asd.tsession->get_tls_host() == nullptr and
        (field = attribute_data.tls_host(false)) != nullptr)
    {
        asd.tsession->set_tls_host(field->c_str(), field->size(), change_bits);
        if (reinspect_ssl_appid)
            asd.scan_flags |= SCAN_SSL_HOST_FLAG;
    }

    if (!(asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
        asd.tsession->get_tls_cname() == nullptr and
        (field = attribute_data.tls_cname()) != nullptr)
    {
        asd.tsession->set_tls_cname(field->c_str(), field->size(), change_bits);
        if (reinspect_ssl_appid)
            asd.scan_flags |= SCAN_SSL_CERTIFICATE_FLAG;
    }

    if (reinspect_ssl_appid)
    {
        if (!(asd.scan_flags & SCAN_CERTVIZ_ENABLED_FLAG) and
            asd.tsession->get_tls_org_unit() == nullptr and
            (field = attribute_data.tls_org_unit()) != nullptr)
        {
            asd.tsession->set_tls_org_unit(field->c_str(), field->size());
        }
    }
}

static inline void process_ftp_control(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, AppidChangeBits& change_bits)
{
    const string* field=nullptr;
    if (!asd.get_odp_ctxt().ftp_userid_disabled &&
        (field=attribute_data.ftp_command_user()) != nullptr)
    {
        asd.set_client_user(APP_ID_FTP_CONTROL, field->c_str(), change_bits);
        asd.set_user_logged_in();
    }
}

static inline void process_quic(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, AppidChangeBits& change_bits)
{
    const string* field = nullptr;
    if ( !asd.tsession )
        asd.tsession = new TlsSession();

    if ( !asd.tsession->get_tls_host() and (field=attribute_data.quic_sni()) != nullptr )
    {
        if ( appidDebug->is_active() )
            LogMessage("AppIdDbg %s Flow is QUIC\n", appidDebug->get_debug_session());
        asd.tsession->set_tls_host(field->c_str(), field->size(), change_bits);
        if ( asd.get_service_id() <= APP_ID_NONE )
            asd.set_service_appid_data(APP_ID_QUIC, change_bits);
    }
}

static inline void process_third_party_results(const Packet& p, AppIdSession& asd, int confidence,
    const vector<AppId>& proto_list, ThirdPartyAppIDAttributeData& attribute_data,
    AppidChangeBits& change_bits)
{
    if ( asd.get_payload_id() == APP_ID_NONE and contains(proto_list, APP_ID_EXCHANGE) )
        asd.set_payload_id(APP_ID_EXCHANGE);

    if ( contains(proto_list, APP_ID_HTTP) )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Flow is HTTP\n", appidDebug->get_debug_session());
        asd.set_session_flags(APPID_SESSION_HTTP_SESSION);
    }

    if ( contains(proto_list, APP_ID_SPDY) )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Flow is SPDY\n", appidDebug->get_debug_session());

        asd.set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    if (contains(proto_list, APP_ID_SSL))
        process_ssl(asd, attribute_data, change_bits);

    if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
        process_http_session(p, asd, attribute_data, change_bits);

    else if (contains(proto_list, APP_ID_RTMP) ||
        contains(proto_list, APP_ID_RTSP) )
        process_rtmp(asd, attribute_data, confidence, change_bits);

    else if (contains(proto_list, APP_ID_FTP_CONTROL))
        process_ftp_control(asd, attribute_data, change_bits);

    else if (contains(proto_list, APP_ID_QUIC))
        process_quic(asd, attribute_data, change_bits);
}

static inline void check_terminate_tp_module(AppIdSession& asd, uint16_t tpPktCount)
{
    AppIdHttpSession* hsession = asd.get_http_session();

    if ((tpPktCount >= asd.get_odp_ctxt().max_tp_flow_depth) ||
        (asd.get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) ==
        (APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) && hsession &&
        hsession->get_field(REQ_URI_FID) &&
        (!hsession->get_chp_candidate() || hsession->is_chp_finished())))
    {
        if (asd.get_tp_app_id() == APP_ID_NONE)
            asd.set_tp_app_id(APP_ID_UNKNOWN);

        if ( !hsession and asd.service_disco_state == APPID_DISCO_STATE_FINISHED and
            asd.get_payload_id() == APP_ID_NONE )
            asd.set_payload_id(APP_ID_UNKNOWN);

        if ( hsession and asd.service_disco_state == APPID_DISCO_STATE_FINISHED and
            hsession->payload.get_id() == APP_ID_NONE )
            hsession->payload.set_id(APP_ID_UNKNOWN);

        if (asd.tpsession)
            asd.tpsession->reset();
    }
}

static void set_tp_reinspect(AppIdSession& asd, const Packet* p, AppidSessionDirection direction)
{
    // restart inspection by 3rd party
    if (!asd.tp_reinspect_by_initiator and (direction == APP_ID_FROM_INITIATOR) and
        check_reinspect(p, asd) and p->packet_flags & PKT_STREAM_ORDER_OK)
    {
        asd.tp_reinspect_by_initiator = true;
        asd.set_session_flags(APPID_SESSION_APP_REINSPECT);
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                appidDebug->get_debug_session());
        asd.init_tpPackets = 0;
        asd.resp_tpPackets = 0;
        asd.clear_http_data();
    }
}

static void clear_tp_reinspect(AppIdSession& asd, const Packet* p, AppidSessionDirection direction)
{
    if ( asd.tp_reinspect_by_initiator and check_reinspect(p, asd) )
    {
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
        if (direction == APP_ID_FROM_RESPONDER)
            asd.tp_reinspect_by_initiator = false;     //toggle at OK response
    }
}

bool do_tp_discovery(ThirdPartyAppIdContext& tp_appid_ctxt, AppIdSession& asd, IpProtocol protocol,
    Packet* p, AppidSessionDirection& direction, AppidChangeBits& change_bits)
{
    AppId tp_app_id = asd.get_tp_app_id();

    if (tp_app_id == APP_ID_SSH && asd.get_payload_id() != APP_ID_SFTP &&
        asd.session_packet_count >= MIN_SFTP_PACKET_COUNT &&
        asd.session_packet_count < MAX_SFTP_PACKET_COUNT)
    {
        if ( p->ptrs.ip_api.tos() == 8 )
        {
            asd.set_payload_id(APP_ID_SFTP);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Payload is SFTP\n", appidDebug->get_debug_session());
        }

        return true;
    }

    if (!p->dsize and !asd.get_odp_ctxt().tp_allow_probes)
        return false;

    bool process_packet = (protocol != IpProtocol::TCP or (p->packet_flags & PKT_STREAM_ORDER_OK) or
        asd.get_odp_ctxt().tp_allow_probes);

    if (!process_packet)
        return false;

    set_tp_reinspect(asd, p, direction);

    if (asd.is_tp_processing_done())
    {
        clear_tp_reinspect(asd, p, direction);
        return false;
    }

    if (!asd.tpsession)
    {
        const TPLibHandler* tph = TPLibHandler::get();
        TpAppIdCreateSession tpsf = tph->tpsession_factory();
        if ( !(asd.tpsession = tpsf(tp_appid_ctxt)) )
        {
            ErrorMessage("Could not allocate asd.tpsession data");
            return false;
        }
    }

    int tp_confidence;
    ThirdPartyAppIDAttributeData tp_attribute_data;
    vector<AppId> tp_proto_list;

    TPState current_tp_state = asd.tpsession->process(*p, direction,
        tp_proto_list, tp_attribute_data);
    tp_app_id = asd.tpsession->get_appid(tp_confidence);

    // First SSL decrypted packet is now being inspected. Reset the flag so that SSL
    // decrypted traffic gets processed like regular traffic from next packet onwards
    if (asd.get_session_flags(APPID_SESSION_APP_REINSPECT_SSL))
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT_SSL);

    if (current_tp_state == TP_STATE_CLASSIFIED)
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
    else if (current_tp_state == TP_STATE_MONITORING)
    {
        asd.tpsession->disable_flags(TP_SESSION_FLAG_ATTRIBUTE |
            TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
    }

    if (appidDebug->is_active())
    {
        const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(tp_app_id);
        LogMessage("AppIdDbg %s 3rd party returned %s (%d)\n",
            appidDebug->get_debug_session(), app_name ? app_name : "unknown", tp_app_id);
    }

    process_third_party_results(*p, asd, tp_confidence, tp_proto_list, tp_attribute_data, change_bits);

    AppIdHttpSession* hsession = nullptr;
    if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
    {
        hsession = asd.get_http_session();
        assert(hsession);
    }

    unsigned app_info_flags = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_flags(tp_app_id,
        APPINFO_FLAG_TP_CLIENT | APPINFO_FLAG_IGNORE );

    // if the third-party appId must be treated as a client, do it now
    if (app_info_flags & APPINFO_FLAG_TP_CLIENT)
    {
        if (hsession)
            hsession->set_client(tp_app_id, change_bits, "Third Party");
        else
            asd.set_client_id(*p, direction, tp_app_id, change_bits);
    }

    if ( app_info_flags & APPINFO_FLAG_IGNORE )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s 3rd party ignored\n",
                appidDebug->get_debug_session());

        if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
            tp_app_id = APP_ID_HTTP;
        else if ( asd.get_session_flags(APPID_SESSION_SSL_SESSION) )
            tp_app_id = APP_ID_SSL;
        else
            tp_app_id = APP_ID_NONE;
    }

    if (tp_app_id == APP_ID_SSL &&
        (Stream::get_snort_protocol_id(p->flow) ==
            asd.config.snort_proto_ids[PROTO_INDEX_FTP_DATA]))
    {
        // If we see SSL on an FTP data channel set tpAppId back
        // to APP_ID_NONE so the FTP inspector picks up the flow.
        tp_app_id = APP_ID_NONE;
    }

    if ( tp_app_id > APP_ID_NONE )
    {
        AppId snort_app_id = APP_ID_NONE;

        if ( hsession )
        {
            snort_app_id = APP_ID_HTTP;
            //data should never be APP_ID_HTTP
            if (tp_app_id != APP_ID_HTTP)
                asd.set_tp_payload_app_id(*p, direction, tp_app_id, change_bits);

            asd.set_tp_app_id(APP_ID_HTTP);

            // Handle HTTP tunneling and SSL possibly then being used in that tunnel
            if (tp_app_id == APP_ID_HTTP_TUNNEL)
                hsession->set_payload(APP_ID_HTTP_TUNNEL, change_bits, "3rd party");
            else if (hsession->payload.get_id() == APP_ID_HTTP_TUNNEL and tp_app_id != APP_ID_SSL)
                hsession->set_payload(tp_app_id, change_bits, "3rd party");

            hsession->process_http_packet(direction, change_bits, asd.get_odp_ctxt().get_http_matchers());

            if (asd.get_tp_app_id() == APP_ID_HTTP and
                !asd.get_session_flags(APPID_SESSION_APP_REINSPECT) and
                asd.is_tp_appid_available())
            {
                asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
                asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
                asd.set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                    APPID_SESSION_SERVICE_DETECTED);
                asd.clear_session_flags(APPID_SESSION_CONTINUE);
                if (direction == APP_ID_FROM_INITIATOR)
                    asd.set_server_info(*(p->ptrs.ip_api.get_dst()), p->ptrs.dp,
                        p->get_egress_group());
                else
                    asd.set_server_info(*(p->ptrs.ip_api.get_src()), p->ptrs.sp,
                        p->get_ingress_group());
            }
        }
        else if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) && asd.tsession)
        {
            asd.examine_ssl_metadata(change_bits);
            uint16_t serverPort;
            AppId portAppId;
            serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;
            portAppId = getSslServiceAppId(serverPort);
            if (tp_app_id == APP_ID_SSL)
            {
                tp_app_id = portAppId;
                //SSL policy determines IMAPS/POP3S etc before appId sees first server
                // packet
                asd.set_port_service_id(portAppId);
                if (appidDebug->is_active())
                {
                    const char *service_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(tp_app_id);
                    const char *port_service_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(asd.get_port_service_id());
                    LogMessage("AppIdDbg %s SSL is service %s (%d), portServiceAppId %s (%d)\n",
                        appidDebug->get_debug_session(),
                        service_name ? service_name : "unknown", tp_app_id,
                        port_service_name ? port_service_name : "unknown", asd.get_port_service_id());
                }
            }
            else
            {
                if (!(asd.scan_flags & SCAN_SPOOFED_SNI_FLAG))
                    asd.set_tp_payload_app_id(*p, direction, tp_app_id, change_bits);
                tp_app_id = portAppId;
                if (appidDebug->is_active())
                {
                    const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(tp_app_id);
                    LogMessage("AppIdDbg %s SSL is %s (%d)\n", appidDebug->get_debug_session(),
                        app_name ? app_name : "unknown", tp_app_id);
                }
            }
            snort_app_id = APP_ID_SSL;
        }
        else if (asd.get_service_id() == APP_ID_QUIC)
            asd.set_tp_payload_app_id(*p, direction, tp_app_id, change_bits);
        else
        {
            //for non-http protocols, tp id is treated like serviceId
            snort_app_id = tp_app_id;
        }

        asd.set_tp_app_id(*p, direction, tp_app_id, change_bits);
        asd.sync_with_snort_protocol_id(snort_app_id, p);
    }

    if (direction == APP_ID_FROM_INITIATOR)
    {
        asd.init_tpPackets++;
        check_terminate_tp_module(asd, asd.init_tpPackets);
    }
    else
    {
        asd.resp_tpPackets++;
        check_terminate_tp_module(asd, asd.resp_tpPackets);
    }

    clear_tp_reinspect(asd, p, direction);

    return true;
}

