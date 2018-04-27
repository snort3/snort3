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

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "detector_plugins/http_url_patterns.h"
#include "service_plugins/service_ssl.h"
#include "protocols/packet.h"
#include "main/snort_debug.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "stream/stream.h"
#include "tp_appid_types.h"
#include "tp_appid_session_api.h"
#include "tp_lib_handler.h"

using namespace std;
using namespace snort;

THREAD_LOCAL ProfileStats tpLibPerfStats;
THREAD_LOCAL ProfileStats tpPerfStats;

bool do_discovery(AppIdSession&, IpProtocol, Packet*, AppidSessionDirection&);

// std::vector does not have a convenient find() function.
// There is a generic std::find() in <algorithm>, but this might be faster.
template<class Type_t, class ValType_t>
static bool contains(const vector<Type_t>& vec, const ValType_t& val)
{
    const Type_t* v=&vec[0], * vend=v+vec.size();
    while (v<vend)
        if ( *(v++)==(Type_t)val )
            return true;
    return false;
}

// FIXIT-L bogus placeholder for this func, need to find out what it should do
static inline bool is_appid_done(const ThirdPartyAppIDSession* tpsession)
{
    UNUSED(tpsession);
    return false;
}

static inline bool check_reinspect(const Packet* p, const AppIdSession& asd)
{
    return p->dsize && !asd.get_session_flags(APPID_SESSION_NO_TPI) &&
        asd.get_session_flags(APPID_SESSION_HTTP_SESSION) && is_appid_done(asd.tpsession);
}

static inline int check_ssl_appid_for_reinspect(AppId app_id)
{
    if (app_id <= SF_APPID_MAX &&
        (app_id == APP_ID_SSL ||
        AppInfoManager::get_instance().get_app_info_flags(app_id,
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
// Or, register observers with THirdPartyAppIDAttributeData and modify the
// set functions to copy the tp buffers directly into the appropriate observer.
static inline void process_http_session(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data)
{
    AppIdHttpSession* hsession = asd.get_http_session();
    const string* field=0;

    hsession->reset_ptype_scan_counts();

    if (asd.get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        const string* spdyRequestScheme=attribute_data.spdy_request_scheme();
        const string* spdyRequestHost=attribute_data.spdy_request_host();
        const string* spdyRequestPath=attribute_data.spdy_request_path();

        if (spdyRequestScheme && spdyRequestHost && spdyRequestPath )
        {
            static const char httpsScheme[] = "https";
            static const char httpScheme[] = "http";
            std::string url;

            if (asd.get_session_flags(APPID_SESSION_DECRYPTED)
                &&
                memcmp(spdyRequestScheme->c_str(), httpScheme,
                sizeof(httpScheme) - 1) == 0)
            {
                url = httpsScheme;
            }
            else
            {
                url = *spdyRequestScheme;
            }

            if (hsession->get_url())
                hsession->set_chp_finished(false);

            url += "://" + *spdyRequestHost + *spdyRequestPath;
            hsession->set_url(url.c_str());
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if (spdyRequestHost)
        {
            if (hsession->get_host())
                hsession->set_chp_finished(false);

            hsession->update_host((const uint8_t*)spdyRequestHost->c_str(),
                spdyRequestHost->size());
            hsession->set_field_offset(REQ_HOST_FID,
                attribute_data.spdy_request_host_begin());
            hsession->set_field_end_offset(REQ_HOST_FID,
                attribute_data.spdy_request_host_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s SPDY host (%u-%u) is %s\n",
                    appidDebug->get_debug_session(),
                    hsession->get_field_offset(REQ_HOST_FID),
                    hsession->get_field_end_offset(REQ_HOST_FID), hsession->get_host());
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if (spdyRequestPath)
        {
            if (hsession->get_uri())
                hsession->set_chp_finished(false);

            hsession->update_uri((const uint8_t*)spdyRequestPath->c_str(),
                spdyRequestPath->size());
            hsession->set_field_offset(REQ_URI_FID, attribute_data.spdy_request_path_begin());
            hsession->set_field_end_offset(REQ_URI_FID, attribute_data.spdy_request_path_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s SPDY URI (%u-%u) is %s\n", appidDebug->get_debug_session(),
                    hsession->get_field_offset(REQ_URI_FID),
                    hsession->get_field_end_offset(REQ_URI_FID), hsession->get_uri());
        }
    }
    else
    {
        if ( (field=attribute_data.http_request_host()) != nullptr )
        {
            if (hsession->get_host())
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->update_host((const uint8_t*)field->c_str(),
                field->size());
            hsession->set_field_offset(REQ_HOST_FID, attribute_data.http_request_host_begin());
            hsession->set_field_end_offset(REQ_HOST_FID, attribute_data.http_request_host_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s HTTP host is %s\n",
                    appidDebug->get_debug_session(), field->c_str());
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if ( (field=attribute_data.http_request_url()) != nullptr )
        {
            static const char httpScheme[] = "http://";

            if (hsession->get_url() and !asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

            // Change http to https if session was decrypted.
            if (asd.get_session_flags(APPID_SESSION_DECRYPTED) and
                memcmp(field->c_str(), httpScheme, sizeof(httpScheme)-1)==0)
            {
                std::string url("https://");
                url.append(field->c_str() + sizeof(httpScheme)-1);
                hsession->set_url(url.c_str());
            }
            else
                hsession->set_url(field->c_str());

            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if ( (field=attribute_data.http_request_uri()) != nullptr)
        {
            if (hsession->get_uri())
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->update_uri((const uint8_t*)field->c_str(),field->size());
            hsession->set_field_offset(REQ_URI_FID, attribute_data.http_request_uri_begin());
            hsession->set_field_end_offset(REQ_URI_FID, attribute_data.http_request_uri_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s uri (%u-%u) is %s\n", appidDebug->get_debug_session(),
                    hsession->get_field_offset(REQ_URI_FID),
                    hsession->get_field_end_offset(REQ_URI_FID), hsession->get_uri());
        }
    }

    // FIXIT-M: these cases are duplicate.
    if ( (field=attribute_data.http_request_via()) != nullptr )
    {
        if (hsession->get_via())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_via((const uint8_t*)field->c_str(),field->size());
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
    }
    else if ( (field=attribute_data.http_response_via()) != nullptr )
    {
        if (hsession->get_via())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_via((const uint8_t*)field->c_str(),field->size());
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
    }

    if ( (field=attribute_data.http_request_user_agent()) != nullptr )
    {
        if (hsession->get_user_agent())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_useragent((const uint8_t*)field->c_str(),field->size());
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s User Agent (%u-%u) is %s\n",
                appidDebug->get_debug_session(), hsession->get_field_offset(REQ_AGENT_FID),
                hsession->get_field_end_offset(REQ_AGENT_FID), hsession->get_user_agent());
        asd.scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
    }

    // Check to see if third party discovered HTTP/2. - once it supports it...
    if ( (field=attribute_data.http_response_version()) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s HTTP response version is %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if (strncmp(field->c_str(), "HTTP/2", 6) == 0)
        {
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s 3rd party detected and parsed HTTP/2\n",
                    appidDebug->get_debug_session());
            asd.is_http2 = true;
        }
    }

    if ( (field=attribute_data.http_response_code()) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s HTTP response code is %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if (hsession->get_response_code())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_response_code((const char*)field->c_str());
    }

    // Check to see if we've got an upgrade to HTTP/2 (if enabled).
    //  - This covers the "without prior knowledge" case (i.e., the client
    //    asks the server to upgrade to HTTP/2).
    if ( (field=attribute_data.http_response_upgrade()) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s HTTP response upgrade is %s\n",
                appidDebug->get_debug_session(),field->c_str());

        if (asd.config->mod_config->http2_detection_enabled)
            if ( hsession->get_response_code()
                && (strncmp(hsession->get_response_code(), "101", 3) == 0) )
                if (strncmp(field->c_str(), "h2c", 3) == 0)
                {
                    if (appidDebug->is_active())
                        LogMessage("AppIdDbg %s Got an upgrade to HTTP/2\n",
                            appidDebug->get_debug_session());
                    asd.is_http2 = true;
                }
    }

    if ( (field=attribute_data.http_request_referer()) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s referrer is %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if (hsession->get_referer())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_referer((const uint8_t*)field->c_str(), field->size());
        hsession->set_field_offset(REQ_REFERER_FID, attribute_data.http_request_referer_begin());
        hsession->set_field_end_offset(REQ_REFERER_FID, attribute_data.http_request_referer_end());
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Referer (%u-%u) is %s\n", appidDebug->get_debug_session(),
                hsession->get_field_offset(REQ_REFERER_FID),
                hsession->get_field_end_offset(REQ_REFERER_FID),
                hsession->get_referer());
    }

    if ( (field=attribute_data.http_request_cookie()) != nullptr )
    {
        if (hsession->get_cookie())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_cookie((const uint8_t*)field->c_str(), field->size());
        hsession->set_field_offset(REQ_COOKIE_FID, attribute_data.http_request_cookie_begin());
        hsession->set_field_end_offset(REQ_COOKIE_FID, attribute_data.http_request_cookie_end());
        // FIXIT-M currently we're not doing this, check if necessary
        // attribute_data.httpRequestCookie = nullptr;
        // attribute_data.httpRequestCookieOffset = 0;
        // attribute_data.httpRequestCookieEndOffset = 0;
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s cookie (%u-%u) is %s\n", appidDebug->get_debug_session(),
                hsession->get_field_offset(REQ_COOKIE_FID),
                hsession->get_field_offset(REQ_COOKIE_FID),
                hsession->get_cookie());
    }

    if ( (field=attribute_data.http_response_content()) != nullptr )
    {
        if (hsession->get_content_type())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_content_type((const uint8_t*)field->c_str(), field->size());
        asd.scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
    }

    if (hsession->get_ptype_scan_count(RSP_LOCATION_FID) &&
        (field=attribute_data.http_response_location()) != nullptr)
    {
        if (hsession->get_location())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_location((const uint8_t*)field->c_str(), field->size());
    }

    if ( (field=attribute_data.http_request_body()) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s got a request body %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if (hsession->get_req_body())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->update_req_body((const uint8_t*)field->c_str(), field->size());
    }

    if (hsession->get_ptype_scan_count(RSP_BODY_FID) &&
        (field=attribute_data.http_response_body()) != nullptr)
    {
        if (hsession->get_body())
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->update_body((const uint8_t*)field->c_str(), field->size());
    }

    if (attribute_data.numXffFields)
        hsession->update_http_xff_address(attribute_data.xffFieldValue,
            attribute_data.numXffFields);

    if (!hsession->is_chp_finished() || hsession->is_chp_hold_flow())
    {
        asd.set_session_flags(APPID_SESSION_CHP_INSPECTING);
        asd.tpsession->set_attr(TP_ATTR_CONTINUE_MONITORING);
    }

    if ( (field=attribute_data.http_response_server()) != nullptr)
    {
        hsession->update_server((const uint8_t*)field->c_str(), field->size());
        asd.scan_flags |= SCAN_HTTP_VENDOR_FLAG;
    }

    if ( (field=attribute_data.http_request_x_working_with()) != nullptr )
    {
        hsession->update_x_working_with((const uint8_t*)field->c_str(), field->size());
        asd.scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
    }
}

static inline void process_rtmp(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, int confidence)
{
    AppIdHttpSession* hsession = asd.get_http_session();
    AppId serviceAppId = 0;
    AppId client_id = 0;
    AppId payload_id = 0;
    AppId referred_payload_app_id = 0;

    const string* field=0;

    if (!hsession->get_url())
    {
        if ( (field=attribute_data.http_request_url()) != nullptr )
        {
            hsession->set_url(field->c_str());
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }
    }

    if ( !asd.config->mod_config->referred_appId_disabled && !hsession->get_referer() )
    {
        if ( (field=attribute_data.http_request_referer()) != nullptr )
        {
            hsession->update_referer((const uint8_t*)field->c_str(), field->size());
        }
    }

    if (hsession->get_url() || (confidence == 100 &&
        asd.session_packet_count > asd.config->mod_config->rtmp_max_packets))
    {
        if (hsession->get_url())
        {
            HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();

            if ( ( ( http_matchers->get_appid_from_url(nullptr, hsession->get_url(),
                nullptr, hsession->get_referer(), &client_id, &serviceAppId,
                &payload_id, &referred_payload_app_id, 1) )
                ||
                ( http_matchers->get_appid_from_url(nullptr, hsession->get_url(), nullptr,
                hsession->get_referer(), &client_id, &serviceAppId, &payload_id,
                &referred_payload_app_id, 0) ) ) == 1 )
            {
                // do not overwrite a previously-set client or service
                if (client_id <= APP_ID_NONE)
                    asd.set_client_appid_data(client_id, nullptr);
                if (serviceAppId <= APP_ID_NONE)
                    asd.set_service_appid_data(serviceAppId, nullptr, nullptr);

                // DO overwrite a previously-set data
                asd.set_payload_appid_data(payload_id, nullptr);
                asd.set_referred_payload_app_id_data(referred_payload_app_id);
            }
        }

        asd.tpsession->disable_flags(
            TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
            TP_SESSION_FLAG_FUTUREFLOW);
        asd.tpsession->reset();
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
    }
}

static inline void process_ssl(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data)
{
    AppId tmpAppId = APP_ID_NONE;
    int tmpConfidence = 0;
    const string* field=0;

    // if (tp_appid_module && asd.tpsession)
    tmpAppId = asd.tpsession->get_appid(tmpConfidence);

    asd.set_session_flags(APPID_SESSION_SSL_SESSION);

    if (!asd.tsession)
        asd.tsession = (TlsSession*)snort_calloc(sizeof(TlsSession));

    if (!asd.client.get_id())
        asd.set_client_appid_data(APP_ID_SSL_CLIENT, nullptr);

    if ( (field=attribute_data.tls_host()) != nullptr )
    {
        if (asd.tsession->tls_host)
            snort_free(asd.tsession->tls_host);
        asd.tsession->tls_host = snort_strdup(field->c_str());
        if (check_ssl_appid_for_reinspect(tmpAppId))
            asd.scan_flags |= SCAN_SSL_HOST_FLAG;
    }

    if (check_ssl_appid_for_reinspect(tmpAppId))
    {
        if ( (field=attribute_data.tls_cname()) != nullptr )
        {
            if (asd.tsession->tls_cname)
                snort_free(asd.tsession->tls_cname);
            asd.tsession->tls_cname = snort_strdup(field->c_str());
        }

        if ( (field=attribute_data.tls_org_unit()) != nullptr )
        {
            if (asd.tsession->tls_orgUnit)
                snort_free(asd.tsession->tls_orgUnit);
            asd.tsession->tls_orgUnit = snort_strdup(field->c_str());
        }
    }
}

static inline void process_ftp_control(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data)
{
    const string* field=0;
    if (!asd.config->mod_config->ftp_userid_disabled &&
        (field=attribute_data.ftp_command_user()) != nullptr)
    {
        asd.client.update_user(APP_ID_FTP_CONTROL, field->c_str());
        asd.set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
        // attribute_data.ftpCommandUser = nullptr;
    }
}

static inline void process_third_party_results(AppIdSession& asd, int confidence,
    vector<AppId>& proto_list, ThirdPartyAppIDAttributeData& attribute_data)
{
    if ( asd.payload.get_id() == APP_ID_NONE and contains(proto_list, APP_ID_EXCHANGE) )
        asd.payload.set_id(APP_ID_EXCHANGE);

    if ( contains(proto_list, APP_ID_HTTP) )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s flow is HTTP\n", appidDebug->get_debug_session());
        asd.set_session_flags(APPID_SESSION_HTTP_SESSION);
    }

    if ( contains(proto_list, APP_ID_SPDY) )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s flow is SPDY\n", appidDebug->get_debug_session());

        asd.set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
        process_http_session(asd, attribute_data);

    else if (contains(proto_list, APP_ID_RTMP) ||
        contains(proto_list, APP_ID_RTSP) )
        process_rtmp(asd, attribute_data, confidence);

    else if (contains(proto_list, APP_ID_SSL))
        process_ssl(asd, attribute_data);

    else if (contains(proto_list, APP_ID_FTP_CONTROL))
        process_ftp_control(asd, attribute_data);
}

static inline void check_terminate_tp_module(AppIdSession& asd, uint16_t tpPktCount)
{
    AppIdHttpSession* hsession = asd.get_http_session();

    if ((tpPktCount >= asd.config->mod_config->max_tp_flow_depth) ||
        (asd.get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) ==
        (APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) &&
        hsession->get_uri() && (!hsession->get_chp_candidate() || hsession->is_chp_finished())))
    {
        if (asd.tp_app_id == APP_ID_NONE)
            asd.tp_app_id = APP_ID_UNKNOWN;
        if (asd.payload.get_id() == APP_ID_NONE)
            asd.payload.set_id(APP_ID_UNKNOWN);

        if (asd.tpsession)
            asd.tpsession->reset();
    }
}

bool do_discovery(AppIdSession& asd, IpProtocol protocol,
    Packet* p, AppidSessionDirection& direction)
{
    ThirdPartyAppIDAttributeData tp_attribute_data;
    vector<AppId> tp_proto_list;
    bool isTpAppidDiscoveryDone = false;

    if ( !asd.config->have_tp() )
        return true;

    //restart inspection by 3rd party
    if (!asd.tp_reinspect_by_initiator && (direction == APP_ID_FROM_INITIATOR) &&
        check_reinspect(p, asd))
    {
        asd.tp_reinspect_by_initiator = true;
        asd.set_session_flags(APPID_SESSION_APP_REINSPECT);
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                appidDebug->get_debug_session());
        asd.reset_session_data();
    }

    if (asd.tp_app_id == APP_ID_SSH && asd.payload.get_id() != APP_ID_SFTP &&
        asd.session_packet_count >= MIN_SFTP_PACKET_COUNT &&
        asd.session_packet_count < MAX_SFTP_PACKET_COUNT)
    {
        if ( p->ptrs.ip_api.tos() == 8 )
        {
            asd.payload.set_id(APP_ID_SFTP);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Payload is SFTP\n", appidDebug->get_debug_session());
        }
    }

    Profile tpPerfStats_profile_context(tpPerfStats);

    /*** Start of third-party processing. ***/
    if ( asd.config->have_tp()
        && !asd.get_session_flags(APPID_SESSION_NO_TPI)
        && (!is_appid_done(asd.tpsession)
        || asd.get_session_flags(APPID_SESSION_APP_REINSPECT
        | APPID_SESSION_APP_REINSPECT_SSL)))
    {
        // First SSL decrypted packet is now being inspected. Reset the flag so that SSL decrypted
        // traffic gets processed like regular traffic from next packet onwards
        if (asd.get_session_flags(APPID_SESSION_APP_REINSPECT_SSL))
            asd.clear_session_flags(APPID_SESSION_APP_REINSPECT_SSL);

        if (p->dsize || asd.config->mod_config->tp_allow_probes)
        {
            if (protocol != IpProtocol::TCP || (p->packet_flags & PKT_STREAM_ORDER_OK)
                || asd.config->mod_config->tp_allow_probes)
            {
                Profile tpLibPerfStats_profile_context(tpLibPerfStats);
                int tp_confidence;
                if (!asd.tpsession)
                {
		    const TPLibHandler* tph = asd.config->tp_handler();
                    CreateThirdPartyAppIDSession_t tpsf = tph->tpsession_factory();
                    if ( !(asd.tpsession = tpsf()) )
                        FatalError("Could not allocate asd.tpsession data");
                }      // debug output of packet content

                asd.tpsession->process(*p, direction,
                    tp_proto_list, tp_attribute_data);
                asd.tp_app_id=asd.tpsession->get_appid(tp_confidence);

                isTpAppidDiscoveryDone = true;
                if (asd.tpsession->get_state() == TP_STATE_CLASSIFIED)
                    asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);

                if (appidDebug->is_active())
                    LogMessage("AppIdDbg %s 3rd party returned %d\n",
                        appidDebug->get_debug_session(),
                        asd.tp_app_id);

                // For now, third party can detect HTTP/2 (w/o metadata) for
                // some cases.  Treat it like HTTP w/ is_http2 flag set.
                if ((asd.tp_app_id == APP_ID_HTTP2) && (tp_confidence == 100))
                {
                    if (appidDebug->is_active())
                        LogMessage("AppIdDbg %s 3rd party saw HTTP/2\n",
                            appidDebug->get_debug_session());

                    asd.tp_app_id = APP_ID_HTTP;
                    asd.is_http2 = true;
                }
                // if the third-party appId must be treated as a client, do it now
                if (asd.app_info_mgr->get_app_info_flags(asd.tp_app_id, APPINFO_FLAG_TP_CLIENT))
                    asd.client.set_id(asd.tp_app_id);

                process_third_party_results(asd, tp_confidence, tp_proto_list, tp_attribute_data);

                if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) &&
                    !(asd.scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, asd.tp_app_id, asd.get_inspector());
                }

                if (asd.app_info_mgr->get_app_info_flags(asd.tp_app_id, APPINFO_FLAG_IGNORE))
                {
                    if (appidDebug->is_active())
                        LogMessage("AppIdDbg %s 3rd party ignored\n",
                            appidDebug->get_debug_session());

                    if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
                        asd.tp_app_id = APP_ID_HTTP;
                    else
                        asd.tp_app_id = APP_ID_NONE;
                }
            }
            else
            {
                asd.tp_app_id = APP_ID_NONE;
                if (appidDebug->is_active() && !asd.get_session_flags(
                    APPID_SESSION_TPI_OOO_LOGGED))
                {
                    asd.set_session_flags(APPID_SESSION_TPI_OOO_LOGGED);
                    LogMessage("AppIdDbg %s 3rd party packet out-of-order\n",
                        appidDebug->get_debug_session());
                }
            }

            if (asd.tpsession and asd.tpsession->get_state() == TP_STATE_MONITORING)
            {
                asd.tpsession->disable_flags(TP_SESSION_FLAG_ATTRIBUTE |
                    TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
            }

            if (asd.tp_app_id == APP_ID_SSL &&
                (Stream::get_snort_protocol_id(p->flow) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                asd.tp_app_id = APP_ID_NONE;
            }

            if ( asd.tp_app_id > APP_ID_NONE
                && (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT)
                || asd.payload.get_id() > APP_ID_NONE) )
            {
                AppId snort_app_id;
                AppIdHttpSession* hsession = asd.get_http_session();

                // if the packet is HTTP, then search for via pattern
                if ( asd.get_session_flags(APPID_SESSION_HTTP_SESSION) )
                {
                    snort_app_id = APP_ID_HTTP;
                    //data should never be APP_ID_HTTP
                    if (asd.tp_app_id != APP_ID_HTTP)
                        asd.tp_payload_app_id = asd.tp_app_id;

                    asd.tp_app_id = APP_ID_HTTP;
                    // Handle HTTP tunneling and SSL possibly then being used in that tunnel
                    if (asd.tp_app_id == APP_ID_HTTP_TUNNEL)
                        asd.set_payload_appid_data(APP_ID_HTTP_TUNNEL, NULL);
                    if ((asd.payload.get_id() == APP_ID_HTTP_TUNNEL) && (asd.tp_app_id ==
                        APP_ID_SSL))
                        asd.set_payload_appid_data(APP_ID_HTTP_SSL_TUNNEL, NULL);

                    hsession->process_http_packet(direction);

                    // If SSL over HTTP tunnel, make sure Snort knows that it's encrypted.
                    if (asd.payload.get_id() == APP_ID_HTTP_SSL_TUNNEL)
                        snort_app_id = APP_ID_SSL;

                    if (asd.is_third_party_appid_available() && asd.tp_app_id ==
                        APP_ID_HTTP
                        && !asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    {
                        asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
                        asd.set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                            APPID_SESSION_SERVICE_DETECTED);
                        asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
                        asd.clear_session_flags(APPID_SESSION_CONTINUE);
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            asd.service_ip = *p->ptrs.ip_api.get_dst();
                            asd.service_port = p->ptrs.dp;
                        }
                        else
                        {
                            asd.service_ip = *p->ptrs.ip_api.get_src();
                            asd.service_port = p->ptrs.sp;
                        }
                    }
                }
                else if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) && asd.tsession)
                {
                    asd.examine_ssl_metadata(p);
                    uint16_t serverPort;
                    AppId porAppId;
                    serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;
                    porAppId = serverPort;
                    if (asd.tp_app_id == APP_ID_SSL)
                    {
                        asd.tp_app_id = porAppId;
                        //SSL policy determines IMAPS/POP3S etc before appId sees first server
                        // packet
                        asd.service.set_port_service_id(porAppId);
                        if (appidDebug->is_active())
                            LogMessage("AppIdDbg %s SSL is service %d, portServiceAppId %d\n",
                                appidDebug->get_debug_session(),
                                asd.tp_app_id, asd.service.get_port_service_id());
                    }
                    else
                    {
                        asd.tp_payload_app_id = asd.tp_app_id;
                        asd.tp_app_id = porAppId;
                        if (appidDebug->is_active())
                            LogMessage("AppIdDbg %s SSL is %d\n", appidDebug->get_debug_session(),
                                asd.tp_app_id);
                    }
                    snort_app_id = APP_ID_SSL;
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId
                    snort_app_id = asd.tp_app_id;
                }

                asd.sync_with_snort_protocol_id(snort_app_id, p);
            }
            else
            {
                if (protocol != IpProtocol::TCP ||
                    (p->packet_flags & (PKT_STREAM_ORDER_OK | PKT_STREAM_ORDER_BAD)))
                {
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
                }
            }
        }
    }

    if ( asd.tp_reinspect_by_initiator && check_reinspect(p, asd) )
    {
        asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
        if (direction == APP_ID_FROM_RESPONDER)
            asd.tp_reinspect_by_initiator = false;     //toggle at OK response
    }

    return isTpAppidDiscoveryDone;
}
