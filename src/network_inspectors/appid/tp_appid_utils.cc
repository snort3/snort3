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
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_lib_handler.h"
#include "tp_appid_utils.h"
#endif

using namespace std;
using namespace snort;

typedef AppIdHttpSession::pair_t pair_t;

THREAD_LOCAL ProfileStats tpLibPerfStats;
THREAD_LOCAL ProfileStats tpPerfStats;

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

static inline bool check_reinspect(const Packet* p, const AppIdSession& asd)
{
    return p->dsize && !asd.get_session_flags(APPID_SESSION_NO_TPI) &&
           asd.get_session_flags(APPID_SESSION_HTTP_SESSION) && asd.is_tp_appid_done();
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
    string* field=0;
    bool own=true;

    hsession->reset_ptype_scan_counts();

    if (asd.get_session_flags(APPID_SESSION_SPDY_SESSION))
    {
        const string* spdyRequestScheme=attribute_data.spdy_request_scheme(false);
        const string* spdyRequestHost=attribute_data.spdy_request_host(own);
        const string* spdyRequestPath=attribute_data.spdy_request_path(own);

        if (spdyRequestScheme && spdyRequestHost && spdyRequestPath )
        {
            std::string* url;
            if (asd.get_session_flags(APPID_SESSION_DECRYPTED)
                && *spdyRequestScheme == "http")
            {
                url = new std::string("http://" + *spdyRequestHost + *spdyRequestPath);
            }
            else
            {
                url = new std::string("https://" + *spdyRequestHost + *spdyRequestPath);
            }

            if ( hsession->get_field(MISC_URL_FID) )
                hsession->set_chp_finished(false);

            hsession->set_field(MISC_URL_FID, url);
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if (spdyRequestHost)
        {
            if (hsession->get_field(REQ_HOST_FID))
                hsession->set_chp_finished(false);

            hsession->set_field(REQ_HOST_FID, spdyRequestHost);
            hsession->set_offset(REQ_HOST_FID,
                attribute_data.spdy_request_host_begin(),
                attribute_data.spdy_request_host_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s SPDY host (%u-%u) is %s\n",
                    appidDebug->get_debug_session(),
                    attribute_data.spdy_request_host_begin(),
                    attribute_data.spdy_request_host_end(),
                    hsession->get_field(REQ_HOST_FID)->c_str());
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if (spdyRequestPath)
        {
            if ( hsession->get_field(REQ_URI_FID) )
                hsession->set_chp_finished(false);

            hsession->set_field(REQ_URI_FID, spdyRequestPath);
            hsession->set_offset(REQ_URI_FID,
                attribute_data.spdy_request_path_begin(),
                attribute_data.spdy_request_path_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s SPDY URI (%u-%u) is %s\n", appidDebug->get_debug_session(),
                    attribute_data.spdy_request_path_begin(),
                    attribute_data.spdy_request_path_end(),
                    hsession->get_field(REQ_URI_FID)->c_str());
        }
    }
    else
    {
        if ( (field=attribute_data.http_request_host(own)) != nullptr )
        {
            if ( hsession->get_field(REQ_HOST_FID) )
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->set_field(REQ_HOST_FID, field);
            hsession->set_offset(REQ_HOST_FID,
                attribute_data.http_request_host_begin(),
                attribute_data.http_request_host_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s HTTP host (%u-%u) is %s\n",
                    appidDebug->get_debug_session(),
                    attribute_data.http_request_host_begin(),
                    attribute_data.http_request_host_end(), field->c_str() );
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
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
            hsession->set_field(MISC_URL_FID, field);
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }

        if ( (field=attribute_data.http_request_uri(own)) != nullptr)
        {
            if ( hsession->get_field(REQ_URI_FID) )
                if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                    hsession->set_chp_finished(false);

            hsession->set_field(REQ_URI_FID, field);
            hsession->set_offset(REQ_URI_FID,
                attribute_data.http_request_uri_begin(),
                attribute_data.http_request_uri_end());
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s URI (%u-%u) is %s\n", appidDebug->get_debug_session(),
                    attribute_data.http_request_uri_begin(),
                    attribute_data.http_request_uri_end(),
                    hsession->get_cfield(REQ_URI_FID));
        }
    }

    // FIXIT-M: except for request/response, these cases are duplicate.
    if ( (field=attribute_data.http_request_via(own)) != nullptr )
    {
        if ( hsession->get_field(MISC_VIA_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_VIA_FID, field);
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
    }
    else if ( (field=attribute_data.http_response_via(own)) != nullptr )
    {
        if ( hsession->get_field(MISC_VIA_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_VIA_FID, field);
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
    }

    if ( (field=attribute_data.http_request_user_agent(own)) != nullptr )
    {
        if (hsession->get_field(REQ_AGENT_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_AGENT_FID, field);
        hsession->set_offset(REQ_AGENT_FID,
            attribute_data.http_request_user_agent_begin(),
            attribute_data.http_request_user_agent_end());
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s User Agent (%u-%u) is %s\n",
                appidDebug->get_debug_session(),
                attribute_data.http_request_user_agent_begin(),
                attribute_data.http_request_user_agent_end(),
                field->c_str());
        asd.scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
    }

    // Check to see if third party discovered HTTP/2. - once it supports it...
    if ( (field=attribute_data.http_response_version(false)) != nullptr )
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

    if ( (field=attribute_data.http_response_code(own)) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s HTTP response code is %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if ( hsession->get_field(MISC_RESP_CODE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(MISC_RESP_CODE_FID, field);
    }

    // Check to see if we've got an upgrade to HTTP/2 (if enabled).
    //  - This covers the "without prior knowledge" case (i.e., the client
    //    asks the server to upgrade to HTTP/2).
    if ( (field=attribute_data.http_response_upgrade(false) ) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s HTTP response upgrade is %s\n",
                appidDebug->get_debug_session(),field->c_str());

        if (asd.config->mod_config->http2_detection_enabled)
        {
            const std::string* rc = hsession->get_field(MISC_RESP_CODE_FID);
            if ( rc && *rc == "101" )
                if (strncmp(field->c_str(), "h2c", 3) == 0)
                {
                    if (appidDebug->is_active())
                        LogMessage("AppIdDbg %s Got an upgrade to HTTP/2\n",
                            appidDebug->get_debug_session());
                    asd.is_http2 = true;
                }
        }
    }

    if ( (field=attribute_data.http_request_referer(own)) != nullptr )
    {
        if ( hsession->get_field(REQ_REFERER_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_REFERER_FID, field);
        hsession->set_offset(REQ_REFERER_FID,
            attribute_data.http_request_referer_begin(),
            attribute_data.http_request_referer_end());
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Referer (%u-%u) is %s\n", appidDebug->get_debug_session(),
                attribute_data.http_request_referer_begin(),
                attribute_data.http_request_referer_end(),
                hsession->get_cfield(REQ_REFERER_FID) );
    }

    if ( (field=attribute_data.http_request_cookie(own)) != nullptr )
    {
        if ( hsession->get_field(REQ_COOKIE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(REQ_COOKIE_FID, field);
        hsession->set_offset(REQ_COOKIE_FID,
            attribute_data.http_request_cookie_begin(),
            attribute_data.http_request_cookie_end());
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Cookie (%u-%u) is %s\n", appidDebug->get_debug_session(),
                attribute_data.http_request_cookie_begin(),
                attribute_data.http_request_cookie_end(),
                hsession->get_cfield(REQ_COOKIE_FID));
    }

    if ( (field=attribute_data.http_response_content(own)) != nullptr )
    {
        if ( hsession->get_field(RSP_CONTENT_TYPE_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);

        hsession->set_field(RSP_CONTENT_TYPE_FID, field);
        asd.scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
    }

    if (hsession->get_ptype_scan_count(RSP_LOCATION_FID) &&
        (field=attribute_data.http_response_location(own)) != nullptr)
    {
        if ( hsession->get_field(RSP_LOCATION_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(RSP_LOCATION_FID, field);
    }

    if ( (field=attribute_data.http_request_body(own)) != nullptr )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Got a request body %s\n",
                appidDebug->get_debug_session(), field->c_str());
        if ( hsession->get_field(REQ_BODY_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(REQ_BODY_FID, field);
    }

    if (hsession->get_ptype_scan_count(RSP_BODY_FID) &&
        (field=attribute_data.http_response_body(own)) != nullptr)
    {
        if (hsession->get_field(RSP_BODY_FID) )
            if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
                hsession->set_chp_finished(false);
        hsession->set_field(RSP_BODY_FID, field);
    }

    if (attribute_data.numXffFields)
        hsession->update_http_xff_address(attribute_data.xffFieldValue,
            attribute_data.numXffFields);

    if (!hsession->is_chp_finished() || hsession->is_chp_hold_flow())
    {
        asd.set_session_flags(APPID_SESSION_CHP_INSPECTING);
        asd.tpsession->set_attr(TP_ATTR_CONTINUE_MONITORING);
    }

    if ( (field=attribute_data.http_response_server(own)) != nullptr)
    {
        hsession->set_field(MISC_SERVER_FID, field);
        asd.scan_flags |= SCAN_HTTP_VENDOR_FLAG;
    }

    if ( (field=attribute_data.http_request_x_working_with(own)) != nullptr )
    {
        hsession->set_field(MISC_XWW_FID, field);
        asd.scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
    }
}

static inline void process_rtmp(AppIdSession& asd,
    ThirdPartyAppIDAttributeData& attribute_data, int confidence)
{
    AppIdHttpSession* hsession = asd.get_http_session();
    AppId service_id = 0;
    AppId client_id = 0;
    AppId payload_id = 0;
    AppId referred_payload_app_id = 0;
    bool own = true;
    uint16_t size = 0;

    const string* field=0;

    if ( !hsession->get_field(MISC_URL_FID) )
    {
        if ( ( field=attribute_data.http_request_url(own) ) != nullptr )
        {
            hsession->set_field(MISC_URL_FID, field);
            asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        }
    }

    if ( !asd.config->mod_config->referred_appId_disabled &&
        !hsession->get_field(REQ_REFERER_FID) )
    {
        if ( ( field=attribute_data.http_request_referer(own) ) != nullptr )
        {
            hsession->set_field(REQ_REFERER_FID, field);
        }
    }

    if ( !hsession->get_field(REQ_AGENT_FID) )
    {
        if ( ( field=attribute_data.http_request_user_agent(own) ) != nullptr )
        {
            hsession->set_field(REQ_AGENT_FID, field);
            hsession->set_offset(REQ_AGENT_FID,
                attribute_data.http_request_user_agent_begin(),
                attribute_data.http_request_user_agent_end());

            asd.scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
    }
    
    if ( ( asd.scan_flags & SCAN_HTTP_USER_AGENT_FLAG ) and 
         asd.client.get_id() <= APP_ID_NONE and
         ( field = hsession->get_field(REQ_AGENT_FID) ) and 
         ( size = attribute_data.http_request_user_agent_end() -
           attribute_data.http_request_user_agent_begin() ) > 0 )
    {
        char *version = nullptr;
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
       
        http_matchers->identify_user_agent(field->c_str(), size, service_id, 
        client_id, &version);
        
        asd.set_client_appid_data(client_id, version);
        
        // do not overwrite a previously-set service
        if ( service_id <= APP_ID_NONE )
            asd.set_service_appid_data(service_id, nullptr, nullptr);
        
        asd.scan_flags |= ~SCAN_HTTP_USER_AGENT_FLAG;
        snort_free(version);
    }     

    if ( hsession->get_field(MISC_URL_FID) || (confidence == 100 &&
        asd.session_packet_count > asd.config->mod_config->rtmp_max_packets) )
    {
        const std::string* url;
        if ( ( url = hsession->get_field(MISC_URL_FID) ) != nullptr )
        {
            HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
            const char* referer = hsession->get_cfield(REQ_REFERER_FID);
            if ( ( ( http_matchers->get_appid_from_url(nullptr, url->c_str(),
                nullptr, referer, &client_id, &service_id,
                &payload_id, &referred_payload_app_id, 1) )
                ||
                ( http_matchers->get_appid_from_url(nullptr, url->c_str(),
                nullptr, referer, &client_id, &service_id,
                &payload_id, &referred_payload_app_id, 0) ) ) == 1 )
            {
                // do not overwrite a previously-set client or service
                if ( client_id <= APP_ID_NONE )
                    asd.set_client_appid_data(client_id, nullptr);
                if ( service_id <= APP_ID_NONE )
                    asd.set_service_appid_data(service_id, nullptr, nullptr);

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
    const string* field = 0;

    // if (tp_appid_module && asd.tpsession)
    tmpAppId = asd.tpsession->get_appid(tmpConfidence);

    asd.set_session_flags(APPID_SESSION_SSL_SESSION);

    if (!asd.tsession)
        asd.tsession = (TlsSession*)snort_calloc(sizeof(TlsSession));

    if (!asd.client.get_id())
        asd.set_client_appid_data(APP_ID_SSL_CLIENT, nullptr);

    if ( (field=attribute_data.tls_host(false)) != nullptr )
    {
        asd.tsession->set_tls_host(field->c_str(), field->size());
        if (check_ssl_appid_for_reinspect(tmpAppId))
            asd.scan_flags |= SCAN_SSL_HOST_FLAG;
    }

    if (check_ssl_appid_for_reinspect(tmpAppId))
    {
        if ( (field=attribute_data.tls_cname()) != nullptr )
        {
            asd.tsession->set_tls_cname(field->c_str(), field->size());
        }

        if ( (field=attribute_data.tls_org_unit()) != nullptr )
        {
            asd.tsession->set_tls_org_unit(field->c_str(), field->size());
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
            LogMessage("AppIdDbg %s Flow is HTTP\n", appidDebug->get_debug_session());
        asd.set_session_flags(APPID_SESSION_HTTP_SESSION);
    }

    if ( contains(proto_list, APP_ID_SPDY) )
    {
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Flow is SPDY\n", appidDebug->get_debug_session());

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
        hsession->get_field(REQ_URI_FID) &&
        (!hsession->get_chp_candidate() || hsession->is_chp_finished())))
    {
        if (asd.get_tp_app_id() == APP_ID_NONE)
            asd.set_tp_app_id(APP_ID_UNKNOWN);

        if ( asd.service_disco_state == APPID_DISCO_STATE_FINISHED && asd.payload.get_id() ==
            APP_ID_NONE )
            asd.payload.set_id(APP_ID_UNKNOWN);

        if (asd.tpsession)
            asd.tpsession->reset();
    }
}

bool do_tp_discovery(AppIdSession& asd, IpProtocol protocol,
    Packet* p, AppidSessionDirection& direction)
{
    if ( !TPLibHandler::have_tp() )
        return true;

    AppId tp_app_id = asd.get_tp_app_id();

    if (tp_app_id == APP_ID_SSH && asd.payload.get_id() != APP_ID_SFTP &&
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

    /*** Start of third-party processing. ***/
    bool isTpAppidDiscoveryDone = false;

    if (p->dsize || asd.config->mod_config->tp_allow_probes)
    {
        Profile tpPerfStats_profile_context(tpPerfStats);

        //restart inspection by 3rd party
        if (!asd.tp_reinspect_by_initiator && (direction == APP_ID_FROM_INITIATOR) &&
            check_reinspect(p, asd))
        {
            asd.tp_reinspect_by_initiator = true;
            asd.set_session_flags(APPID_SESSION_APP_REINSPECT);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                    appidDebug->get_debug_session());
            asd.clear_http_data();
        }

        if (!asd.is_tp_processing_done())
        {
            if (protocol != IpProtocol::TCP || (p->packet_flags & PKT_STREAM_ORDER_OK)
                || asd.config->mod_config->tp_allow_probes)
            {
                Profile tpLibPerfStats_profile_context(tpLibPerfStats);
                int tp_confidence;
                ThirdPartyAppIDAttributeData tp_attribute_data;
                vector<AppId> tp_proto_list;
                if (!asd.tpsession)
                {
                    const TPLibHandler* tph = TPLibHandler::get();
                    CreateThirdPartyAppIDSession_t tpsf = tph->tpsession_factory();
                    if ( !(asd.tpsession = tpsf()) )
                        FatalError("Could not allocate asd.tpsession data");
                }      // debug output of packet content

                asd.tpsession->process(*p, direction,
                    tp_proto_list, tp_attribute_data);
                tp_app_id = asd.tpsession->get_appid(tp_confidence);

                isTpAppidDiscoveryDone = true;

                // First SSL decrypted packet is now being inspected. Reset the flag so that SSL
                // decrypted
                // traffic gets processed like regular traffic from next packet onwards
                if (asd.get_session_flags(APPID_SESSION_APP_REINSPECT_SSL))
                    asd.clear_session_flags(APPID_SESSION_APP_REINSPECT_SSL);

                if (asd.tpsession->get_state() == TP_STATE_CLASSIFIED)
                    asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);

                if (appidDebug->is_active())
                {
                    const char *app_name = AppInfoManager::get_instance().get_app_name(tp_app_id);
                    LogMessage("AppIdDbg %s 3rd party returned %s (%d)\n",
                        appidDebug->get_debug_session(),
                        app_name ? app_name : "unknown",
                        tp_app_id);
                }

                // For now, third party can detect HTTP/2 (w/o metadata) for
                // some cases.  Treat it like HTTP w/ is_http2 flag set.
                if ((tp_app_id == APP_ID_HTTP2) && (tp_confidence == 100))
                {
                    if (appidDebug->is_active())
                        LogMessage("AppIdDbg %s 3rd party saw HTTP/2\n",
                            appidDebug->get_debug_session());

                    tp_app_id = APP_ID_HTTP;
                    asd.is_http2 = true;
                }
                // if the third-party appId must be treated as a client, do it now
                unsigned app_info_flags = asd.app_info_mgr->get_app_info_flags(tp_app_id,
                    APPINFO_FLAG_TP_CLIENT | APPINFO_FLAG_IGNORE);

                if ( app_info_flags & APPINFO_FLAG_TP_CLIENT )
                    asd.client.set_id(tp_app_id);

                process_third_party_results(asd, tp_confidence, tp_proto_list, tp_attribute_data);

                if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) &&
                    !(asd.scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, tp_app_id, asd.get_inspector());
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
            }
            else
            {
                tp_app_id = APP_ID_NONE;
            }

            if (asd.tpsession and asd.tpsession->get_state() == TP_STATE_MONITORING)
            {
                asd.tpsession->disable_flags(TP_SESSION_FLAG_ATTRIBUTE |
                    TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
            }

            if (tp_app_id == APP_ID_SSL &&
                (Stream::get_snort_protocol_id(p->flow) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                tp_app_id = APP_ID_NONE;
            }

            if ( tp_app_id > APP_ID_NONE
                && (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT)
                || asd.payload.get_id() > APP_ID_NONE) )
            {
                AppId snort_app_id;

                // if the packet is HTTP, then search for via pattern
                if ( asd.get_session_flags(APPID_SESSION_HTTP_SESSION) )
                {
                    snort_app_id = APP_ID_HTTP;
                    //data should never be APP_ID_HTTP
                    if (tp_app_id != APP_ID_HTTP)
                        asd.set_tp_payload_app_id(tp_app_id);

                    asd.set_tp_app_id(APP_ID_HTTP);

                    // Handle HTTP tunneling and SSL possibly then being used in that tunnel
                    if (tp_app_id == APP_ID_HTTP_TUNNEL)
                        asd.set_payload_appid_data(APP_ID_HTTP_TUNNEL, NULL);
                    else if ((asd.payload.get_id() == APP_ID_HTTP_TUNNEL) &&
                        (tp_app_id == APP_ID_SSL))
                        asd.set_payload_appid_data(APP_ID_HTTP_SSL_TUNNEL, NULL);

                    AppIdHttpSession* hsession = asd.get_http_session();
                    hsession->process_http_packet(direction);

                    // If SSL over HTTP tunnel, make sure Snort knows that it's encrypted.
                    if (asd.payload.get_id() == APP_ID_HTTP_SSL_TUNNEL)
                        snort_app_id = APP_ID_SSL;

                    if (asd.is_tp_appid_available() && asd.get_tp_app_id() ==
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
                    AppId portAppId;
                    serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;
                    portAppId = getSslServiceAppId(serverPort);
                    if (tp_app_id == APP_ID_SSL)
                    {
                        tp_app_id = portAppId;
                        //SSL policy determines IMAPS/POP3S etc before appId sees first server
                        // packet
                        asd.service.set_port_service_id(portAppId);
                        if (appidDebug->is_active())
                        {
                            const char *service_name = AppInfoManager::get_instance().get_app_name(tp_app_id);
                            const char *port_service_name = AppInfoManager::get_instance().get_app_name(asd.service.get_port_service_id());
                            LogMessage("AppIdDbg %s SSL is service %s (%d), portServiceAppId %s (%d)\n",
                                appidDebug->get_debug_session(),
                                service_name ? service_name : "unknown", tp_app_id,
                                port_service_name ? port_service_name : "unknown", asd.service.get_port_service_id());
                        }
                    }
                    else
                    {
                        asd.set_tp_payload_app_id(tp_app_id);
                        tp_app_id = portAppId;
                        if (appidDebug->is_active())
                        {
                            const char *app_name = AppInfoManager::get_instance().get_app_name(tp_app_id);
                            LogMessage("AppIdDbg %s SSL is %s (%d)\n", appidDebug->get_debug_session(),
                                app_name ? app_name : "unknown", tp_app_id);
                        }
                    }
                    snort_app_id = APP_ID_SSL;
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId
                    snort_app_id = tp_app_id;
                }

                asd.set_tp_app_id(tp_app_id);
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
        if ( asd.tp_reinspect_by_initiator && check_reinspect(p, asd) )
        {
            if (isTpAppidDiscoveryDone)
                asd.clear_session_flags(APPID_SESSION_APP_REINSPECT);
            if (direction == APP_ID_FROM_RESPONDER)
                asd.tp_reinspect_by_initiator = false;     //toggle at OK response
        }
    }

    return isTpAppidDiscoveryDone;
}

