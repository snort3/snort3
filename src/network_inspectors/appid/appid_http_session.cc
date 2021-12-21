//--------------------------------------------------------------------------
// Copyright (C) 2017-2021 Cisco and/or its affiliates. All rights reserved.
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

// appid_http_session.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Apr 19, 2017

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_http_session.h"

#include "flow/ha.h"
#include "memory/memory_cap.h"
#include "profiler/profiler.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_session.h"
#include "detector_plugins/http_url_patterns.h"
#include "tp_lib_handler.h"
#define PORT_MAX 65535

using namespace snort;

AppIdHttpSession::AppIdHttpSession(AppIdSession& asd, uint32_t http2_stream_id)
    : asd(asd), http2_stream_id(http2_stream_id)
{ }

AppIdHttpSession::~AppIdHttpSession()
{
    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
        delete meta_data[i];
    if (tun_dest)
        delete tun_dest;
}

void AppIdHttpSession::free_chp_matches(ChpMatchDescriptor& cmd, unsigned num_matches)
{
    for (unsigned i = 0; i <= num_matches; i++)
        if ( !cmd.chp_matches[i].empty() )
            cmd.chp_matches[i].clear();
}

void AppIdHttpSession::set_http_change_bits(AppidChangeBits& change_bits, HttpFieldIds id)
{
    switch (id)
    {
    case REQ_HOST_FID:
        change_bits.set(APPID_HOST_BIT);
        assert(asd.flow);
        if (asd.flow->ha_state)
            asd.flow->ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
        break;
    case MISC_URL_FID:
        change_bits.set(APPID_URL_BIT);
        assert(asd.flow);
        if (asd.flow->ha_state)
            asd.flow->ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
        break;
    case REQ_AGENT_FID:
        change_bits.set(APPID_USERAGENT_BIT);
        break;
    case MISC_RESP_CODE_FID:
        change_bits.set(APPID_RESPONSE_BIT);
        break;
    case REQ_REFERER_FID:
        change_bits.set(APPID_REFERER_BIT);
        break;
    default:
        break;
    }
}

void AppIdHttpSession::set_scan_flags(HttpFieldIds id)
{
    switch (id)
    {
    case REQ_URI_FID:
        asd.scan_flags |= SCAN_HTTP_URI_FLAG;
        break;
    case MISC_VIA_FID:
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
        break;
    case REQ_AGENT_FID:
        asd.scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        break;
    case RSP_CONTENT_TYPE_FID:
        asd.scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        break;
    case MISC_SERVER_FID:
        asd.scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        break;
    case MISC_XWW_FID:
        asd.scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        break;
    case REQ_HOST_FID:
    case MISC_URL_FID:
        asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        break;
    default:
        break;
    }
}

void AppIdHttpSession::set_tun_dest()
{
    assert(meta_data[REQ_URI_FID]);
    char *host = nullptr, *host_start, *host_end = nullptr, *url_end;
    char *port_str = nullptr;
    uint16_t port = 0;
    int is_IPv6 = 0;
    char* url = strdup(meta_data[REQ_URI_FID]->c_str());
    url_end = url + strlen(url) - 1;
    host_start = url;

    if (url[0] == '[')
    {
        is_IPv6 = 1;
        port_str = strchr(url, ']');
        if (port_str && port_str < url_end)
        {
            if (*(++port_str) != ':')
            {
                port_str = nullptr;
            }
        }
    }
    else if(isdigit(url[0]))
    {
        port_str = strrchr(url, ':');
    }

    if (port_str && port_str < url_end )
    {
        host_end = port_str;
        if (*(++port_str) != '\0')
        {
            char *end = nullptr;
            long ret = strtol(port_str, &end, 10);
            if (end != port_str && *end == '\0' && ret >= 1 && ret <= PORT_MAX)
            {
                port = (uint16_t)ret;
            }
        }
    }

    if (port)
    {
        if (is_IPv6)
        {
            host_start++;
            host_end--;
        }

        if (host_start <= host_end)
        {
            char tmp = *host_end;
            *host_end = '\0';
            host = strdup(host_start);
            *host_end = tmp;
        }
    }
    if (host)
    {
        if(tun_dest)
            delete tun_dest;
        tun_dest= new TunnelDest(host, port);
        free(host);
    }
    free(url );
}

bool AppIdHttpSession::initial_chp_sweep(ChpMatchDescriptor& cmd, HttpPatternMatchers& http_matchers)
{
    CHPApp* cah = nullptr;

    for (unsigned i = 0; i <= MAX_KEY_PATTERN; i++)
    {
        if (cmd.buffer[i] && cmd.length[i])
        {
            cmd.cur_ptype = (HttpFieldIds)i;
            http_matchers.scan_key_chp(cmd);
        }
    }

    if (cmd.match_tally.empty())
    {
        free_chp_matches(cmd, MAX_KEY_PATTERN);
        return false;
    }

    int longest = 0;
    for (auto& item: cmd.match_tally)
    {
        // Only those items with key_pattern_countdown field reduced to zero are a full match
        if (item.key_pattern_countdown)
            continue;
        if (longest < item.key_pattern_length_sum)
        {
            // We've found a new longest pattern set
            longest = item.key_pattern_length_sum;
            cah = item.chpapp;
        }
    }

    if ( !cah )
    {
        free_chp_matches(cmd, MAX_KEY_PATTERN);
        return false;
    }

    /***************************************************************
       candidate has been chosen and it is pointed to by cah
       we will preserve any match sets until the calls to scanCHP()
     ***************************************************************/
    for (unsigned i = 0; i < NUM_HTTP_FIELDS; i++)
    {
        ptype_scan_counts[i] = cah->ptype_scan_counts[i];
        ptype_req_counts[i] = cah->ptype_req_counts[i] + cah->ptype_rewrite_insert_used[i];
        if (i > 3 && !cah->ptype_scan_counts[i]
            && !asd.get_session_flags(APPID_SESSION_SPDY_SESSION))
        {
            asd.clear_session_flags(APPID_SESSION_CHP_INSPECTING);
            if (asd.tpsession)
                asd.tpsession->clear_attr(TP_ATTR_CONTINUE_MONITORING);
        }
    }
    chp_candidate = cah->appIdInstance;
    app_type_flags = cah->app_type_flags;
    num_matches = cah->num_matches;
    num_scans = cah->num_scans;

    if (asd.tpsession)
    {
        if ((ptype_scan_counts[RSP_CONTENT_TYPE_FID]))
            asd.tpsession->set_attr(TP_ATTR_COPY_RESPONSE_CONTENT);
        else
            asd.tpsession->clear_attr(TP_ATTR_COPY_RESPONSE_CONTENT);

        if ((ptype_scan_counts[RSP_LOCATION_FID]))
            asd.tpsession->set_attr(TP_ATTR_COPY_RESPONSE_LOCATION);
        else
            asd.tpsession->clear_attr(TP_ATTR_COPY_RESPONSE_LOCATION);

        if ((ptype_scan_counts[RSP_BODY_FID]))
            asd.tpsession->set_attr(TP_ATTR_COPY_RESPONSE_BODY);
        else
            asd.tpsession->clear_attr(TP_ATTR_COPY_RESPONSE_BODY);
    }

    return true;
}

void AppIdHttpSession::init_chp_match_descriptor(ChpMatchDescriptor& cmd)
{
    for (int i = REQ_AGENT_FID; i < NUM_HTTP_FIELDS; i++)
    {
        const std::string* field = meta_data[i];
        if (field)
        {
            cmd.buffer[i] = field->c_str();
            cmd.length[i] = field->size();
        }
        else
        {
            cmd.buffer[i] = nullptr;
            cmd.length[i] = 0;
        }
    }
}

void AppIdHttpSession::process_chp_buffers(AppidChangeBits& change_bits, HttpPatternMatchers& http_matchers)
{
    ChpMatchDescriptor cmd;

    init_chp_match_descriptor(cmd);
    if ( chp_hold_flow )
        chp_finished = false;

    if ( !chp_candidate )
    {
        if ( !initial_chp_sweep(cmd, http_matchers) )
            chp_finished = true; // this is a failure case.
    }

    if (chp_finished or !chp_candidate)
        return;

    char* user = nullptr;
    char* version = nullptr;

    for (unsigned i = 0; i < NUM_HTTP_FIELDS; i++)
    {
        if ( !ptype_scan_counts[i] )
            continue;

        if ( cmd.buffer[i] && cmd.length[i] )
        {
            int num_found = 0;
            cmd.cur_ptype = (HttpFieldIds)i;
            AppId ret = http_matchers.scan_chp(cmd, &version, &user, &num_found, this, asd.get_odp_ctxt());
            total_found += num_found;
            if (!ret || num_found < ptype_req_counts[i])
            {
                // No match at all or the required matches for the field was NOT made
                if (!num_matches)
                {
                    // num_matches == 0 means: all must succeed
                    // give up early
                    chp_candidate = 0;
                    break;
                }
            }
        }
        else if ( !num_matches )
        {
            // num_matches == 0 means: all must succeed  give up early
            chp_candidate = 0;
            break;
        }

        // Decrement the expected scan count toward 0.
        ptype_scan_counts[i] = 0;
        num_scans--;
        // if we have reached the end of the list of scans (which have something to do), then
        // num_scans == 0
        if (num_scans == 0)
        {
            // we finished the last scan
            // either the num_matches value was zero and we failed early-on or we need to check
            // for the min.
            if (num_matches && total_found < num_matches)
            {
                // There was a minimum scans match count (num_matches != 0)
                // And we did not reach that minimum
                chp_candidate = 0;
                break;
            }
            // All required matches were met.
            chp_finished = true;
            break;
        }
    }

    // pass the index of last chp_matcher, not the length the array!
    free_chp_matches(cmd, NUM_HTTP_FIELDS-1);

    if ( !chp_candidate )
    {
        chp_finished = true;
        if ( version )
        {
            snort_free(version);
            version = nullptr;
        }

        if ( user )
        {
            snort_free(user);
            user = nullptr;
        }

        memset(ptype_scan_counts, 0, sizeof(ptype_scan_counts));

        // Make it possible for other detectors to run.
        skip_simple_detect = false;
        return;
    }

    if (chp_finished)
    {
        AppId chp_final = chp_alt_candidate ? chp_alt_candidate
            : CHP_APPIDINSTANCE_TO_ID(chp_candidate);

        if (app_type_flags & APP_TYPE_SERVICE)
            asd.set_service_appid_data(chp_final, change_bits, version);

        if (app_type_flags & APP_TYPE_CLIENT)
            set_client(chp_final, change_bits, "CHP", version);

        if ( app_type_flags & APP_TYPE_PAYLOAD )
            set_payload(chp_final, change_bits, "CHP", version);

        if ( version )
        {
            snort_free(version);
            version = nullptr;
        }

        if ( user )
        {
            if (app_type_flags & APP_TYPE_SERVICE)
                client.update_user(chp_final, user, change_bits);
            else
                client.update_user(asd.get_service_id(), user, change_bits);
            user = nullptr;
            asd.set_user_logged_in();
        }

        chp_candidate = 0;
        chp_hold_flow = false;
        asd.scan_flags &= ~SCAN_HTTP_VIA_FLAG;
        asd.scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
        asd.scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
        memset(ptype_scan_counts, 0, sizeof(ptype_scan_counts));
    }
    else /* if we have a candidate, but we're not finished */
    {
        if ( user )
        {
            snort_free(user);
            user = nullptr;
        }
    }
}

void AppIdHttpSession::set_client(AppId app_id, AppidChangeBits& change_bits,
    const char* type, const char* version)
{
    if (app_id <= APP_ID_NONE or (app_id == client.get_id()))
        return;

    client.set_id(app_id);
    change_bits.set(APPID_CLIENT_BIT);
    assert(asd.flow);
    if (asd.flow->ha_state)
        asd.flow->ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    if (asd.get_service_id() == APP_ID_HTTP2)
        AppIdPegCounts::inc_client_count(app_id);

    if (version)
    {
        client.set_version(version);
        change_bits.set(APPID_CLIENT_INFO_BIT);
    }

    if (appidDebug->is_active())
    {
        const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
        LogMessage("AppIdDbg %s %s is client %s (%d)\n", appidDebug->get_debug_session(),
            type, app_name ? app_name : "unknown", app_id);
    }
}

void AppIdHttpSession::set_payload(AppId app_id, AppidChangeBits& change_bits,
    const char* type, const char* version)
{
    if (app_id == APP_ID_NONE or (app_id == payload.get_id()))
        return;

    payload.set_id(app_id);
    change_bits.set(APPID_PAYLOAD_BIT);
    assert(asd.flow);
    if (asd.flow->ha_state)
        asd.flow->ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    if (asd.get_service_id() == APP_ID_HTTP2)
        AppIdPegCounts::inc_payload_count(app_id);
    payload.set_version(version);

    if (appidDebug->is_active())
    {
        const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
        if(app_id == APP_ID_UNKNOWN)
            LogMessage("AppIdDbg %s Payload is Unknown (%d)\n", appidDebug->get_debug_session(),
                app_id);
        else
            LogMessage("AppIdDbg %s %s is payload %s (%d)\n", appidDebug->get_debug_session(),
                type, app_name ? app_name : "unknown", app_id);
    }
}

void AppIdHttpSession::set_referred_payload(AppId app_id, AppidChangeBits& change_bits)
{
    if (app_id <= APP_ID_NONE or (app_id == referred_payload_app_id))
        return;

    referred_payload_app_id = app_id;
    if (asd.get_service_id() == APP_ID_HTTP2)
        AppIdPegCounts::inc_referred_count(app_id);
    change_bits.set(APPID_REFERRED_BIT);

    if (appidDebug->is_active())
    {
        const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
        LogMessage("AppIdDbg %s URL is referred %s (%d)\n", appidDebug->get_debug_session(),
            app_name ? app_name : "unknown", app_id);
    }
}

int AppIdHttpSession::process_http_packet(AppidSessionDirection direction,
    AppidChangeBits& change_bits, HttpPatternMatchers& http_matchers)
{
    const std::string* useragent = meta_data[REQ_AGENT_FID];
    const std::string* host = meta_data[REQ_HOST_FID];
    const std::string* referer = meta_data[REQ_REFERER_FID];
    const std::string* uri = meta_data[REQ_URI_FID];

    // For fragmented HTTP headers, do not process if none of the fields are set.
    // These fields will get set when the HTTP header is reassembled.
    if ( !useragent && !host && !referer && !uri )
    {
        if (!skip_simple_detect)
            asd.clear_http_flags();
        return 0;
    }

    if ( direction == APP_ID_FROM_RESPONDER &&
        !asd.get_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED) )
    {
        const std::string* response_code;
        if ( (response_code = meta_data[MISC_RESP_CODE_FID]) != nullptr )
        {
            asd.set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            constexpr auto RESPONSE_CODE_LENGTH = 3;
            if (response_code->size() != RESPONSE_CODE_LENGTH)
            {
                if (appidDebug->is_active())
                    LogMessage("AppIdDbg %s Bad http response code.\n",
                        appidDebug->get_debug_session());
                asd.reset_session_data(change_bits);
                return 0;
            }
        }
#if RESPONSE_CODE_PACKET_THRESHHOLD
        else if (++(response_code_packets) == RESPONSE_CODE_PACKET_THRESHHOLD)
        {
            set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            /* didn't receive response code in first X packets. Stop processing this session */
            asd.reset_session_data(change_bits);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s No response code received\n",
                    appidDebug->get_debug_session());
            return 0;
        }
#endif
    }

    if (asd.get_service_id() == APP_ID_NONE or asd.get_service_id() == APP_ID_HTTP2)
    {
        if (asd.get_service_id() == APP_ID_NONE)
            asd.set_service_id(APP_ID_HTTP, asd.get_odp_ctxt());
        asd.set_session_flags(APPID_SESSION_SERVICE_DETECTED);
        asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
    }

    if (!chp_finished || chp_hold_flow)
        process_chp_buffers(change_bits, http_matchers);

    if (skip_simple_detect) // true if process_chp_buffers() found match
        return 0;

    if (!asd.get_session_flags(APPID_SESSION_APP_REINSPECT))
    {
        // Scan Server Header for Vendor & Version
        const std::string* server = meta_data[MISC_SERVER_FID];
        if ( (asd.scan_flags & SCAN_HTTP_VENDOR_FLAG) and server)
        {
            if ( asd.get_service_id() == APP_ID_NONE or asd.get_service_id() == APP_ID_HTTP  or
                asd.get_service_id() == APP_ID_HTTP2)
            {
                char* vendorVersion = nullptr;
                char* vendor = nullptr;
                AppIdServiceSubtype* subtype = nullptr;

                http_matchers.get_server_vendor_version(server->c_str(), server->size(),
                    &vendorVersion, &vendor, &subtype);
                if (vendor || vendorVersion)
                {
                    asd.set_service_vendor(vendor, change_bits);
                    asd.set_service_version(vendorVersion, change_bits);
                    asd.scan_flags &= ~SCAN_HTTP_VENDOR_FLAG;

                    snort_free(vendor);
                    snort_free(vendorVersion);
                }

                if (subtype)
                    asd.add_service_subtype(*subtype, change_bits);
            }
        }

        if (is_webdav)
            set_payload(APP_ID_WEBDAV, change_bits, "webdav");

        // Scan User-Agent for Browser types or Skype
        if ( (asd.scan_flags & SCAN_HTTP_USER_AGENT_FLAG)
            and client.get_id() <= APP_ID_NONE and useragent )
        {
            char* version = nullptr;
            AppId service_id = APP_ID_NONE;
            AppId client_id = APP_ID_NONE;

            http_matchers.identify_user_agent(useragent->c_str(), useragent->size(),
                service_id, client_id, &version);
            if (appidDebug->is_active())
            {
                if (service_id > APP_ID_NONE and service_id != APP_ID_HTTP and
                    asd.get_service_id() != service_id)
                {
                    const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(service_id);
                    LogMessage("AppIdDbg %s User Agent is service %s (%d)\n",
                        appidDebug->get_debug_session(), app_name ? app_name : "unknown", service_id);
                }
            }
            asd.set_service_appid_data(service_id, change_bits);
            if (client_id != APP_ID_HTTP)
                set_client(client_id, change_bits, "User Agent", version);

            asd.scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            snort_free(version);
        }

        /* Scan Via Header for squid */
        const std::string* via = meta_data[MISC_VIA_FID];
        if ( !asd.get_tp_payload_app_id() and payload.get_id() <= APP_ID_NONE and
            (asd.scan_flags & SCAN_HTTP_VIA_FLAG) and via )
        {
            AppId payload_id = http_matchers.get_appid_by_pattern(via->c_str(), via->size(),
                nullptr);
            set_payload(payload_id, change_bits, "VIA");
            is_payload_processed = true;
            asd.scan_flags &= ~SCAN_HTTP_VIA_FLAG;
        }
    }

    /* Scan X-Working-With HTTP header */
    const std::string* x_working_with = meta_data[MISC_XWW_FID];
    if ( (asd.scan_flags & SCAN_HTTP_XWORKINGWITH_FLAG) and x_working_with)
    {
        char* version = nullptr;

        AppId app_id = http_matchers.scan_header_x_working_with(x_working_with->c_str(),
            x_working_with->size(), &version);

        if (direction == APP_ID_FROM_INITIATOR)
            set_client(app_id, change_bits, "X-working-with", version);
        else
        {
            if (app_id and asd.get_service_id() != app_id)
            {
                asd.set_service_appid_data(app_id, change_bits, version);
                if (appidDebug->is_active())
                {
                    const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
                    LogMessage("AppIdDbg %s X service %s (%d)\n", appidDebug->get_debug_session(),
                        app_name ? app_name : "unknown", app_id);
                }
            }
        }
        asd.scan_flags &= ~SCAN_HTTP_XWORKINGWITH_FLAG;

        snort_free(version);
    }

    // Scan Content-Type Header for multimedia types and scan contents
    const std::string* content_type = meta_data[RSP_CONTENT_TYPE_FID];
    if ( (asd.scan_flags & SCAN_HTTP_CONTENT_TYPE_FLAG)
         and content_type and !asd.get_tp_payload_app_id() and payload.get_id() <= APP_ID_NONE)
    {
        AppId payload_id = http_matchers.get_appid_by_content_type(content_type->c_str(),
            content_type->size());
        set_payload(payload_id, change_bits, "Content-Type");
        is_payload_processed = true;
        asd.scan_flags &= ~SCAN_HTTP_CONTENT_TYPE_FLAG;
    }

    if (asd.scan_flags & SCAN_HTTP_HOST_URL_FLAG)
    {
        AppId referredPayloadAppId = APP_ID_NONE;
        char* version = nullptr;
        char* my_host = host ? snort_strdup(host->c_str()) : nullptr;
        const char* refStr = referer ? referer->c_str() : nullptr;
        const std::string* url = meta_data[MISC_URL_FID];
        const char* urlStr = url ? url->c_str() : nullptr;
        AppId service_id = APP_ID_NONE;
        AppId client_id = APP_ID_NONE;
        AppId payload_id = APP_ID_NONE;

        if ( http_matchers.get_appid_from_url(my_host, urlStr, &version,
            refStr, &client_id, &service_id, &payload_id,
            &referredPayloadAppId, false, asd.get_odp_ctxt()) )
        {
            // do not overwrite a previously-set client or service
            if (client.get_id() <= APP_ID_NONE and client_id != APP_ID_HTTP)
                set_client(client_id, change_bits, "URL", version);

            if (asd.get_service_id() <= APP_ID_NONE)
            {
                if (appidDebug->is_active() && service_id > APP_ID_NONE && service_id !=
                    APP_ID_HTTP && asd.get_service_id() != service_id)
                {
                    const char *app_name = asd.get_odp_ctxt().get_app_info_mgr().get_app_name(service_id);
                    LogMessage("AppIdDbg %s URL is service %s (%d)\n",
                        appidDebug->get_debug_session(),
                        app_name ? app_name : "unknown",
                        service_id);
                }
                asd.set_service_appid_data(service_id, change_bits);
            }

            // DO overwrite a previously-set payload
            set_payload(payload_id, change_bits, "URL");
            set_referred_payload(referredPayloadAppId, change_bits);
        }

        is_payload_processed = true;
        asd.scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
        if ( version )
            snort_free(version);
        if ( my_host )
            snort_free(my_host);
    }

    if (client.get_id() == APP_ID_APPLE_CORE_MEDIA)
    {
        AppInfoTableEntry* entry;
        AppId tp_payload_app_id = asd.get_tp_payload_app_id();
        if (tp_payload_app_id > APP_ID_NONE)
        {
            entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(tp_payload_app_id);
            // only move tpPayloadAppId to client if client app id is valid
            if (entry && entry->clientId > APP_ID_NONE)
            {
                misc_app_id = client.get_id();
                client.set_id(tp_payload_app_id);
            }
        }
        else if (payload.get_id() > APP_ID_NONE)
        {
            entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(payload.get_id());
            // only move payload_app_id to client if it has a ClientAppid
            if (entry && entry->clientId > APP_ID_NONE)
            {
                misc_app_id = client.get_id();
                client.set_id(payload.get_id());
            }
        }
    }
    if (payload.get_id() <= APP_ID_NONE and is_payload_processed and
        (asd.get_service_id() == APP_ID_HTTP2 or (asd.get_service_id() == APP_ID_HTTP and
            asd.is_tp_appid_available())))
        set_payload(APP_ID_UNKNOWN, change_bits);

    asd.clear_http_flags();

    return 0;
}

void AppIdHttpSession::update_url(AppidChangeBits& change_bits)
{
    const std::string* host = meta_data[REQ_HOST_FID];
    const std::string* uri = meta_data[REQ_URI_FID];
    if (host and uri)
    {
        if (meta_data[MISC_URL_FID])
            delete meta_data[MISC_URL_FID];
        if (asd.get_session_flags(APPID_SESSION_DECRYPTED))
            meta_data[MISC_URL_FID] = new std::string(std::string("https://") + *host + *uri);
        else
            meta_data[MISC_URL_FID] = new std::string(std::string("http://") + *host + *uri);
        change_bits.set(APPID_URL_BIT);
        asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
    }
}

void AppIdHttpSession::reset_ptype_scan_counts()
{
    memset(ptype_scan_counts, 0, sizeof(ptype_scan_counts));
}

void AppIdHttpSession::clear_all_fields()
{
    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
    {
        delete meta_data[i];
        meta_data[i] = nullptr;
    }
}

void AppIdHttpSession::set_field(HttpFieldIds id, const std::string* str,
    AppidChangeBits& change_bits)
{
    if (str and !str->empty())
    {
        delete meta_data[id];
        meta_data[id] = str;
        set_http_change_bits(change_bits, id);
        set_scan_flags(id);

        if (appidDebug->is_active())
            print_field(id, str);
    }
    else if (str)
        delete str;
}

void AppIdHttpSession::set_field(HttpFieldIds id, const uint8_t* str, int32_t len,
    AppidChangeBits& change_bits)
{
    if (str and len)
    {
        delete meta_data[id];
        meta_data[id] = new std::string((const char*)str, len);
        set_http_change_bits(change_bits, id);
        set_scan_flags(id);

        if (appidDebug->is_active())
            print_field(id, meta_data[id]);
    }
}

void AppIdHttpSession::set_req_body_field(HttpFieldIds id, const uint8_t* str, int32_t len,
    AppidChangeBits& change_bits)
{
    if (str and len)
    {
        if (rcvd_full_req_body)
        {
            delete meta_data[id];
            meta_data[id] = nullptr;
            rcvd_full_req_body = false;
        }

        if (!meta_data[id])
            meta_data[id] = new std::string((const char*)str, len);
        else
        {
            std::string *req_body = new std::string(*meta_data[id]);
            delete meta_data[id];
            req_body->append((const char*)str);
            meta_data[id] = req_body;
        }
        set_http_change_bits(change_bits, id);
        set_scan_flags(id);

        if (appidDebug->is_active())
            print_field(id, meta_data[id]);
    }
}
void AppIdHttpSession::print_field(HttpFieldIds id, const std::string* field)
{
    string field_name;

    if (asd.get_session_flags(APPID_SESSION_SPDY_SESSION))
        field_name = "SPDY ";
    else if (asd.get_session_flags(APPID_SESSION_HTTP_SESSION))
      field_name = "HTTP ";
    else
        // This could be RTMP session; not printing RTMP fields for now
        return;

    switch (id)
    {
    case REQ_AGENT_FID:
        field_name += "user agent";
        break;

    case REQ_HOST_FID:
        field_name += "host";
        break;

    case REQ_REFERER_FID:
        field_name += "referer";
        break;

    case REQ_URI_FID:
        field_name += "URI";
        break;

    case REQ_COOKIE_FID:
        field_name += "cookie";
        break;

    case REQ_BODY_FID:
        field_name += "request body";
        break;

    case RSP_CONTENT_TYPE_FID:
        field_name += "content type";
        break;

    case RSP_LOCATION_FID:
        field_name += "location";
        break;

    case MISC_VIA_FID:
        field_name += "via";
        break;

    case MISC_RESP_CODE_FID:
        field_name += "response code";
        break;

    case MISC_SERVER_FID:
        field_name += "server";
        break;

    case MISC_XWW_FID:
        field_name += "x-working-with";
        break;

    // don't print these fields
    case MISC_URL_FID:
    case RSP_BODY_FID:
    default:
        return;
    }

    if (http2_stream_id > 0)
        LogMessage("AppIdDbg %s stream %u: %s is %s\n", appidDebug->get_debug_session(),
            http2_stream_id, field_name.c_str(), field->c_str());
    else
        LogMessage("AppIdDbg %s %s is %s\n", appidDebug->get_debug_session(),
            field_name.c_str(), field->c_str());
}
