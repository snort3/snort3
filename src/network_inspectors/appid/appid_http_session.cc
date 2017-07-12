//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_inspector.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Apr 19, 2017

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_http_session.h"

#include "appid_config.h"
#include "appid_module.h"
#include "appid_session.h"
#include "app_info_table.h"
#include "thirdparty_appid_utils.h"
#include "profiler/profiler.h"

static const char* httpFieldName[ NUMBER_OF_PTYPES ] = // for use in debug messages
{
    "useragent",
    "host",
    "referer",
    "uri",
    "cookie",
    "req_body",
    "content_type",
    "location",
    "body",
};

ProfileStats httpPerfStats;

AppIdHttpSession::AppIdHttpSession(AppIdSession* asd)
    : asd(asd)
{
    http_matchers = HttpPatternMatchers::get_instance();
}

AppIdHttpSession::~AppIdHttpSession()
{
    snort_free(body);
    snort_free(content_type);
    snort_free(cookie);
    snort_free(host);
    snort_free(location);
    snort_free(referer);
    snort_free(req_body);
    snort_free(response_code);
    snort_free(server);
    snort_free(uri);
    snort_free(url);
    snort_free(useragent);
    snort_free(via);
    snort_free(x_working_with);
    delete xffAddr;

    if (new_field_contents)
        for ( unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
            if (nullptr != new_field[i])
                snort_free(new_field[i]);
}

void AppIdHttpSession::free_chp_matches(ChpMatchDescriptor& cmd, unsigned max_matches)
{
    for (unsigned i = 0; i <= max_matches; i++)
        if ( cmd.chp_matches[i].size() )
            cmd.chp_matches[i].clear();
}

int AppIdHttpSession::initial_chp_sweep(ChpMatchDescriptor& cmd)
{
    CHPApp* cah = nullptr;

    for (unsigned i = 0; i <= MAX_KEY_PATTERN; i++)
    {
        if (cmd.buffer[i] && cmd.length[i])
        {
            cmd.cur_ptype = (PatternType)i;
            http_matchers->scan_key_chp(cmd);
        }

    }

    if (cmd.match_tally.empty())
    {
        free_chp_matches(cmd, MAX_KEY_PATTERN);
        return 0;
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
        return 0;
    }

    /***************************************************************
       candidate has been chosen and it is pointed to by cah
       we will preserve any match sets until the calls to scanCHP()
      ***************************************************************/
    for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
    {
        ptype_scan_counts[i] = cah->ptype_scan_counts[i];
        ptype_req_counts[i] = cah->ptype_req_counts[i] +
            cah->ptype_rewrite_insert_used[i];
        if (i > 3 && !cah->ptype_scan_counts[i]
            && !asd->get_session_flags(APPID_SESSION_SPDY_SESSION))
        {
            asd->clear_session_flags(APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_clear(asd->tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
    }
    chp_candidate = cah->appIdInstance;
    app_type_flags = cah->app_type_flags;
    num_matches = cah->num_matches;
    num_scans = cah->num_scans;

    if (thirdparty_appid_module)
    {
        if ((ptype_scan_counts[CONTENT_TYPE_PT]))
            thirdparty_appid_module->session_attr_set(asd->tpsession,
                TP_ATTR_COPY_RESPONSE_CONTENT);
        else
            thirdparty_appid_module->session_attr_clear(asd->tpsession,
                TP_ATTR_COPY_RESPONSE_CONTENT);

        if ((ptype_scan_counts[LOCATION_PT]))
            thirdparty_appid_module->session_attr_set(asd->tpsession,
                TP_ATTR_COPY_RESPONSE_LOCATION);
        else
            thirdparty_appid_module->session_attr_clear(asd->tpsession,
                TP_ATTR_COPY_RESPONSE_LOCATION);

        if ((ptype_scan_counts[BODY_PT]))
            thirdparty_appid_module->session_attr_set(asd->tpsession, TP_ATTR_COPY_RESPONSE_BODY);
        else
            thirdparty_appid_module->session_attr_clear(asd->tpsession,
                TP_ATTR_COPY_RESPONSE_BODY);
    }

    return 1;
}

void AppIdHttpSession::init_chp_match_descriptor(ChpMatchDescriptor& cmd)
{
   cmd.buffer[AGENT_PT] = useragent;
   cmd.buffer[HOST_PT] = host;
   cmd.buffer[REFERER_PT] = referer;
   cmd.buffer[URI_PT] = uri;
   cmd.buffer[COOKIE_PT] = cookie;
   cmd.buffer[REQ_BODY_PT] = req_body;
   cmd.buffer[CONTENT_TYPE_PT] = content_type;
   cmd.buffer[LOCATION_PT] = location;
   cmd.buffer[BODY_PT] = body;

   cmd.length[AGENT_PT] = useragent_buflen;
   cmd.length[HOST_PT] = host_buflen;
   cmd.length[REFERER_PT] = referer_buflen;
   cmd.length[URI_PT] = uri_buflen;
   cmd.length[COOKIE_PT] = cookie_buflen;
   cmd.length[REQ_BODY_PT] = req_body_buflen;
   cmd.length[CONTENT_TYPE_PT] = content_type_buflen;
   cmd.length[LOCATION_PT] = location_buflen;
   cmd.length[BODY_PT] = body_buflen;
}

void AppIdHttpSession::process_chp_buffers()
{
    ChpMatchDescriptor cmd;

    init_chp_match_descriptor(cmd);
    if ( chp_hold_flow )
        chp_finished = false;

    if ( !chp_candidate )
    {
        // remove artifacts from previous matches before we start again.
        for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
            if (new_field[i])
            {
                snort_free(new_field[i]);
                new_field[i] = nullptr;
            }

        if ( !initial_chp_sweep(cmd) )
            chp_finished = true; // this is a failure case.
    }

    if ( !chp_finished && chp_candidate )
    {
        char* user = nullptr;
        char* version = nullptr;

        for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if ( !ptype_scan_counts[i] )
                continue;

            if ( cmd.buffer[i] && cmd.length[i] )
            {
                int num_found = 0;
                cmd.cur_ptype = (PatternType)i;
                AppId ret = http_matchers->scan_chp(cmd, &version, &user, &num_found, this,
                        asd->config->mod_config);
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
                if (num_matches &&
                    total_found < num_matches)
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

        free_chp_matches(cmd, NUMBER_OF_PTYPES);

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

            cmd.free_rewrite_buffers();
            memset(ptype_scan_counts, 0, NUMBER_OF_PTYPES * sizeof(int));

            // Make it possible for other detectors to run.
            skip_simple_detect = false;
            return;
        }

        if (chp_candidate && chp_finished)
        {
            AppId chp_final = chp_alt_candidate ? chp_alt_candidate
                : CHP_APPIDINSTANCE_TO_ID(chp_candidate);

            if (app_type_flags & APP_TYPE_SERVICE)
                asd->set_service_appid_data(chp_final, nullptr, version);

            if (app_type_flags & APP_TYPE_CLIENT)
                asd->set_client_app_id_data(chp_final, version);

            if ( app_type_flags & APP_TYPE_PAYLOAD )
                asd->set_payload_app_id_data((ApplicationId)chp_final, version);

            if ( version )
                version = nullptr;

            if ( user )
            {
                asd->username = user;
                user = nullptr;
                if (app_type_flags & APP_TYPE_SERVICE)
                    asd->username_service = chp_final;
                else
                    asd->username_service = asd->service_app_id;
                asd->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
            }

            for (unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
                if ( cmd.chp_rewritten[i] )
                {
                    if (asd->session_logging_enabled)
                        LogMessage("AppIdDbg %s rewritten %s: %s\n", asd->session_logging_id,
                            httpFieldName[i], cmd.chp_rewritten[i]);
                    if (new_field[i])
                        snort_free(new_field[i]);
                    new_field[i] = cmd.chp_rewritten[i];
                    new_field_contents = true;
                    cmd.chp_rewritten[i] = nullptr;
                }

            chp_candidate = 0;
            //if we're doing safesearch rewrites, we want to continue to hold the flow
            if (!get_offsets_from_rebuilt)
                chp_hold_flow = 0;
            asd->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            asd->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            asd->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
            memset(ptype_scan_counts, 0,
                NUMBER_OF_PTYPES * sizeof(ptype_scan_counts[0]));
        }
        else /* if we have a candidate, but we're not finished */
        {
            if ( user )
            {
                snort_free(user);
                user = nullptr;
            }

            cmd.free_rewrite_buffers();
        }
    }
}

int AppIdHttpSession::process_http_packet(int direction)
{
    Profile http_profile_context(httpPerfStats);
    constexpr auto RESPONSE_CODE_LENGTH = 3;
    AppId service_id = APP_ID_NONE;
    AppId client_id = APP_ID_NONE;
    AppId payload_id = APP_ID_NONE;

    // For fragmented HTTP headers, do not process if none of the fields are set.
    // These fields will get set when the HTTP header is reassembled.
    if ((!useragent) && (!host) && (!referer) && (!uri))
    {
        if (!skip_simple_detect)
            asd->clear_http_flags();

        return 0;
    }

    if (direction == APP_ID_FROM_RESPONDER &&
        !asd->get_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED))
    {
        if (response_code)
        {
            asd->set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            if (response_code_buflen != RESPONSE_CODE_LENGTH)
            {
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s bad http response code.\n", asd->session_logging_id);
                asd->reset_session_data();
                return 0;
            }
        }
#if RESPONSE_CODE_PACKET_THRESHHOLD
        else if (++(response_code_packets) == RESPONSE_CODE_PACKET_THRESHHOLD)
        {
            set_session_flags(APPID_SESSION_RESPONSE_CODE_CHECKED);
            /* didn't receive response code in first X packets. Stop processing this session */
            asd->reset_session_data();
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s no response code received\n", asd->session_logging_id);
            return 0;
        }
#endif
    }

    if (asd->service_app_id == APP_ID_NONE)
        asd->service_app_id = APP_ID_HTTP;

    if (asd->session_logging_enabled)
        LogMessage("AppIdDbg %s chp_finished %d chp_hold_flow %d\n", asd->session_logging_id,
            chp_finished, chp_hold_flow);

    if (!chp_finished || chp_hold_flow)
        process_chp_buffers();

    if (!skip_simple_detect)  // true if processCHP found match
    {
        if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
        {
            // Scan Server Header for Vendor & Version
            // FIXIT-M: Should we be checking the scan_flags even when
            //     thirdparty_appid_module is off?
            if ((thirdparty_appid_module && (asd->scan_flags & SCAN_HTTP_VENDOR_FLAG) &&
                server) || (!thirdparty_appid_module && server))
            {
                if (asd->service_app_id == APP_ID_NONE || asd->service_app_id == APP_ID_HTTP)
                {
                    AppIdServiceSubtype* local_subtype = nullptr;
                    char* vendorVersion = nullptr;
                    char* vendor = nullptr;

                    http_matchers->get_server_vendor_version((uint8_t*)server,
                        strlen(server), &vendorVersion, &vendor, &asd->subtype);
                    if (vendor || vendorVersion)
                    {
                        if (asd->service_vendor)
                        {
                            snort_free(asd->service_vendor);
                            asd->service_vendor = nullptr;
                        }
                        if (asd->service_version)
                        {
                            snort_free(asd->service_version);
                            asd->service_version = nullptr;
                        }
                        if (vendor)
                            asd->service_vendor = vendor;
                        if (vendorVersion)
                            asd->service_version = vendorVersion;
                        asd->scan_flags &= ~SCAN_HTTP_VENDOR_FLAG;
                    }
                    if (local_subtype)
                    {
                        AppIdServiceSubtype** tmpSubtype;

                        for (tmpSubtype = &asd->subtype; *tmpSubtype; tmpSubtype =
                            &(*tmpSubtype)->next)
                            ;

                        *tmpSubtype = local_subtype;
                    }
                }
            }

            if (is_webdav)
            {
                if (asd->session_logging_enabled and asd->payload_app_id != APP_ID_WEBDAV)
                    LogMessage("AppIdDbg %s data is webdav\n", asd->session_logging_id);
                asd->set_payload_app_id_data(APP_ID_WEBDAV, nullptr);
            }

            // Scan User-Agent for Browser types or Skype
            if ((asd->scan_flags & SCAN_HTTP_USER_AGENT_FLAG) && asd->client_app_id <= APP_ID_NONE
                && useragent && useragent_buflen)
            {
                char* version = nullptr;

                http_matchers->identify_user_agent((uint8_t*)useragent, useragent_buflen,
                    &service_id, &client_id, &version);
                if (asd->session_logging_enabled && service_id > APP_ID_NONE &&
                    service_id != APP_ID_HTTP && asd->service_app_id != service_id)
                    LogMessage("AppIdDbg %s User Agent is service %d\n", asd->session_logging_id,
                        service_id);
                asd->set_service_appid_data(service_id, nullptr, nullptr);
                if (asd->session_logging_enabled && client_id > APP_ID_NONE &&
                    client_id != APP_ID_HTTP && asd->client_app_id != client_id)
                    LogMessage("AppIdDbg %s User Agent is client %d\n", asd->session_logging_id,
                        client_id);
                asd->set_client_app_id_data(client_id, version);
                asd->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
                snort_free(version);
            }

            /* Scan Via Header for squid */
            int size;
            if (!asd->is_payload_appid_set() && (asd->scan_flags & SCAN_HTTP_VIA_FLAG) && via &&
                (size = strlen(via)) > 0)
            {
                payload_id = http_matchers->get_appid_by_pattern((uint8_t*)via, size, nullptr);
                if (asd->session_logging_enabled && payload_id > APP_ID_NONE &&
                    asd->payload_app_id != payload_id)
                    LogMessage("AppIdDbg %s VIA is data %d\n", asd->session_logging_id,
                        payload_id);
                asd->set_payload_app_id_data((ApplicationId)payload_id, nullptr);
                asd->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            }
        }

        /* Scan X-Working-With HTTP header */
        // FIXIT-M: Should we be checking the scan_flags even when
        //     thirdparty_appid_module is off?
        if ((thirdparty_appid_module && (asd->scan_flags & SCAN_HTTP_XWORKINGWITH_FLAG) &&
            x_working_with) || (!thirdparty_appid_module && x_working_with))
        {
            AppId appId;
            char* version = nullptr;

            appId = http_matchers->scan_header_x_working_with((uint8_t*)x_working_with,
                strlen(x_working_with), &version);
            if ( appId )
            {
                if (direction == APP_ID_FROM_INITIATOR)
                {
                    if (asd->session_logging_enabled && client_id > APP_ID_NONE && client_id !=
                        APP_ID_HTTP && asd->client_app_id != client_id)
                        LogMessage("AppIdDbg %s X is client %d\n", asd->session_logging_id, appId);

                    asd->set_client_app_id_data(appId, version);
                }
                else
                {
                    if (asd->session_logging_enabled && service_id > APP_ID_NONE && service_id !=
                        APP_ID_HTTP && asd->service_app_id != service_id)
                        LogMessage("AppIdDbg %s X is service %d\n", asd->session_logging_id,
                            appId);
                    asd->set_service_appid_data(appId, nullptr, version);
                }
                asd->scan_flags &= ~SCAN_HTTP_XWORKINGWITH_FLAG;
            }

            snort_free(version);
        }

        // Scan Content-Type Header for multimedia types and scan contents
        // FIXIT-M: Should we be checking the scan_flags even when
        //     thirdparty_appid_module is off?
        if ((thirdparty_appid_module && (asd->scan_flags & SCAN_HTTP_CONTENT_TYPE_FLAG)
            && content_type  && !asd->is_payload_appid_set())
            || (!thirdparty_appid_module && !asd->is_payload_appid_set() && content_type))
        {
            payload_id = http_matchers->get_appid_by_content_type((uint8_t*)content_type,
                strlen(content_type));
            if (asd->session_logging_enabled && payload_id > APP_ID_NONE
                && asd->payload_app_id != payload_id)
                LogMessage("AppIdDbg %s Content-Type is data %d\n", asd->session_logging_id,
                    payload_id);
            asd->set_payload_app_id_data((ApplicationId)payload_id, nullptr);
            asd->scan_flags &= ~SCAN_HTTP_CONTENT_TYPE_FLAG;
        }

        if (asd->scan_flags & SCAN_HTTP_HOST_URL_FLAG)
        {
            AppId referredPayloadAppId = 0;
            char* version = nullptr;

            if ( http_matchers->get_appid_from_url(host, url, &version, referer, &client_id,
                &service_id, &payload_id, &referredPayloadAppId, false) )
            {
                // do not overwrite a previously-set client or service
                if (asd->client_app_id <= APP_ID_NONE)
                {
                    if (asd->session_logging_enabled && client_id > APP_ID_NONE && client_id !=
                        APP_ID_HTTP && asd->client_app_id != client_id)
                        LogMessage("AppIdDbg %s URL is client %d\n", asd->session_logging_id,
                            client_id);
                    asd->set_client_app_id_data(client_id, nullptr);
                }

                if (asd->service_app_id <= APP_ID_NONE)
                {
                    if (asd->session_logging_enabled && service_id > APP_ID_NONE && service_id !=
                        APP_ID_HTTP && asd->service_app_id != service_id)
                        LogMessage("AppIdDbg %s URL is service %d\n", asd->session_logging_id,
                            service_id);
                    asd->set_service_appid_data(service_id, nullptr, nullptr);
                }

                // DO overwrite a previously-set data
                if (asd->session_logging_enabled && payload_id > APP_ID_NONE &&
                    asd->payload_app_id != payload_id)
                    LogMessage("AppIdDbg %s URL is data %d\n", asd->session_logging_id,
                        payload_id);
                asd->set_payload_app_id_data((ApplicationId)payload_id, version);
                asd->set_referred_payload_app_id_data(referredPayloadAppId);
            }

            asd->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
            snort_free(version);
        }

        if (asd->client_app_id == APP_ID_APPLE_CORE_MEDIA)
        {
            AppInfoTableEntry* entry;

            if (asd->tp_payload_app_id > APP_ID_NONE)
            {
                entry = asd->app_info_mgr->get_app_info_entry(asd->tp_payload_app_id);
                // only move tpPayloadAppId to client if its got a client_app_id
                if (entry && entry->clientId > APP_ID_NONE)
                {
                    asd->misc_app_id = asd->client_app_id;
                    asd->client_app_id = asd->tp_payload_app_id;
                }
            }
            else if (asd->payload_app_id > APP_ID_NONE)
            {
                entry =  asd->app_info_mgr->get_app_info_entry(asd->payload_app_id);
                // only move payload_app_id to client if it has a ClientAppid
                if (entry && entry->clientId > APP_ID_NONE)
                {
                    asd->misc_app_id = asd->client_app_id;
                    asd->client_app_id = asd->payload_app_id;
                }
            }
        }

        asd->clear_http_flags();
    }  // end DON'T skip_simple_detect

    return 0;
}

