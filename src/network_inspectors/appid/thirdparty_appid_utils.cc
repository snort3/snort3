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

// thirdparty_appid_utils.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "thirdparty_appid_utils.h"

#include <dlfcn.h>

#include "appid_config.h"
#include "appid_http_session.h"
#include "app_info_table.h"
#include "detector_plugins/http_url_patterns.h"
#include "service_plugins/service_ssl.h"

#include "protocols/packet.h"
#include "main/snort_debug.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "stream/stream.h"

#define MODULE_SYMBOL "thirdparty_appid_impl_module"

static THREAD_LOCAL void* module_handle = nullptr;
static THREAD_LOCAL struct ThirdPartyConfig thirdpartyConfig;
THREAD_LOCAL ThirdPartyAppIDModule* thirdparty_appid_module = nullptr;

static char const* defaultXffFields[] = { HTTP_XFF_FIELD_X_FORWARDED_FOR,
                                          HTTP_XFF_FIELD_TRUE_CLIENT_IP };

ProfileStats tpLibPerfStats;
ProfileStats tpPerfStats;

inline int testSSLAppIdForReinspect(AppId app_id)
{
    if (app_id <= SF_APPID_MAX &&
        (app_id == APP_ID_SSL || AppInfoManager::get_instance().get_app_info_flags(app_id,
        APPINFO_FLAG_SSL_INSPECT)))
        return 1;
    else
        return 0;
}

#ifdef REMOVED_WHILE_NOT_IN_USE
static int LoadCallback(const char* const path, int /* indent */)
{
    void* handle;
    ThirdPartyAppIDModule* tp_module;

    if (thirdparty_appid_module != nullptr)
    {
        ErrorMessage("Ignoring additional 3rd party AppID module (%s)!\n", path);
        return 0;
    }

    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr)
    {
        ErrorMessage("Failed to load 3rd party AppID module: %s - %s\n", path, dlerror());
        return 0;
    }

    tp_module = (ThirdPartyAppIDModule*)dlsym(handle, MODULE_SYMBOL);
    if (tp_module == nullptr)
    {
        ErrorMessage("Failed to fine symbol %s in library %s\n", MODULE_SYMBOL, path);
        dlclose(handle);
        return 0;
    }

    if ( (tp_module->api_version != THIRD_PARTY_APP_ID_API_VERSION)
        || ((tp_module->module_name == nullptr) || (tp_module->module_name[0] == 0))
        || (tp_module->init == nullptr)
        || (tp_module->fini == nullptr)
        || (tp_module->session_create == nullptr)
        || (tp_module->session_delete == nullptr)
        || (tp_module->session_process == nullptr)
        || (tp_module->print_stats == nullptr)
        || (tp_module->reset_stats == nullptr)
        || (tp_module->disable_flags == nullptr) )
    {
        ErrorMessage("Ignoring incomplete 3rd party AppID module (%s)!\n", path);
        dlclose(handle);
        return 0;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID, "Found 3rd party AppID module (%s).\n",
        tp_module->module_name ? tp_module->module_name : ""); );
    module_handle = handle;
    thirdparty_appid_module = tp_module;
    return 0;
}

#endif

static void getXffFields(void)
{
    // FIXIT-M need to get xff fields from http config
    char** xffFields = nullptr; // = _dpd.getHttpXffFields(&thirdpartyConfig.numXffFields);
    if (!xffFields)
    {
        xffFields = (char**)defaultXffFields;
        thirdpartyConfig.numXffFields = sizeof(defaultXffFields) / sizeof(defaultXffFields[0]);
    }
    thirdpartyConfig.xffFields = (char**)snort_alloc(thirdpartyConfig.numXffFields *
        sizeof(char*));
    for (unsigned i = 0; i < thirdpartyConfig.numXffFields; i++)
        thirdpartyConfig.xffFields[i] = snort_strndup(xffFields[i], UINT8_MAX);
}

void ThirdPartyAppIDInit(AppIdModuleConfig* config)
{
    const char* thirdparty_appid_dir = config->thirdparty_appid_dir;
    int ret;
    struct ThirdPartyUtils thirdpartyUtils;

    if ( ( thirdparty_appid_module != nullptr ) || ( thirdparty_appid_dir == nullptr )
        || ( thirdparty_appid_dir[0] == 0 ) )
        return;

    // FIXIT-L need to port loadAllLibs function to snort3
    // _dpd.loadAllLibs(thirdparty_appid_dir, LoadCallback);
    if (thirdparty_appid_module == nullptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_APPID, "No 3rd party AppID module loaded.\n"); );
        return;
    }

    memset(&thirdpartyConfig, 0, sizeof(thirdpartyConfig));
    thirdpartyConfig.chp_body_collection_max = config->chp_body_collection_max;
    thirdpartyConfig.ftp_userid_disabled = config->ftp_userid_disabled;
    thirdpartyConfig.chp_body_collection_disabled =
        config->chp_body_collection_disabled;
    thirdpartyConfig.tp_allow_probes = config->tp_allow_probes;
    if (config->http2_detection_enabled)
        thirdpartyConfig.http_upgrade_reporting_enabled = 1;
    else
        thirdpartyConfig.http_upgrade_reporting_enabled = 0;
    thirdpartyConfig.appid_tp_dir[0] = '\0';    // use default path

    // FIXIT-M need to provide log function and getSnortInstance function to 3rd party utils
#ifdef REMOVED_WHILE_NOT_IN_USE
    //thirdpartyUtils.logMsg           = &DebugFormat;
    //thirdpartyUtils.getSnortInstance = _dpd.getSnortInstance;
#endif

    getXffFields();

    ret = thirdparty_appid_module->init(&thirdpartyConfig, &thirdpartyUtils);
    if (ret != 0)
    {
        ErrorMessage("Unable to initialize 3rd party AppID module (%d)!\n", ret);
        dlclose(module_handle);
        module_handle = nullptr;
        thirdparty_appid_module = nullptr;
        return;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID,
        "3rd party AppID module loaded and initialized OK (%s).\n",
        thirdparty_appid_module->module_name ? thirdparty_appid_module->module_name : ""); );
}

void ThirdPartyAppIDReconfigure(void)
{
    int ret;

    if (thirdparty_appid_module == nullptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_APPID, "No 3rd party AppID module loaded.\n"); );
        return;
    }

    thirdpartyConfig.oldNumXffFields = thirdpartyConfig.numXffFields;
    thirdpartyConfig.oldXffFields = thirdpartyConfig.xffFields;
    getXffFields();

    ret = thirdparty_appid_module->reconfigure(&thirdpartyConfig);
    for (unsigned i = 0; i < thirdpartyConfig.oldNumXffFields; i++)
        snort_free(thirdpartyConfig.oldXffFields[i]);
    snort_free(thirdpartyConfig.oldXffFields);

    if (ret != 0)
    {
        ErrorMessage("Unable to reconfigure 3rd party AppID module (%d)!\n", ret);
        return;
    }

    DEBUG_WRAP(DebugFormat(DEBUG_APPID, "3rd party AppID module reconfigured OK (%s).\n",
        thirdparty_appid_module->module_name ? thirdparty_appid_module->module_name : ""); );
}

void ThirdPartyAppIDFini(void)
{
    int ret;

    if (thirdparty_appid_module != nullptr)
    {
        ret = thirdparty_appid_module->fini();
        if (ret != 0)
        {
            ErrorMessage("Could not finalize 3rd party AppID module (%d)!\n", ret);
        }

        dlclose(module_handle);
        module_handle = nullptr;
        thirdparty_appid_module = nullptr;

        DEBUG_WRAP(DebugMessage(DEBUG_APPID,
            "3rd party AppID module finalized and unloaded OK.\n"); );
    }
}

#ifdef REMOVED_WHILE_NOT_IN_USE

// FIXIT-L bogus placeholder for this func, need to find out what it should do
static inline bool TPIsAppIdDone(void*)
{
    return false;
}

inline int ThirdPartyAppIDFoundProto(AppId proto, AppId* proto_list)
{
    unsigned int proto_cnt = 0;
    while (proto_list[proto_cnt] != APP_ID_NONE)
        if (proto_list[proto_cnt++] == proto)
            return 1;
    // found

    return 0;            // not found
}

bool checkThirdPartyReinspect(const Packet* p, AppIdSession* asd)
{
    return p->dsize && !asd->get_session_flags(APPID_SESSION_NO_TPI) &&
           asd->get_session_flags(APPID_SESSION_HTTP_SESSION) && TPIsAppIdDone(asd->tpsession);
}

void ProcessThirdPartyResults(AppIdSession* asd, Packet* p, int confidence,
    AppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data)
{
    int size;
    AppId serviceAppId = 0;
    AppId client_app_id = 0;
    AppId payload_app_id = 0;
    AppId referred_payload_app_id = 0;

    if (ThirdPartyAppIDFoundProto(APP_ID_EXCHANGE, proto_list))
    {
        if (!payload_app_id)
            payload_app_id = APP_ID_EXCHANGE;
    }

    if (ThirdPartyAppIDFoundProto(APP_ID_HTTP, proto_list))
    {
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s flow is HTTP\n", asd->session_logging_id);
        asd->set_session_flags(APPID_SESSION_HTTP_SESSION);
    }
    if (ThirdPartyAppIDFoundProto(APP_ID_SPDY, proto_list))
    {
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s flow is SPDY\n", asd->session_logging_id);

        asd->set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION))
    {
        if (!asd->hsession)
        {
            asd->hsession = new AppIdHttpSession(asd);
            memset(asd->hsession->ptype_scan_counts, 0,
                NUMBER_OF_PTYPES * sizeof(asd->hsession->ptype_scan_counts[0]));
        }

        if (asd->get_session_flags(APPID_SESSION_SPDY_SESSION))
        {
            if (attribute_data->spdyRequestScheme &&
                attribute_data->spdyRequestHost &&
                attribute_data->spdyRequestPath)
            {
                static const char httpsScheme[] = "https";
                static const char httpScheme[] = "http";
                const char* scheme;

                if (asd->hsession->url)
                {
                    snort_free(asd->hsession->url);
                    asd->hsession->chp_finished = false;
                }
                if (asd->get_session_flags(APPID_SESSION_DECRYPTED)
                    && memcmp(attribute_data->spdyRequestScheme, httpScheme, sizeof(httpScheme)-
                    1) == 0)
                {
                    scheme = httpsScheme;
                }
                else
                {
                    scheme = attribute_data->spdyRequestScheme;
                }

                size = strlen(scheme) +
                    strlen(attribute_data->spdyRequestHost) +
                    strlen(attribute_data->spdyRequestPath) +
                    sizeof("://");    // see sprintf() format
                asd->hsession->url = (char*)snort_calloc(size);
                sprintf(asd->hsession->url, "%s://%s%s",
                    scheme, attribute_data->spdyRequestHost, attribute_data->spdyRequestPath);
                asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

                snort_free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = nullptr;
            }
            else if (attribute_data->spdyRequestScheme)
            {
                snort_free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = nullptr;
            }

            if (attribute_data->spdyRequestHost)
            {
                if (asd->hsession->host)
                {
                    snort_free(asd->hsession->host);
                    asd->hsession->chp_finished = false;
                }
                asd->hsession->host = attribute_data->spdyRequestHost;
                attribute_data->spdyRequestHost = nullptr;
                asd->hsession->fieldOffset[REQ_HOST_FID] = attribute_data->spdyRequestHostOffset;
                asd->hsession->fieldEndOffset[REQ_HOST_FID] =
                    attribute_data->spdyRequestHostEndOffset;
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s SPDY Host (%u-%u) is %s\n", asd->session_logging_id,
                        asd->hsession->fieldOffset[REQ_HOST_FID],
                        asd->hsession->fieldEndOffset[REQ_HOST_FID], asd->hsession->host);
                asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }

            if (attribute_data->spdyRequestPath)
            {
                if (asd->hsession->uri)
                {
                    free(asd->hsession->uri);
                    asd->hsession->chp_finished = false;
                }
                asd->hsession->uri = attribute_data->spdyRequestPath;
                attribute_data->spdyRequestPath = nullptr;
                asd->hsession->fieldOffset[REQ_URI_FID] = attribute_data->spdyRequestPathOffset;
                asd->hsession->fieldEndOffset[REQ_URI_FID] =
                    attribute_data->spdyRequestPathEndOffset;
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s SPDY URI (%u-%u) is %s\n", asd->session_logging_id,
                        asd->hsession->fieldOffset[REQ_URI_FID],
                        asd->hsession->fieldEndOffset[REQ_URI_FID], asd->hsession->uri);
            }
        }
        else
        {
            if (attribute_data->httpRequestHost)
            {
                if (asd->hsession->host)
                {
                    snort_free(asd->hsession->host);
                    if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                        asd->hsession->chp_finished = false;
                }
                asd->hsession->host = attribute_data->httpRequestHost;
                asd->hsession->host_buflen = attribute_data->httpRequestHostLen;
                asd->hsession->fieldOffset[REQ_HOST_FID] = attribute_data->httpRequestHostOffset;
                asd->hsession->fieldEndOffset[REQ_HOST_FID] =
                    attribute_data->httpRequestHostEndOffset;
                attribute_data->httpRequestHost = nullptr;
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s HTTP host is %s\n",
                        asd->session_logging_id, attribute_data->httpRequestHost);
                asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUrl)
            {
                static const char httpScheme[] = "http://";

                if (asd->hsession->url)
                {
                    snort_free(asd->hsession->url);
                    if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                        asd->hsession->chp_finished = false;
                }

                //change http to https if session was decrypted.
                if (asd->get_session_flags(APPID_SESSION_DECRYPTED)
                    &&
                    memcmp(attribute_data->httpRequestUrl, httpScheme, sizeof(httpScheme)-1) == 0)
                {
                    asd->hsession->url = (char*)snort_calloc(strlen(
                        attribute_data->httpRequestUrl) + 2);

                    if (asd->hsession->url)
                        sprintf(asd->hsession->url, "https://%s",
                            attribute_data->httpRequestUrl + sizeof(httpScheme)-1);

                    snort_free(attribute_data->httpRequestUrl);
                    attribute_data->httpRequestUrl = nullptr;
                }
                else
                {
                    asd->hsession->url = attribute_data->httpRequestUrl;
                    attribute_data->httpRequestUrl = nullptr;
                }

                asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUri)
            {
                if (asd->hsession->uri)
                {
                    snort_free(asd->hsession->uri);
                    if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                        asd->hsession->chp_finished = false;
                }
                asd->hsession->uri = attribute_data->httpRequestUri;
                asd->hsession->uri_buflen = attribute_data->httpRequestUriLen;
                asd->hsession->fieldOffset[REQ_URI_FID] = attribute_data->httpRequestUriOffset;
                asd->hsession->fieldEndOffset[REQ_URI_FID] =
                    attribute_data->httpRequestUriEndOffset;
                attribute_data->httpRequestUri = nullptr;
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s uri (%u-%u) is %s\n", asd->session_logging_id,
                        asd->hsession->fieldOffset[REQ_URI_FID],
                        asd->hsession->fieldEndOffset[REQ_URI_FID],
                        asd->hsession->uri);
            }
        }
        if (attribute_data->httpRequestVia)
        {
            if (asd->hsession->via)
            {
                snort_free(asd->hsession->via);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->via = attribute_data->httpRequestVia;
            attribute_data->httpRequestVia = nullptr;
            asd->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        else if (attribute_data->httpResponseVia)
        {
            if (asd->hsession->via)
            {
                snort_free(asd->hsession->via);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->via = attribute_data->httpResponseVia;
            attribute_data->httpResponseVia = nullptr;
            asd->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (attribute_data->httpRequestUserAgent)
        {
            if (asd->hsession->useragent)
            {
                snort_free(asd->hsession->useragent);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->useragent = attribute_data->httpRequestUserAgent;
            attribute_data->httpRequestUserAgent = nullptr;
            asd->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        // Check to see if third party discovered HTTP/2.
        //  - once it supports it...
        if (attribute_data->httpResponseVersion)
        {
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response version is %s\n", asd->session_logging_id,
                    attribute_data->httpResponseVersion);
            if (strncmp(attribute_data->httpResponseVersion, "HTTP/2", 6) == 0)
            {
                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s 3rd party detected and parsed HTTP/2\n",
                        asd->session_logging_id);
                asd->is_http2 = true;
            }
            snort_free(attribute_data->httpResponseVersion);
            attribute_data->httpResponseVersion = nullptr;
        }
        if (attribute_data->httpResponseCode)
        {
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response code is %s\n", asd->session_logging_id,
                    attribute_data->httpResponseCode);
            if (asd->hsession->response_code)
            {
                snort_free(asd->hsession->response_code);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->response_code = attribute_data->httpResponseCode;
            asd->hsession->response_code_buflen = attribute_data->httpResponseCodeLen;
            attribute_data->httpResponseCode = nullptr;
        }
        // Check to see if we've got an upgrade to HTTP/2 (if enabled).
        //  - This covers the "without prior knowledge" case (i.e., the client
        //    asks the server to upgrade to HTTP/2).
        if (attribute_data->httpResponseUpgrade)
        {
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s HTTP response upgrade is %s\n", asd->session_logging_id,
                    attribute_data->httpResponseUpgrade);
            if (asd->config->mod_config->http2_detection_enabled)
                if (asd->hsession->response_code && (strncmp(
                    asd->hsession->response_code, "101", 3) == 0))
                    if (strncmp(attribute_data->httpResponseUpgrade, "h2c", 3) == 0)
                    {
                        if (asd->session_logging_enabled)
                            LogMessage("AppIdDbg %s Got an upgrade to HTTP/2\n",
                                asd->session_logging_id);
                        asd->is_http2 = true;
                    }
            snort_free(attribute_data->httpResponseUpgrade);
            attribute_data->httpResponseUpgrade = nullptr;
        }
        if (attribute_data->httpRequestReferer)
        {
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s referrer is %s\n", asd->session_logging_id,
                    attribute_data->httpRequestReferer);
            if (asd->hsession->referer)
            {
                snort_free(asd->hsession->referer);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->referer = attribute_data->httpRequestReferer;
            asd->hsession->referer_buflen = attribute_data->httpRequestRefererLen;
            attribute_data->httpRequestReferer = nullptr;
            asd->hsession->fieldOffset[REQ_REFERER_FID] = attribute_data->httpRequestRefererOffset;
            asd->hsession->fieldEndOffset[REQ_REFERER_FID] =
                attribute_data->httpRequestRefererEndOffset;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s Referer (%u-%u) is %s\n", asd->session_logging_id,
                    asd->hsession->fieldOffset[REQ_REFERER_FID],
                    asd->hsession->fieldEndOffset[REQ_REFERER_FID],
                    asd->hsession->referer);
        }

        if (attribute_data->httpRequestCookie)
        {
            if (asd->hsession->cookie)
            {
                snort_free(asd->hsession->cookie);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->cookie = attribute_data->httpRequestCookie;
            asd->hsession->cookie_buflen = attribute_data->httpRequestCookieLen;
            asd->hsession->fieldOffset[REQ_COOKIE_FID] = attribute_data->httpRequestCookieOffset;
            asd->hsession->fieldEndOffset[REQ_COOKIE_FID] =
                attribute_data->httpRequestCookieEndOffset;
            attribute_data->httpRequestCookie = nullptr;
            attribute_data->httpRequestCookieOffset = 0;
            attribute_data->httpRequestCookieEndOffset = 0;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s cookie (%u-%u) is %s\n", asd->session_logging_id,
                    asd->hsession->fieldOffset[REQ_COOKIE_FID],
                    asd->hsession->fieldEndOffset[REQ_COOKIE_FID],
                    asd->hsession->cookie);
        }
        if (attribute_data->httpResponseContent)
        {
            if (asd->hsession->content_type)
            {
                snort_free(asd->hsession->content_type);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->content_type = attribute_data->httpResponseContent;
            asd->hsession->content_type_buflen = attribute_data->httpResponseContentLen;
            attribute_data->httpResponseContent = nullptr;
            asd->scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        }
        if (asd->hsession->ptype_scan_counts[LOCATION_PT] && attribute_data->httpResponseLocation)
        {
            if (asd->hsession->location)
            {
                snort_free(asd->hsession->location);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->location = attribute_data->httpResponseLocation;
            asd->hsession->location_buflen = attribute_data->httpResponseLocationLen;
            attribute_data->httpResponseLocation = nullptr;
        }
        if (attribute_data->httpRequestBody)
        {
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s got a request body %s\n", asd->session_logging_id,
                    attribute_data->httpRequestBody);
            if (asd->hsession->req_body)
            {
                snort_free(asd->hsession->req_body);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->req_body = attribute_data->httpRequestBody;
            asd->hsession->req_body_buflen = attribute_data->httpRequestBodyLen;
            attribute_data->httpRequestBody = nullptr;
        }
        if (asd->hsession->ptype_scan_counts[BODY_PT] && attribute_data->httpResponseBody)
        {
            if (asd->hsession->body)
            {
                snort_free(asd->hsession->body);
                if (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    asd->hsession->chp_finished = false;
            }
            asd->hsession->body = attribute_data->httpResponseBody;
            asd->hsession->body_buflen = attribute_data->httpResponseBodyLen;
            attribute_data->httpResponseBody = nullptr;
        }
        if (attribute_data->numXffFields)
        {
            pickHttpXffAddress(asd, p, attribute_data);
        }
        if (!asd->hsession->chp_finished || asd->hsession->chp_hold_flow)
        {
            asd->set_session_flags(APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_set(asd->tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
        if (attribute_data->httpResponseServer)
        {
            if (asd->hsession->server)
                snort_free(asd->hsession->server);
            asd->hsession->server = attribute_data->httpResponseServer;
            attribute_data->httpResponseServer = nullptr;
            asd->scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        }
        if (attribute_data->httpRequestXWorkingWith)
        {
            if (asd->hsession->x_working_with)
                snort_free(asd->hsession->x_working_with);
            asd->hsession->x_working_with = attribute_data->httpRequestXWorkingWith;
            attribute_data->httpRequestXWorkingWith = nullptr;
            asd->scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_RTMP, proto_list) ||
        ThirdPartyAppIDFoundProto(APP_ID_RTSP, proto_list))
    {
        if (!asd->hsession)
            asd->hsession = new AppIdHttpSession(asd);

        if (!asd->hsession->url)
        {
            if (attribute_data->httpRequestUrl)
            {
                asd->hsession->url = attribute_data->httpRequestUrl;
                attribute_data->httpRequestUrl = nullptr;
                asd->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
        }

        if (!asd->config->mod_config->referred_appId_disabled &&
            !asd->hsession->referer)
        {
            if (attribute_data->httpRequestReferer)
            {
                asd->hsession->referer = attribute_data->httpRequestReferer;
                attribute_data->httpRequestReferer = nullptr;
            }
        }

        if (asd->hsession->url || (confidence == 100 &&
            asd->session_packet_count > asd->config->mod_config->rtmp_max_packets))
        {
            if (asd->hsession->url)
            {
                if ( ( ( asd->http_matchers->get_appid_from_url(nullptr, asd->hsession->url,
                    nullptr, asd->hsession->referer, &client_app_id, &serviceAppId,
                    &payload_app_id, &referred_payload_app_id, 1) )
                    ||
                    ( asd->http_matchers->get_appid_from_url(nullptr, asd->hsession->url, nullptr,
                    asd->hsession->referer, &client_app_id, &serviceAppId, &payload_app_id,
                    &referred_payload_app_id, 0) ) ) == 1 )
                {
                    // do not overwrite a previously-set client or service
                    if (client_app_id <= APP_ID_NONE)
                        asd->set_client_app_id_data(client_app_id, nullptr);
                    if (serviceAppId <= APP_ID_NONE)
                        asd->set_service_appid_data(serviceAppId, nullptr, nullptr);

                    // DO overwrite a previously-set data
                    asd->set_payload_app_id_data((ApplicationId)payload_app_id, nullptr);
                    asd->set_referred_payload_app_id_data(referred_payload_app_id);
                }
            }

            if (thirdparty_appid_module)
            {
                thirdparty_appid_module->disable_flags(asd->tpsession,
                    TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
                    TP_SESSION_FLAG_FUTUREFLOW);
                thirdparty_appid_module->session_delete(asd->tpsession, 1);
            }
            asd->tpsession = nullptr;
            asd->clear_session_flags(APPID_SESSION_APP_REINSPECT);
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_SSL, proto_list))
    {
        AppId tmpAppId = APP_ID_NONE;

        if (thirdparty_appid_module && asd->tpsession)
            tmpAppId = thirdparty_appid_module->session_appid_get(asd->tpsession);

        asd->set_session_flags(APPID_SESSION_SSL_SESSION);

        if (!asd->tsession)
            asd->tsession = (TlsSession*)snort_calloc(sizeof(TlsSession));

        if (!client_app_id)
            asd->set_client_app_id_data(APP_ID_SSL_CLIENT, nullptr);

        if (attribute_data->tlsHost)
        {
            if (asd->tsession->tls_host)
                snort_free(asd->tsession->tls_host);
            asd->tsession->tls_host = attribute_data->tlsHost;
            attribute_data->tlsHost = nullptr;
            if (testSSLAppIdForReinspect(tmpAppId))
                asd->scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        if (testSSLAppIdForReinspect(tmpAppId))
        {
            if (attribute_data->tlsCname)
            {
                if (asd->tsession->tls_cname)
                    snort_free(asd->tsession->tls_cname);
                asd->tsession->tls_cname = attribute_data->tlsCname;
                attribute_data->tlsCname = nullptr;
            }
            if (attribute_data->tlsOrgUnit)
            {
                if (asd->tsession->tls_orgUnit)
                    snort_free(asd->tsession->tls_orgUnit);
                asd->tsession->tls_orgUnit = attribute_data->tlsOrgUnit;
                attribute_data->tlsOrgUnit = nullptr;
            }
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_FTP_CONTROL, proto_list))
    {
        if (!asd->config->mod_config->ftp_userid_disabled && attribute_data->ftpCommandUser)
        {
            if (asd->username)
                snort_free(asd->username);
            asd->username = attribute_data->ftpCommandUser;
            attribute_data->ftpCommandUser = nullptr;
            asd->username_service = APP_ID_FTP_CONTROL;
            asd->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
        }
    }
}

void checkTerminateTpModule(AppIdSession* asd, uint16_t tpPktCount)
{
    if ((tpPktCount >= asd->config->mod_config->max_tp_flow_depth) ||
        (asd->get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) ==
        (APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) &&
        asd->hsession && asd->hsession->uri && (!asd->hsession->chp_candidate ||
        asd->hsession->chp_finished)))
    {
        if (asd->tp_app_id == APP_ID_NONE)
            asd->tp_app_id = APP_ID_UNKNOWN;
        if (asd->payload_app_id == APP_ID_NONE)
            asd->payload_app_id = APP_ID_UNKNOWN;
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_delete(asd->tpsession, 1);
    }
}

bool do_third_party_discovery(AppIdSession* asd, IpProtocol protocol, const SfIp* ip,
    Packet* p, int& direction)
{
    ThirdPartyAppIDAttributeData* tp_attribute_data;
    AppId* tp_proto_list;
    int tp_confidence;
    bool isTpAppidDiscoveryDone = false;

    //restart inspection by 3rd party
    if (!asd->tp_reinspect_by_initiator && (direction == APP_ID_FROM_INITIATOR) &&
        checkThirdPartyReinspect(p, asd))
    {
        asd->tp_reinspect_by_initiator = true;
        asd->set_session_flags(APPID_SESSION_APP_REINSPECT);
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                asd->session_logging_id);
        asd->reset_session_data();
    }

    if (asd->tp_app_id == APP_ID_SSH && asd->payload_app_id != APP_ID_SFTP &&
        asd->session_packet_count >= MIN_SFTP_PACKET_COUNT &&
        asd->session_packet_count < MAX_SFTP_PACKET_COUNT)
    {
        if ( p->ptrs.ip_api.tos() == 8 )
        {
            asd->payload_app_id = APP_ID_SFTP;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s data is SFTP\n", asd->session_logging_id);
        }
    }

    Profile tpPerfStats_profile_context(tpPerfStats);

    /*** Start of third-party processing. ***/
    if (thirdparty_appid_module && !asd->get_session_flags(APPID_SESSION_NO_TPI)
        && (!TPIsAppIdDone(asd->tpsession)
        || asd->get_session_flags(APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
    {
        // First SSL decrypted packet is now being inspected. Reset the flag so that SSL decrypted
        // traffic
        // gets processed like regular traffic from next packet onwards
        if (asd->get_session_flags(APPID_SESSION_APP_REINSPECT_SSL))
            asd->clear_session_flags(APPID_SESSION_APP_REINSPECT_SSL);

        if (p->dsize || asd->config->mod_config->tp_allow_probes)
        {
            if (protocol != IpProtocol::TCP || (p->packet_flags & PKT_STREAM_ORDER_OK)
                || asd->config->mod_config->tp_allow_probes)
            {
                Profile tpLibPerfStats_profile_context(tpLibPerfStats);
                if (!asd->tpsession)
                {
                    if (!(asd->tpsession = thirdparty_appid_module->session_create()))
                        FatalError("Could not allocate asd->tpsession data");
                }  // debug output of packet content
                thirdparty_appid_module->session_process(asd->tpsession, p, direction,
                    &asd->tp_app_id, &tp_confidence,
                    &tp_proto_list, &tp_attribute_data);

                isTpAppidDiscoveryDone = true;
                if (thirdparty_appid_module->session_state_get(asd->tpsession) ==
                    TP_STATE_CLASSIFIED)
                    asd->clear_session_flags(APPID_SESSION_APP_REINSPECT);

                if (asd->session_logging_enabled)
                    LogMessage("AppIdDbg %s 3rd party returned %d\n", asd->session_logging_id,
                        asd->tp_app_id);

                // For now, third party can detect HTTP/2 (w/o metadata) for
                // some cases.  Treat it like HTTP w/ is_http2 flag set.
                if ((asd->tp_app_id == APP_ID_HTTP2) && (tp_confidence == 100))
                {
                    if (asd->session_logging_enabled)
                        LogMessage("AppIdDbg %s 3rd party saw HTTP/2\n", asd->session_logging_id);

                    asd->tp_app_id = APP_ID_HTTP;
                    asd->is_http2 = true;
                }
                // if the third-party appId must be treated as a client, do it now
                if (asd->app_info_mgr->get_app_info_flags(asd->tp_app_id, APPINFO_FLAG_TP_CLIENT))
                    asd->client_app_id = asd->tp_app_id;

                ProcessThirdPartyResults(asd, p, tp_confidence, tp_proto_list, tp_attribute_data);

                if (asd->get_session_flags(APPID_SESSION_SSL_SESSION) &&
                    !(asd->scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, asd->tp_app_id);
                }

                if (asd->app_info_mgr->get_app_info_flags(asd->tp_app_id, APPINFO_FLAG_IGNORE))
                {
                    if (asd->session_logging_enabled)
                        LogMessage("AppIdDbg %s 3rd party ignored\n", asd->session_logging_id);

                    if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION))
                        asd->tp_app_id = APP_ID_HTTP;
                    else
                        asd->tp_app_id = APP_ID_NONE;
                }
            }
            else
            {
                asd->tp_app_id = APP_ID_NONE;
                if (asd->session_logging_enabled && !asd->get_session_flags(
                    APPID_SESSION_TPI_OOO_LOGGED))
                {
                    asd->set_session_flags(APPID_SESSION_TPI_OOO_LOGGED);
                    LogMessage("AppIdDbg %s 3rd party packet out-of-order\n",
                        asd->session_logging_id);
                }
            }

            if (thirdparty_appid_module->session_state_get(asd->tpsession) == TP_STATE_MONITORING)
            {
                thirdparty_appid_module->disable_flags(asd->tpsession,
                    TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
                    TP_SESSION_FLAG_FUTUREFLOW);
            }

            if (asd->tp_app_id == APP_ID_SSL &&
                (Stream::get_application_protocol_id(p->flow) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                asd->tp_app_id = APP_ID_NONE;
            }

            if (asd->tp_app_id > APP_ID_NONE
                && (!asd->get_session_flags(APPID_SESSION_APP_REINSPECT) || asd->payload_app_id >
                APP_ID_NONE))
            {
                AppId snort_app_id;
                // if the packet is HTTP, then search for via pattern
                if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION) && asd->hsession)
                {
                    snort_app_id = APP_ID_HTTP;
                    //data should never be APP_ID_HTTP
                    if (asd->tp_app_id != APP_ID_HTTP)
                        asd->tp_payload_app_id = asd->tp_app_id;

                    asd->tp_app_id = APP_ID_HTTP;
                    // Handle HTTP tunneling and SSL possibly then being used in that tunnel
                    if (asd->tp_app_id == APP_ID_HTTP_TUNNEL)
                        asd->set_payload_app_id_data(APP_ID_HTTP_TUNNEL, NULL);
                    if ((asd->payload_app_id == APP_ID_HTTP_TUNNEL) && (asd->tp_app_id ==
                        APP_ID_SSL))
                        asd->set_payload_app_id_data(APP_ID_HTTP_SSL_TUNNEL, NULL);

                    asd->hsession->process_http_packet(direction);

                    // If SSL over HTTP tunnel, make sure Snort knows that it's encrypted.
                    if (asd->payload_app_id == APP_ID_HTTP_SSL_TUNNEL)
                        snort_app_id = APP_ID_SSL;

                    if (is_third_party_appid_available(asd->tpsession) && asd->tp_app_id ==
                        APP_ID_HTTP
                        && !asd->get_session_flags(APPID_SESSION_APP_REINSPECT))
                    {
                        asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
                        asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                            APPID_SESSION_SERVICE_DETECTED);
                        asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
                        asd->clear_session_flags(APPID_SESSION_CONTINUE);
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            ip = p->ptrs.ip_api.get_dst();
                            asd->service_ip = *ip;
                            asd->service_port = p->ptrs.dp;
                        }
                        else
                        {
                            ip = p->ptrs.ip_api.get_src();
                            asd->service_ip = *ip;
                            asd->service_port = p->ptrs.sp;
                        }
                    }
                }
                else if (asd->get_session_flags(APPID_SESSION_SSL_SESSION) && asd->tsession)
                {
                    asd->examine_ssl_metadata(p);
                    uint16_t serverPort;
                    AppId porAppId;
                    serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;
                    porAppId = serverPort;
                    if (asd->tp_app_id == APP_ID_SSL)
                    {
                        asd->tp_app_id = porAppId;
                        //SSL policy determines IMAPS/POP3S etc before appId sees first server
                        // packet
                        asd->port_service_id = porAppId;
                        if (asd->session_logging_enabled)
                            LogMessage("AppIdDbg %s SSL is service %d, portServiceAppId %d\n",
                                asd->session_logging_id,
                                asd->tp_app_id, asd->port_service_id);
                    }
                    else
                    {
                        asd->tp_payload_app_id = asd->tp_app_id;
                        asd->tp_app_id = porAppId;
                        if (asd->session_logging_enabled)
                            LogMessage("AppIdDbg %s SSL is %d\n", asd->session_logging_id,
                                asd->tp_app_id);
                    }
                    snort_app_id = APP_ID_SSL;
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId
                    snort_app_id = asd->tp_app_id;
                }

                asd->sync_with_snort_id(snort_app_id, p);
            }
            else
            {
                if (protocol != IpProtocol::TCP ||
                    (p->packet_flags & (PKT_STREAM_ORDER_OK | PKT_STREAM_ORDER_BAD)))
                {
                    if (direction == APP_ID_FROM_INITIATOR)
                    {
                        asd->init_tpPackets++;
                        checkTerminateTpModule(asd, asd->init_tpPackets);
                    }
                    else
                    {
                        asd->resp_tpPackets++;
                        checkTerminateTpModule(asd, asd->resp_tpPackets);
                    }
                }
            }
        }
    }

    if ( asd->tp_reinspect_by_initiator && checkThirdPartyReinspect(p, asd) )
    {
        asd->clear_session_flags(APPID_SESSION_APP_REINSPECT);
        if (direction == APP_ID_FROM_RESPONDER)
            asd->tp_reinspect_by_initiator = false; //toggle at OK response
    }

    return isTpAppidDiscoveryDone;
}

void pickHttpXffAddress(AppIdSession* asd, Packet*, ThirdPartyAppIDAttributeData* attribute_data)
{
    static const char* defaultXffPrecedence[] =
    {
        HTTP_XFF_FIELD_X_FORWARDED_FOR,
        HTTP_XFF_FIELD_TRUE_CLIENT_IP
    };

    // XFF precedence configuration cannot change for a session. Do not get it again if we already
    // got it.
    char** xffPrecedence = _dpd.sessionAPI->get_http_xff_precedence(p->stream_session, p->flags,
        &appIdSession->hsession->numXffFields);
    if (!xffPrecedence)
    {
        xffPrecedence = defaultXffPrecedence;
        appIdSession->hsession->numXffFields = sizeof(defaultXffPrecedence) /
            sizeof(defaultXffPrecedence[0]);
    }

    appIdSession->hsession->xffPrecedence = malloc(appIdSession->hsession->numXffFields *
        sizeof(char*));

    for (unsigned j = 0; j < appIdSession->hsession->numXffFields; j++)
        appIdSession->hsession->xffPrecedence[j] = strndup(xffPrecedence[j], UINT8_MAX);

    if (asd->session_logging_enabled)
    {
        for (unsigned i = 0; i < attribute_data->numXffFields; i++)
            LogMessage("AppIdDbg %s %s : %s\n", asd->session_logging_id,
                attribute_data->xffFieldValue[i].field, attribute_data->xffFieldValue[i].value);
    }

    // xffPrecedence array is sorted based on precedence
    for (unsigned i = 0;
        (i < asd->hsession->numXffFields) && asd->hsession->xffPrecedence[i];
        i++)
    {
        for (unsigned j = 0; j < attribute_data->numXffFields; j++)
        {
            if (asd->hsession->xffAddr)
            {
                delete asd->hsession->xffAddr;
                asd->hsession->xffAddr = nullptr;
            }

            if (strncasecmp(attribute_data->xffFieldValue[j].field,
                asd->hsession->xffPrecedence[i], UINT8_MAX) == 0)
            {
                if (!attribute_data->xffFieldValue[j].value ||
                    (attribute_data->xffFieldValue[j].value[0] == '\0'))
                    return;

                // For a comma-separated list of addresses, pick the last address
                // FIXIT-L: change to select last address port from 2.9.10-42..not tested
                asd->hsession->xffAddr = new SfIp();
                char* xff_addr = nullptr;
                char* tmp = strchr(attribute_data->xffFieldValue[j].value, ',');

                if (tmp)
                {
                    xff_addr = tmp + 1;
                }
                else
                {
                    attribute_data->xffFieldValue[j].value[tmp -
                    attribute_data->xffFieldValue[j].value] = '\0';
                    xff_addr = attribute_data->xffFieldValue[j].value;
                }

                if (asd->hsession->xffAddr->set(xff_addr) != SFIP_SUCCESS)
                {
                    delete asd->hsession->xffAddr;
                    asd->hsession->xffAddr = nullptr;
                }
                break;
            }
        }

        if (asd->hsession->xffAddr)
            break;
    }
}

#endif

