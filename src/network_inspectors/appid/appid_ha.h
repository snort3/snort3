//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_ha.h author Kani Murthi <kamurthi@cisco.com>

#ifndef APPID_HA_H
#define APPID_HA_H

#include "flow/flow.h"
#include "flow/ha.h"
#include "main/reload_tuner.h"
#include "appid_inspector.h"

#define APPID_HA_MAX_FIELD_LEN 32

// Stable wire-name suffixes; the mod_name part comes from MOD_NAME.
#define APPID_HA_SUFFIX_APPS  "apps"
#define APPID_HA_SUFFIX_HTTP  "http"
#define APPID_HA_SUFFIX_TLS   "tls"

enum AppIdHAAppType
{
    APPID_HA_APP_SERVICE = 0,
    APPID_HA_APP_CLIENT,
    APPID_HA_APP_PAYLOAD,
    APPID_HA_APP_MISC,
    APPID_HA_APP_REFERRED,
    APPID_HA_APP_CLIENT_INFERRED_SERVICE,
    APPID_HA_APP_PORT_SERVICE,
    APPID_HA_APP_TP,
    APPID_HA_APP_TP_PAYLOAD,
    APPID_HA_APP_MAX
};

struct AppIdSessionHAApps
{
    uint16_t flags;
    AppId appId[APPID_HA_APP_MAX];
};

struct AppIdSessionHAHttp
{
    char url[APPID_HA_MAX_FIELD_LEN];
    char host[APPID_HA_MAX_FIELD_LEN];
};

struct AppIdSessionHATlsHost
{
    char tls_host[APPID_HA_MAX_FIELD_LEN];
};

class AppIdHAAppsClient : public snort::FlowHAClient
{
public:
    AppIdHAAppsClient() : FlowHAClient(sizeof(AppIdSessionHAApps), MOD_NAME, APPID_HA_SUFFIX_APPS) { }
    bool consume(snort::Flow*&, const snort::FlowKey*, snort::HAMessage&, uint8_t size) override;
    bool produce(snort::Flow&, snort::HAMessage&) override;
};

class AppIdHAHttpClient : public snort::FlowHAClient
{
public:
    AppIdHAHttpClient() : FlowHAClient(sizeof(AppIdSessionHAHttp), MOD_NAME, APPID_HA_SUFFIX_HTTP) { }
    bool consume(snort::Flow*&, const snort::FlowKey*, snort::HAMessage&, uint8_t size) override;
    bool produce(snort::Flow&, snort::HAMessage&) override;
};

class AppIdHATlsHostClient : public snort::FlowHAClient
{
public:
    AppIdHATlsHostClient() : FlowHAClient(sizeof(AppIdSessionHATlsHost), MOD_NAME, APPID_HA_SUFFIX_TLS) { }
    bool consume(snort::Flow*&, const snort::FlowKey*, snort::HAMessage&, uint8_t size) override;
    bool produce(snort::Flow&, snort::HAMessage&) override;
};

class AppIdHAManager
{
public:
    static void tinit()
    {
        if ( ha_apps_client || ha_http_client || ha_tls_host_client )
            return;
        if ( snort::HighAvailabilityManager::configured() )
        {
            ha_apps_client = new AppIdHAAppsClient;
            ha_http_client = new AppIdHAHttpClient;
            ha_tls_host_client = new AppIdHATlsHostClient;
        }
    }
    static void tterm()
    {
        delete ha_apps_client;
        ha_apps_client = nullptr;
        delete ha_http_client;
        ha_http_client = nullptr;
        delete ha_tls_host_client;
        ha_tls_host_client = nullptr;
    }
    static void tswap()
    {
        delete ha_apps_client;
        ha_apps_client = nullptr;
        delete ha_http_client;
        ha_http_client = nullptr;
        delete ha_tls_host_client;
        ha_tls_host_client = nullptr;
        if ( snort::HighAvailabilityManager::configured() )
        {
            ha_apps_client = new AppIdHAAppsClient;
            ha_http_client = new AppIdHAHttpClient;
            ha_tls_host_client = new AppIdHATlsHostClient;
        }
    }


    static THREAD_LOCAL AppIdHAAppsClient* ha_apps_client;
    static THREAD_LOCAL AppIdHAHttpClient* ha_http_client;
    static THREAD_LOCAL AppIdHATlsHostClient* ha_tls_host_client;
};

class AppIdHAReloadSwapper : public snort::ReloadSwapper
{
public:
    const char* name() const override { return "AppIdHAReloadSwapper"; }
    void tswap() override
    {
        AppIdHAManager::tswap();
    }
};

#endif
