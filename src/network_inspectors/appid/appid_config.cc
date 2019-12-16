//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

// appid_config.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_config.h"

#include <glob.h>
#include <climits>

#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_session.h"
#include "detector_plugins/detector_pattern.h"
#include "host_port_app_cache.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "lua_detector_module.h"
#include "utils/util.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "target_based/snort_protocols.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_appid_utils.h"
#include "tp_lib_handler.h"
#endif

using namespace snort;

#define ODP_PORT_DETECTORS "odp/port/*"
#define CUSTOM_PORT_DETECTORS "custom/port/*"
#define MAX_DISPLAY_SIZE   65536
#define MAX_LINE    2048

using namespace snort;

uint32_t app_id_netmasks[33] =
{ 0x00000000, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000, 0xF8000000, 0xFC000000,
  0xFE000000, 0xFF000000, 0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000,
  0xFFFC0000, 0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
  0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0,
  0xFFFFFFF0, 0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF };

struct PortList
{
    PortList* next;
    uint16_t port;
};

SnortProtocolId snortId_for_unsynchronized;
SnortProtocolId snortId_for_ftp_data;
SnortProtocolId snortId_for_http2;

static void map_app_names_to_snort_ids(SnortConfig* sc)
{
    /* init globals for snortId compares */
    snortId_for_unsynchronized = sc->proto_ref->add("unsynchronized");
    snortId_for_ftp_data = sc->proto_ref->add("ftp-data");
    snortId_for_http2    = sc->proto_ref->add("http2");

    // Have to create SnortProtocolIds during configuration initialization.
    sc->proto_ref->add("rexec");
    sc->proto_ref->add("rsh-error");
    sc->proto_ref->add("snmp");
    sc->proto_ref->add("sunrpc");
    sc->proto_ref->add("tftp");
}

AppIdModuleConfig::~AppIdModuleConfig()
{
    snort_free((void*)app_detector_dir);
}

// FIXIT-M: RELOAD - move initialization back to AppIdConfig class constructor
AppInfoManager& AppIdConfig::app_info_mgr = AppInfoManager::get_instance();
std::array<AppId, APP_ID_PORT_ARRAY_SIZE> AppIdConfig::tcp_port_only = {APP_ID_NONE};
std::array<AppId, APP_ID_PORT_ARRAY_SIZE> AppIdConfig::udp_port_only = {APP_ID_NONE};
std::array<AppId, 256> AppIdConfig::ip_protocol = {APP_ID_NONE};

// FIXIT-M: RELOAD - Move app info table cleanup back to AppId config destructor - cleanup()
void AppIdConfig::pterm()
{
    AppIdConfig::app_info_mgr.cleanup_appid_info_table();
}

void AppIdConfig::read_port_detectors(const char* files)
{
    int rval;
    glob_t globs;
    char pattern[PATH_MAX];
    uint32_t n;

    snprintf(pattern, sizeof(pattern), "%s/%s", mod_config->app_detector_dir, files);

    memset(&globs, 0, sizeof(globs));
    rval = glob(pattern, 0, nullptr, &globs);
    if (rval != 0 && rval != GLOB_NOMATCH)
    {
        ErrorMessage("Unable to read directory '%s'\n",pattern);
        return;
    }

    for (n = 0; n < globs.gl_pathc; n++)
    {
        FILE* file;
        unsigned proto = 0;
        AppId appId = APP_ID_NONE;
        char line[1024];
        PortList* port = nullptr;
        PortList* tmp_port;

        if ((file = fopen(globs.gl_pathv[n], "r")) == nullptr)
        {
            ErrorMessage("Unable to read port service '%s'\n",globs.gl_pathv[n]);
            continue;
        }

        while (fgets(line, sizeof(line), file))
        {
            char* key, * value, * p;
            size_t len;

            len = strlen(line);
            for (; len && (line[len - 1] == '\n' || line[len - 1] == '\r'); len--)
                line[len - 1] = 0;

            /* find key/value for lines of the format "key: value\n" */
            if ((value = strchr(line, ':')))
            {
                key = line;
                *value = '\0';
                value++;
                while (*value == ' ')
                    value++;

                if (strcasecmp(key, "ports") == 0)
                {
                    char* context = nullptr;
                    char* ptr;
                    unsigned long tmp;

                    for (ptr = strtok_r(value, ",", &context); ptr; ptr = strtok_r(nullptr, ",",
                            &context))
                    {
                        while (*ptr == ' ')
                            ptr++;
                        len = strlen(ptr);
                        for (; len && ptr[len - 1] == ' '; len--)
                            ptr[len - 1] = 0;
                        tmp = strtoul(ptr, &p, 10);
                        if (!*ptr || *p || !tmp || tmp > 65535)
                        {
                            ErrorMessage("Invalid port, '%s', in lua detector '%s'\n",ptr,
                                globs.gl_pathv[n]);
                            goto next;
                        }
                        tmp_port = (PortList*)snort_calloc(sizeof(PortList));
                        tmp_port->port = (uint16_t)tmp;
                        tmp_port->next = port;
                        port = tmp_port;
                    }
                }
                else if (strcasecmp(key, "protocol") == 0)
                {
                    if (strcasecmp(value, "tcp") == 0)
                        proto = 1;
                    else if (strcasecmp(value, "udp") == 0)
                        proto = 2;
                    else if (strcasecmp(value, "tcp/udp") == 0)
                        proto = 3;
                    else
                    {
                        ErrorMessage("Invalid protocol, '%s', in port service '%s'\n",value,
                            globs.gl_pathv[n]);
                        goto next;
                    }
                }
                else if (strcasecmp(key, "appId") == 0)
                {
                    appId = (AppId)strtoul(value, &p, 10);
                    if (!*value || *p || appId <= APP_ID_NONE)
                    {
                        ErrorMessage("Invalid app ID, '%s', in port service '%s'\n",value,
                            globs.gl_pathv[n]);
                        goto next;
                    }
                }
            }
        }

        if (port && proto && appId > APP_ID_NONE)
        {
            while ((tmp_port = port))
            {
                port = tmp_port->next;
                if (proto & 1)
                    tcp_port_only[tmp_port->port] = appId;
                if (proto & 2)
                    udp_port_only[tmp_port->port] = appId;

                snort_free(tmp_port);
                AppIdConfig::app_info_mgr.set_app_info_active(appId);
            }
            AppIdConfig::app_info_mgr.set_app_info_active(appId);
        }
        else
            ErrorMessage("Missing parameter(s) in port service '%s'\n",globs.gl_pathv[n]);

next:   ;
        while ((tmp_port = port))
        {
            port = tmp_port->next;
            snort_free(tmp_port);
        }
        fclose(file);
    }

    globfree(&globs);
}

bool AppIdConfig::init_appid(SnortConfig* sc)
{
    // FIXIT-M: RELOAD - Get rid of "once" flag
    // Handle the if condition in AppIdConfig::init_appid
    static bool once = false;
    if (!once)
    {   
        AppIdConfig::app_info_mgr.init_appid_info_table(mod_config, sc);
        HostPortCache::initialize();
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
        AppIdDiscovery::initialize_plugins();
        init_length_app_cache();
        LuaDetectorManager::initialize(*this, 1);
        PatternServiceDetector::finalize_service_port_patterns();
        PatternClientDetector::finalize_client_port_patterns();
        AppIdDiscovery::finalize_plugins();
        http_matchers->finalize_patterns();
        ssl_detector_process_patterns();
        dns_host_detector_process_patterns();
        read_port_detectors(ODP_PORT_DETECTORS);
        read_port_detectors(CUSTOM_PORT_DETECTORS);
        once = true;
    }

#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::pinit(mod_config);
#endif
    map_app_names_to_snort_ids(sc);
    return true;
}

AppId AppIdConfig::get_port_service_id(IpProtocol proto, uint16_t port)
{
    AppId appId;

    if (proto == IpProtocol::TCP)
        appId = tcp_port_only[port];
    else
        appId = udp_port_only[port];

    return appId;
}

AppId AppIdConfig::get_protocol_service_id(IpProtocol proto)
{
    return ip_protocol[(uint16_t)proto];
}

void AppIdConfig::show()
{
    if (!mod_config->tp_appid_path.empty())
        LogMessage("    3rd Party Dir: %s\n", mod_config->tp_appid_path.c_str());
}

void AppIdConfig::display_port_config()
{
    bool first = true;

    for ( auto& i : tcp_port_only )
        if (tcp_port_only[i])
        {
            if (first)
            {
                LogMessage("    TCP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, tcp_port_only[i]);
        }

    first = true;
    for ( auto& i : udp_port_only )
        if (udp_port_only[i])
        {
            if (first)
            {
                LogMessage("    UDP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, udp_port_only[i]);
        }
}

