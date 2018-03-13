//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors.h"

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* sin_imap;
extern const BaseApi* sin_pop;
extern const BaseApi* sin_smtp;

extern const BaseApi* sin_file[];
extern const BaseApi* sin_http[];
extern const BaseApi* sin_http2[];
extern const BaseApi* sin_sip[];
extern const BaseApi* sin_ssl[];

#ifdef STATIC_INSPECTORS
extern const BaseApi* sin_bo;
extern const BaseApi* sin_dns;
extern const BaseApi* sin_ftp_client;
extern const BaseApi* sin_ftp_server;
extern const BaseApi* sin_ftp_data;
extern const BaseApi* sin_rpc_decode;
extern const BaseApi* sin_ssh;
extern const BaseApi* sin_telnet;
extern const BaseApi* sin_wizard;

extern const BaseApi* sin_dce[];
extern const BaseApi* sin_dnp3[];
extern const BaseApi* sin_gtp[];
extern const BaseApi* sin_modbus[];
#endif

const BaseApi* service_inspectors[] =
{
    sin_imap,
    sin_pop,
    sin_smtp,

#ifdef STATIC_INSPECTORS
    sin_bo,
    sin_dns,
    sin_ftp_client,
    sin_ftp_server,
    sin_ftp_data,
    sin_rpc_decode,
    sin_ssh,
    sin_telnet,
    sin_wizard,
#endif

    nullptr
};

void load_service_inspectors()
{
    PluginManager::load_plugins(service_inspectors);

    PluginManager::load_plugins(sin_file);
    PluginManager::load_plugins(sin_http);
    PluginManager::load_plugins(sin_http2);
    PluginManager::load_plugins(sin_sip);
    PluginManager::load_plugins(sin_ssl);

#ifdef STATIC_INSPECTORS
    PluginManager::load_plugins(sin_dce);
    PluginManager::load_plugins(sin_dnp3);
    PluginManager::load_plugins(sin_gtp);
    PluginManager::load_plugins(sin_modbus);
#endif
}

