//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// connector_manager.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connector_manager.h"

#include <cassert>
#include <list>
#include <map>
#include <unordered_map>

#include "framework/connector.h"
#include "log/messages.h"
#include "utils/util.h"

using namespace snort;

//  ConnectorManager Private Data

// One ConnectorElem for each Connector within the ConnectorCommon configuration
struct ConnectorElem
{
    ConnectorConfig* config;
    std::unordered_map<pid_t, Connector*> thread_connectors;
};

// One ConnectorCommonElem created for each ConnectorCommon configured
struct ConnectorCommonElem
{
    const ConnectorApi* api;
    ConnectorCommon* connector_common;
    std::map<std::string, ConnectorElem*> connectors;

    ConnectorCommonElem(const ConnectorApi* p)
    {
        api = p;
        connector_common = nullptr;
    }
};

typedef std::list<ConnectorCommonElem> CList;
static CList s_connector_commons;

//-------------------------------------------------------------------------

void ConnectorManager::add_plugin(const ConnectorApi* api)
{
    if ( api->pinit )
        api->pinit();
}

void ConnectorManager::dump_plugins()
{
    Dumper d("Connectors");

    for ( auto& sc : s_connector_commons )
        d.dump(sc.api->base.name, sc.api->base.version);
}

void ConnectorManager::release_plugins()
{
    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->dtor )
            sc.api->dtor(sc.connector_common);

        for ( auto& conn : sc.connectors )
            delete conn.second;

        sc.connectors.clear();

        if ( sc.api->pterm )
            sc.api->pterm();
    }

    s_connector_commons.clear();
}

Connector* ConnectorManager::get_connector(const std::string& connector_name)
{
    for ( auto& sc : s_connector_commons )
    {
        pid_t tid = gettid();
        if ( sc.connectors.count(connector_name) > 0 )
        {
            ConnectorElem* map = sc.connectors[connector_name];
            if ( map->thread_connectors.count(tid) == 1 )
                return ( map->thread_connectors[tid] );
        }
    }
    return ( nullptr );
}

void ConnectorManager::thread_init()
{
    pid_t tid = gettid();

    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->tinit )
        {
            for ( auto& conn : sc.connectors )
            {
                /* There must NOT be a connector for this thread present. */
                assert(conn.second->thread_connectors.count(tid) == 0);

                Connector* connector = sc.api->tinit(conn.second->config);
                std::pair<pid_t, Connector*> element (tid, std::move(connector));
                conn.second->thread_connectors.insert(element);
            }
        }
    }
}

void ConnectorManager::thread_term()
{
    pid_t tid = gettid();

    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->tterm )
        {
            for ( auto& conn : sc.connectors )
            {
                /* There must be a connector for this thread present. */
                assert(conn.second->thread_connectors.count(tid) != 0);

                sc.api->tterm(conn.second->thread_connectors[tid]);

                conn.second->thread_connectors.clear();
            }
        }
    }
}

void ConnectorManager::instantiate(const ConnectorApi* api, Module* mod, SnortConfig*)
{
    assert(mod);
    ConnectorCommonElem c(api);

    ConnectorCommon* connector_common = api->ctor(mod);
    assert(connector_common);

    c.connector_common = connector_common;
    ConnectorConfig::ConfigSet* config_set = connector_common->config_set;

    // iterate through the config_set and create the connector entries
    for ( auto cfg : *config_set )
    {
        ConnectorElem* connector_elem = new ConnectorElem;
        connector_elem->config = &*cfg;
        std::pair<std::string, ConnectorElem*> element (cfg->connector_name, std::move(connector_elem));
        c.connectors.insert(element);
    }

    s_connector_commons.push_back(c);
}

