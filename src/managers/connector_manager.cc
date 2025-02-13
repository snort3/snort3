//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "utils/util.h"

using namespace snort;

//  ConnectorManager Private Data

// One ConnectorElem for each Connector within the ConnectorCommon configuration
struct ConnectorElem
{
    ConnectorElem(const ConnectorConfig& config) : config(config),
        thread_connectors(ThreadConfig::get_instance_max(), nullptr)
    { }

    const ConnectorConfig& config;
    std::vector<Connector*> thread_connectors;
};

// One ConnectorCommonElem created for each ConnectorCommon configured
struct ConnectorCommonElem
{
    const ConnectorApi* api;
    ConnectorCommon* connector_common;
    std::map<std::string, ConnectorElem> connectors;

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

    for ( const auto& sc : s_connector_commons )
        d.dump(sc.api->base.name, sc.api->base.version);
}

void ConnectorManager::release_plugins()
{
    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->dtor )
            sc.api->dtor(sc.connector_common);

        sc.connectors.clear();

        if ( sc.api->pterm )
            sc.api->pterm();
    }

    s_connector_commons.clear();
}

Connector* ConnectorManager::get_connector(const std::string& connector_name)
{
    unsigned instance = get_instance_id();

    for ( auto& sc : s_connector_commons )
    {
        auto connector_ptr = sc.connectors.find(connector_name);

        if ( connector_ptr != sc.connectors.end() )
        {
            if ( connector_ptr->second.thread_connectors[instance] )
                return ( connector_ptr->second.thread_connectors[instance] );
        }
    }
    return ( nullptr );
}

void ConnectorManager::thread_init()
{
    unsigned instance = get_instance_id();

    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->tinit )
        {
            for ( auto& conn : sc.connectors )
            {
                assert(!conn.second.thread_connectors[instance]);

                Connector* connector = sc.api->tinit(conn.second.config);
                conn.second.thread_connectors[instance] = std::move(connector);
            }
        }
    }
}

void ConnectorManager::thread_reinit()
{
    unsigned instance = get_instance_id();

    for ( auto& sc : s_connector_commons )
    {
        for ( auto& conn : sc.connectors )
        {
            if (conn.second.thread_connectors[instance])
                conn.second.thread_connectors[instance]->reinit();
        }
    }
}

void ConnectorManager::thread_term()
{
    unsigned instance = get_instance_id();

    for ( auto& sc : s_connector_commons )
    {
        if ( sc.api->tterm )
        {
            for ( auto& conn : sc.connectors )
            {
                if ( conn.second.thread_connectors[instance] )
                {
                    sc.api->tterm(conn.second.thread_connectors[instance]);
                    conn.second.thread_connectors[instance] = nullptr;
                }
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

    // iterate through the config_set and create the connector entries
    for ( auto& cfg : connector_common->config_set )
    {
        if ( is_instantiated(cfg->connector_name) != Connector::CONN_UNDEFINED )
        {
            ParseError("redefinition of \"%s\" connector", cfg->connector_name.c_str());
            continue;
        }

        ConnectorElem connector_elem(*cfg);
        c.connectors.emplace(cfg->connector_name, std::move(connector_elem));
    }

    s_connector_commons.emplace_back(c);
}

Connector::Direction ConnectorManager::is_instantiated(const std::string& name)
{
    for ( auto& conn : s_connector_commons )
    {
        auto connector_ptr = conn.connectors.find(name);

        if ( connector_ptr != conn.connectors.end() )
            return connector_ptr->second.config.direction;
    }

    return Connector::CONN_UNDEFINED;
}
