//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "plugin_manager.h"
#include "plug_interface.h"

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

class ConnectorCommonElem : public PlugInterface
{
public:
    const ConnectorApi* api;
    ConnectorCommon* connector_common = nullptr;
    std::map<std::string, ConnectorElem> connectors;

    ConnectorCommonElem(const ConnectorApi* p)
    { api = p; }

    ~ConnectorCommonElem() override
    { connectors.clear(); }

    void global_init() override
    {
        if ( api->pinit )
            api->pinit();
    }

    void global_term() override
    {
        if ( api->dtor )
            api->dtor(connector_common);

        if ( api->pterm )
            api->pterm();
    }

    void thread_init() override
    {
        if ( !api->tinit )
            return;

        unsigned instance = get_instance_id();

        for ( auto& conn : connectors )
        {
            assert(!conn.second.thread_connectors[instance]);
            Connector* connector = api->tinit(conn.second.config);
            conn.second.thread_connectors[instance] = std::move(connector);
        }
    }

    void thread_term() override
    {
        if ( !api->tterm )
            return;

        unsigned instance = get_instance_id();

        for ( auto& conn : connectors )
        {
            if ( conn.second.thread_connectors[instance] )
            {
                api->tterm(conn.second.thread_connectors[instance]);
                conn.second.thread_connectors[instance] = nullptr;
            }
        }
    }
    void instantiate(Module* mod, SnortConfig*, const char*) override
    {
        assert(mod);

        ConnectorCommon* con_com = api->ctor(mod);
        assert(con_com);

        for ( auto& cfg : con_com->config_set )
        {
            if ( ConnectorManager::is_instantiated(cfg->connector_name) != Connector::CONN_UNDEFINED )
            {
                ParseError("redefinition of \"%s\" connector", cfg->connector_name.c_str());
                continue;
            }
            ConnectorElem connector_elem(*cfg);
            connectors.emplace(cfg->connector_name, std::move(connector_elem));
        }
        connector_common = con_com;
    }
};

//-------------------------------------------------------------------------

PlugInterface* ConnectorManager::get_interface(const ConnectorApi* api)
{ return new ConnectorCommonElem(api); }

Connector* ConnectorManager::get_connector(const std::string& connector_name)
{
    unsigned instance = get_instance_id();
    std::vector<PlugInterface*> piv = PluginManager::get_interfaces(PT_CONNECTOR);

    for ( auto& sc : piv )
    {
        ConnectorCommonElem* c = (ConnectorCommonElem*)sc;
        auto connector_ptr = c->connectors.find(connector_name);

        if ( connector_ptr != c->connectors.end() )
        {
            if ( connector_ptr->second.thread_connectors[instance] )
                return ( connector_ptr->second.thread_connectors[instance] );
        }
    }
    return ( nullptr );
}

void ConnectorManager::update_thread_connector(
    const std::string& connector_name, int instance_id, snort::Connector* connector)
{
    std::vector<PlugInterface*> piv = PluginManager::get_interfaces(PT_CONNECTOR);

    for ( auto& sc : piv )
    {
        ConnectorCommonElem* c = (ConnectorCommonElem*)sc;
        auto connector_ptr = c->connectors.find(connector_name);

        if (connector_ptr != c->connectors.end())
        {
            if (connector_ptr->second.thread_connectors[instance_id]) {
                if (connector != connector_ptr->second.thread_connectors[instance_id])
                    c->api->tterm(connector_ptr->second.thread_connectors[instance_id]);
            }

            connector_ptr->second.thread_connectors[instance_id] = connector;
            break;
        }
    }
}

void ConnectorManager::thread_reinit()
{
    unsigned instance = get_instance_id();
    std::vector<PlugInterface*> piv = PluginManager::get_interfaces(PT_CONNECTOR);

    for ( auto& sc : piv )
    {
        ConnectorCommonElem* c = (ConnectorCommonElem*)sc;

        for ( auto& conn : c->connectors )
        {
            if (conn.second.thread_connectors[instance])
                conn.second.thread_connectors[instance]->reinit();
        }
    }
}

Connector::Direction ConnectorManager::is_instantiated(const std::string& name)
{
    std::vector<PlugInterface*> piv = PluginManager::get_interfaces(PT_CONNECTOR);

    for ( auto& sc : piv )
    {
        ConnectorCommonElem* c = (ConnectorCommonElem*)sc;

        if ( !c->connector_common )
            continue;

        auto connector_ptr = c->connectors.find(name);

        if ( connector_ptr != c->connectors.end() )
            return connector_ptr->second.config.direction;
    }

    return Connector::CONN_UNDEFINED;
}

