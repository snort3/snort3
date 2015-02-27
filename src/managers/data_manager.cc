//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// data_manager.h author Russ Combs <rucombs@cisco.com>

#include "data_manager.h"

#include <list>
using namespace std;

#include "framework/plug_data.h"
#include "framework/module.h"
#include "module_manager.h"
#include "snort.h"

struct DataBlock
{
    const DataApi* api;

    // FIXIT-H move data to snort config for reload
    PlugData* data;

    DataBlock(const DataApi* p)
    { api = p; data = nullptr; }

    ~DataBlock()
    {
        if ( data )
            api->dtor(data);
    }
};

static list<DataBlock*> s_data;

static DataBlock* get_block(const char* keyword)
{
    for ( auto* p : s_data )
        if ( !strcasecmp(p->api->base.name, keyword) )
            return p;

    return nullptr;
}

static DataBlock* get_block(PlugData* d)
{
    for ( auto* p : s_data )
        if ( p->data == d )
            return p;

    return nullptr;
}

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void DataManager::add_plugin(const DataApi* api)
{
    s_data.push_back(new DataBlock(api));
}

void DataManager::release_plugins()
{
    for ( auto p : s_data )
        delete p;

    s_data.clear();
}

void DataManager::dump_plugins()
{
    Dumper d("Data");

    for ( auto* p : s_data )
        d.dump(p->api->base.name, p->api->base.version);
}

void DataManager::instantiate(
    const DataApi* api, Module* mod, SnortConfig*)
{
    DataBlock* b = get_block(api->base.name);
    assert(b);

    if ( b )
        b->data = api->ctor(mod);
}

PlugData* DataManager::get_data(const char* key, SnortConfig* sc)
{
    DataBlock* b = get_block(key);

    if ( !b )
        return nullptr;

    if ( !b->data )
    {
        // create default instance
        Module* mod = ModuleManager::get_module(key);
        mod->begin(key, 0, sc);
        mod->end(key, 0, nullptr);
        b->data = b->api->ctor(mod);
    }
    return b->data;
}

PlugData* DataManager::acquire(const char* key, SnortConfig* sc)
{
    PlugData* pd = get_data(key, sc);
    assert(pd);

    if ( pd )
        pd->add_ref();

    return pd;
}

void DataManager::release(PlugData* p)
{
    DataBlock* b = get_block(p);

    // FIXIT-H this implementation can't reload
    //assert(b && b->data);
    if ( !b )
        return;

    b->data->rem_ref();

    if ( !b->data->get_ref() )
    {
        b->api->dtor(b->data);
        b->data = nullptr;
    }
}

