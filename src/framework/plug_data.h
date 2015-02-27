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
// plug_data.h author Russ Combs <rucombs@cisco.com>

#ifndef PLUG_DATA_H
#define PLUG_DATA_H

#include "framework/base_api.h"

struct SnortConfig;

// this is the current version of the api
#define PDAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define PDAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

class PlugData
{
public:
    virtual ~PlugData() { }

    unsigned get_ref() { return ref_count; }
    void set_ref(unsigned r) { ref_count = r; }

    void add_ref() { ++ref_count; }
    void rem_ref() { --ref_count; }

    bool is_inactive();

protected:
    PlugData() { ref_count = 0; }

private:
    unsigned ref_count;
};

template <typename T>
class PlugDataType : public PlugData
{
public:
    PlugDataType(T* t)
    { data = t; }

    ~PlugDataType()
    { delete data; }

    T* data;
};

typedef PlugData* (* DataNewFunc)(class Module*);
typedef void (* DataDelFunc)(PlugData*);

struct DataApi
{
    BaseApi base;

    DataNewFunc ctor;    // new
    DataDelFunc dtor;    // delete
};

#endif

