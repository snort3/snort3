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
// connector.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef CONNECTOR_H
#define CONNECTOR_H

// Connector provides out-of-band communications among packet processing
// threads, high-availability partners, and other threads.

#include <string>
#include <vector>

#include "framework/base_api.h"
#include "main/snort_types.h"

namespace snort
{
// this is the current version of the api
#define CONNECTOR_API_VERSION ((BASE_API_VERSION << 16) | 0)

//-------------------------------------------------------------------------
// api for class
// ctor, dtor are in main thread
// other methods are packet thread specific
//-------------------------------------------------------------------------

struct ConnectorApi;
class ConnectorConfig;

struct ConnectorMsg
{
    uint32_t length;
    uint8_t* data;
};

class ConnectorMsgHandle
{
};

class SO_PUBLIC Connector
{
public:
    enum Direction
    {
        CONN_UNDEFINED,
        CONN_RECEIVE,
        CONN_TRANSMIT,
        CONN_DUPLEX
    };

    virtual ~Connector() = default;

    virtual ConnectorMsgHandle* alloc_message(const uint32_t, const uint8_t**) = 0;
    virtual void discard_message(ConnectorMsgHandle*) = 0;
    virtual bool transmit_message(ConnectorMsgHandle*) = 0;
    virtual ConnectorMsgHandle* receive_message(bool block) = 0;
    virtual ConnectorMsg* get_connector_msg(ConnectorMsgHandle*) = 0;
    virtual Direction get_connector_direction() = 0;

    const std::string connector_name;
    const ConnectorConfig* config;

protected:
    Connector() = default;
};

class ConnectorConfig
{
public:
    typedef std::vector<ConnectorConfig*> ConfigSet;
    Connector::Direction direction;
    std::string connector_name;
};

class SO_PUBLIC ConnectorCommon
{
public:
    ConnectorConfig::ConfigSet* config_set;
};

typedef ConnectorCommon* (* ConnectorNewFunc)(Module*);
typedef void (* ConnectorDelFunc)(ConnectorCommon*);
typedef Connector* (* ConnectorThreadInitFunc)(ConnectorConfig*);
typedef void (* ConnectorThreadTermFunc)(Connector*);
typedef void (* ConnectorFunc)();

struct ConnectorApi
{
    BaseApi base;
    unsigned flags;

    ConnectorFunc pinit;     // plugin init
    ConnectorFunc pterm;     // cleanup pinit()
    ConnectorThreadInitFunc tinit;     // thread local init
    ConnectorThreadTermFunc tterm;     // cleanup tinit()

    ConnectorNewFunc ctor;
    ConnectorDelFunc dtor;
};
}
#endif

