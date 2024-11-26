//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// the CONNECTOR_API_VERSION will change if anything in this file changes.
// see also framework/base_api.h.

#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "framework/base_api.h"
#include "main/snort_types.h"

namespace snort
{
// this is the current version of the api
#define CONNECTOR_API_VERSION ((BASE_API_VERSION << 16) | 3)

//-------------------------------------------------------------------------
// api for class
// ctor, dtor are in main thread
// other methods are packet thread specific
//-------------------------------------------------------------------------

class ConnectorConfig;

class ConnectorMsg
{
public:
    ConnectorMsg() = default;

    ConnectorMsg(const uint8_t* data, uint32_t length, bool pass_ownership = false) :
        data(data), length(length), owns(pass_ownership)
    { }

    ~ConnectorMsg()
    { if (owns) delete[] data; }

    ConnectorMsg(ConnectorMsg&) = delete;
    ConnectorMsg& operator=(ConnectorMsg& other) = delete;

    ConnectorMsg(ConnectorMsg&& other) :
        data(other.data), length(other.length), owns(other.owns)
    { other.owns = false; }

    ConnectorMsg& operator=(ConnectorMsg&& other)
    {
        if ( owns )
            delete[] data;

        data = other.data;
        length = other.length;
        owns = other.owns;

        other.owns = false;

        return *this;
    }

    const uint8_t* get_data() const
    { return data; }

    uint32_t get_length() const
    { return length; }

private:
    const uint8_t* data = nullptr;
    uint32_t length = 0;
    bool owns = false;
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

    using ID = std::variant<const char*, int>;

    Connector(const ConnectorConfig& config) : config(config) { }
    virtual ~Connector() = default;

    virtual const ID get_id(const char*) const
    { return null; }

    virtual bool transmit_message(const ConnectorMsg&, const ID& = null) = 0;
    virtual bool transmit_message(const ConnectorMsg&&, const ID& = null) = 0;

    virtual ConnectorMsg receive_message(bool block) = 0;

    virtual bool flush()
    { return true; }

    virtual void reinit()
    { }

    inline Direction get_connector_direction() const;
    inline const std::string& get_connector_name() const;

protected:
    const ConnectorConfig& config;
    static constexpr ID null {nullptr};
};

class ConnectorConfig
{
public:
    typedef std::vector<std::unique_ptr<ConnectorConfig>> ConfigSet;
    Connector::Direction direction;
    std::string connector_name;

    virtual ~ConnectorConfig() = default;
};

Connector::Direction Connector::get_connector_direction() const
{ return config.direction; }

const std::string& Connector::get_connector_name() const
{ return config.connector_name; }

class SO_PUBLIC ConnectorCommon
{
public:
    ConnectorCommon(ConnectorConfig::ConfigSet&& c_s) :
        config_set(std::move(c_s))
    { }

    virtual ~ConnectorCommon() = default;

    const ConnectorConfig::ConfigSet config_set;
};

typedef ConnectorCommon* (* ConnectorNewFunc)(Module*);
typedef void (* ConnectorDelFunc)(ConnectorCommon*);
typedef Connector* (* ConnectorThreadInitFunc)(const ConnectorConfig&);
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

