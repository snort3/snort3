//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// ssl_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#include "ssl_module.h"

#include <assert.h>
#include <sstream>

#include "parser/parser.h"
#include "ssl_inspector.h"

using namespace std;

#define SSL_INVALID_CLIENT_HELLO_STR "Invalid Client HELLO after Server HELLO Detected"
#define SSL_INVALID_SERVER_HELLO_STR "Invalid Server HELLO without Client HELLO Detected"
#define SSL_HEARTBLEED_REQUEST_STR "Heartbeat Read Overrun Attempt Detected"
#define SSL_HEARTBLEED_RESPONSE_STR "Large Heartbeat Response Detected"

static const Parameter s_params[] =
{
    { "trust_servers", Parameter::PT_BOOL, nullptr, "false",
      "disables requirement that application (encrypted) data must be observed on both sides" },

    { "max_heartbeat_length", Parameter::PT_INT, "0:65535", "0",
      "maximum length of heartbeat record allowed" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap ssl_rules[] =
{
    { SSL_INVALID_CLIENT_HELLO, SSL_INVALID_CLIENT_HELLO_STR },
    { SSL_INVALID_SERVER_HELLO, SSL_INVALID_SERVER_HELLO_STR },
    { SSL_ALERT_HB_REQUEST, SSL_HEARTBLEED_REQUEST_STR },
    { SSL_ALERT_HB_RESPONSE, SSL_HEARTBLEED_RESPONSE_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// ssl module
//-------------------------------------------------------------------------

SslModule::SslModule() : Module(SSL_NAME, SSL_HELP, s_params)
{
    conf = nullptr;
}

SslModule::~SslModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* SslModule::get_rules() const
{ return ssl_rules; }

const PegInfo* SslModule::get_pegs() const
{ return ssl_peg_names; }

PegCount* SslModule::get_counts() const
{ return (PegCount*)&sslstats; }

ProfileStats* SslModule::get_profile() const
{ return &sslPerfStats; }

bool SslModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("trust_servers") )
    {
        if (v.get_bool())
            conf->trustservers = true;
    }
    else if ( v.is("max_heartbeat_length") )
        conf->max_heartbeat_len = v.get_long();

    else
        return false;

    return true;
}

SSL_PROTO_CONF* SslModule::get_data()
{
    SSL_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool SslModule::begin(const char*, int, SnortConfig*)
{
    conf = new SSL_PROTO_CONF;
    conf->max_heartbeat_len = 0;
    conf->trustservers = false;
    return true;
}

