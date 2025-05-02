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
// mp_unix_transport_module.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mp_unix_transport_module.h"

#include "main/snort_config.h"
#include "log/messages.h"
#include "utils/stats.h"

#define DEFAULT_UNIX_DOMAIN_SOCKET_PATH "/tmp/snort_unix_connectors"

using namespace snort;

static const Parameter unix_transport_params[] =
{
    { "unix_domain_socket_path" , Parameter::PT_STRING, nullptr, DEFAULT_UNIX_DOMAIN_SOCKET_PATH, "unix socket folder" },
    { "max_connect_retries", Parameter::PT_INT, nullptr, "5", "max connection retries" },
    { "retry_interval_seconds", Parameter::PT_INT, nullptr, "30", "retry interval in seconds" },
    { "connect_timeout_seconds", Parameter::PT_INT, nullptr, "30", "connect timeout in seconds" },
    { "consume_message_timeout_milliseconds", Parameter::PT_INT, nullptr, "100", "consume message timeout in milliseconds" },
    { "consume_message_batch_size", Parameter::PT_INT, nullptr, "5", "consume message batch size" },
    { "enable_logging", Parameter::PT_BOOL, nullptr, "false", "enable logging" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo mp_unix_transport_pegs[] =
{
    { CountType::SUM, "sent_events", "mp_transport events sent count" },
    { CountType::SUM, "sent_bytes", "mp_transport events bytes sent count" },
    { CountType::SUM, "receive_events", "mp_transport events received count" },
    { CountType::SUM, "receive_bytes", "mp_transport events bytes received count" },
    { CountType::SUM, "sent_errors", "mp_transport events errors count" },
    { CountType::SUM, "successful_connections", "successful mp_transport connections count" },
    { CountType::SUM, "closed_connections", "closed mp_transport connections count" },
    { CountType::SUM, "connection_retries", "mp_transport connection retries count" },
    { CountType::END, nullptr, nullptr },
};

MPUnixDomainTransportModule::MPUnixDomainTransportModule(): Module(MODULE_NAME, MODULE_HELP, unix_transport_params)
{ 
    config = nullptr;
}

bool MPUnixDomainTransportModule::begin(const char *, int, SnortConfig *sc)
{
    assert(sc);
    assert(!config);
    config = new MPUnixDomainTransportConfig;
    config->max_processes = sc->max_procs;
    return true;
}

bool MPUnixDomainTransportModule::set(const char *, Value & v, SnortConfig *)
{
    if (v.is("unix_domain_socket_path"))
    {
        config->unix_domain_socket_path = v.get_string();
    }
    else if (v.is("max_connect_retries"))
    {
        config->conn_retries = true;
        config->max_retries = v.get_int32();
    }
    else if (v.is("retry_interval_seconds"))
    {
        config->retry_interval_seconds = v.get_int32();    
    }
    else if (v.is("connect_timeout_seconds"))
    {
        config->connect_timeout_seconds = v.get_int32();
    }
    else if (v.is("consume_message_timeout_milliseconds"))
    {
        config->consume_message_timeout_milliseconds = v.get_int32();
    }
    else if (v.is("consume_message_batch_size"))
    {
        config->consume_message_batch_size = v.get_int32();
    }
    else if (v.is("enable_logging"))
    {
        config->enable_logging = v.get_bool();
    }
    else
    {
        WarningMessage("MPUnixDomainTransportModule: received unrecognized parameter %s\n", v.get_as_string().c_str());
        return false;
    }

    return true;
}

const PegInfo *MPUnixDomainTransportModule::get_pegs() const
{
    return mp_unix_transport_pegs;
}

PegCount *MPUnixDomainTransportModule::get_counts() const
{
    return (PegCount*)&unix_transport_stats;
}

static struct MPTransportApi mp_unixdomain_transport_api =
{
    {
        PT_MP_TRANSPORT,
        sizeof(MPTransportApi),
        MP_TRANSPORT_API_VERSION,
        2,
        API_RESERVED,
        API_OPTIONS,
        MODULE_NAME,
        MODULE_HELP,
        mod_ctor,
        mod_dtor
    },
    0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    mp_unixdomain_transport_ctor,
    mp_unixdomain_transport_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* mp_unix_transport[] =
#endif
{
    &mp_unixdomain_transport_api.base,
    nullptr
};
