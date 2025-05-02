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
// mp_unix_transport_module.h author Oleksandr Stepanov <ostepano@cisco.com>

#ifndef MP_UNIX_TRANSPORT_MODULE_H
#define MP_UNIX_TRANSPORT_MODULE_H

#define MODULE_NAME "unix_transport"
#define MODULE_HELP "manage the unix transport layer"

#include "framework/module.h"
#include "framework/mp_transport.h"
#include "mp_unix_transport.h"

namespace snort
{

class MPUnixDomainTransportModule : public Module
{
    public:

    MPUnixDomainTransportModule();

    ~MPUnixDomainTransportModule() override
    { delete config; }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return GLOBAL; }

    MPUnixDomainTransportConfig* config;
    MPUnixTransportStats unix_transport_stats;
};

static Module* mod_ctor()
{
    return new MPUnixDomainTransportModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static MPTransport* mp_unixdomain_transport_ctor(Module* m)
{
    auto unix_tr_mod = (MPUnixDomainTransportModule*)m;
    return new MPUnixDomainTransport(unix_tr_mod->config, unix_tr_mod->unix_transport_stats);
}

static void mp_unixdomain_transport_dtor(MPTransport* t)
{
    delete t;
}

}

#endif
