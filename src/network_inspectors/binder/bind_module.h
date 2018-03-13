//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// bind_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef BIND_MODULE_H
#define BIND_MODULE_H

// binder management interface

#include "framework/module.h"
#include "binding.h"

#define BIND_NAME "binder"
#define BIND_HELP "configure processing based on CIDRs, ports, services, etc."

struct BindStats
{
    PegCount packets;
    PegCount verdicts[BindUse::BA_MAX];
};

extern THREAD_LOCAL BindStats bstats;
extern THREAD_LOCAL snort::ProfileStats bindPerfStats;

class BinderModule : public snort::Module
{
public:
    BinderModule();
    ~BinderModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    // used to create default binder
    void add(const char* service, const char* type);
    void add(unsigned proto, const char* type);

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    std::vector<Binding*>& get_data();

    Usage get_usage() const override
    { return INSPECT; }

private:
    Binding* work;
    std::vector<Binding*> bindings;
    bool unsplit_nets;
    bool unsplit_ports;
    unsigned use_name_count;
    unsigned use_type_count;

    void add_file(const char* name, const char* type);
};

#endif

