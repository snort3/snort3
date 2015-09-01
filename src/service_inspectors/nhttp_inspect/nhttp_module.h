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
// nhttp_module.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MODULE_H
#define NHTTP_MODULE_H

#include "framework/module.h"

#include "nhttp_enum.h"

#define NHTTP_NAME "new_http_inspect"
#define NHTTP_HELP "new HTTP inspector"

struct NHttpParaList
{
public:
    bool test_input;
    bool test_output;
    long request_depth;
    long response_depth;
};

class NHttpModule : public Module
{
public:
    NHttpModule() : Module(NHTTP_NAME, NHTTP_HELP, nhttp_params) { }
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override { return true; }
    bool set(const char*, Value&, SnortConfig*) override;
    unsigned get_gid() const override { return NHttpEnums::NHTTP_GID; }
    const RuleMap* get_rules() const override { return nhttp_events; }
    NHttpParaList get_params() const { return params; }

private:
    static const Parameter nhttp_params[];
    static const RuleMap nhttp_events[];
    NHttpParaList params;
};

#endif

