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
// so_rule.h author Russ Combs <rucombs@cisco.com>

#ifndef SO_RULE_H
#define SO_RULE_H

// SO rule = shared object rule; allows implementing arbitrary C++ for
// detection below and beyond the text rule options.  An SO rule is just
// like a text rule except that it can call function hooks. It can also
// define its own rule options and any other plugins it may need.

#include "framework/base_api.h"
#include "framework/ips_option.h"
#include "main/snort_types.h"

namespace snort
{
struct Packet;
}

// this is the current version of the api
#define SOAPI_VERSION ((BASE_API_VERSION << 16) | 0)

//-------------------------------------------------------------------------
// rule format is:  header ( [<stub opts>;] soid:<tag>; [<remaining opts>;] )
// <remaining opts> may include so opts like so:<key>;
// ctor(<key>) returns eval func and optional data
// data is freed with dtor(data)

typedef snort::IpsOption::EvalStatus (* SoEvalFunc)(void*, class Cursor&, snort::Packet*);
typedef SoEvalFunc (* SoNewFunc)(const char* key, void**);
typedef void (* SoDelFunc)(void*);
typedef void (* SoAuxFunc)();

struct SoApi
{
    snort::BaseApi base;

    const uint8_t* rule;
    unsigned length;

    // these may be nullptr
    SoAuxFunc pinit;  // initialize global plugin data
    SoAuxFunc pterm;  // clean-up pinit()

    SoAuxFunc tinit;  // initialize thread-local plugin data
    SoAuxFunc tterm;  // clean-up tinit()

    // these must be set
    SoNewFunc ctor;   // get eval with optional instance data
    SoDelFunc dtor;   // clean up instance data
};

#endif

