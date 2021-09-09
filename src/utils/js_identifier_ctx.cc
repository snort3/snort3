//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// js_identifier_ctx.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_identifier_ctx.h"

#if !defined(CATCH_TEST_BUILD) && !defined(BENCHMARK_TEST)
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_module.h"
#else
namespace HttpEnums
{
enum PEG_COUNT
{
    PEG_JS_IDENTIFIER
};
}

class HttpModule
{
public:
    static void increment_peg_counts(HttpEnums::PEG_COUNT) {}
};
#endif // CATCH_TEST_BUILD

#define FIRST_NAME_SIZE   26
#define LAST_NAME_SIZE  9999

static const char s_ident_first_names[FIRST_NAME_SIZE] =
{
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

const char* JSIdentifierCtx::substitute(const char* identifier)
{
    const auto it = ident_names.find(identifier);
    if (it != ident_names.end())
        return it->second.c_str();

    if (++ident_last_name > LAST_NAME_SIZE)
    {
        if (++ident_first_name > FIRST_NAME_SIZE - 1)
            return nullptr;

        ident_last_name = 0;
    }

    if (++unique_ident_cnt > depth)
        return nullptr;

    ident_names[identifier] = s_ident_first_names[ident_first_name]
        + std::to_string(ident_last_name);

    HttpModule::increment_peg_counts(HttpEnums::PEG_JS_IDENTIFIER);
    return ident_names[identifier].c_str();
}

void JSIdentifierCtx::reset()
{
    ident_first_name = 0;
    ident_last_name = -1;
    unique_ident_cnt = 0;
    ident_names.clear();
}

