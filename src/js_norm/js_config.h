//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// js_config.h author Danylo Kyrylov <dkyrylov@cisco.com>

#ifndef JS_CONFIG_H
#define JS_CONFIG_H

#include <string>
#include <unordered_set>

struct JSNormConfig
{
    int64_t bytes_depth = -1;
    int32_t identifier_depth = 0xffff;
    uint8_t max_template_nesting = 32;
    uint32_t max_bracket_depth = 256;
    uint32_t max_scope_depth = 256;
    uint32_t pdf_max_dictionary_depth = 32;
    std::unordered_set<std::string> ignored_ids;
    std::unordered_set<std::string> ignored_props;
};

#endif
