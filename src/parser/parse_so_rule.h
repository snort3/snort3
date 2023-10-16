//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef PARSE_SO_RULE_H
#define PARSE_SO_RULE_H

// must parse out stub options for --dump-dynamic-rules
//
// only selected options are shown in so rule stubs
// all other options are stripped out of the stub
//
// assumes valid rule syntax
// deletes all # comments
// replaces each /* comment */ with a single space
// replaces each newline with a single space
// deletes more than one space between options
// return true if parsed rule body close

#include <string>

bool get_so_stub(const char* in, std::string& stub);

#endif

