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
// markup.h author Russ Combs <rucombs@cisco.com>

#ifndef HELPERS_MARKUP_H
#define HELPERS_MARKUP_H

#include <string>

namespace parser
{
class Markup
{
public:
    static void enable(bool = true);

    static const char* head(unsigned level = 1);
    static const char* item();

    static const char* emphasis_on();
    static const char* emphasis_off();
    static const std::string& emphasis(const std::string&);
    static const std::string& escape(const char* const);
    static const std::string& escape(const std::string&);
    static const char* add_newline();

private:
    static bool enabled;
};
}

#endif

