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
// s2l_markup.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s2l_markup.h"

#include <cstring>

using namespace std;

namespace parser
{
bool Markup::enabled = false;

void Markup::enable(bool e)
{ enabled = e; }

const char hn[] = "========== ";

const char* Markup::head(unsigned level)
{
    std::size_t max = strlen(hn);

    if ( level >= max )
        level = (unsigned)max - 1;

    return enabled ? hn+max-level-1 : "";
}

const char* Markup::item()
{ return enabled ? "* " : ""; }

const char* Markup::emphasis_on()
{ return enabled ? "*" : ""; }

const char* Markup::emphasis_off()
{ return enabled ? "*" : ""; }

const string& Markup::emphasis(const string& s)
{
    static string m;
    m.clear();
    m += emphasis_on();
    m += s;
    m += emphasis_off();
    m += "  ";
    return m;
}

const string& Markup::escape(const char* const c)
{ return escape(string(c)); }

// FIXIT-L some asciidoc characters need to be escaped.
// This function should escape all of those characters
const string& Markup::escape(const string& s)
{
    static string m;
    m = s;

#if 0

    const char* const asciidoc_chars = "*<>^'";

    if (enabled)
    {
        for (size_t found = m.find_first_of(asciidoc_chars, 0);
            found != string::npos;
            found = m.find_first_of(asciidoc_chars, found))
        {
            m.insert(found, "\\");
            found +=2;
        }
    }
#endif
    return m;
}

const char* Markup::add_newline()
{
    static const char* const newline = "\n\0";
    static const char* const empty = "\0";

    return enabled ? newline : empty;
}
}

