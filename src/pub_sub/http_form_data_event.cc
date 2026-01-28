//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_form_data_event.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_form_data_event.h"

using namespace snort;
using namespace std;

static string normalize(const string& value)
{
    string field;
    field.reserve(value.length());
    bool in_space = true;

    for (const auto& ch : value)
    {
        if (isspace(ch))
        {
            in_space = true;
        }
        else
        {
            if (in_space && !field.empty())
                field += " ";
            field += ch;
            in_space = false;
        }
    }

    return field;
}

void HttpFormDataEvent::format_as_uri() const
{
    if (form_data_fields.empty())
        return;

    size_t estimated_size = 0;
    for (const auto& field : form_data_fields)
        estimated_size += field.first.length() + field.second.length() + 2; // for "=&"

    form_data_uri.reserve(estimated_size);

    auto it = form_data_fields.begin();
    form_data_uri = it->first;
    form_data_uri += '=';
    form_data_uri += normalize(it->second);

    for (++it; it != form_data_fields.end(); ++it)
    {
        form_data_uri += '&';
        form_data_uri += it->first;
        form_data_uri += '=';
        form_data_uri += normalize(it->second);
    }
}
