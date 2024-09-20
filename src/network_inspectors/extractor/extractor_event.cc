//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor_event.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_event_handlers.h"

using namespace snort;
using namespace std;

vector<const char*> ExtractorEvent::get_field_names() const
{
    vector<const char*> res;

    for (auto& f : nts_fields)
        res.push_back(f.name);

    for (auto& f : sip_fields)
        res.push_back(f.name);

    for (auto& f : num_fields)
        res.push_back(f.name);

    for (auto& f : str_fields)
        res.push_back(f.name);

    return res;
}
