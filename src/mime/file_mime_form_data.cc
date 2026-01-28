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
// file_mime_form_data.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_form_data.h"

using namespace snort;

void MimeFormDataCollector::finalize_field(const std::string& filename)
{
    if (!is_form_data or current_field_name.empty() or is_size_exceeded)
        return;

    const std::string& value_to_use = (is_file_upload and !filename.empty())
        ? filename : current_field_value;

    const size_t field_total_len = current_field_name.length() + 1 + value_to_use.length() +
        (form_fields.empty() ? 0 : 1);

    if (accumulated_size + field_total_len > MAX_FORM_DATA_SIZE)
    {
        is_size_exceeded = true;
        return;
    }

    form_fields.emplace_back(current_field_name, value_to_use);
    accumulated_size += field_total_len;
}

