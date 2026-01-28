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
// file_mime_form_data.h author Anna Norokh <anorokh@cisco.com>

#ifndef FILE_MIME_FORM_DATA_H
#define FILE_MIME_FORM_DATA_H

#include <string>
#include <vector>
#include <utility>

namespace snort
{

// Maximum size of form-data content to collect for SQL injection analysis
#define MAX_FORM_DATA_SIZE 4096
// size to be discussed
// trigger built-in? + publish truncated

class MimeFormDataCollector
{
public:
    using FieldPair = std::pair<std::string, std::string>;
    using FieldVector = std::vector<FieldPair>;

    MimeFormDataCollector() = default;
    ~MimeFormDataCollector() = default;

    MimeFormDataCollector(const MimeFormDataCollector&) = delete;
    MimeFormDataCollector& operator=(const MimeFormDataCollector&) = delete;

    FieldVector&& take_fields()
    { return std::move(form_fields); }

    void set_field_name(const std::string& name)
    { current_field_name = name; }

    void set_field_value(const std::string& value)
    { current_field_value = value; }

    void set_is_form_data(bool is_form)
    { is_form_data = is_form; }

    void set_is_file_upload(bool is_file)
    { is_file_upload = is_file; }

    bool get_is_form_data() const
    { return is_form_data; }

    bool get_is_file_upload() const
    { return is_file_upload; }

    void finalize_field(const std::string& filename);

    void reset_part()
    {
        current_field_name.clear();
        current_field_value.clear();
        is_form_data = false;
        is_file_upload = false;
    }

private:
    FieldVector form_fields;
    std::string current_field_name;
    std::string current_field_value;
    size_t accumulated_size = 0;
    bool is_form_data = false;
    bool is_file_upload = false;
    bool is_size_exceeded = false;
};

}
#endif

