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
// http_form_data_event.h author Anna Norokh <anorokh@cisco.com>

#ifndef HTTP_FORM_DATA_EVENT_H
#define HTTP_FORM_DATA_EVENT_H

#include <string>
#include <vector>
#include <utility>

#include "framework/data_bus.h"
#include "service_inspectors/http_inspect/http_enum.h"

namespace snort
{
// This event is published when HTTP multipart/form-data content is present and processing completes.
class SO_PUBLIC HttpFormDataEvent : public snort::DataEvent
{
public:
    using FieldPair = std::pair<std::string, std::string>;
    using FieldVector = std::vector<FieldPair>;

    HttpFormDataEvent(const FieldVector& fields, HttpEnums::MethodId method)
        : form_data_fields(fields), method_id(method) { }

    const std::string& get_form_data_uri() const
    {
        if (form_data_uri.empty() and !form_data_fields.empty())
            format_as_uri();
        return form_data_uri;
    }

    HttpEnums::MethodId get_method_id() const
    { return method_id; }

private:
    void format_as_uri() const;

    const FieldVector& form_data_fields;
    mutable std::string form_data_uri;
    HttpEnums::MethodId method_id;
};

}
#endif

