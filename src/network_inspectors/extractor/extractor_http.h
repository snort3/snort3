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
// extractor_http.h author Maya Dagon <mdagon@cisco.com>

#ifndef EXTRACTOR_HTTP_H
#define EXTRACTOR_HTTP_H

#include "extractors.h"

class Field;

class HttpExtractor : public ExtractorEvent
{
public:
    using SubGetFn = const Field& (*) (const DataEvent*, const Packet*, const Flow*);
    using SubField = DataField<const Field&, const DataEvent*, const Packet*, const Flow*>;

    HttpExtractor(Extractor&, ExtractorLogger&, uint32_t tenant, const std::vector<std::string>& fields);

    std::vector<const char*> get_field_names() const override;
    void handle(DataEvent&, Flow*);

private:
    using Eot = Handler<HttpExtractor>;

    std::vector<SubField> sub_fields;
};

#endif
