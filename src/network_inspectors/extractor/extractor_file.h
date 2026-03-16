//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// extractor_file.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_FILE_H
#define EXTRACTOR_FILE_H

#include "extractors.h"

class FileExtractor : public ExtractorEvent
{
public:
    using SubGetFn = bool (*) (const DataEvent*, const Flow*);
    using SubField = DataField<bool, const DataEvent*, const Flow*>;

    FileExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields);

    void handle(DataEvent&, Flow*);
    std::vector<const char*> get_field_names() const override;

private:
    using Eof = Handler<FileExtractor>;

    void internal_tinit(const snort::Connector::ID*) override;

    std::vector<SubField> sub_fields;
    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

#endif
