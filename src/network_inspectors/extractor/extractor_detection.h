//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_detection.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_RULES_H
#define EXTRACTOR_RULES_H

#include "extractors.h"

class BuiltinExtractor : public ExtractorEvent
{
public:
    BuiltinExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields);

    void handle(DataEvent&, Flow*);

private:
    using IpsBuiltin = Handler<BuiltinExtractor>;

    void internal_tinit(const snort::Connector::ID*) override;

    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

class IpsUserExtractor : public ExtractorEvent
{
public:
    using VecGetFn = const std::vector<const char*>& (*) (const DataEvent*, const Flow*);
    using VecField = DataField<const std::vector<const char*>&, const DataEvent*, const Flow*>;

    IpsUserExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields, bool contextual);

    std::vector<const char*> get_field_names() const override;
    void handle(DataEvent&, Flow*);

private:
    using IpsUser = Handler<IpsUserExtractor>;

    void internal_tinit(const snort::Connector::ID*) override;

    std::vector<VecField> vec_fields;
    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

#endif
