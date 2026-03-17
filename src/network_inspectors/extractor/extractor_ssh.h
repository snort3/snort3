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
// extractor_ssh.h author Cisco

#ifndef EXTRACTOR_SSH_H
#define EXTRACTOR_SSH_H

#include <cassert>

#include "extractors.h"

class SshExtractorFlowData;

class SshExtractor : public ExtractorEvent
{
public:
    using FdNumGetFn = uint64_t (*) (const SshExtractorFlowData&);
    using FdNumField = DataField<uint64_t, const SshExtractorFlowData&>;
    using FdBufGetFn = const char* (*) (const SshExtractorFlowData&);
    using FdBufField = DataField<const char*, const SshExtractorFlowData&>;

    SshExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields, bool detailed);

    std::vector<const char*> get_field_names() const override;
    void dump(const SshExtractorFlowData&);

private:
    struct Version : public DataHandler
    {
        Version(SshExtractor& owner, const char* name) : DataHandler(name), owner(owner) {}
        void handle(DataEvent&, Flow*) override;
        SshExtractor& owner;
    };

    struct Validation : public DataHandler
    {
        Validation(SshExtractor& owner, const char* name, bool detailed)
            : DataHandler(name), owner(owner), more(detailed) {}
        void handle(DataEvent&, Flow*) override;
        SshExtractor& owner;
        bool more;
    };

    void internal_tinit(const snort::Connector::ID*) override;

    std::vector<FdNumField> fd_num_fields;
    std::vector<FdBufField> fd_buf_fields;
    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

#endif
