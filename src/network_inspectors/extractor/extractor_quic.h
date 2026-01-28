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
// extractor_quic.h author Volodymyr Shpyrka <vshpyrka@cisco.com>

#ifndef EXTRACTOR_QUIC_H
#define EXTRACTOR_QUIC_H

#include "extractors.h"

class QuicExtractorFlowData;

class QuicExtractor : public ExtractorEvent
{
public:
    using FdStrGetFn = const char* (*) (const QuicExtractorFlowData&);
    using FdStrField = DataField<const char*, const QuicExtractorFlowData&>;

    QuicExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields);

    std::vector<const char*> get_field_names() const override;
    void dump(const QuicExtractorFlowData&);

private:
    struct ClientHello : public DataHandler
    {
        ClientHello(QuicExtractor& owner, const char* name)
            : DataHandler(name), owner(owner) {}
        void handle(DataEvent&, Flow*) override;
        QuicExtractor& owner;
    };

    struct HandshakeComplete : public DataHandler
    {
        HandshakeComplete(QuicExtractor& owner, const char* name)
            : DataHandler(name), owner(owner) {}
        void handle(DataEvent&, Flow*) override;
        QuicExtractor& owner;
    };

    void internal_tinit(const snort::Connector::ID*) override;

    std::vector<FdStrField> fd_str_fields;

    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

#endif
