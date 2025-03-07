//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_dns.h author Cisco

#ifndef EXTRACTOR_DNS_H
#define EXTRACTOR_DNS_H

#include "extractors.h"

class DnsResponseExtractor : public ExtractorEvent
{
public:
    DnsResponseExtractor(Extractor&, uint32_t tenant, const std::vector<std::string>& fields);

    void handle(DataEvent&, Flow*);

private:
    using Resp = Handler<DnsResponseExtractor>;

    void internal_tinit(const snort::Connector::ID*) override;

    static THREAD_LOCAL const snort::Connector::ID* log_id;
};

#endif
