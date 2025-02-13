//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractors.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractors.h"

using namespace std;
using namespace snort;

THREAD_LOCAL ExtractorLogger* ExtractorEvent::logger = nullptr;

void ExtractorEvent::tinit(ExtractorLogger* l, const snort::Connector::ID* service_id)
{
    logger = l;
    internal_tinit(service_id);
}

vector<const char*> ExtractorEvent::get_field_names() const
{
    vector<const char*> res;

    for (auto& f : nts_fields)
        res.push_back(f.name);

    for (auto& f : sip_fields)
        res.push_back(f.name);

    for (auto& f : num_fields)
        res.push_back(f.name);

    for (auto& f : buf_fields)
        res.push_back(f.name);

    for (auto& f : str_fields)
        res.push_back(f.name);

    return res;
}

const std::map<std::string, ExtractorEvent::NtsGetFn> ExtractorEvent::nts_getters =
{
    {"ts", get_timestamp},
};

const std::map<std::string, ExtractorEvent::SipGetFn> ExtractorEvent::sip_getters =
{
    {"id.orig_h", get_ip_src},
    {"id.resp_h", get_ip_dst},
};

const std::map<std::string, ExtractorEvent::NumGetFn> ExtractorEvent::num_getters =
{
    {"id.orig_p", ExtractorEvent::get_ip_src_port},
    {"id.resp_p", ExtractorEvent::get_ip_dst_port},
    {"uid", ExtractorEvent::get_uid},
    {"pkt_num", ExtractorEvent::get_pkt_num}
};
