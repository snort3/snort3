//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_http.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http.h"

#include "framework/cursor.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "protocols/packet.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_flow_data.h"
#include "http_inspect.h"
#include "http_msg_head_shared.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;


bool HttpRuleOptModule::begin(const char*, int, SnortConfig*)
{
    sub_id = 0;
    form = 0;
    return true;
}

bool HttpRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("field"))
    {
        if (sub_id != 0)
            ParseError("Only specify one header field to match");
        std::string field = v.get_string();
        const int32_t name_size = (field.size() <= MAX_FIELD_NAME_LENGTH) ?
            field.size() : MAX_FIELD_NAME_LENGTH;
        uint8_t lower_name[MAX_FIELD_NAME_LENGTH];
        for (int32_t k=0; k < name_size; k++)
        {
            lower_name[k] = ((field[k] < 'A') || (field[k] > 'Z')) ?
                field[k] : field[k] - ('A' - 'a');
        }
        sub_id = str_to_code(lower_name, name_size, HttpMsgHeadShared::header_list);
        if (sub_id == STAT_OTHER)
            ParseError("Unrecognized header field name");
    }
    else if (v.is("request"))
    {
        form |= FORM_REQUEST;
    }
    return true;
}

uint32_t HttpIpsOption::hash() const
{
    uint32_t a = IpsOption::hash();
    uint32_t b = (uint32_t)pdu_section;
    uint32_t c = buffer_info.hash();
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpIpsOption::operator==(const IpsOption& ips) const
{
    const HttpIpsOption& hio = static_cast<const HttpIpsOption&>(ips);
    return IpsOption::operator==(ips) &&
           pdu_section == hio.pdu_section &&
           buffer_info == hio.buffer_info;
}

// If pdu_section isn't NONE get inspector pointer.
HttpInspect const* HttpIpsOption::eval_helper(Packet* p)
{
    if (!p->flow || !p->flow->gadget || (HttpInspect::get_latest_is(p) == PS_NONE))
        return nullptr;

    const HttpFlowData* const hi_flow_data = HttpInspect::http_get_flow_data(p->flow);

    const HttpInspect* const hi = (hi_flow_data->is_for_httpx()) ?
        (HttpInspect*)(p->flow->assistant_gadget) : (HttpInspect*)(p->flow->gadget);

    return hi;
}

section_flags HttpIpsOption::get_pdu_section(bool to_server) const
{
    // Trailer with request sub-option in a rule working on the response
    // should be evaluated during the response headers
    if (pdu_section == PS_TRAILER && buffer_info.is_request() && !to_server)
        return section_to_flag(PS_HEADER);
    return section_to_flag(pdu_section);
}
