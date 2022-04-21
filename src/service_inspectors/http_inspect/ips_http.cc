//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "service_inspectors/http2_inspect/http2_flow_data.h"

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
    para_list.reset();
    sub_id = 0;
    form = 0;
    is_trailer_opt = false;
    return true;
}

bool HttpRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("field"))
    {
        if (sub_id != 0)
            ParseError("Only specify one header field to match");
        para_list.field = v.get_string();
        const int32_t name_size = (para_list.field.size() <= MAX_FIELD_NAME_LENGTH) ?
            para_list.field.size() : MAX_FIELD_NAME_LENGTH;
        uint8_t lower_name[MAX_FIELD_NAME_LENGTH];
        for (int32_t k=0; k < name_size; k++)
        {
            lower_name[k] = ((para_list.field[k] < 'A') || (para_list.field[k] > 'Z')) ?
                para_list.field[k] : para_list.field[k] - ('A' - 'a');
        }
        sub_id = str_to_code(lower_name, name_size, HttpMsgHeadShared::header_list);
        if (sub_id == STAT_OTHER)
            ParseError("Unrecognized header field name");
    }
    else if (v.is("request"))
    {
        para_list.request = true;
        form |= FORM_REQUEST;
    }
    else if (v.is("with_header"))
    {
        para_list.with_header = true;
        inspect_section = IS_HEADER;
    }
    else if (v.is("with_body"))
    {
        para_list.with_body = true;
        inspect_section = IS_BODY;
    }
    else if (v.is("with_trailer"))
    {
        para_list.with_trailer = true;
        inspect_section = IS_TRAILER;
    }
    return true;
}

bool HttpRuleOptModule::end(const char*, int, SnortConfig*)
{
    // Check for option conflicts
    if (para_list.with_header + para_list.with_body + para_list.with_trailer > 1)
        ParseError("Only specify one with_ option. Use the one that happens last.");
    if ( is_trailer_opt && (para_list.with_header || para_list.with_body) &&
        !para_list.request)
        ParseError("Trailers with with_ option must also specify request");
    return true;
}

void HttpRuleOptModule::HttpRuleParaList::reset()
{
    field.clear();
    request = false;
    with_header = false;
    with_body = false;
    with_trailer = false;
}

uint32_t HttpIpsOption::hash() const
{
    uint32_t a = IpsOption::hash();
    uint32_t b = (uint32_t)inspect_section;
    uint32_t c = buffer_info.hash();
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpIpsOption::operator==(const IpsOption& ips) const
{
    const HttpIpsOption& hio = static_cast<const HttpIpsOption&>(ips);
    return IpsOption::operator==(ips) &&
           inspect_section == hio.inspect_section &&
           buffer_info == hio.buffer_info;
}

// Verify inspect_section matches. If it does get inspector pointer.
HttpInspect const* HttpIpsOption::eval_helper(Packet* p)
{
    if (!p->flow || !p->flow->gadget || (HttpInspect::get_latest_is(p) == IS_NONE))
        return nullptr;

    const bool section_match =
        (p->packet_flags & PKT_FAST_PAT_EVAL) ||
        (HttpInspect::get_latest_is(p) == inspect_section) ||
        ((HttpInspect::get_latest_is(p) == IS_HEADER) && (inspect_section == IS_FLEX_HEADER)) ||
        ((HttpInspect::get_latest_is(p) == IS_FIRST_BODY) && (inspect_section == IS_BODY)) ||
        ((HttpInspect::get_latest_src(p) == SRC_CLIENT) && (inspect_section == IS_FLEX_HEADER));
    if (!section_match)
        return nullptr;

    const Http2FlowData* const h2i_flow_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    const HttpInspect* const hi = (h2i_flow_data != nullptr) ?
        (HttpInspect*)(p->flow->assistant_gadget) : (HttpInspect*)(p->flow->gadget);

    return hi;
}

