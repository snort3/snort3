//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_http2.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http2.h"

#include "framework/cursor.h"
#include "protocols/packet.h"

#include "http2_flow_data.h"
#include "http2_inspect.h"

using namespace snort;
using namespace Http2Enums;

THREAD_LOCAL std::array<ProfileStats, PSI_MAX> Http2CursorModule::http2_ps;

bool Http2CursorModule::begin(const char*, int, SnortConfig*)
{
    para_list.reset();
    return true;
}

bool Http2CursorModule::set(const char*, Value& /*v*/, SnortConfig*)
{
    return false;
}

bool Http2CursorModule::end(const char*, int, SnortConfig*)
{
    return true;
}

void Http2CursorModule::Http2RuleParaList::reset()
{
}

uint32_t Http2IpsOption::hash() const
{
    return IpsOption::hash();
}

bool Http2IpsOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus Http2IpsOption::eval(Cursor& c, Packet* p)
{
    Profile profile(Http2CursorModule::http2_ps[psi]);

    if (!p->flow || !p->flow->gadget)
        return NO_MATCH;

    InspectionBuffer hb;

    if (! ((Http2Inspect*)(p->flow->gadget))->get_buf((unsigned)buffer_index, p, hb))
        return NO_MATCH;

    c.set(key, hb.data, hb.len);

    return MATCH;
}

//-------------------------------------------------------------------------
// http2_frame_data
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http2_frame_data"
#undef IPS_HELP
#define IPS_HELP "rule option to see HTTP/2 frame body"

static Module* frame_data_mod_ctor()
{
    return new Http2CursorModule(IPS_OPT, IPS_HELP, HTTP2_BUFFER_FRAME_DATA, CAT_SET_OTHER,
        PSI_FRAME_DATA);
}

static const IpsApi frame_data_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        1,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        IPS_HELP,
        frame_data_mod_ctor,
        Http2CursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    Http2IpsOption::opt_ctor,
    Http2IpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http2_frame_header
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http2_frame_header"
#undef IPS_HELP
#define IPS_HELP "rule option to see 9-octet HTTP/2 frame header"

static Module* frame_header_mod_ctor()
{
    return new Http2CursorModule(IPS_OPT, IPS_HELP, HTTP2_BUFFER_FRAME_HEADER, CAT_SET_OTHER,
        PSI_FRAME_HEADER);
}

static const IpsApi frame_header_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        1,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        IPS_HELP,
        frame_header_mod_ctor,
        Http2CursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    Http2IpsOption::opt_ctor,
    Http2IpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

const BaseApi* ips_http2_frame_data = &frame_data_api.base;
const BaseApi* ips_http2_frame_header = &frame_header_api.base;

