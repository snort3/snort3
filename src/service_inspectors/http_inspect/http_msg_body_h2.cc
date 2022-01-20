//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_body_h2.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body_h2.h"

using namespace HttpEnums;

void HttpMsgBodyH2::update_flow()
{
    session_data->body_octets[source_id] = body_octets;
    if (session_data->h2_body_state[source_id] == H2_BODY_NOT_COMPLETE ||
        session_data->h2_body_state[source_id] == H2_BODY_LAST_SEG)
        update_depth();
    else if (session_data->h2_body_state[source_id] == H2_BODY_COMPLETE_EXPECT_TRAILERS)
        session_data->trailer_prep(source_id);
}

#ifdef REG_TEST
void HttpMsgBodyH2::print_section(FILE* output)
{
    print_body_section(output, "HTTP/2 body");
}
#endif

