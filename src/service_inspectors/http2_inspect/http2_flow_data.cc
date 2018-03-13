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
// http2_flow_data.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_flow_data.h"

#include "http2_enum.h"
#include "http2_module.h"

using namespace snort;
using namespace Http2Enums;

unsigned Http2FlowData::inspector_id = 0;

Http2FlowData::Http2FlowData() : FlowData(inspector_id)
{
    Http2Module::increment_peg_counts(PEG_CONCURRENT_SESSIONS);
    if (Http2Module::get_peg_counts(PEG_MAX_CONCURRENT_SESSIONS) <
        Http2Module::get_peg_counts(PEG_CONCURRENT_SESSIONS))
        Http2Module::increment_peg_counts(PEG_MAX_CONCURRENT_SESSIONS);
}

Http2FlowData::~Http2FlowData()
{
    if (Http2Module::get_peg_counts(PEG_CONCURRENT_SESSIONS) > 0)
        Http2Module::decrement_peg_counts(PEG_CONCURRENT_SESSIONS);

    for (int k=0; k <= 1; k++)
    {
        delete[] frame_header[k];
        delete[] frame[k];
    }
}

