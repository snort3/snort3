//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// stream_flow.h author Abhijit Pal <abhpal@cisco.com>

#ifndef STREAM_FLOW_H
#define STREAM_FLOW_H

// for munged services like http2

#include "network_inspectors/appid/application_ids.h"

namespace snort
{
class Flow;
class FlowData;

class SO_PUBLIC StreamFlowIntf
{
public:
    virtual FlowData* get_stream_flow_data(const Flow*) = 0;
    virtual void set_stream_flow_data(Flow*, FlowData*) = 0;
    virtual void get_stream_id(const Flow*, int64_t& stream_id) = 0;
    virtual void* get_hi_msg_section(const Flow*) = 0;
    virtual void set_hi_msg_section(Flow*, void* section) = 0;
    virtual AppId get_appid_from_stream(const Flow*) { return APP_ID_NONE; }
    // Stream based flows should override this interface to return parent flow
    // when child flow is passed as input
    virtual Flow* get_stream_parent_flow(Flow* cflow) { return cflow; }
};

}
#endif

