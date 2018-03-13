//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// gtp_inspect.h author Russ Combs <rucombs@cisco.com>

#ifndef GTP_INSPECT_H
#define GTP_INSPECT_H

#include "flow/flow.h"

#include "gtp_parser.h"

// FIXIT-M why store per packet on flow?
struct GTP_Roptions
{
    uint8_t gtp_type;
    uint8_t gtp_version;
    const uint8_t* gtp_header;
    uint32_t msg_id;  /* used to associate to current msg */
    GTP_IEData* gtp_infoElements;
};

class GtpFlowData : public snort::FlowData
{
public:
    GtpFlowData();
    ~GtpFlowData() override;

    static void init();

public:
    static unsigned inspector_id;
    GTP_Roptions ropts;
};

int get_message_type(int version, const char* name);
int get_info_type(int version, const char* name);

struct GTP_IEData* get_infos();

#endif

