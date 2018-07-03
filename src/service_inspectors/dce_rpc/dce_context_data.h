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
// dce_context_data.h author Bhagya Tholpady <bbantwal@cisco.com>

#ifndef DCE_CONTEXT_DATA_H
#define DCE_CONTEXT_DATA_H

#include "detection/ips_context.h"
#include "dce_utils.h"

struct DCE2_Roptions;
struct DCE2_SsnData;

class DceContextData : public snort::IpsContextData
{
public:
    void clear() override;

    static unsigned smb_ips_id;
    static unsigned tcp_ips_id;
    static unsigned udp_ips_id;

    DCE2_Roptions* current_ropts = nullptr;
    bool no_inspect = false;

    static void init(DCE2_TransType trans);
    static unsigned get_ips_id(DCE2_TransType trans);
    static void set_ips_id(DCE2_TransType trans, unsigned id);

    static DceContextData* get_current_data(const snort::Packet* p);
    static DCE2_Roptions* get_current_ropts(const snort::Packet* p);
    static bool is_noinspect(const snort::Packet* p);
    static void set_current_ropts(DCE2_SsnData* sd);
    static void clear_current_ropts(const snort::Packet* p, DCE2_TransType trans);
    static void clear_current_ropts(snort::IpsContext* context, DCE2_TransType trans);
};

#endif

