//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_info.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_INFO_H
#define IPS_INFO_H

// enables keeping OTN private

namespace snort
{
    struct SnortConfig;
    class IpsOption;
};

struct OptTreeNode;

struct IpsInfo
{
public:
    IpsInfo(OptTreeNode* o, snort::SnortConfig* s)
    { otn = o; sc = s; }

private:
    friend class snort::IpsOption;

    OptTreeNode* otn;
    snort::SnortConfig* sc;
};

#endif

