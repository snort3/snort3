//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// gtp_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef GTP_MODULE_H
#define GTP_MODULE_H

#include "framework/module.h"

#define GID_GTP 143

#define GTP_EVENT_BAD_MSG_LEN        (1)
#define GTP_EVENT_BAD_IE_LEN         (2)
#define GTP_EVENT_OUT_OF_ORDER_IE    (3)

#define GTP_NAME "gtp_inspect"
#define GTP_HELP "gtp control channel inspection"

extern THREAD_LOCAL ProfileStats gtp_inspect_prof;

struct GtpStuff
{
    std::string name;
    int version;
    int type;
    int length;
};

class GtpInspectModule : public Module
{
public:
    GtpInspectModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_GTP; }

    const RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    ProfileStats* get_profile() const override
    { return &gtp_inspect_prof; }

public:
    GtpStuff stuff;
    std::vector<GtpStuff> temp;
    std::vector<GtpStuff> config;
};

#endif

