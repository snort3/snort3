//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// act_log.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"

#include "actions.h"

using namespace snort;

#define s_name "log"

#define s_help \
    "log the current packet"

//-------------------------------------------------------------------------
class LogAction : public IpsAction
{
public:
    LogAction() : IpsAction(s_name, nullptr) { }

    void exec(Packet*, const OptTreeNode* otn) override;
};

void LogAction::exec(Packet* p, const OptTreeNode* otn)
{
    if ( otn )
        Actions::log(p, otn);
}

//-------------------------------------------------------------------------

static IpsAction* log_ctor(Module*)
{ return new LogAction; }

static void log_dtor(IpsAction* p)
{ delete p; }

static ActionApi log_api
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        nullptr,  // mod_ctor
        nullptr,  // mod_dtor
    },
    IpsAction::IAP_LOG,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    log_ctor,
    log_dtor
};

const BaseApi* act_log[] =
{
    &log_api.base,
    nullptr
};

