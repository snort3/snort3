//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// act_drop.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

#include "actions.h"

using namespace snort;

#define s_name "drop"

#define s_help \
    "drop the current packet"

//-------------------------------------------------------------------------
class DropAction : public IpsAction
{
public:
    DropAction() : IpsAction(s_name, nullptr) { }

    void exec(Packet*, const OptTreeNode* otn) override;
    bool drops_traffic() override { return true; }
};

void DropAction::exec(Packet* p, const OptTreeNode* otn)
{
    p->active->drop_packet(p);
    p->active->set_drop_reason("ips");
    if ( otn )
        Actions::alert(p, otn);
}

//-------------------------------------------------------------------------

static IpsAction* drop_ctor(Module*)
{ return new DropAction; }

static void drop_dtor(IpsAction* p)
{ delete p; }

static ActionApi drop_api
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
    IpsAction::IAP_DROP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    drop_ctor,
    drop_dtor
};

const BaseApi* act_drop[] =
{
    &drop_api.base,
    nullptr
};

