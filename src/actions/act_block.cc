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
// act_block.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

#include "actions.h"

using namespace snort;

#define s_name "block"

#define s_help \
    "block current packet and all the subsequent packets in this flow"

//-------------------------------------------------------------------------
class BlockAction : public IpsAction
{
public:
    BlockAction() : IpsAction(s_name, nullptr) { }

    void exec(Packet*, const OptTreeNode* otn) override;
    bool drops_traffic() override { return true; }
};

void BlockAction::exec(Packet* p, const OptTreeNode* otn)
{
    p->active->block_session(p);
    p->active->set_drop_reason("ips");

    Actions::alert(p, otn);
}

//-------------------------------------------------------------------------

static IpsAction* block_ctor(Module*)
{ return new BlockAction; }

static void block_dtor(IpsAction* p)
{ delete p; }

static ActionApi block_api
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
    IpsAction::IAP_BLOCK,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    block_ctor,
    block_dtor
};

const BaseApi* act_block[] =
{
    &block_api.base,
    nullptr
};

