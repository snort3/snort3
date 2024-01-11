//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// act_file_id.cc author Bhargava Jandhyala <bjandhya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions.h"
#include "detection/detect.h"
#include "file_api/file_flows.h"
#include "file_api/file_identifier.h"
#include "managers/action_manager.h"
#include "parser/parser.h"
#include "utils/stats.h"

using namespace snort;

#define s_name "file_id"

#define s_help \
    "file_id file type id"

//-------------------------------------------------------------------------
// ips action
//-------------------------------------------------------------------------

class File_IdAction : public IpsAction
{
public:
    File_IdAction() : IpsAction(s_name, nullptr) { }
    void exec(Packet*, const OptTreeNode* otn) override;
};

void File_IdAction::exec(Packet* p, const OptTreeNode* otn)
{
    if (!p->flow)
      return;
    FileFlows* files = FileFlows::get_file_flows(p->flow, false);
    if (!files)
        return;
    FileContext* file = files->get_current_file_context();
    if (!file)
        return;
    file->set_file_type(otn->sigInfo.file_id);
}

//-------------------------------------------------------------------------

static IpsAction* file_id_ctor(Module*)
{ return new File_IdAction; }

static void file_id_dtor(IpsAction* p)
{ delete p; }

static ActionApi file_id_api
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
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    file_id_ctor,
    file_id_dtor
};

const BaseApi* act_file_id[] =
{
    &file_id_api.base,
    nullptr
};

