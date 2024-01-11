//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_mms_data.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after ips_modbus_data.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mms.h"

using namespace snort;

static const char* s_name = "mms_data";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats mms_data_prof;

class MmsDataOption : public IpsOption
{
public:
    MmsDataOption() : IpsOption(s_name) { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FAST_PATTERN; }

    EvalStatus eval(Cursor&, Packet*) override;
};

IpsOption::EvalStatus MmsDataOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(mms_data_prof);

    if (!p->flow)
    {
        return NO_MATCH;
    }

    // not including any checks for a full PDU as we're not guaranteed to
    // have one with the available pipelining options to get to MMS

    MmsFlowData* mmsfd = (MmsFlowData*)p->flow->get_flow_data(MmsFlowData::inspector_id);

    if (!mmsfd)
    {
        return NO_MATCH;
    }

    if (!mmsfd->is_mms_found())
    {
        return NO_MATCH;
    }

    if (mmsfd->get_mms_offset() >= p->dsize)
    {
        return NO_MATCH;
    }

    // setting the cursor to the offset previously determined by util_tpkt
    // to be the start of the MMS message
    c.set(s_name, p->data + mmsfd->get_mms_offset(), p->dsize - mmsfd->get_mms_offset());

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set cursor to MMS data"

class MmsDataModule : public Module
{
public:
    MmsDataModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &mms_data_prof; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MmsDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module*, OptTreeNode*)
{
    return new MmsDataOption;
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_mms_data = &ips_api.base;

