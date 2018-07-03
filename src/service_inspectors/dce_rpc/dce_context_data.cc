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
// dce_context_data.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_context_data.h"

#include "protocols/packet.h"

#include "dce_utils.h"
#include "dce_common.h"

using namespace snort;

unsigned DceContextData::smb_ips_id = 0;
unsigned DceContextData::tcp_ips_id = 0;
unsigned DceContextData::udp_ips_id = 0;

void DceContextData::init(DCE2_TransType trans)
{
    set_ips_id(trans, IpsContextData::get_ips_id());
}

unsigned DceContextData::get_ips_id(DCE2_TransType trans)
{
    switch(trans)
    {
        case DCE2_TRANS_TYPE__SMB: 
            return DceContextData::smb_ips_id;
        case DCE2_TRANS_TYPE__TCP:
            return DceContextData::tcp_ips_id;
        case DCE2_TRANS_TYPE__UDP:
            return DceContextData::udp_ips_id;
        default:
            break;
    }
    return 0;
}

void DceContextData::set_ips_id(DCE2_TransType trans, unsigned id)
{
    switch(trans)
    {
        case DCE2_TRANS_TYPE__SMB: 
            DceContextData::smb_ips_id = id;
            break;
        case DCE2_TRANS_TYPE__TCP:
            DceContextData::tcp_ips_id = id;
            break;
        case DCE2_TRANS_TYPE__UDP:
            DceContextData::udp_ips_id = id;
            break;
        default:
            break;
    }
    return;
}

DceContextData* DceContextData::get_current_data(const Packet* p)
{
    IpsContext* context = p ? p->context : nullptr;
    unsigned ips_id = get_ips_id(get_dce2_trans_type(p));

    if ( !ips_id )
        return nullptr;

    DceContextData* dcd = (DceContextData*)DetectionEngine::get_data(ips_id, context);

    if ( !dcd )
        return nullptr;

    return dcd;
}

bool DceContextData::is_noinspect(const Packet* p)
{
    DceContextData* dcd = get_current_data(p);

    if ( !dcd )
        return true;

    return dcd->no_inspect;
}

DCE2_Roptions* DceContextData::get_current_ropts(const Packet* p)
{
    DceContextData* dcd = get_current_data(p);

    if ( !dcd )
        return nullptr;

    return dcd->current_ropts;
}

void DceContextData::set_current_ropts(DCE2_SsnData* sd)
{
    unsigned ips_id = get_ips_id(sd->trans);

    if ( !ips_id )
        return;

    DceContextData* dcd = (DceContextData*)DetectionEngine::get_data(ips_id);

    if ( !dcd )
    {
        dcd = new DceContextData;
        DetectionEngine::set_data(ips_id, dcd);
    }

    if ( !dcd->current_ropts )
    {
        dcd->current_ropts = new DCE2_Roptions;
    }

    *(dcd->current_ropts) = sd->ropts;
    dcd->no_inspect = DCE2_SsnNoInspect(sd);
}

void DceContextData::clear_current_ropts(IpsContext* context, DCE2_TransType trans)
{
    unsigned ips_id = get_ips_id(trans);

    if ( !ips_id )
        return;

    DceContextData* dcd = (DceContextData*)DetectionEngine::get_data(ips_id, context);

    if ( dcd )
    {
        dcd->clear();
    }

    return;
}
void DceContextData::clear_current_ropts(const Packet* p, DCE2_TransType trans)
{
    IpsContext* context = p ? p->context : nullptr;
    clear_current_ropts(context, trans);
}

void DceContextData::clear()
{
    if ( current_ropts )
        delete current_ropts;
    current_ropts = nullptr;
    no_inspect = false;
}

