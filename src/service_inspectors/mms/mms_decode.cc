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

// mms_decode.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_decode.cc (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_decode.cc (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mms_decode.h"

#include "detection/detection_engine.h"
#include "helpers/ber.h"
#include "log/messages.h"
#include "managers/plugin_manager.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"

#include "mms.h"
#include "mms_module.h"

using namespace snort;

bool mms_decode(Packet* p, MmsFlowData* mmsfd)
{
    if (p->dsize < MMS_MIN_LEN)
    {
        return false;
    }

    switch (*(p->data + mmsfd->get_mms_offset()))
    {
    case MMS_MSG__CONFIRMED_REQUEST:        // fallthrough
    case MMS_MSG__CONFIRMED_RESPONSE:       // fallthrough
    case MMS_MSG__CONFIRMED_ERROR:          // fallthrough
    case MMS_MSG__UNCONFIRMED:              // fallthrough
    case MMS_MSG__REJECT:                   // fallthrough
    case MMS_MSG__CANCEL_REQUEST:           // fallthrough
    case MMS_MSG__CANCEL_RESPONSE:          // fallthrough
    case MMS_MSG__CANCEL_ERROR:             // fallthrough
    case MMS_MSG__INITIATE_REQUEST:         // fallthrough
    case MMS_MSG__INITIATE_RESPONSE:        // fallthrough
    case MMS_MSG__INITIATE_ERROR:           // fallthrough
    case MMS_MSG__CONCLUDE_REQUEST:         // fallthrough
    case MMS_MSG__CONCLUDE_RESPONSE:        // fallthrough
    case MMS_MSG__CONCLUDE_ERROR:
        // allow these through
        break;

    default:
        return false;
    }
    return true;
}

