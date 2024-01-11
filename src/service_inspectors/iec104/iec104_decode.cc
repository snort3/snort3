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

// iec104_decode.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_decode.cc (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_decode.cc (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104_decode.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"

#include "iec104.h"
#include "iec104_module.h"
#include "iec104_parse_apdu.h"
#include "iec104_trace.h"

using namespace snort;

//-------------------------------------------------------------------------
// APCI determination
//-------------------------------------------------------------------------

// Function to determine the APCI type of the current message based on the
// major and (where needed) minor codes
// returns an ApciType enum value corresponding to the determined APCI
static uint32_t getApciType(Packet* p)
{
    // overlay a generic apci struct over the first three bytes of the stream
    const Iec104GenericApci* apci = (const Iec104GenericApci*) p->data;

    // default apci type to a non-used value
    // if this somehow makes it through it errors out in the apci type switch
    uint32_t curApciType = IEC104_NO_APCI;

    // Check the APCI Major type flag
    if (apci->apciTypeMajor)
    {
        // Check the APCI Minor type flag
        if (apci->apciTypeMinor)
        {
            // APCI Type U
            curApciType = IEC104_APCI_TYPE_U;
        }
        else
        {
            // APCI Type S
            curApciType = IEC104_APCI_TYPE_S;
        }
    }
    else
    {
        // APCI Type I
        curApciType = IEC104_APCI_TYPE_I;
    }

    return curApciType;
}

bool Iec104Decode(Packet* p, Iec104FlowData* iec104fd)
{
    if (p->dsize < IEC104_MIN_LEN)
    {
        return false;
    }

    // build the correct APCI based on the returned type
    uint32_t apciType = getApciType(p);

    if (apciType > 2)
    {
        // An APCI type cannot be determined. Message does not appear to be IEC104
        return false;
    }
    else
    {
        // apply the appropriate structure to the packet buffer based on the
        // earlier type determination
        switch (apciType)
        {
        case IEC104_APCI_TYPE_U:
        {
            // build up the APCI
            const Iec104ApciU* apci = (const Iec104ApciU*) p->data;

            // set the apci type
            iec104fd->ssn_data.iec104_apci_type = apciType;

            // clear out the asdu since it isn't applicable here
            iec104fd->ssn_data.iec104_asdu_func = IEC104_NO_ASDU;

            // print out the APCI
            print_debug_information(p, "Unnumbered Control Function APCI\n");
            parseIec104ApciU(apci);

            break;
        }

        case IEC104_APCI_TYPE_S:
        {
            // build up the APCI
            const Iec104ApciS* apci = (const Iec104ApciS*) p->data;

            // set the apci type
            iec104fd->ssn_data.iec104_apci_type = apciType;

            // clear out the asdu since it isn't applicable here
            iec104fd->ssn_data.iec104_asdu_func = IEC104_NO_ASDU;

            // print out the APCI
            print_debug_information(p, "Numbered Supervisory Function APCI\n");
            parseIec104ApciS(apci);

            break;
        }

        case IEC104_APCI_TYPE_I:
        {
            // build up the APCI
            const Iec104ApciI* apci = (const Iec104ApciI*) p->data;

            // set the apci type
            iec104fd->ssn_data.iec104_apci_type = apciType;

            // set the asdu function type in the session data
            iec104fd->ssn_data.iec104_asdu_func = apci->asdu.typeId;

            // print out the APCI
            print_debug_information(p, "Information Transfer Format APCI\n");
            parseIec104ApciI(apci);

            break;
        }
        }
    }

    return true;
}

