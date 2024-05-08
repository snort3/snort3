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

// iec104_paf.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_paf.cc (author Ryan Jordan)
// modeled after s7comm_paf.cc (author Pradeep Damodharan <prdamodh@cisco.com>)

// Protocol-Aware Flushing (PAF) code for the IEC104 inspector.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104_paf.h"

#include "detection/detection_engine.h"
#include "profiler/profiler.h"

#include "iec104.h"
#include "iec104_decode.h"
#include "iec104_module.h"

using namespace snort;

#define IEC104_MIN_HDR_LEN 2         // Enough for the Start and Length fields

Iec104Splitter::Iec104Splitter(bool b) :
    StreamSplitter(b)
{
    state = IEC104_PAF_STATE__START;
    iec104_apci_length = 0;
}

// IEC104/TCP PAF:
// Statefully inspects IEC104 traffic from the start of a session,
// Reads up until the length octet is found, then sets a flush point.

StreamSplitter::Status Iec104Splitter::scan(Packet*, const uint8_t* data, uint32_t len,
    uint32_t /*flags*/, uint32_t* fp)
{
    Profile profile(iec104_prof);

    uint32_t bytes_processed = 0;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (state)
        {
        // skip the start state
        case IEC104_PAF_STATE__START:
        {
            state = IEC104_PAF_STATE__LEN;
            break;
        }

        // length field is only one byte long
        case IEC104_PAF_STATE__LEN:
        {
            iec104_apci_length = *(data + bytes_processed);
            state = IEC104_PAF_STATE__SET_FLUSH;
            break;
        }

        case IEC104_PAF_STATE__SET_FLUSH:
        {
            *fp = iec104_apci_length + bytes_processed;      // flush point at the end of payload
            state = IEC104_PAF_STATE__START;
            iec104_apci_length = 0;
            return StreamSplitter::FLUSH;
        }
        }
        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

