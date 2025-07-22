//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

#define IEC104_MAX_OCTETS 2560 // using max length of iec104 packet (max size is a byte) times 10
#define IEC104_LSBIT_MASK 0x01
#define IEC104_FUNCTION_FIELDS_MASK 0xFC
#define IEC104_APCI_TYPE_MASK 0x03
#define IEC104_TYPE_I 0
#define IEC104_TYPE_S 1
#define IEC104_TYPE_I_2 2
#define IEC104_TYPE_U 3

Iec104Splitter::Iec104Splitter(bool b) :
    StreamSplitter(b)
{
    state = IEC104_PAF_STATE__START;
    iec104_apci_length = 0;
    bytes_seen = 0;
    valid_bytes = true;
}

//each u format frame can only have one function bit set
static inline bool onlyOneBitSet(uint8_t n) {
    if (n == 0)
        return false;
    return (n & (n - 1)) == 0; // If non-zero after clearing LSB, more than one bit was set
}

static inline bool validate_control_fields(const uint8_t* data)
{
    uint8_t apci_type = data[2] & IEC104_APCI_TYPE_MASK;

    switch(apci_type)
    {
        case IEC104_TYPE_U:
        {
            bool are_fields_unset = (data[3] | data[4] | data[5]) == 0;
            uint8_t function_fields = data[2] & IEC104_FUNCTION_FIELDS_MASK;
            return are_fields_unset and onlyOneBitSet(function_fields);
        }
        case IEC104_TYPE_S:
        {
            bool is_field3_lsb_unset = (data[4] & IEC104_LSBIT_MASK) == 0;
            return data[2] == 1 and data[3] == 0 and is_field3_lsb_unset;
        }
        default: //IEC104_TYPE_I format
        {
            bool is_field3_lsb_unset = (data[4] & IEC104_LSBIT_MASK) == 0;
            return is_field3_lsb_unset;
        }
    }
}

// IEC104/TCP PAF:
// Statefully inspects IEC104 traffic from the start of a session,
// Reads up until the length octet is found, then sets a flush point.

StreamSplitter::Status Iec104Splitter::scan(Packet*, const uint8_t* data, uint32_t len,
    uint32_t /*flags*/, uint32_t* fp)
{
    Profile profile(iec104_prof);

    uint32_t bytes_processed = 0;

    if (len < IEC104_MIN_LEN or !validate_control_fields(data))
        valid_bytes = false;

    /* Process this packet 1 byte at a time */
    while (bytes_processed < len)
    {
        switch (state)
        {
        // skip the start state
        case IEC104_PAF_STATE__START:
        {
            uint8_t iec104_byte = *data;
            state = IEC104_PAF_STATE__LEN;
            if (iec104_byte != IEC104_START_ID)
            {
                valid_bytes = false;
            }
            break;
        }

        // length field is only one byte long
        case IEC104_PAF_STATE__LEN:
        {
            iec104_apci_length = *(data + bytes_processed);
            state = IEC104_PAF_STATE__SET_FLUSH;
            if (iec104_apci_length > len)
            {
                valid_bytes = false;
            }
            break;
        }

        case IEC104_PAF_STATE__SET_FLUSH:
        {
            *fp = iec104_apci_length + bytes_processed;      // flush point at the end of payload
            state = IEC104_PAF_STATE__START;
            iec104_apci_length = 0;
            if (!valid_bytes)
            {
                valid_bytes = true;
                bytes_seen += len;
                if (bytes_seen > IEC104_MAX_OCTETS)
                {
                    return StreamSplitter::ABORT;
                }
            }
            else
            {
                bytes_seen = 0;
            }
            return StreamSplitter::FLUSH;
        }
        }
        bytes_processed++;
    }

    return StreamSplitter::SEARCH;
}

