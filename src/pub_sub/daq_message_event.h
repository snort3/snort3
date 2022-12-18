//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// daq_message_event.h author Michael Altizer <mialtize@cisco.com>

#ifndef DAQ_MESSAGE_EVENT_H
#define DAQ_MESSAGE_EVENT_H

#include <daq.h>

#include "pub_sub/intrinsic_event_ids.h"

namespace snort
{
class SO_PUBLIC DaqMessageEvent : public snort::DataEvent
{
public:
    DaqMessageEvent(DAQ_Msg_h msg, DAQ_Verdict& v) : msg(msg), verdict(v) { }

    DAQ_Msg_h get_message()
    { return msg; }

    DAQ_MsgType get_type() const
    { return daq_msg_get_type(msg); }

    size_t get_header_length() const
    { return daq_msg_get_hdr_len(msg); }

    const void* get_header() const
    { return daq_msg_get_hdr(msg); }

    uint32_t get_data_length() const
    { return daq_msg_get_data_len(msg); }

    const uint8_t* get_data() override
    { return daq_msg_get_data(msg); }

    DAQ_Verdict get_verdict()
    { return verdict; }

    void set_verdict(DAQ_Verdict v)
    { verdict = v; }

private:
    DAQ_Msg_h msg;
    DAQ_Verdict& verdict;
};
}

#endif
