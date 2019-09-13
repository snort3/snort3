//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// other_message_event.h author Steven Baigal <sbaigal@cisco.com>

#ifndef OTHER_MESSAGE_EVENT_H
#define OTHER_MESSAGE_EVENT_H

#include <daq_common.h>

#include "framework/data_bus.h"

#define OTHER_MESSAGE_EVENT "daq.other.message"

namespace snort
{

class SO_PUBLIC OtherMessageEvent : public snort::DataEvent
{
public:
    OtherMessageEvent(DAQ_Msg_h msg, DAQ_Verdict& v) :
        daq_msg(msg), verdict(v)
    {
    }

    DAQ_Msg_h get_daq_msg()
    { return daq_msg; }

    DAQ_Verdict& get_verdict()
    { return verdict; }

private:
    DAQ_Msg_h daq_msg;
    DAQ_Verdict& verdict;
};

}

#endif
