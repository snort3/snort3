//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// data_decrypt_event.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef DATA_DECRYPT_EVENT_H
#define DATA_DECRYPT_EVENT_H

#include "pub_sub/external_event_ids.h"

class DataDecryptEvent : public snort::DataEvent
{
public:

    enum StateEventType : uint16_t
    {
        DATA_DECRYPT_MONITOR_EVENT,
        DATA_DECRYPT_DO_NOT_DECRYPT_EVENT,
        DATA_DECRYPT_BLOCK_EVENT,
        DATA_DECRYPT_BLOCK_WITH_RESET_EVENT,
        DATA_DECRYPT_START_EVENT
    };

    DataDecryptEvent(const StateEventType& type)  : m_type(type)  { }
    StateEventType get_type() const { return m_type; }

private:
    StateEventType m_type;
};

#endif

