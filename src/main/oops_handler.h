//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// oops_handler.h author Michael Altizer <mialtize@cisco.com>

#ifndef OOPS_HANDLER_H
#define OOPS_HANDLER_H

#include <daq_common.h>

class OopsHandler
{
public:
    static void handle_crash(int fd);

    OopsHandler() = default;
    ~OopsHandler() = default;

    void tinit();
    void set_current_message(DAQ_Msg_h cm) { msg = cm; }
    void tterm();

private:
    void eternalize(int fd);

private:
    DAQ_Msg_h msg = nullptr;
    // Eternalized data
    DAQ_MsgType type = static_cast<DAQ_MsgType>(0);
    uint8_t header[UINT16_MAX] = { };
    size_t header_len = 0;
    uint8_t data[UINT16_MAX] = { };
    uint32_t data_len = 0;
};

#endif

