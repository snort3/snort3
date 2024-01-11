//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// oops_handler.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "oops_handler.h"

#include <daq.h>

#include <cassert>
#include <cstring>

#include "helpers/sigsafe.h"

#include "thread.h"

static THREAD_LOCAL OopsHandler* local_oops_handler = nullptr;

void OopsHandler::handle_crash(int fd)
{
    if (local_oops_handler)
        local_oops_handler->eternalize(fd);
}

void OopsHandler::tinit()
{
    assert(local_oops_handler == nullptr);
    local_oops_handler = this;
}

void OopsHandler::tterm()
{
    local_oops_handler = nullptr;
}

void OopsHandler::set_current_message(DAQ_Msg_h cur_msg, snort::SFDAQInstance* daq_instance)
{
    msg = cur_msg;
    priv_data_len = 0;

    if (daq_instance)
    {
        DIOCTL_GetPrivDataLen ioctl_data = {cur_msg,  0};
        if (DAQ_SUCCESS == daq_instance->ioctl(DIOCTL_GET_PRIV_DATA_LEN, &ioctl_data, sizeof(ioctl_data)))
        {
            priv_data_len = ioctl_data.priv_data_len;
        }
    }
}

void OopsHandler::eternalize(int fd)
{
    if (!msg)
        return;

    // Copy the crashed thread's data.  C++11 specs ensure the thread that segfaulted will
    // still be running.
    // Signal safety of functions called from here (POSIX async-signal-safe requirement):
    //  memcpy                  POSIX.1-2016
    type = daq_msg_get_type(msg);
    header_len = daq_msg_get_hdr_len(msg);
    memcpy(header, daq_msg_get_hdr(msg), std::min<size_t>(header_len, sizeof(header)));
    data_len = daq_msg_get_data_len(msg);
    memcpy(data, daq_msg_get_data(msg), std::min<size_t>(data_len, sizeof(data)));

    if (fd < 0)
        return;

    // Dump the eternalized information to the file descriptor for coreless debugging
    SigSafePrinter ssp(fd);
    ssp.printf("= Current DAQ Message (Type %u) =\n\n", static_cast<uint64_t>(type));
    ssp.printf("== Header (%u) ==\n", header_len);
    ssp.hex_dump(header, header_len);
    ssp.printf("\n== Data (%u) ==\n", data_len);
    ssp.hex_dump(data, data_len);
    ssp.printf("\n");
    if (priv_data_len)
    {
        memcpy(priv_data, daq_msg_get_priv_data(msg), std::min<size_t>(priv_data_len, sizeof(priv_data)));
        ssp.printf("== Private Data (%u) ==\n", priv_data_len);
        ssp.hex_dump(priv_data, priv_data_len);
    }
}
