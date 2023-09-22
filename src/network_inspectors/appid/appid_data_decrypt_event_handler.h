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

// appid_data_decrypt_event_handler.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef APPID_DATA_DECRYPT_EVENT_HANDLER_H
#define APPID_DATA_DECRYPT_EVENT_HANDLER_H

#include "framework/data_bus.h"

#include "appid_module.h"

class DataDecryptEventHandler : public snort::DataHandler
{
public:
    DataDecryptEventHandler(AppIdInspector& inspector) : DataHandler(MOD_NAME), inspector(inspector)
    { }

    void handle(snort::DataEvent& event, snort::Flow* flow) override;

private:
    AppIdInspector& inspector;
};

#endif

