//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// buffer_data.h author Amarnath Nayak <amarnaya@cisco.com>
#ifndef BUFFER_DATA_H
#define BUFFER_DATA_H

#include <cstdint>

#include "main/snort_types.h"

namespace snort
{
class SO_PUBLIC BufferData
{
public:
    BufferData(int32_t length, const uint8_t* data_, bool own_the_buffer_);
    BufferData() = default;

    ~BufferData();

    int32_t length() const;
    const uint8_t* data_ptr() const;

    void set(int32_t length, const uint8_t* data_, bool own_the_buffer_);

    void reset();

    static const BufferData buffer_null;

private:
    int32_t len = 0;
    const uint8_t* data = nullptr;
    bool own_the_buffer = false;
};
}
#endif
