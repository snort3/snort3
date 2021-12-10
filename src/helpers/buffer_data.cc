//--------------------------------------------------------------------------
// Copyright (C) 2021 Cisco and/or its affiliates. All rights reserved.
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
// buffer_data.cc author Amarnath Nayak <amarnaya@cisco.com>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "buffer_data.h"

namespace snort
{
BufferData::BufferData(int32_t length, const uint8_t* data_, bool own_the_buffer_ = false) :
            len(length), data(data_), own_the_buffer(own_the_buffer_){}

BufferData::~BufferData() 
{ 
    if (own_the_buffer) 
        delete[] data; 
}

int32_t BufferData::length() const
{ 
    return len;
}

const uint8_t* BufferData::data_ptr() const
{ 
    return data; 
}

void BufferData::set(int32_t length, const uint8_t* data_, bool own_the_buffer_)
{
    len = length; 
    data = data_; 
    own_the_buffer = own_the_buffer_; 
}

void BufferData::reset()
{ 
    if (own_the_buffer) 
        delete[] data;

    len = 0; 
    data = nullptr; 
    own_the_buffer = false; 
}
}
