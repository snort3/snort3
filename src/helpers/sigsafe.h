//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// sigsafe.h author Michael Altizer <mialtize@cisco.com>

#ifndef SIGSAFE_H
#define SIGSAFE_H

#include <cstddef>
#include <cstdint>

class SigSafePrinter
{
public:
    SigSafePrinter(char *buf, size_t size);
    SigSafePrinter(int fd) : fd(fd) { }

    void hex_dump(const uint8_t* data, unsigned len);
    void printf(const char* format, ...);

private:
    void write_string(const char* str);

private:
    char* buf = nullptr;
    size_t buf_size = 0;
    size_t buf_idx = 0;
    int fd = -1;
};

#endif

