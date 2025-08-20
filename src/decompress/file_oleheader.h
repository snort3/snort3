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

// file_oleheader.h author Vigneshwari Viswanathan vignvisw@cisco.com

#ifndef FILE_OLE_HEADER_H
#define FILE_OLE_HEADER_H

#include <cmath>
#include <cstring>

#include "main/snort_types.h"
#include "utils/endian.h"

#define MAX_DIFAT_SECTORS                 109

#define HEADER_MINOR_VER_OFFSET            24
#define HEADER_MAJOR_VER_OFFSET            26
#define HEADER_BYTE_ORDER_OFFSET           28
#define HEADER_SECTR_SIZE_OFFSET           30
#define HEADER_MIN_SECTR_SIZE_OFFSET       32
#define HEADER_DIR_SECTR_CNT_OFFSET        40
#define HEADER_FAT_SECTR_CNT_OFFSET        44
#define HEADER_FIRST_DIR_SECTR_OFFSET      48
#define HEADER_MINFAT_CUTOFF_OFFSET        56
#define HEADER_FIRST_MINFAT_OFFSET         60
#define HEADER_MINFAT_COUNT_OFFSET         64
#define HEADER_FIRST_DIFAT_OFFSET          68
#define HEADER_DIFAT_CNT_OFFSET            72
#define HEADER_DIFAT_ARRY_OFFSET           76

enum byte_order_endianess
{
    LITL_END = 0,
    BIG_END = 1
};

class OleHeader
{
public:
    bool set_byte_order(const uint8_t* buf);
    byte_order_endianess get_byte_order();
    bool match_ole_sig(const uint8_t* buf);
    void set_minor_version(const uint8_t* buf);
    uint16_t get_minor_version();
    void set_major_version(const uint8_t* buf);
    uint16_t get_major_version();
    void set_sector_size(const uint8_t* buf);
    uint16_t get_sector_size();
    void set_mini_sector_size(const uint8_t* buf);
    uint16_t get_mini_sector_size();
    void set_dir_sector_count(const uint8_t* buf);
    int32_t get_dir_sector_count();
    void set_first_dir(const uint8_t* buf);
    int32_t get_first_dir();
    void set_difat_count(const uint8_t* buf);
    int32_t get_difat_count();
    void set_fat_sector_count(const uint8_t* buf);
    int32_t get_fat_sector_count();
    void set_minifat_cutoff(const uint8_t* buf);
    uint32_t get_minifat_cutoff();
    void set_first_minifat(const uint8_t* buf);
    int32_t get_first_minifat();
    void set_minifat_count(const uint8_t* buf);
    int32_t get_minifat_count();
    void set_first_difat(const uint8_t* buf);
    int32_t get_first_difat();
    void set_difat_array(const uint8_t* buf);
    int32_t get_difat_array(int num);
    OleHeader() = default;

private:
    unsigned char sig[8] = {}; //0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
    uint16_t minor_version = 0;
    uint16_t major_version = 0;
    uint16_t byte_order = 0;
    uint16_t sector_size = 0;
    uint16_t mini_sector_size = 0;
    int32_t dir_sector_count = 0;
    int32_t first_dir = -1;
    int32_t difat_count = 0;
    int32_t fat_sector_count = 0;
    uint32_t minifat_cutoff = 0;
    int32_t first_minifat = 0;
    int32_t minifat_count = 0;
    int32_t first_difat = 0;
    int32_t difat_array[MAX_DIFAT_SECTORS] = {};

    byte_order_endianess byte_order_endian = LITL_END;

#ifdef UNIT_TEST
public:
    void set_mini_sector_size_raw(uint16_t val) { mini_sector_size = val; }
#endif
};
#endif

