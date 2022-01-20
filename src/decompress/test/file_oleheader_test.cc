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

// file_oleheader_test.cc author Amarnath Nayak <amarnaya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../file_oleheader.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(OleHeader_big_endian_test)
{
    OleHeader header;
    void setup() override
    {
        const uint8_t buf[2] =  { 0xFF, 0xFE };
        header.set_byte_order(buf);
    }
};

TEST(OleHeader_big_endian_test, set_byte_order)
{
    byte_order_endianess byte_order = header.get_byte_order();
    CHECK(byte_order == BIG_END);
}

TEST(OleHeader_big_endian_test, set_minor_version)
{
    const uint8_t buf[2] =  { 0x00, 0x3B };
    header.set_minor_version(buf);
    uint16_t minor_version = header.get_minor_version();
    CHECK(minor_version == 0X003B);
}

TEST(OleHeader_big_endian_test, set_major_version)
{
    const uint8_t buf[2] =  { 0x00, 0x03 };
    header.set_major_version(buf);
    uint16_t major_version = header.get_major_version();
    CHECK(major_version == 0x0003);
}

TEST(OleHeader_big_endian_test, set_dir_sector_count)
{
    const uint8_t buf[4] = { 0x00, 0x00, 0x00, 0x01 };
    header.set_dir_sector_count(buf);
    int32_t dir_sec_count = header.get_dir_sector_count();
    CHECK(dir_sec_count == 0x00000001);
}

TEST(OleHeader_big_endian_test, set_difat_count)
{
    const uint8_t buf[4] = { 0x00, 0x00, 0x00, 0x01 };
    header.set_difat_count(buf);
    int32_t difat_count = header.get_difat_count();
    CHECK(difat_count == 0x00000001);
}

TEST(OleHeader_big_endian_test, set_fat_sector_count)
{
    const uint8_t buf[4] = { 0x00, 0x00, 0x00, 0x01 };
    header.set_fat_sector_count(buf);
    int32_t fat_sector_count = header.get_fat_sector_count();
    CHECK(fat_sector_count == 0x00000001);
}

TEST(OleHeader_big_endian_test, set_minifat_count)
{
    const uint8_t buf[4] = { 0x00, 0x00, 0x00, 0x01 };
    header.set_minifat_count(buf);
    int32_t minfat_sector_count = header.get_minifat_count();
    CHECK(minfat_sector_count == 0x00000001);
}

TEST(OleHeader_big_endian_test, set_first_difat)
{
    const uint8_t buf[4] = { 0x00, 0x00, 0x02, 0x00 };
    header.set_first_difat(buf);
    int32_t first_difat = header.get_first_difat();
    CHECK(first_difat == 0x00000200);
}

TEST(OleHeader_big_endian_test, BETOHLL_UNALIGNED)
{
    const uint8_t buf[8] = { 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04 };
    int64_t value  = BETOHLL_UNALIGNED(buf);
    CHECK(value == 0x0102030401020304);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

