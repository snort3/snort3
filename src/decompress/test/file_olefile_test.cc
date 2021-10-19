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

//file_olefile_test.cc author Amarnath Nayak <amarnaya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../file_olefile.h"
#include "../file_oleheader.h"

#include "detection/detection_engine.h"
#include "helpers/literal_search.h"
#include "utils/util_utf.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL const snort::Trace* vba_data_trace = nullptr;

namespace snort
{
LiteralSearch::Handle* LiteralSearch::setup() { return nullptr; }
void LiteralSearch::cleanup(LiteralSearch::Handle*) { }
LiteralSearch* LiteralSearch::instantiate(LiteralSearch::Handle*, const uint8_t*, unsigned, bool,
    bool) { return nullptr; }
void UtfDecodeSession::set_decode_utf_state_charset(CharsetCode) { }
bool UtfDecodeSession::decode_utf(unsigned char const*, unsigned int, unsigned char*, unsigned int,
    int*) { return true; }
UtfDecodeSession::UtfDecodeSession() { }
Packet* DetectionEngine::get_current_packet() { return nullptr; }
void trace_vprintf(char const*, unsigned char, char const*, snort::Packet const*, char const*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(snort::Packet const&) { }
}

TEST_GROUP(Olefile_oleprocess_test)
{
};

TEST(Olefile_oleprocess_test, wrong_ole_sig)
{
    uint8_t ole_file[1000] = { 0 };
    ole_file[28] = 0XFE;
    ole_file[29] = 0XFF;
    uint32_t ole_length = 1000;
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    oleprocess(ole_file, ole_length, vba_buf, vba_buf_len);
}

TEST(Olefile_oleprocess_test, wrong_byte_order)
{
    uint8_t ole_file[1000] = { 0 };
    const uint32_t ole_length = 1000;
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    oleprocess(ole_file, ole_length, vba_buf, vba_buf_len);
}

TEST(Olefile_oleprocess_test, short_header_len)
{
    uint8_t ole_file[100] = { 0 };
    uint32_t ole_length = 100;
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    oleprocess(ole_file, ole_length, vba_buf, vba_buf_len);
}

TEST_GROUP(Olefile_ole)
{
};

TEST(Olefile_ole, get_file_offset)
{
    OleFile* olefile = new OleFile(nullptr, 0);
    int32_t res = olefile->get_file_offset(nullptr,0);
    CHECK(res == -1);
    delete olefile;
}

TEST(Olefile_ole, decompression_empty_data)
{
    uint8_t* ole_data = nullptr;
    uint8_t* buf = nullptr;
    int32_t len = 0;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data, &len, buf, nullptr);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_invalid_data_1)
{
    uint8_t ole_data[10] = { 0 };
    uint8_t* buf = nullptr;
    int32_t len = 10;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data,&len, buf, nullptr);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_invalid_chunk_header)
{
    uint8_t ole_data[10] ={ 0 };
    uint8_t* buf = nullptr;
    int32_t len = 10;
    ole_data[0] = 0x01;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data,&len, buf, nullptr);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_flag_0)
{
    uint8_t ole_data[10] ={ 0 };
    uint8_t* buf = nullptr;
    int32_t len = 10;
    ole_data[0] = 0x01;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data,&len, buf, nullptr);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, get_next_fat_sector_failure)
{
    OleFile* olefile = new OleFile(nullptr, 0);
    int32_t res = olefile->get_next_fat_sector(20);
    CHECK(res == -1);
    delete olefile;
}

TEST(Olefile_ole, get_next_mini_fat_sector_failure)
{
    OleFile* olefile = new OleFile(nullptr, 0);
    int32_t res = olefile->get_next_mini_fat_sector(20);
    CHECK(res == -1);
    delete olefile;
}

TEST(Olefile_ole, get_file_node_failure)
{
    char test[] = {'a','b',0};
    DirectoryList* dir_list = new DirectoryList();
    FileProperty* res = dir_list->get_file_node(test);
    delete dir_list;
    CHECK(res == nullptr);
}

TEST_GROUP(fat_mini_fat_list)
{
};

TEST(fat_mini_fat_list, fat_list_short_buf_len)
{
    uint8_t ole_buf[520] = { 0 };
    uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    memcpy(ole_buf, ole_header_sig, 8);
    ole_buf[28] = 0xFF;
    ole_buf[29] = 0xFE;
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x09;
    ole_buf[519] = 0xFE;
    OleFile* olefile = new OleFile(ole_buf, 520);
    olefile->parse_ole_header();
    olefile->populate_fat_list();
    CHECK(olefile->get_next_fat_sector(1) == -1);
    delete olefile;
}

TEST(fat_mini_fat_list, fat_list_read_r)
{
    uint8_t ole_buf[1025] = { 0 };
    uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    memcpy(ole_buf, ole_header_sig, 8);
    ole_buf[28] = 0xFF;
    ole_buf[29] = 0xFE;
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x09;
    ole_buf[47] = 0x01;
    memset(ole_buf + 80, 0xFF, 435);
    ole_buf[519] = 0x02;
    OleFile* olefile = new OleFile(ole_buf, 1025);
    olefile->parse_ole_header();
    olefile->populate_fat_list();
    CHECK(olefile->get_next_fat_sector(1) == 2);
    delete olefile;
}

TEST(fat_mini_fat_list, mini_fat_list_short_buf_len)
{
    uint8_t ole_buf[1550] = { 0 };
    uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    memcpy(ole_buf, ole_header_sig, 8);
    ole_buf[28] = 0xFF;
    ole_buf[29] = 0xFE;
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x09;
    ole_buf[32] = 0x00;
    ole_buf[33] = 0x06;
    ole_buf[61] = 0x03;
    ole_buf[519] = 0xFE;
    ole_buf[527] = 0xFE;
    ole_buf[1539] = 0x01;
    OleFile* olefile = new OleFile(ole_buf, 1550);
    olefile->parse_ole_header();
    olefile->populate_fat_list();
    olefile->populate_mini_fat_list();
    CHECK(olefile->get_next_mini_fat_sector(1) == -1);
    delete olefile;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

