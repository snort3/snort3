//--------------------------------------------------------------------------
// Copyright (C) 2021-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "helpers/boyer_moore_search.h"
#include "helpers/literal_search.h"
#include "helpers/utf.h"

#include <chrono>
#include <cstdlib>
#include <cstring>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

#include <vector>

THREAD_LOCAL const snort::Trace* vba_data_trace = nullptr;

snort::LiteralSearch::Handle* search_handle = nullptr;
const snort::LiteralSearch* searcher = nullptr ;

// Configurable by tests (default: 0, matching the previous hardcoded stub)
// so that walk_directory_list() tests can drive the decode_utf() output at
// the OLE_MAX_FILENAME_ASCII - 1 (31) boundary and inspect the resulting
// name, instead of every test always seeing an empty decode. Reset to 0 in
// each test group's setup()/teardown() to avoid cross-test leakage.
static int stub_decode_utf_bytes_copied = 0;
static uint8_t stub_decode_utf_fill_byte = 'A';

namespace snort
{
LiteralSearch::Handle* LiteralSearch::setup() { return nullptr; }
void LiteralSearch::cleanup(LiteralSearch::Handle*) { }
LiteralSearch* LiteralSearch::instantiate(LiteralSearch::Handle*, const uint8_t*, unsigned, bool,
    bool) { return nullptr; }
void UtfDecodeSession::set_decode_utf_state_charset(CharsetCode, CharsetSrc) { }

bool UtfDecodeSession::decode_utf(unsigned char const*, unsigned int, unsigned char* dst,
    unsigned int dst_len, int* bytes_copied)
{
    // Callers (walk_directory_list()) index name_buf with the value written
    // here. Always clamp to the caller-supplied capacity and initialize it,
    // so a stubbed "success" never yields an indeterminate or out-of-range
    // index into name_buf, mirroring the real decoder's dst_len contract.
    int copied = stub_decode_utf_bytes_copied;
    if (copied < 0)
        copied = 0;
    else if ((unsigned int)copied > dst_len)
        copied = (int)dst_len;

    if (dst and copied > 0)
        memset(dst, stub_decode_utf_fill_byte, (size_t)copied);

    if (bytes_copied)
        *bytes_copied = copied;
    return true;
}
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
    const uint8_t ole_file[1000] = { 0 };
    const uint32_t ole_length = 1000;
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    oleprocess(ole_file, ole_length, vba_buf, vba_buf_len);
}

TEST(Olefile_oleprocess_test, short_header_len)
{
    const uint8_t ole_file[100] = { 0 };
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
    const uint8_t* ole_data = nullptr;
    uint8_t* buf = nullptr;
    uint32_t len = 0;
    uint32_t buf_len;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data, len, buf, buf_len);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_short_data)
{
    const uint8_t ole_data[VBA_COMPRESSION_HEADER_LEN] = { SIG_COMP_CONTAINER, 0x00, 0x30 };
    uint8_t buf[MAX_VBA_BUFFER_LEN + 1] = { 0 };
    uint8_t* vba_buf = buf;
    uint32_t len = VBA_COMPRESSION_HEADER_LEN - 1;
    uint32_t buf_len = 7;
    buf[0] = 0x5a;

    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data, len, vba_buf, buf_len);
    CHECK_EQUAL(7, buf_len);
    CHECK_EQUAL(0x5a, vba_buf[0]);
    delete olefile;
}

TEST(Olefile_ole, decompression_invalid_data_1)
{
    const uint8_t ole_data[10] = { 0 };
    uint8_t* buf = nullptr;
    uint32_t len = 10;
    uint32_t buf_len;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data,len, buf, buf_len);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_invalid_chunk_header)
{
    uint8_t ole_data[10] ={ 0 };
    uint8_t* buf = nullptr;
    uint32_t len = 10;
    uint32_t buf_len;
    ole_data[0] = 0x01;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data, len, buf, buf_len);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_flag_0)
{
    uint8_t ole_data[10] ={ 0 };
    uint8_t* buf = nullptr;
    uint32_t len = 10;
    uint32_t buf_len;
    ole_data[0] = 0x01;
    OleFile* olefile = new OleFile(nullptr, 0);
    olefile->decompression(ole_data, len, buf, buf_len);
    CHECK(buf == nullptr);
    delete olefile;
}

TEST(Olefile_ole, decompression_flag_0_large_data)
{
    constexpr uint32_t payload_len = VBA_COMPRESSION_WINDOW * 2;
    constexpr uint32_t input_len = payload_len + VBA_COMPRESSION_HEADER_LEN;
    std::vector<uint8_t> ole_data(input_len, 0x41);
    std::vector<uint8_t> buf(MAX_VBA_BUFFER_LEN + 1);
    uint8_t* vba_buf = buf.data();
    uint32_t len = input_len;
    uint32_t buf_len = 0;

    ole_data[0] = SIG_COMP_CONTAINER;
    ole_data[1] = 0x00;
    ole_data[2] = 0x30;

    OleFile olefile(nullptr, 0);
    olefile.decompression(ole_data.data(), len, vba_buf, buf_len);
    CHECK_EQUAL(VBA_COMPRESSION_WINDOW, buf_len);
    MEMCMP_EQUAL(ole_data.data() + VBA_COMPRESSION_HEADER_LEN, buf.data(), VBA_COMPRESSION_WINDOW);
}

TEST(Olefile_ole, decompression_compressed_data_without_null)
{
    constexpr uint32_t literal_groups = VBA_COMPRESSION_WINDOW / 8;
    constexpr uint32_t input_len = VBA_COMPRESSION_HEADER_LEN + literal_groups * 9;
    std::vector<uint8_t> ole_data(input_len, 0x41);
    std::vector<uint8_t> buf(MAX_VBA_BUFFER_LEN + 1);
    uint8_t* vba_buf = buf.data();
    uint32_t len = input_len;
    uint32_t buf_len = 0;

    ole_data[0] = SIG_COMP_CONTAINER;
    ole_data[1] = 0x00;
    ole_data[2] = 0xB0;

    for (uint32_t pos = VBA_COMPRESSION_HEADER_LEN; pos < input_len; pos += 9)
        ole_data[pos] = 0x00;

    OleFile olefile(nullptr, 0);
    olefile.decompression(ole_data.data(), len, vba_buf, buf_len);
    CHECK_EQUAL(VBA_COMPRESSION_WINDOW, buf_len);

    std::vector<uint8_t> expected(VBA_COMPRESSION_WINDOW, 0x41);
    MEMCMP_EQUAL(expected.data(), buf.data(), VBA_COMPRESSION_WINDOW);
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
    const FileProperty* res = dir_list->get_file_node(test);
    delete dir_list;
    CHECK(res == nullptr);
}

TEST(Olefile_ole, bytes_to_copy_test)
{
    OleFile* olefile = new OleFile(nullptr, 100);
    uint32_t bytes_to_copy;
    bytes_to_copy = olefile->find_bytes_to_copy(70, 50, 60, 64);
    CHECK(bytes_to_copy == 10);
    delete olefile;
}

TEST(Olefile_ole, get_mini_fat_offset_divide_by_zero)
{
    uint8_t dummy_buf[512] = {0};
    OleFile* olefile = new OleFile(dummy_buf, sizeof(dummy_buf));
    OleHeader* test_header = new OleHeader();
    test_header->set_mini_sector_size_raw(0);
    olefile->set_header(test_header);
    int32_t result = olefile->get_mini_fat_offset(0);
    CHECK(result == -1);
    delete olefile;
}

TEST_GROUP(fat_mini_fat_list)
{
};

TEST(fat_mini_fat_list, fat_list_short_buf_len)
{
    uint8_t ole_buf[520] = { 0 };
    const uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
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
    const uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
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
    const uint8_t ole_header_sig[8] =  { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
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

// Test: overflow in populate_fat_list via crafted OLE header
TEST(fat_mini_fat_list, fat_list_overflow_guard)
{
    uint8_t ole_buf[512] = {0};
    const uint8_t ole_header_sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, ole_header_sig, 8);
    // Set sector size to 512 (little-endian at offset 30)
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x02;
    uint32_t sector_size = 512;
    // Set first FAT sector index in DIFAT array (offset 76) to cause overflow
    uint32_t fat_sector = (UINT32_MAX - OLE_HEADER_LEN - 256) / sector_size;
    ole_buf[76] = (uint8_t)(fat_sector & 0xFF);
    ole_buf[77] = (uint8_t)((fat_sector >> 8) & 0xFF);
    ole_buf[78] = (uint8_t)((fat_sector >> 16) & 0xFF);
    ole_buf[79] = (uint8_t)((fat_sector >> 24) & 0xFF);

    OleFile* olefile = new OleFile(ole_buf, sizeof(ole_buf));
    olefile->parse_ole_header();
    // This test makes populate_fat_list hit its integer overflow check.
    // i.e ( byte_offset + sector_size < byte_offset ) condition
    olefile->populate_fat_list();

    delete olefile;
}

// Test: overflow in populate_mini_fat_list via crafted OLE header
TEST(fat_mini_fat_list, mini_fat_list_overflow_guard)
{
    uint8_t ole_buf[512] = {0};
    const uint8_t ole_header_sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, ole_header_sig, 8);
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x02;
    uint32_t sector_size = 512;
    // Set first mini FAT sector index (offset 60)
    uint32_t minifat_sector = (UINT32_MAX - OLE_HEADER_LEN - 256) / sector_size;
    ole_buf[60] = (uint8_t)(minifat_sector & 0xFF);
    ole_buf[61] = (uint8_t)((minifat_sector >> 8) & 0xFF);
    ole_buf[62] = (uint8_t)((minifat_sector >> 16) & 0xFF);
    ole_buf[63] = (uint8_t)((minifat_sector >> 24) & 0xFF);

    OleFile* olefile = new OleFile(ole_buf, sizeof(ole_buf));
    olefile->parse_ole_header();
    // This test makes populate_mini_fat_list hit its integer overflow check.
    // i.e ( byte_offset + sector_size < byte_offset ) condition
    olefile->populate_mini_fat_list();

    delete olefile;
}

// Test: overflow in walk_directory_list via crafted OLE header
TEST(fat_mini_fat_list, walk_directory_list_overflow_guard)
{
    uint8_t ole_buf[512] = {0};
    const uint8_t ole_header_sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, ole_header_sig, 8);
    ole_buf[30] = 0x00;
    ole_buf[31] = 0x02;
    uint32_t sector_size = 512;
    // Set first directory sector index (offset 48)
    uint32_t dir_sector = (UINT32_MAX - OLE_HEADER_LEN - 256) / sector_size;
    ole_buf[48] = (uint8_t)(dir_sector & 0xFF);
    ole_buf[49] = (uint8_t)((dir_sector >> 8) & 0xFF);
    ole_buf[50] = (uint8_t)((dir_sector >> 16) & 0xFF);
    ole_buf[51] = (uint8_t)((dir_sector >> 24) & 0xFF);

    OleFile* olefile = new OleFile(ole_buf, sizeof(ole_buf));
    olefile->parse_ole_header();
    // This test makes walk_directory_list hit its integer overflow check.
    // i.e ( start_offset + sector_size < start_offset ) condition
    olefile->walk_directory_list();

    delete olefile;
}

TEST_GROUP(OLECycleDetection)
{
};

TEST(OLECycleDetection, FatSectorCycle)
{
    uint8_t ole_buf[OLE_HEADER_LEN + 2*512] = {0};
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, sig, 8);
    ole_buf[28] = 0xFF; ole_buf[29] = 0xFE;
    ole_buf[30] = 0x09; ole_buf[31] = 0x00;
    ole_buf[76] = 0x00; ole_buf[77] = 0x00; ole_buf[78] = 0x00; ole_buf[79] = 0x00;
    ole_buf[44] = 0x03; ole_buf[45] = 0x00; ole_buf[46] = 0x00; ole_buf[47] = 0x00;
    ole_buf[48] = 0x01; ole_buf[49] = 0x00; ole_buf[50] = 0x00; ole_buf[51] = 0x00;
    const int32_t fat[] = { 1, 2, 1 };
    memcpy(ole_buf + OLE_HEADER_LEN, fat, sizeof(fat));
    int dir_offset = OLE_HEADER_LEN + 512; 
    ole_buf[dir_offset + 66] = 0x02; 
    ole_buf[dir_offset + 116] = 0x00; 
    uint64_t stream_size = 8;
    memcpy(ole_buf + dir_offset + 120, &stream_size, sizeof(stream_size));
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    oleprocess(ole_buf, sizeof(ole_buf), vba_buf, vba_buf_len);
    CHECK(vba_buf_len == 0);
}

TEST(OLECycleDetection, DirectorySectorCycle)
{
    uint8_t ole_buf[OLE_HEADER_LEN + 2*512] = {0};
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, sig, 8);
    ole_buf[28] = 0xFF; ole_buf[29] = 0xFE;
    ole_buf[30] = 0x09; ole_buf[31] = 0x00;
    ole_buf[48] = 0x00; ole_buf[49] = 0x00; ole_buf[50] = 0x00; ole_buf[51] = 0x00;
    ole_buf[44] = 0x03; ole_buf[45] = 0x00; ole_buf[46] = 0x00; ole_buf[47] = 0x00;
    ole_buf[76] = 0x01; ole_buf[77] = 0x00; ole_buf[78] = 0x00; ole_buf[79] = 0x00;
    const int32_t fat[] = { 1, 2, 1 };
    memcpy(ole_buf + OLE_HEADER_LEN, fat, sizeof(fat));
    OleFile olefile(ole_buf, sizeof(ole_buf));
    olefile.parse_ole_header();
    olefile.populate_fat_list();
    olefile.walk_directory_list();
    CHECK_TRUE(true);
}

TEST(OLECycleDetection, MiniFatSectorCycle)
{
    uint8_t ole_buf[OLE_HEADER_LEN + 2*512] = {0};
    const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    memcpy(ole_buf, sig, 8);
    ole_buf[28] = 0xFF; ole_buf[29] = 0xFE;
    ole_buf[30] = 0x09; ole_buf[31] = 0x00;
    ole_buf[60] = 0x00; ole_buf[61] = 0x00; ole_buf[62] = 0x00; ole_buf[63] = 0x00;
    ole_buf[64] = 0x03; ole_buf[65] = 0x00; ole_buf[66] = 0x00; ole_buf[67] = 0x00;
    ole_buf[44] = 0x03; ole_buf[45] = 0x00; ole_buf[46] = 0x00; ole_buf[47] = 0x00;
    ole_buf[76] = 0x01; ole_buf[77] = 0x00; ole_buf[78] = 0x00; ole_buf[79] = 0x00;
    const int32_t fat[] = { 1, 2, 1 };
    memcpy(ole_buf + OLE_HEADER_LEN, fat, sizeof(fat));
    OleFile olefile(ole_buf, sizeof(ole_buf));
    olefile.parse_ole_header();
    olefile.populate_fat_list();
    olefile.populate_mini_fat_list();
    CHECK_TRUE(true);
}

TEST_GROUP(GetMiniFatOffsetInfiniteLoop)
{
};

// Shared helper: build an OleFile with a small FAT containing a 2-cycle
// (0 -> 1 -> 0). sector_size = 512, mini_sector_size = 64
// (=> mini_fat_persector = 8). Root mini-stream sector = 0 (head of cycle).
// Ownership of hdr/dl/fat transfers to the returned OleFile via the
// UNIT_TEST setters; ~OleFile deletes header, dir_list, fat_list[].
static OleFile* build_cyclic_fat_olefile(const uint8_t* dummy, uint32_t dummy_len)
{
    OleHeader* hdr = new OleHeader();
    const uint8_t sec_size_bytes[2]  = { 0x09, 0x00 };
    const uint8_t mini_size_bytes[2] = { 0x06, 0x00 };
    hdr->set_sector_size(sec_size_bytes);
    hdr->set_mini_sector_size(mini_size_bytes);

    const int32_t fat_len = 4;
    int32_t* fat = new int32_t[fat_len];
    fat[0] = 1; fat[1] = 0; fat[2] = -1; fat[3] = -1;

    DirectoryList* dl = new DirectoryList();
    dl->set_mini_stream_sector(0);

    OleFile* olefile = new OleFile(dummy, dummy_len);
    olefile->set_header(hdr);
    olefile->set_dir_list(dl);
    olefile->set_fat_list(fat, fat_len);
    return olefile;
}

// Length-clamp path: attacker-supplied sec_id makes sec_position vastly
// exceed fat_list_len, so the clamp at file_olefile.cc bails out with -1
// before the walk begins. Bounded-time guarantee against huge sec_id.
TEST(GetMiniFatOffsetInfiniteLoop, LengthClampReturnsError)
{
    uint8_t dummy[16] = { 0 };
    OleFile* olefile = build_cyclic_fat_olefile(dummy, sizeof(dummy));

    const int32_t attack_sec_id = 8 * 1024 * 1024;

    auto t0 = std::chrono::steady_clock::now();
    int32_t rv = olefile->get_mini_fat_offset(attack_sec_id);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    CHECK_EQUAL(-1, rv);
    CHECK(elapsed_ms < 60000.0);

    delete olefile;
}

// Visited-set path: pick sec_id small enough to pass the length clamp
// (sec_position = 3, fat_list_len = 4) but large enough to force the walk
// to a third iteration, at which point current_sector == 0 is already in
// visited_fat_sectors and the cycle-detection branch fires. mini_fat_persector
// * 2 is NOT sufficient: it only walks 0 -> 1 -> 0 and exits before the
// visited-set is checked a third time. mini_fat_persector * 3 forces the
// third check and hits the guard.
TEST(GetMiniFatOffsetInfiniteLoop, CycleDetectionReturnsError)
{
    uint8_t dummy[16] = { 0 };
    OleFile* olefile = build_cyclic_fat_olefile(dummy, sizeof(dummy));

    const int32_t mini_fat_persector = 8;
    const int32_t attack_sec_id = mini_fat_persector * 3;

    auto t0 = std::chrono::steady_clock::now();
    int32_t rv = olefile->get_mini_fat_offset(attack_sec_id);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    CHECK_EQUAL(-1, rv);
    CHECK(elapsed_ms < 1000.0);

    delete olefile;
}

// Full attack vector from the CSCwv17631 PoC (sec_id = 0x7FFFFFFE, which is
// ~268M loop iterations on the unpatched code). Gated behind OLE_FULL_ATTACK
// so an accidental run on a still-vulnerable build cannot wedge CI.
TEST(GetMiniFatOffsetInfiniteLoop, FullAttackVector)
{
    const char* env = std::getenv("OLE_FULL_ATTACK");
    if (!env || env[0] == '0' || env[0] == '\0')
        return;

    uint8_t dummy[16] = { 0 };
    OleFile* olefile = build_cyclic_fat_olefile(dummy, sizeof(dummy));

    const int32_t attack_sec_id = 0x7FFFFFFE;

    auto t0 = std::chrono::steady_clock::now();
    int32_t rv = olefile->get_mini_fat_offset(attack_sec_id);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    CHECK_EQUAL(-1, rv);
    CHECK(elapsed_ms < 1000.0);

    delete olefile;
}

TEST_GROUP(OleFileVbaOffsetGuard)
{
    void teardown() override
    {
        // The searcher/search_handle globals are process-wide; restore them
        // to the file's default (unset) state so later tests such as
        // Olefile_ole::get_file_offset keep exercising the searcher==nullptr
        // guard rather than inheriting this group's real searcher.
        searcher = nullptr;
        search_handle = nullptr;
    }
};

// Regression test for the Copilot review on PR #5829: exercise
// find_and_extract_vba()'s "offset < 4" guard with a *real* LiteralSearch
// implementation (BoyerMooreSearchNoCase, matching the production/fuzz
// wiring in file_olefile_fuzz.cc) instead of the searcher==nullptr
// short-circuit in get_file_offset(). A prior test attempt left the global
// searcher unset, so it never reached the "data += offset - 4" arithmetic
// that the guard protects. This builds a minimal single-sector FAT stream
// whose raw bytes contain the "ATTRIBUT" literal at attribut_offset, and
// confirms the stream is safely skipped (no vba data produced) for every
// offset value the guard is meant to catch (0..3), without an out-of-bounds
// or pointer-underflow access.
static void check_short_attribut_offset_is_skipped(uint32_t attribut_offset)
{
    static const uint8_t pattern[] = { 'A', 'T', 'T', 'R', 'I', 'B', 'U', 'T' };
    snort::BoyerMooreSearchNoCase local_searcher(pattern, sizeof(pattern));
    searcher = &local_searcher;
    search_handle = nullptr;

    const uint16_t sector_size = 512;
    const uint32_t buf_len = OLE_HEADER_LEN + sector_size;
    std::vector<uint8_t> file_buf(buf_len, 0);
    memcpy(file_buf.data() + OLE_HEADER_LEN + attribut_offset, pattern, sizeof(pattern));

    OleHeader* header = new OleHeader();
    const uint8_t sec_size_bytes[2] = { 0x09, 0x00 };
    header->set_sector_size(sec_size_bytes);

    FileProperty* node = new FileProperty();
    const uint8_t stream_type_byte = static_cast<uint8_t>(STREAM);
    node->set_file_type(&stream_type_byte);
    const uint8_t starting_sector_bytes[4] = { 0x00, 0x00, 0x00, 0x00 };
    node->set_starting_sector(starting_sector_bytes, LITL_END);
    const uint8_t stream_size_bytes[8] = { 16, 0, 0, 0, 0, 0, 0, 0 };
    node->set_stream_size(stream_size_bytes, LITL_END);

    DirectoryList* dir_list = new DirectoryList();
    dir_list->oleentry.push_back(node);

    int32_t* fat = new int32_t[1];
    fat[0] = -1;

    OleFile* olefile = new OleFile(file_buf.data(), buf_len);
    olefile->set_header(header);
    olefile->set_dir_list(dir_list);
    olefile->set_fat_list(fat, 1);

    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    olefile->find_and_extract_vba(vba_buf, vba_buf_len);

    CHECK(vba_buf == nullptr);
    CHECK_EQUAL(0u, vba_buf_len);

    delete olefile;
}

TEST(OleFileVbaOffsetGuard, AttributAtOffset0)
{
    check_short_attribut_offset_is_skipped(0);
}

TEST(OleFileVbaOffsetGuard, AttributAtOffset1)
{
    check_short_attribut_offset_is_skipped(1);
}

TEST(OleFileVbaOffsetGuard, AttributAtOffset2)
{
    check_short_attribut_offset_is_skipped(2);
}

TEST(OleFileVbaOffsetGuard, AttributAtOffset3)
{
    check_short_attribut_offset_is_skipped(3);
}

TEST_GROUP(OleFileFilenameTruncation)
{
    void setup() override
    {
        stub_decode_utf_bytes_copied = 0;
    }

    void teardown() override
    {
        // stub_decode_utf_bytes_copied is a process-wide global; restore it
        // to the default (0) "empty decode" behavior other test groups rely
        // on so this group's boundary value never leaks into later tests.
        stub_decode_utf_bytes_copied = 0;
    }
};

// Regression test for the Copilot review on PR #5829: walk_directory_list()
// requests at most OLE_MAX_FILENAME_ASCII - 1 (31) bytes from decode_utf()
// into the 32-byte name_buf, then writes the null terminator itself at
// name_buf[bytes_copied]. No prior test exercised that boundary because the
// decode_utf stub always reported bytes_copied == 0. This drives the stub
// to report the maximum permitted length (31) and fills the output with a
// recognizable pattern, then walks a single-entry OLE directory sector and
// verifies the resulting stored name is exactly 31 characters and is
// correctly terminated at index 31 -- the last valid index of the 32-byte
// allocation -- so the fix's truncation/termination logic is actually
// covered, not just its crash-safety.
TEST(OleFileFilenameTruncation, MaxLengthNameIsTruncatedAndTerminated)
{
    const uint16_t sector_size = 512;
    const uint32_t buf_len = OLE_HEADER_LEN + sector_size;
    std::vector<uint8_t> ole_buf(buf_len, 0);

    // Single directory sector holding sector_size / DIR_ENTRY_SIZE == 4
    // entries. Entry 0 is a real STREAM (kept by walk_directory_list());
    // entries 1-3 stay EMPTY (0x00) and are discarded, but still exercise
    // the decode_utf()/terminator path on the way there.
    ole_buf[OLE_HEADER_LEN + DIR_FILE_TYPE_OFFSET] = STREAM;
    const uint8_t stream_size_bytes[8] = { 4, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(ole_buf.data() + OLE_HEADER_LEN + DIR_STREAM_SIZE_OFFSET, stream_size_bytes, 8);

    OleHeader* header = new OleHeader();
    const uint8_t sec_size_bytes[2] = { 0x09, 0x00 }; // 2^9 == 512
    header->set_sector_size(sec_size_bytes);
    const uint8_t first_dir_bytes[4] = { 0x00, 0x00, 0x00, 0x00 };
    header->set_first_dir(first_dir_bytes);

    int32_t* fat = new int32_t[1];
    fat[0] = -1; // single-sector directory: no next sector to chase

    OleFile* olefile = new OleFile(ole_buf.data(), buf_len);
    olefile->set_header(header);
    olefile->set_fat_list(fat, 1);

    // Simulate a decoder that has a full 32-character UTF-16 name available
    // and would happily fill the entire destination buffer it's given --
    // exactly the CSCwq23367 scenario. The stub clamps this sentinel to
    // whatever dst_len walk_directory_list() actually passes, so if that
    // call site regresses to requesting OLE_MAX_FILENAME_ASCII (32) instead
    // of OLE_MAX_FILENAME_ASCII - 1 (31), this test will both observe a
    // 32-character name below and let ASAN catch the resulting
    // name_buf[32] = '\0' heap-buffer-overflow (name_buf is only 32 bytes,
    // valid indices 0-31).
    stub_decode_utf_bytes_copied = OLE_MAX_FILENAME_LEN_UTF16;

    olefile->walk_directory_list();

    DirectoryList* dir_list = olefile->get_dir_list();
    CHECK(dir_list != nullptr);
    CHECK_EQUAL((size_t)1, dir_list->oleentry.size());

    const char* name = dir_list->oleentry.front()->get_name();
    CHECK(name != nullptr);
    CHECK_EQUAL((size_t)(OLE_MAX_FILENAME_ASCII - 1), strlen(name));
    for (int i = 0; i < OLE_MAX_FILENAME_ASCII - 1; i++)
        CHECK_EQUAL('A', name[i]);

    delete olefile;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
