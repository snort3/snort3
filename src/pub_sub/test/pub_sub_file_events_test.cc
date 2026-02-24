//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// pub_sub_file_events_test.cc author Shilpa Nagpal <shinagpa@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_api/file_lib.h"
#include "pub_sub/file_events.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

FileContext::FileContext () { }
FileContext::~FileContext () { }
FileInfo::~FileInfo() { }
void FileInfo::set_file_id(uint64_t id)
{
    file_id = id;
}

void FileInfo::set_file_name(const char* name, uint32_t name_size)
{
    if (name and name_size)
        file_name.assign(name, name_size);

    file_name_set = true;
}

void FileInfo::set_file_direction(FileDirection dir) { direction = dir; }

void FileInfo::set_file_size(uint64_t size) { file_size = size; }

uint64_t FileInfo::get_file_id() const { return file_id; }

const std::string& FileInfo::get_file_name() const { return file_name; }

std::string FileContext::get_mime_type() const { return std::string(); }

FileDirection FileInfo::get_file_direction() const { return direction; }

uint64_t FileInfo::get_file_size() const { return file_size; }

uint8_t* FileInfo::get_file_sig_sha256() const { return (sha256); }

std::string FileInfo::sha_to_string(const uint8_t* sha256) const
{
    const uint8_t conv[] = "0123456789ABCDEF";
    const uint8_t* index;
    const uint8_t* end;
    std::string sha_out;
    index = sha256;
    end = index + SHA256_HASH_SIZE;
    while (index < end)
    {
        sha_out.push_back(conv[((*index & 0xFF)>>4)]);
        sha_out.push_back(conv[((*index & 0xFF)&0x0F)]);
        index++;
    }
    return sha_out;
}

TEST_GROUP(pub_sub_file_events_test) { };

TEST(pub_sub_file_events_test, file_event)
{
    uint64_t fuid = 12345;
    const char *filename = "test";
    double duration = 0.506;
    uint64_t filesize = 110;
    
    FileContext file_ctx;
    file_ctx.set_file_id(fuid);
    file_ctx.set_file_name(filename, 4);
    file_ctx.set_duration(duration);
    file_ctx.set_file_direction(FILE_UPLOAD);
    file_ctx.set_file_size(filesize);

    FileEvent event(file_ctx);

    CHECK(event.get_fuid() == std::to_string(fuid));
    CHECK(event.get_source() == std::string());
    CHECK(event.get_mime_type() == std::string());
    CHECK(event.get_filename() == std::string(filename));
    CHECK(event.get_duration() == duration);
    CHECK(event.get_is_orig() == true);
    CHECK(event.get_seen_bytes() == filesize);
    CHECK(event.get_total_bytes() == filesize);
    CHECK(event.get_timedout() == false);
    CHECK(event.get_sha256() == std::string());
    CHECK(event.get_extracted_name() == std::string());
    CHECK(event.get_extracted_cutoff() == true);
    CHECK(event.get_extracted_size() == 0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

