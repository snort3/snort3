//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// fbstreamer.cc author Carter Waxman

//  This program is a simple utility for reading the flatbuffers files
//  Snort generates. The files consist of a schema with a stream of
//  timestamped records that this program converts into a YAML array for
//  further data processing.

#include <csignal>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>

#include <flatbuffers/idl.h>
#include <flatbuffers/reflection.h>

#include "src/utils/endian.h"

#define OPT_INFILE     0x1
#define OPT_BEFORE     0x2
#define OPT_AFTER      0x4
#define OPT_TAIL       0x8

using namespace std;

string in_file;
uint64_t b_stamp = 0, a_stamp = 0;
uint8_t opt_flags = 0;
bool done = false;
FILE* file;

static void help()
{
    cout << "Flatbuffers Multirecord Streamer for Snort 3\n\n"
         << "Records are output in pairs of YAML objects, representing\n"
         << "timestamp and record data\n\n"
         << "Usage: fbstreamer -i file [-b time] [-a time] [-t]\n"
         << "-i: FlatBuffers records file from Snort (required)\n"
         << "-b: Stream all records before or equal to this timestamp\n"
         << "-a: Stream all records after or equal to this timestamp\n"
         << "-t: Tail mode for reading live files\n";
}

static void error(const string& e)
{
    if( done )
        return;

    cerr << "{ error: \"" << e << "\" }\n";
    cout << "]\n";
    if( file )
        fclose(file);
    exit(-1);
}

static bool tail_read(void* buf, size_t size)
{
    bool tail = opt_flags & OPT_TAIL;

    if( ferror(file) || (feof(file) && !tail) )
        return false;

    size_t to_read = size;
    do {
        if( tail )
            clearerr(file);

        to_read -= fread((char*)buf + (size - to_read), 1, to_read, file);

    } while( to_read && tail && !done && feof(file) );

    if( tail )
        clearerr(file);

    if( to_read )
        return false;

    return true;
}

static uint8_t* read(size_t size, const char* on_error = nullptr)
{
    uint8_t* ret = (uint8_t*) malloc(size);

    if( !ret )
    {
        string s = "Unable to allocate memory";
        error(on_error ? s + string(": ") + string(on_error): s);
    }
    if( !tail_read(ret, size) && on_error )
        error(on_error);

    return ret;
}

template<typename T>
inline T read(const char* on_error = nullptr)
{
    T ret = 0;
    if( !tail_read(&ret, sizeof(T)) && on_error )
        error(on_error);
    return ret;
}

static void sigint_handler(int)
{ done = true; }

static bool handle_options(int argc, char* argv[])
{
    int opt;
    while( (opt = getopt(argc, argv, "i:b:a:it")) != -1 )
    {
        switch(opt)
        {
            case 'i':
            {
                in_file = optarg;
                opt_flags |= OPT_INFILE;
                break;
            }
            case 'b':
            {
                b_stamp = strtoull(optarg, nullptr, 10);
                opt_flags |= OPT_BEFORE;
                break;
            }
            case 'a':
            {
                a_stamp = strtoull(optarg, nullptr, 10);
                opt_flags |= OPT_AFTER;
                break;
            }
            case 't':
            {
                opt_flags |= OPT_TAIL;
                break;
            }
            default:
            {
                help();
                return false;
            }
        }
    }
    return true;
}

static const reflection::Schema* load_schema(flatbuffers::Parser& parser)
{
    auto schema_size = ntohl(read<uint32_t>("Unable to read schema size"));
    auto schema = read(schema_size, "Unable to read schema");

    if( !parser.Parse((const char*)schema) )
    {
        free(schema);
        error("Unable to parse schema");
    }
    free(schema);
    parser.Serialize();

    return reflection::GetSchema(parser.builder_.GetBufferPointer());
}

inline bool is_after_b_stamp(uint64_t timestamp)
{ return (opt_flags & OPT_BEFORE) && timestamp > b_stamp; }

inline bool is_before_a_stamp(uint64_t timestamp)
{ return (opt_flags & OPT_AFTER) && timestamp < a_stamp; }

static uint8_t* scan_record(bool skip, uint32_t& size)
{
    size = ntohl(read<uint32_t>("Unable to read record size"));

    if( skip )
        fseek(file, size, SEEK_CUR);
    else
        return read(size, "Unable to read record");

    return nullptr;
}

int main(int argc, char* argv[])
{
    signal(SIGINT, sigint_handler);

    if( !handle_options(argc, argv) )
        return 1;

    cout << "[\n";

    if( !(opt_flags & OPT_INFILE) )
        error("-i is required");

    file = fopen(in_file.c_str(), "rb");
    if( !file )
        error("Unable to open file");

    if( ntohl(read<uint32_t>("Unable to read file magic")) != 0x464C5449 )
        error("Unknown file magic");

    flatbuffers::Parser parser;
    auto schema = load_schema(parser);

    auto timestamp = ntohll(read<uint64_t>());
    while( !ferror(file) && !feof(file) && !done )
    {
        uint32_t size;

        if( is_after_b_stamp(timestamp) )
            break;

        if( is_before_a_stamp(timestamp) )
        {
            scan_record(true, size);
            timestamp = ntohll(read<uint64_t>());
            continue;
        }

        auto record = scan_record(false, size);
        if( flatbuffers::Verify(*schema, *schema->root_table(), record, size) )
        {
            string json;
            if( flatbuffers::GenerateText(parser, record, &json) )
                cout << "[\n{ timestamp: " << timestamp << " },\n" << json << "],\n";
            else
                cerr << "{ status: \"Unable to process record\", timestamp: "
                     << timestamp << " },\n";
        }
        else
            cerr << "{ status: \"Record appears to be corrupt\", timestamp: "
                 << timestamp << " },\n";

        free(record);

        timestamp = ntohll(read<uint64_t>());
    }

    fclose(file);
    cout << "{ status: \"done\" }\n]\n";
    return 0;
}
