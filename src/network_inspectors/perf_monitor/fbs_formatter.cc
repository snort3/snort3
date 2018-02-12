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

// fbs_formatter.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fbs_formatter.h"

#include <queue>

#include <flatbuffers/idl.h>
#include <flatbuffers/reflection.h>

#include "utils/endian.h"

#ifdef UNIT_TEST
#include <cstdio>
#include <cstring>

#include "catch/snort_catch.h"
#include "utils/util.h"
#endif

using namespace std;

typedef flatbuffers::Offset<flatbuffers::Table> TableOffset;
typedef pair<flatbuffers::Offset<void>, flatbuffers::uoffset_t> OffsetPair;

static string lowercase(string s)
{
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

void FbsFormatter::register_field(const std::string& name, PegCount* value)
{
    non_offset_names.push_back(name);
    non_offset_values.push_back(value);
}

void FbsFormatter::register_field(const std::string& name, const char* value)
{
    FormatterValue fv;
    fv.s = value;

    offset_names.push_back(name);
    offset_types.push_back(FT_STRING);
    offset_values.push_back(fv);
}

void FbsFormatter::register_field(const std::string& name, std::vector<PegCount>* value)
{
    FormatterValue fv;
    fv.ipc = value;

    offset_names.push_back(name);
    offset_types.push_back(FT_IDX_PEG_COUNT);
    offset_values.push_back(fv);
}

//Apply order to fields so that leaf nodes are created first in one pass
void FbsFormatter::commit_field_reorder()
{
    for( unsigned i = 0; i < offset_types.size(); i++ )
    {
        switch( offset_types[i] )
        {
            case FT_STRING:
                PerfFormatter::register_field(offset_names[i], offset_values[i].s);
                break;
            case FT_IDX_PEG_COUNT:
                PerfFormatter::register_field(offset_names[i], offset_values[i].ipc);
                break;
            case FT_PEG_COUNT:
                assert(false); //Peg count is not an offset type
        }
    }
    offset_types.clear();
    offset_names.clear();
    offset_values.clear();

    for( unsigned i = 0; i < non_offset_names.size(); i++ )
        PerfFormatter::register_field(non_offset_names[i], non_offset_values[i]);

    non_offset_names.clear();
    non_offset_values.clear();
}

void FbsFormatter::register_section(const std::string& section)
{
    commit_field_reorder();
    PerfFormatter::register_section(section);
}

void FbsFormatter::finalize_fields()
{
    commit_field_reorder();
    vtable_offsets.clear();

    schema = "namespace Perfmon;table ";
    schema += get_tracker_name() + "{";

    string module_tables;
    for( unsigned i = 0; i < section_names.size(); i++ )
    {
        string name = lowercase(section_names[i]);
        schema +=  name + ":";
        name[0] = toupper(name[0]);
        schema += name + ";";

        module_tables += "table " + name + "{";
        for( unsigned j = 0; j < field_names[i].size(); j++ )
        {
            module_tables += lowercase(field_names[i][j]);

            switch(types[i][j])
            {
                case FT_PEG_COUNT:
                    module_tables += ":ulong;";
                    break;
                case FT_STRING:
                    module_tables += ":string;";
                    break;
                case FT_IDX_PEG_COUNT:
                    module_tables += ":[ulong];";
                    module_tables += lowercase(field_names[i][j]);
                    module_tables += "_map:[ushort];";
                    break;
            }
        }
        module_tables += "}";
    }
    schema += "}" + module_tables + "root_type ";
    schema += get_tracker_name() + ";";

    flatbuffers::Parser parser;
    assert(parser.Parse(schema.c_str())); // Above code is broken or bad peg names if this hits
    parser.Serialize();

    auto& schema_builder = parser.builder_;

    auto reflection_schema = reflection::GetSchema(schema_builder.GetBufferPointer());
    auto root_fields = reflection_schema->root_table()->fields();
    vtable_offsets.push_back(vector<flatbuffers::uoffset_t>());

    for( unsigned i = 0; i < section_names.size(); i++ )
    {
        vtable_offsets.push_back(vector<flatbuffers::uoffset_t>());

        auto module_field = root_fields->LookupByKey(lowercase(section_names[i]).c_str());
        vtable_offsets[0].push_back(module_field->offset());

        auto module_table = reflection_schema->objects()->Get(module_field->type()->index());
        for( unsigned j = 0; j < field_names[i].size(); j++ )
        {
            auto field = module_table->fields()->LookupByKey(lowercase(field_names[i][j]).c_str());
            vtable_offsets[i + 1].push_back(field->offset());

            if( types[i][j] == FT_IDX_PEG_COUNT )
            {
                auto field_name = lowercase(field_names[i][j]) + "_map";
                field = module_table->fields()->LookupByKey(field_name.c_str());
                vtable_offsets[i + 1].push_back(field->offset());
            }
        }
    }
}

void FbsFormatter::init_output(FILE* fh)
{
    int size = htonl(schema.length());

    fwrite("FLTI", 4, 1, fh);
    fwrite(&size, sizeof(uint32_t), 1, fh);
    fwrite(schema.c_str(), schema.length(), 1, fh);
}

enum IPC_VERDICT
{
    IPC_EMPTY = 0,
    IPC_INDEXED,
    IPC_MAPPED
};

void FbsFormatter::write(FILE* fh, time_t timestamp)
{
    flatbuffers::FlatBufferBuilder fbb;
    queue<OffsetPair> root_offsets;

    for( unsigned i = 0; i < values.size(); i++ )
    {
        bool nz_found = false;
        queue<OffsetPair> leaf_queue;

        unsigned j = 0, vj = 0;

        for( ; j < values[i].size() && types[i][j] != FT_PEG_COUNT; j++, vj++ )
        {
            switch( types[i][j] )
            {
                case FT_STRING:
                    if( *values[i][j].s )
                    {
                        nz_found = true;
                        leaf_queue.push(OffsetPair(fbb.CreateString(values[i][j].s).Union(),
                            vtable_offsets[i + 1][j]));
                    }

                    break;

                case FT_IDX_PEG_COUNT:
                {
                    auto& ipc = *values[i][j].ipc;

                    // Using a separate vector as map: size = (2 (map_val) + 8 (val)) * nz_elements
                    // Using the index of vector to determine mapping: size = 8 * vector_size
                    unsigned nz_break_even = ipc.size() * 4 / 5;

                    vector<uint16_t> map;
                    vector<PegCount> mapped_ipc;
                    for( unsigned k = 0; k < ipc.size(); k++ )
                    {
                        if( ipc[k] )
                        {
                            nz_found = true;
                            map.push_back(k);
                            mapped_ipc.push_back(ipc[k]);

                            if( map.size() > nz_break_even )
                                break;
                        }
                    }

                    if( !map.empty() )
                    {
                        if( map.size() <= nz_break_even )
                        {
                            leaf_queue.push(OffsetPair(fbb.CreateVector<PegCount>(mapped_ipc).Union(),
                                vtable_offsets[i + 1][vj]));

                            leaf_queue.push(OffsetPair(fbb.CreateVector<uint16_t>(map).Union(),
                                vtable_offsets[i + 1][vj + 1]));
                        }
                        else
                        {
                            leaf_queue.push(OffsetPair(fbb.CreateVector<PegCount>(ipc).Union(),
                                vtable_offsets[i + 1][vj]));
                        }
                    }
                    vj++;
                    break;
                }

                default:
                    break;
            }
        }

        auto start = fbb.StartTable();
        for( ; j < values[i].size(); j++, vj++ )
        {
            if( *values[i][j].pc )
            {
                nz_found = true;
                fbb.AddElement<PegCount>(vtable_offsets[i + 1][vj], *values[i][j].pc, 0);
            }
        }

        while( !leaf_queue.empty() )
        {
            fbb.AddOffset(leaf_queue.front().second, leaf_queue.front().first);
            leaf_queue.pop();
        }

        auto table_offset = TableOffset(fbb.EndTable(start, vtable_offsets[i + 1].size()));
        if( nz_found )
            root_offsets.push(OffsetPair(table_offset.Union(), vtable_offsets[0][i]));
    }

    auto start = fbb.StartTable();
    while( !root_offsets.empty() )
    {
        fbb.AddOffset(root_offsets.front().second, root_offsets.front().first);
        root_offsets.pop();
    }

    fbb.Finish(TableOffset(fbb.EndTable(start, vtable_offsets.size())));

    uint64_t ts = htonll(timestamp);
    uint32_t size = htonl(fbb.GetSize());
    fwrite(&ts, sizeof(uint64_t), 1, fh);
    fwrite(&size, sizeof(uint32_t), 1, fh);
    fwrite(fbb.GetBufferPointer(), fbb.GetSize(), 1, fh);

    fflush(fh);
}

#ifdef UNIT_TEST

static uint8_t* make_prefixed_schema(const char* schema)
{
    size_t len = strlen(schema);
    uint32_t slen = htonl(len);
    uint8_t* cooked = (uint8_t*)snort_alloc(slen + 8);

    memcpy(cooked, "FLTI", 4);
    memcpy(cooked + 4, &slen, 4);
    memcpy(cooked + 8, schema, len);

    return cooked;
}

static bool test_file(FILE* fh, const uint8_t* cooked)
{
    auto size = ftell(fh);
    char* fake_file = (char*)snort_alloc(size + 1);

    rewind(fh);
    fread(fake_file, size, 1, fh);

    bool ret = memcmp(cooked, fake_file, size);

    snort_free(fake_file);

    return ret;
}

TEST_CASE("peg schema", "[FbsFormatter]")
{
    PegCount one = 1, two = 0, three = 0;

    const char* schema =
        "namespace Perfmon;"
        "table fbs_formatter{pegs:Pegs;}"
        "table Pegs{one:ulong;two:ulong;three:ulong}"
        "root_table fbs_formatter;";
    uint8_t* cooked = make_prefixed_schema(schema);

    FILE* fh = tmpfile();
    FbsFormatter f("fbs_formatter");
    f.register_section("pegs");
    f.register_field("one", &one);
    f.register_field("two", &two);
    f.register_field("three", &three);
    f.finalize_fields();
    f.init_output(fh);

    CHECK((test_file(fh, cooked) == true));

    fclose(fh);
    snort_free(cooked);
}

TEST_CASE("string schema", "[FbsFormatter]")
{
    const char one[] = "1", two[] = "0", three[] = "0";

    const char* schema =
        "namespace Perfmon;"
        "table fbs_formatter{strings:Strings;}"
        "table Strings{one:string;two:string;three:string}"
        "root_table fbs_formatter;";
    uint8_t* cooked = make_prefixed_schema(schema);

    FILE* fh = tmpfile();
    FbsFormatter f("fbs_formatter");
    f.register_section("strings");
    f.register_field("one", one);
    f.register_field("two", two);
    f.register_field("three", three);
    f.finalize_fields();
    f.init_output(fh);

    CHECK((test_file(fh, cooked) == true));

    fclose(fh);
    snort_free(cooked);
}

TEST_CASE("vector schema", "[FbsFormatter]")
{
    vector<PegCount> one(10), two(10);

    const char* schema =
        "namespace Perfmon;"
        "table fbs_formatter{vectors:Vectors;}"
        "table Vectors{one:[ulong];one_map:[ulong];two:[ulong];two_map:[ulong];}"
        "root_table fbs_formatter;";
    uint8_t* cooked = make_prefixed_schema(schema);

    FILE* fh = tmpfile();
    FbsFormatter f("fbs_formatter");
    f.register_section("vectors");
    f.register_field("one", &one);
    f.register_field("two", &two);
    f.finalize_fields();
    f.init_output(fh);

    CHECK((test_file(fh, cooked) == true));

    fclose(fh);
    snort_free(cooked);
}

TEST_CASE("mixed schema", "[FbsFormatter]")
{
    PegCount one;
    const char two[] = "0";
    vector<PegCount> three(10);

    // meat of this test: fields are reordered
    const char* schema =
        "namespace Perfmon;"
        "table fbs_formatter{mixed:Mixed;}"
        "table Mixed{two:string;three:[ulong];three_map[ulong];one:ulong;}"
        "root_table fbs_formatter;";
    uint8_t* cooked = make_prefixed_schema(schema);

    FILE* fh = tmpfile();
    FbsFormatter f("fbs_formatter");
    f.register_section("mixed");
    f.register_field("one", &one);
    f.register_field("two", two);
    f.register_field("three", &three);
    f.finalize_fields();
    f.init_output(fh);

    CHECK((test_file(fh, cooked) == true));

    fclose(fh);
    snort_free(cooked);
}

#endif
