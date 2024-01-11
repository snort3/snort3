//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
** Author(s):  Hui Cao <huica@cisco.com>
**
** NOTES
** 5.25.2012 - Initial Source Code. Hcao
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_identifier.h"

#include <algorithm>
#include <cassert>

#include "hash/ghash.h"
#include "log/messages.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

struct MergeNode
{
    IdentifierNode* shared_node;  /*the node that is shared*/
    IdentifierNode* append_node;  /*the node that is added*/
};

void FileMeta::clear()
{
    rev = 0;
    type.clear();
    id = 0;
    category.clear();
    version.clear();
    groups.clear();
}

void FileIdentifier::init_merge_hash()
{
    identifier_merge_hash = new GHash(1000, sizeof(MergeNode), false, nullptr);
}

FileIdentifier::~FileIdentifier()
{
    /*Release memory used for identifiers*/
    for (auto mem_block:id_memory_blocks)
        snort_free(mem_block);

    if (identifier_merge_hash != nullptr)
        delete identifier_merge_hash;
}

void* FileIdentifier::calloc_mem(size_t size)
{
    void* ret = snort_calloc(size);
    memory_used += size;
    /*For memory management*/
    id_memory_blocks.emplace_back(ret);
    return ret;
}

void FileIdentifier::set_node_state_shared(IdentifierNode* start)
{
    unsigned int i;

    if (!start)
        return;

    if (start->state == ID_NODE_SHARED)
        return;

    if (start->state == ID_NODE_USED)
        start->state = ID_NODE_SHARED;
    else
        start->state = ID_NODE_USED;

    for (i = 0; i < MAX_BRANCH; i++)
        set_node_state_shared(start->next[i]);
}

/*Clone a trie*/
IdentifierNode* FileIdentifier::clone_node(IdentifierNode* start)
{
    unsigned int index;
    IdentifierNode* node;
    if (!start)
        return nullptr;

    node = (IdentifierNode*)calloc_mem(sizeof(*node));

    node->offset = start->offset;
    node->type_id = start->type_id;

    for (index = 0; index < MAX_BRANCH; index++)
    {
        if (start->next[index])
        {
            node->next[index] = start->next[index];
        }
    }
    return node;
}

void FileIdentifier::add_file_id(FileMeta& rule)
{
    if (!identifier_root)
    {
        identifier_root = (IdentifierNode*)calloc_mem(sizeof(*identifier_root));
        init_merge_hash();
    }

    if (file_magic_rules[rule.id].id > 0)
    {
        ParseError("file type: rule id %u found duplicate", rule.id);
        return;
    }

    file_magic_rules[rule.id] = rule;
}

/*
 * This is the main function to find file type
 * Find file type is to traverse the tries.
 * Context is saved to continue file type identification as data becomes available
 */
uint32_t FileIdentifier::find_file_type_id(const uint8_t* buf, int len, uint64_t file_offset,
    void** context)
{
    uint32_t file_type_id = SNORT_FILE_TYPE_CONTINUE;

    assert(context);

    if ( !buf || len <= 0 )
        return SNORT_FILE_TYPE_CONTINUE;

    if (!(*context))
        *context = (void*)(identifier_root);

    IdentifierNode* current = (IdentifierNode*)(*context);

    uint64_t end = file_offset + len;

    while (current &&  (current->offset >= file_offset))
    {
        /*Found file id, save and continue*/
        if (current->type_id)
        {
            file_type_id = current->type_id;
        }

        if ( current->offset >= end )
        {
            /* Save current state */
            *context = current;
            if (file_type_id)
                return file_type_id;
            else
                return SNORT_FILE_TYPE_CONTINUE;
        }

        /*Move to the next level*/
        current = current->next[buf[current->offset - file_offset ]];
    }

    /*Either end of magics or passed the current offset*/
    *context = nullptr;

    if ( file_type_id == SNORT_FILE_TYPE_CONTINUE )
        file_type_id = SNORT_FILE_TYPE_UNKNOWN;

    return file_type_id;
}

const FileMeta* FileIdentifier::get_rule_from_id(uint32_t id) const
{
    if ((id < FILE_ID_MAX) && (file_magic_rules[id].id > 0))
    {
        return (&(file_magic_rules[id]));
    }
    else
        return nullptr;
}

void FileIdentifier::get_magic_rule_ids_from_type(const std::string& type,
    const std::string& version, FileTypeBitSet& ids_set) const
{
    ids_set.reset();

    for (uint32_t i = 0; i < FILE_ID_MAX; i++)
    {
        if (type == file_magic_rules[i].type)
        {
            std::string s = "\"", tmp;
            if (!version.empty())
                tmp = s+version+s;
            if (tmp.empty() or tmp == file_magic_rules[i].version)
            {
                ids_set.set(file_magic_rules[i].id);
            }
        }
    }
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
TEST_CASE ("FileIdMemory", "[FileMagic]")
{
    FileIdentifier rc;

    CHECK(rc.memory_usage() == 0);
}

TEST_CASE ("FileIdRulePDF", "[FileMagic]")
{
    FileMeta rule;

    rule.type = "pdf";
    rule.id = 1;

    FileIdentifier rc;

    rc.add_file_id(rule);

    const char* data = "PDF";

    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN);
}

TEST_CASE ("FileIdRuleUnknow", "[FileMagic]")
{
    FileMeta rule;

    rule.type = "pdf";
    rule.id = 1;

    FileIdentifier rc;

    rc.add_file_id(rule);

    const char* data = "DDF";

    void* context = nullptr;

    CHECK((rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN));
}

TEST_CASE ("FileIdRuleEXE", "[FileMagic]")
{
    FileMeta rule;

    rule.type = "exe";
    rule.id = 1;

    FileIdentifier rc;
    rc.add_file_id(rule);

    rule.clear();
    rule.type = "exe";
    rule.id = 3;

    rc.add_file_id(rule);

    const char* data = "PDFooo";
    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN);
}

TEST_CASE ("FileIdRulePDFEXE", "[FileMagic]")
{
    FileMeta rule;

    rule.type = "exe";
    rule.id = 1;

    FileIdentifier rc;
    rc.add_file_id(rule);

    rule.clear();
    rule.type = "exe";
    rule.id = 3;

    rc.add_file_id(rule);

    const char* data = "PDFEXE";
    void* context = nullptr;

    // Match the last one
    CHECK((rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN));
}

TEST_CASE ("FileIdRuleFirst", "[FileMagic]")
{
    FileMeta rule;

    rule.type = "exe";
    rule.id = 1;

    FileIdentifier rc;
    rc.add_file_id(rule);

    rule.clear();
    rule.type = "exe";
    rule.id = 3;

    rc.add_file_id(rule);

    const char* data = "PDF";
    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN);
}
#endif

