//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
} ;

void FileMagicData::clear()
{
    content_str.clear();
    content.clear();
    offset = 0;
}

void FileMagicRule::clear()
{
    rev = 0;
    message.clear();
    type.clear();
    id = 0;
    category.clear();
    version.clear();
    groups.clear();
    file_magics.clear();
}

void FileIdentifier::init_merge_hash()
{
    identifier_merge_hash = snort::ghash_new(1000, sizeof(MergeNode), 0, nullptr);
    assert(identifier_merge_hash);
}

FileIdentifier::~FileIdentifier()
{
    /*Release memory used for identifiers*/
    for (auto mem_block:id_memory_blocks)
    {
        snort_free(mem_block);
    }

    if (identifier_merge_hash != nullptr)
    {
        ghash_delete(identifier_merge_hash);
    }
}

void* FileIdentifier::calloc_mem(size_t size)
{
    void* ret = snort_calloc(size);
    memory_used += size;
    /*For memory management*/
    id_memory_blocks.push_back(ret);
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

IdentifierNode* FileIdentifier::create_trie_from_magic(FileMagicRule& rule, uint32_t type_id)
{
    IdentifierNode* current;
    IdentifierNode* root = nullptr;

    if (rule.file_magics.empty() || !type_id)
        return nullptr;

    /* Content magics are sorted based on offset, this
     * will help compile the file magic trio
     */
    std::sort(rule.file_magics.begin(),rule.file_magics.end());

    current =  (IdentifierNode*)calloc_mem(sizeof(*current));
    current->state = ID_NODE_NEW;
    root = current;

    for (auto magic:rule.file_magics)
    {
        unsigned int i;
        current->offset = magic.offset;
        for (i = 0; i < magic.content.size(); i++)
        {
            IdentifierNode* node = (IdentifierNode*)calloc_mem(sizeof(*node));
            uint8_t index = magic.content[i];
            node->offset = magic.offset + i + 1;
            node->state = ID_NODE_NEW;
            current->next[index] = node;
            current = node;
        }
    }

    /*Last node has type name*/
    current->type_id = type_id;
    return root;
}

/*This function examines whether to update the trie based on shared state*/

bool FileIdentifier::update_next(IdentifierNode* start,IdentifierNode** next_ptr,
    IdentifierNode* append)
{
    IdentifierNode* next = (*next_ptr);
    MergeNode merge_node;
    IdentifierNode* result;

    if (!append || (next == append))
        return false;

    merge_node.append_node = append;
    merge_node.shared_node = next;
    if (!next)
    {
        /*reuse the append*/
        *next_ptr = append;
        set_node_state_shared(append);
        return false;
    }
    else if ((result = (IdentifierNode*)ghash_find(identifier_merge_hash, &merge_node)))
    {
        /*the same pointer has been processed, reuse it*/
        *next_ptr = result;
        set_node_state_shared(result);
        return false;
    }
    else
    {
        if ((start->offset < append->offset) && (next->offset > append->offset))
        {
            /*offset could have gap when non 0 offset is allowed */
            unsigned int index;
            IdentifierNode* node = (IdentifierNode*)calloc_mem(sizeof(*node));
            merge_node.shared_node = next;
            merge_node.append_node = append;
            node->offset = append->offset;

            for (index = 0; index < MAX_BRANCH; index++)
            {
                node->next[index] = next;
            }

            set_node_state_shared(next);
            next = node;
            ghash_add(identifier_merge_hash, &merge_node, next);
        }
        else if (next->state == ID_NODE_SHARED)
        {
            /*shared, need to clone one*/
            IdentifierNode* current_next = next;
            merge_node.shared_node = current_next;
            merge_node.append_node = append;
            next = clone_node(current_next);
            set_node_state_shared(next);
            ghash_add(identifier_merge_hash, &merge_node, next);
        }

        *next_ptr = next;
    }

    return true;
}

/*
 * Append magic to existing trie
 */
void FileIdentifier::update_trie(IdentifierNode* start, IdentifierNode* append)
{
    unsigned int i;

    if ((!start )||(!append)||(start == append))
        return;

    if (start->offset == append->offset )
    {
        /* when we come here, make sure this tree is not shared
         * Update start trie using append information*/

        assert(start->state != ID_NODE_SHARED);

        if (append->type_id)
        {
            if (start->type_id)
                ParseWarning(WARN_RULES, "Duplicated type definition '%u -> %u at offset %u",
                    start->type_id, append->type_id, append->offset);
            start->type_id = append->type_id;
        }

        for (i = 0; i < MAX_BRANCH; i++)
        {
            if (update_next(start,&start->next[i], append->next[i]))
            {
                update_trie(start->next[i], append->next[i]);
            }
        }
    }
    else if (start->offset < append->offset )
    {
        for (i = 0; i < MAX_BRANCH; i++)
        {
            if (update_next(start,&start->next[i], append))
                update_trie(start->next[i], append);
        }
    }
}

void FileIdentifier::insert_file_rule(FileMagicRule& rule)
{
    IdentifierNode* node;

    if (!identifier_root)
    {
        identifier_root = (IdentifierNode*)calloc_mem(sizeof(*identifier_root));
        init_merge_hash();
    }

    if (rule.id >= FILE_ID_MAX)
    {
        ParseError("file type: rule id %u exceeds max id of %d", rule.id, FILE_ID_MAX-1);
        return;
    }

    if (file_magic_rules[rule.id].id > 0)
    {
        ParseError("file type: duplicated rule id %u defined", rule.id);
        return;
    }

    file_magic_rules[rule.id] = rule;

    node = create_trie_from_magic(rule, rule.id);
    update_trie(identifier_root, node);
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

FileMagicRule* FileIdentifier::get_rule_from_id(uint32_t id)
{
    if ((id < FILE_ID_MAX) && (file_magic_rules[id].id > 0))
    {
        return (&(file_magic_rules[id]));
    }
    else
        return nullptr;
}

void FileIdentifier::get_magic_rule_ids_from_type(const std::string& type,
    const std::string& version, snort::FileTypeBitSet& ids_set)
{
    ids_set.reset();

    for (uint32_t i = 0; i < FILE_ID_MAX; i++)
    {
        if (type == file_magic_rules[i].type)
        {
            if (version.empty() or version == file_magic_rules[i].version)
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
    FileMagicData magic;

    magic.content = "PDF";
    magic.offset = 0;

    FileMagicRule rule;

    rule.type = "pdf";
    rule.file_magics.push_back(magic);
    rule.id = 1;

    FileIdentifier rc;

    rc.insert_file_rule(rule);

    const char* data = "PDF";

    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) == 1);
}

TEST_CASE ("FileIdRuleUnknow", "[FileMagic]")
{
    FileMagicData magic;

    magic.content = "PDF";
    magic.offset = 0;

    FileMagicRule rule;

    rule.type = "pdf";
    rule.file_magics.push_back(magic);
    rule.id = 1;

    FileIdentifier rc;

    rc.insert_file_rule(rule);

    const char* data = "DDF";

    void* context = nullptr;

    CHECK((rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) ==
        SNORT_FILE_TYPE_UNKNOWN));
}

TEST_CASE ("FileIdRuleEXE", "[FileMagic]")
{
    FileMagicData magic;

    magic.content = "PDF";
    magic.offset = 0;

    FileMagicRule rule;

    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 1;

    FileIdentifier rc;
    rc.insert_file_rule(rule);

    magic.clear();
    magic.content = "EXE";
    magic.offset = 0;

    rule.clear();
    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 3;

    rc.insert_file_rule(rule);

    const char* data = "PDFooo";
    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) == 1);
}

TEST_CASE ("FileIdRulePDFEXE", "[FileMagic]")
{
    FileMagicData magic;

    magic.content = "PDF";
    magic.offset = 0;

    FileMagicRule rule;

    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 1;

    FileIdentifier rc;
    rc.insert_file_rule(rule);

    magic.clear();
    magic.content = "EXE";
    magic.offset = 3;

    rule.clear();
    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 3;

    rc.insert_file_rule(rule);

    const char* data = "PDFEXE";
    void* context = nullptr;

    // Match the last one
    CHECK((rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) == 3));
}

TEST_CASE ("FileIdRuleFirst", "[FileMagic]")
{
    FileMagicData magic;

    magic.content = "PDF";
    magic.offset = 0;

    FileMagicRule rule;

    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 1;

    FileIdentifier rc;
    rc.insert_file_rule(rule);

    magic.clear();
    magic.content = "EXE";
    magic.offset = 3;

    rule.clear();
    rule.type = "exe";
    rule.file_magics.push_back(magic);
    rule.id = 3;

    rc.insert_file_rule(rule);

    const char* data = "PDF";
    void* context = nullptr;

    CHECK(rc.find_file_type_id((const uint8_t*)data, strlen(data), 0, &context) == 1);
}
#endif

