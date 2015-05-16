//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
** Author(s):  Hui Cao <hcao@sourcefire.com>
**
** NOTES
** 5.25.2012 - Initial Source Code. Hcao
*/

#include "file_identifier.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "snort_types.h"
#include "snort_debug.h"
#include "parser.h"
#include "util.h"
#include <algorithm>


typedef struct _IdentifierSharedNode
{
    IdentifierNode* shared_node;  /*the node that is shared*/
    IdentifierNode* append_node;  /*the node that is added*/
} IdentifierSharedNode;

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
    file_magics.clear();
}

void FileIdenfifier::identifierMergeHashInit()
{
    identifier_merge_hash = sfghash_new(1000, sizeof(IdentifierSharedNode), 0, NULL);
    if (identifier_merge_hash == NULL)
    {
        FatalError("%s(%d) Could not create identifier merge hash.\n",
            __FILE__, __LINE__);
    }
}

FileIdenfifier::~FileIdenfifier()
{
    /*Release memory used for identifiers*/
    for (IDMemoryBlocks::iterator idMem = idMemoryBlocks.begin();
            idMem != idMemoryBlocks.end(); idMem++)
    {
        free(idMem->mem);
    }

    if (identifier_merge_hash != NULL)
    {
        sfghash_delete(identifier_merge_hash);
    }
}

void* FileIdenfifier::calloc_mem(size_t size)
{
    void* ret;
    IDMemoryBlock memblock;
    ret = SnortAlloc(size);
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"calloc_mem: %p. size: %d\n", ret, size); );
    memory_used += size;
    /*For memory management*/
    memblock.mem = ret;
    idMemoryBlocks.push_back(memblock);
    return ret;
}

void FileIdenfifier::set_node_state_shared(IdentifierNode* start)
{
    int i;

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
IdentifierNode* FileIdenfifier::clone_node(IdentifierNode* start)
{
    int index;
    IdentifierNode* node;
    if (!start)
        return NULL;

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

void FileIdenfifier::verify_magic_offset(FileMagicData* parent, FileMagicData* current)
{
    if ((parent) && (parent->content.size() + parent->offset > current->offset))
    {
        ParseError("magic content at offset %d overlaps with offset %d.",
            parent->offset, current->offset);
        return;
    }
}

/*Create a trie for the magic*/
IdentifierNode* FileIdenfifier::create_trie_from_magic(FileMagicRule& rule, uint32_t type_id)
{
    IdentifierNode* current;
    IdentifierNode* root = NULL;

    if (!rule.file_magics.size() || !type_id)
        return NULL;

    /* Content magics are sorted based on offset, this
     * will help compile the file magic trio
     */
    std::sort(rule.file_magics.begin(),rule.file_magics.end());

    current =  (IdentifierNode*)calloc_mem(sizeof(*current));
    current->state = ID_NODE_NEW;
    root = current;

    for(FileMagics::iterator magic = rule.file_magics.begin();
            magic !=rule.file_magics.end(); magic++)
    {
        unsigned int i;
        current->offset = magic->offset;
        for (i = 0; i < magic->content.size(); i++)
        {
            IdentifierNode* node = (IdentifierNode*)calloc_mem(sizeof(*node));
            uint8_t index = magic->content[i];
            node->offset = magic->offset + i + 1;
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

bool FileIdenfifier::updateNext(IdentifierNode* start,IdentifierNode** next_ptr,
    IdentifierNode* append)
{
    IdentifierNode* next = (*next_ptr);
    IdentifierSharedNode sharedIdentifier;
    IdentifierNode* result;

    if (!append || (next == append))
        return false;

    sharedIdentifier.append_node = append;
    sharedIdentifier.shared_node = next;
    if (!next)
    {
        /*reuse the append*/
        *next_ptr = append;
        set_node_state_shared(append);
        return false;
    }
    else if ((result = (IdentifierNode*)sfghash_find(identifier_merge_hash, &sharedIdentifier)))
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
            int index;
            IdentifierNode* node = (IdentifierNode*)calloc_mem(sizeof(*node));
            sharedIdentifier.shared_node = next;
            sharedIdentifier.append_node = append;
            node->offset = append->offset;

            for (index = 0; index < MAX_BRANCH; index++)
            {
                node->next[index] = next;
            }

            set_node_state_shared(next);
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Add new node after next %p.\n", next); );
            next = node;
            sfghash_add(identifier_merge_hash, &sharedIdentifier, next);
        }
        else if (next->state == ID_NODE_SHARED)
        {
            /*shared, need to clone one*/
            IdentifierNode* current_next = next;
            sharedIdentifier.shared_node = current_next;
            sharedIdentifier.append_node = append;
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Clone node on %p.\n", current_next); );
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Before clone: %d.\n",
                memory_usage()); );
            next = clone_node(current_next);
            set_node_state_shared(next);
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Cloned node on %p.\n", next); );
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:After clone: %d.\n",
                memory_usage()); );
            sfghash_add(identifier_merge_hash, &sharedIdentifier, next);
        }

        *next_ptr = next;
    }

    return true;
}

/*
 * Append magic to existing trie
 */
void FileIdenfifier::update_trie(IdentifierNode* start, IdentifierNode* append)
{
    int i;

    if ((!start )||(!append)||(start == append))
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Working on %p -> %p at offset %d.\n",
        start, append, append->offset); );

    if (start->offset == append->offset )
    {
        /* when we come here, make sure this tree is not shared
         * Update start trie using append information*/

        if (start->state == ID_NODE_SHARED)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Something is wrong ..."); );
        }

        if (append->type_id)
        {
            if (start->type_id)
                ParseWarning(WARN_RULES, "Duplicated type definition '%d -> %d at offset %d.\n",
                    start->type_id, append->type_id, append->offset);
            start->type_id = append->type_id;
        }

        for (i = 0; i < MAX_BRANCH; i++)
        {
            if (updateNext(start,&start->next[i], append->next[i]))
            {
                update_trie(start->next[i], append->next[i]);
            }
        }
    }
    else if (start->offset < append->offset )
    {
        for (i = 0; i < MAX_BRANCH; i++)
        {
            if (updateNext(start,&start->next[i], append))
                update_trie(start->next[i], append);
        }
    }
    else /*This is impossible*/
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Something is wrong ....."); );
    }
}

void FileIdenfifier::insert_file_rule(FileMagicRule& rule)
{
    IdentifierNode* node;

    if (!identifier_root)
    {
        identifier_root = (IdentifierNode *)calloc_mem(sizeof(*identifier_root));
        identifierMergeHashInit();
    }

    if (rule.id > FILE_ID_MAX)
    {
        ParseError("file type: rule id %d larger than %d", rule.id, FILE_ID_MAX);
        return;
    }

    if (file_magic_rules[rule.id].id > 0)
    {
        ParseError("file type: duplicated rule id %d defined", rule.id);
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
uint32_t FileIdenfifier::find_file_type_id(uint8_t* buf, int len, FileContext* context)
{
    IdentifierNode* current;
    uint64_t end;

    if ((!context)||(!buf)||(len <= 0))
        return 0;

    if (!(context->file_type_context))
        context->file_type_context = (void*)(identifier_root);

    current = (IdentifierNode*)context->file_type_context;

    end = context->processed_bytes + len;

    while (current && (current->offset < end) && len && (current->offset >=
        context->processed_bytes))
    {
        /*Found file id, save and continue*/
        if (current->type_id)
        {
            context->file_type_id = current->type_id;
        }

        /*Move to the next level*/
        current = current->next[buf[current->offset - context->processed_bytes ]];
        len--;
    }

    /*No more checks are needed*/
    if (!current)
    {
        /*Found file type in current buffer, return*/
        if (context->file_type_id)
            return context->file_type_id;
        else
            return SNORT_FILE_TYPE_UNKNOWN;
    }
    else if ((context->file_type_id) && (current->state == ID_NODE_SHARED))
        return context->file_type_id;
    else if (current->offset >= end)
    {
        /*No file type found, save current state and continue*/
        context->file_type_context = current;
        return SNORT_FILE_TYPE_CONTINUE;
    }
    else
        return SNORT_FILE_TYPE_UNKNOWN;
}

FileMagicRule*  FileIdenfifier::get_rule_from_id(uint32_t id)
{
    if ((id < FILE_ID_MAX) && (file_magic_rules[id].id > 0))
    {
        return (&(file_magic_rules[id]));
    }
    else
        return NULL;
}
