/*
 **
 **
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 **  Copyright (C) 2012-2013 Sourcefire, Inc.
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  5.25.2012 - Initial Source Code. Hcao
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
#include "mstring.h"
#include "sfghash.h"
#include "file_config.h"

static THREAD_LOCAL_TBD uint32_t memory_used = 0; /*Track memory usage*/

static THREAD_LOCAL_TBD SFGHASH *identifier_merge_hash = NULL;

typedef struct _IdentifierSharedNode
{
    IdentifierNode *shared_node;  /*the node that is shared*/
    IdentifierNode *append_node;  /*the node that is added*/
} IdentifierSharedNode;

static THREAD_LOCAL_TBD IdentifierMemoryBlock *id_memory_root = NULL;
static THREAD_LOCAL_TBD IdentifierMemoryBlock *id_memory_current = NULL;


static void identifierMergeHashFree(void)
{
    if (identifier_merge_hash != NULL)
    {
        sfghash_delete(identifier_merge_hash);
        identifier_merge_hash = NULL;
    }
}

static void identifierMergeHashInit(void)
{
    if (identifier_merge_hash != NULL)
        identifierMergeHashFree();

    identifier_merge_hash = sfghash_new(1000, sizeof(IdentifierSharedNode), 0, NULL);
    if (identifier_merge_hash == NULL)
    {
        FatalError("%s(%d) Could not create identifier merge hash.\n",
                __FILE__, __LINE__);
    }

}

static inline void *calloc_mem(size_t size)
{
    void *ret;
    IdentifierMemoryBlock *imb;
    ret = SnortAlloc(size);
    memory_used += size;
    /*For memory management*/
    size = sizeof(*imb);
    imb = (IdentifierMemoryBlock *)SnortAlloc(size);
    imb->mem_block = ret;
    if (!id_memory_root)
    {
        id_memory_root = imb;
    }
    else
    {
        id_memory_current->next = imb;
    }
    id_memory_current = imb;
    memory_used += size;
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"calloc:  %p (%d).\n", ret, size););
    return ret;
}

static void  set_node_state_shared(IdentifierNode *start)
{
    int i;

    if (!start)
        return;

    if (start->state == ID_NODE_SHARED)
        return;

    if (start->state == ID_NODE_USED)
       start->state = ID_NODE_SHARED;
    else
    {
       start->state = ID_NODE_USED;
    }

    for(i = 0; i < MAX_BRANCH; i++)
    {
        set_node_state_shared(start->next[i]);
    }
}

/*Clone a trie*/
static IdentifierNode *clone_node(IdentifierNode *start)
{
    int index;
    IdentifierNode *node;
    if (!start)
        return NULL;

    node = (IdentifierNode*)calloc_mem(sizeof(*node));

    node->offset = start->offset;
    node->type_id = start->type_id;

    for(index = 0; index < MAX_BRANCH; index++)
    {
        if (start->next[index])
        {
            node->next[index] = start->next[index];
        }

    }
    return node;
}

static void verify_magic_offset(MagicData *parent, MagicData *current)
{
    if ((parent) && (parent->content_len + parent->offset > current->offset))
    {
        ParseError(" Magic content at offset %d overlaps with offset %d.",
                parent->offset, current->offset);

    }

    if ((current->next) && (current->content_len + current->offset > current->next->offset))
    {
        ParseError(" Magic content at offset %d overlaps with offset %d.",
                current->offset, current->next->offset);

    }
}

/* Add a new node to the sorted magic list
 */
static void add_to_sorted_magic(MagicData **head, MagicData *md )
{
    MagicData *current = *head;

    /*Avoid adding the same magic*/
    if (!md || (current == md))
        return;

    if (md->offset < current->offset)
    {
        /*current becomes new head*/
        md->next = current;
        *head = md;
        verify_magic_offset(NULL, md);
        return;
    }

    /*Find the parent for the new magic*/
    while (current)
    {
        MagicData *next = current->next;
        if ((!next) || (md->offset < next->offset))
        {
            /*current is the parent*/
            current->next = md;
            md->next = next;
            verify_magic_offset(current, md);
            return;
        }
        current = next;
    }

}

/* Content magics are sorted based on offset, this
 * will help compile the file magic trio
 */
static void sort_magics(MagicData **head)
{
    MagicData *current = *head;

    /*Add one magic at a time to sorted magics*/
    while (current)
    {
        MagicData *next = current->next;
        current->next = NULL;
        add_to_sorted_magic(head, current);
        current = next;
    }
}

/*Create a trie for the magic*/
static inline IdentifierNode *create_trie_from_magic(MagicData **head, uint32_t type_id)
{
    int i;
    IdentifierNode *current;
    IdentifierNode *root = NULL;
    MagicData *magic;

    if (!head || !(*head)||(0 == (*head)->content_len) || !type_id)
        return NULL;

    sort_magics(head);
    magic = *head;

    current =  (IdentifierNode*)calloc_mem(sizeof(*current));
    current->state = ID_NODE_NEW;
    root = current;

    while (magic)
    {
        current->offset = magic->offset;
        for(i = 0; i < magic->content_len; i++)
        {
            IdentifierNode *node = (IdentifierNode*)calloc_mem(sizeof(*node));
            node->offset = magic->offset + i + 1;
            node->state = ID_NODE_NEW;
            current->next[magic->content[i]] = node;
            current = node;
        }
        magic = magic->next;
    }

    /*Last node has type name*/
    current->type_id = type_id;
    DEBUG_WRAP( print_identifiers(root););
    return root;

}

/*This function examines whether to update the trie based on shared state*/

static inline bool updateNext(IdentifierNode *start,IdentifierNode **next_ptr, IdentifierNode *append)
{

    IdentifierNode *next = (*next_ptr);
    IdentifierSharedNode sharedIdentifier;
    IdentifierNode *result;

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
    else if ((result = (IdentifierNode*)sfghash_find(identifier_merge_hash, &sharedIdentifier))) /*the same pointer has been processed, reuse it*/
    {
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
            IdentifierNode *node = (IdentifierNode*)calloc_mem(sizeof(*node));
            sharedIdentifier.shared_node = next;
            sharedIdentifier.append_node = append;
            node->offset = append->offset;

            for(index = 0; index < MAX_BRANCH; index++)
            {
                node->next[index] = next;
            }

            set_node_state_shared(next);
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Add new node after next %p.\n", next););
            next = node;
            sfghash_add(identifier_merge_hash, &sharedIdentifier, next);
        }
        else if (next->state == ID_NODE_SHARED)
        {
            /*shared, need to clone one*/
            IdentifierNode *current_next = next;
            sharedIdentifier.shared_node = current_next;
            sharedIdentifier.append_node = append;
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Clone node on %p.\n", current_next););
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Before clone: %d.\n",  memory_usage_identifiers()););
            next = clone_node(current_next);
            set_node_state_shared(next);
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:Cloned node on %p.\n", next););
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"MEM:After clone: %d.\n", memory_usage_identifiers()););
            sfghash_add(identifier_merge_hash, &sharedIdentifier, next);
        }

        *next_ptr = next;
    }

    return true;
}

/*
 * Append magic to existing trie
 *
 */
static void update_trie(IdentifierNode *start, IdentifierNode *append)
{
    int i;

    if ((!start )||(!append)||(start == append))
        return ;


    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Working on %p -> %p at offset %d.\n",
            start, append, append->offset););

    if (start->offset == append->offset )
    {
        /* when we come here, make sure this tree is not shared
         * Update start trie using append information*/

        if (start->state == ID_NODE_SHARED)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Something is wrong ..."););
        }

        if (append->type_id)
        {
            if(start->type_id)
                LogMessage("Duplicated type definition '%d -> %d at offset %d.\n",
                        start->type_id, append->type_id, append->offset);
            start->type_id = append->type_id;
        }

        for(i = 0; i < MAX_BRANCH; i++)
        {
            if (updateNext(start,&start->next[i], append->next[i]))
            {
                update_trie(start->next[i], append->next[i]);
            }
        }
    }
    else  if (start->offset < append->offset )
    {

        for(i = 0; i < MAX_BRANCH; i++)
        {
            if (updateNext(start,&start->next[i], append))
                update_trie(start->next[i], append);
        }
    }
    else /*This is impossible*/
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Something is wrong ....."););
    }
    return;
}


void insert_file_rule(RuleInfo *rule, void *conf)
{
    IdentifierNode *node;
    FileConfig *file_config = NULL;

    file_config = (FileConfig *) conf;

    if (!file_config->identifier_root)
    {
        init_file_identifers();
        file_config->identifier_root = (IdentifierNode*)calloc_mem(sizeof(*file_config->identifier_root));
        file_config->id_memory_root = id_memory_root;
        identifierMergeHashInit();
    }

    node = create_trie_from_magic(&(rule->magics), rule->id);

    update_trie(file_config->identifier_root, node);
    DEBUG_WRAP(test_find_file_type(file_config););
}


void init_file_identifers(void)
{
    memory_used = 0;
    id_memory_root = NULL;
    id_memory_current = NULL;
}


uint32_t memory_usage_identifiers(void)
{
    return memory_used;
}

/*
 * This is the main function to find file type
 * Find file type is to traverse the tries.
 * Context is saved to continue file type identification as data becomes available
 */
uint32_t find_file_type_id(uint8_t *buf, int len, FileContext *context)
{
    FileConfig *file_config;
    IdentifierNode* current;
    uint64_t end;

    if ((!context)||(!buf)||(len <= 0))
        return 0;

    file_config = (FileConfig *)context->file_config;

    if (!(context->file_type_context))
        context->file_type_context = (void *)(file_config->identifier_root);

    current = (IdentifierNode*) context->file_type_context;

    end = context->processed_bytes + len;

    while(current && (current->offset < end) && len && (current->offset >= context->processed_bytes))
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


void free_file_identifiers(void *conf)
{
    IdentifierMemoryBlock *id_memory_next;
    FileConfig *file_config = (FileConfig *)conf;

    if (!file_config)
        return;
    /*Release memory used for identifiers*/
    id_memory_current = file_config->id_memory_root;
    while (id_memory_current)
    {
        id_memory_next = id_memory_current->next;
        free(id_memory_current->mem_block);
        free(id_memory_current);
        id_memory_current = id_memory_next;
    }

    file_config->id_memory_root = NULL;
    identifierMergeHashFree();
}

void print_identifiers(IdentifierNode* current)
{
#ifdef DEBUG_MSGS
    int i;

    if ( !(DEBUG_FILE & GetDebugLevel()) )
        return;

    printf("Working on pointer %p, offset:%d\n", (void *) current, current->offset);

    for (i = 0; i < MAX_BRANCH; i++)
    {
        if (current->next[i])
        {
            printf("Magic number: %x ", i);
            print_identifiers(current->next[i]);
        }

    }
    if (current->type_id)
    {
        printf("Type: %d\n", current->type_id);
    }
#else
    UNUSED(current);
#endif
}

char *test_find_file_type(void *conf)
{
#ifdef DEBUG_MSGS
    if ( !(DEBUG_FILE & GetDebugLevel()) )
        return NULL;

    uint8_t str[100] = {0x4d, 0x5a, 0x46, 0x38, 0x66, 0x72, 0x65, 0x65, 0};
    unsigned int i;
    uint32_t type_id;

    FileContext *context = (FileContext*)SnortAlloc(sizeof (*context));

    static const char *file_type = "MSEXE";

    printf("Check string:");

    for (i = 0; i < strlen((char*)str); i++)
    {
        printf(" %x", str[i]);
    }
    printf("\n");

    context->file_config = conf;

    type_id = find_file_type_id(str, strlen((char *)str), context);
    if (SNORT_FILE_TYPE_UNKNOWN == type_id)
    {
        printf("File type is unknown\n");
    }
    else if (SNORT_FILE_TYPE_CONTINUE != type_id)
        printf("File type is: %s (%d)\n",file_info_from_ID(conf, type_id), type_id);

    free(context);
    return ((char *)file_type);
#else
    UNUSED(conf);
    return NULL;
#endif
}

