//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2008-2013 Sourcefire, Inc.
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

/****************************************************************************
* Provides list, queue and stack data structures and methods for use
* with the preprocessor.
*
* 8/17/2008 - Initial implementation ... Todd Wease <twease@sourcefire.com>
*
****************************************************************************/

#ifndef DCE_LIST_H
#define DCE_LIST_H

#include "dce_utils.h"

#include "main/snort_types.h"

/********************************************************************
 * Enumerations
 ********************************************************************/
enum DCE2_ListType
{
    DCE2_LIST_TYPE__NORMAL = 0,  /* Don't do anything special */
    DCE2_LIST_TYPE__SORTED,      /* Sort list by key */
    DCE2_LIST_TYPE__SPLAYED      /* Move most recently accessed node to head */
};

enum DCE2_ListFlags
{
    DCE2_LIST_FLAG__NO_FLAG  = 0x00,   /* No flags */
    DCE2_LIST_FLAG__NO_DUPS  = 0x01,   /* No duplicate keys in list */
    DCE2_LIST_FLAG__INS_TAIL = 0x02    /* Insert at tail - default is to insert at head */
};

/********************************************************************
 * Callbacks
 ********************************************************************/
typedef void (* DCE2_ListDataFree)(void*);
typedef void (* DCE2_ListKeyFree)(void*);
typedef int (* DCE2_ListKeyCompare)(const void*, const void*);

/********************************************************************
 * Structures
 ********************************************************************/
struct DCE2_ListNode
{
    void* key;
    void* data;
    struct DCE2_ListNode* prev;
    struct DCE2_ListNode* next;
};

struct DCE2_List
{
    DCE2_ListType type;
    uint32_t num_nodes;
    DCE2_ListKeyCompare compare;
    DCE2_ListDataFree data_free;
    DCE2_ListKeyFree key_free;
    int flags;
    struct DCE2_ListNode* head;
    struct DCE2_ListNode* tail;
    struct DCE2_ListNode* current;
    struct DCE2_ListNode* next;
    struct DCE2_ListNode* prev;
};

struct DCE2_QueueNode
{
    void* data;
    DCE2_QueueNode* prev;
    DCE2_QueueNode* next;
};

typedef DCE2_ListDataFree DCE2_QueueDataFree;

struct DCE2_Queue
{
    uint32_t num_nodes;
    DCE2_QueueDataFree data_free;
    DCE2_QueueNode* current;
    DCE2_QueueNode* head;
    DCE2_QueueNode* tail;
    DCE2_QueueNode* next;
    DCE2_QueueNode* prev;
};

/********************************************************************
 * Public function prototypes
 ********************************************************************/
DCE2_List* DCE2_ListNew(DCE2_ListType, DCE2_ListKeyCompare, DCE2_ListDataFree,
    DCE2_ListKeyFree, int);
DCE2_Ret DCE2_ListInsert(DCE2_List*, void*, void*);
void* DCE2_ListFirst(DCE2_List*);
void* DCE2_ListNext(DCE2_List*);
inline bool DCE2_ListIsEmpty(DCE2_List*);
void DCE2_ListEmpty(DCE2_List*);
void DCE2_ListDestroy(DCE2_List*);
void* DCE2_ListFind(DCE2_List*, void*);
DCE2_Ret DCE2_ListFindKey(DCE2_List*, void*);
DCE2_Ret DCE2_ListRemove(DCE2_List*, void*);
void DCE2_ListRemoveCurrent(DCE2_List*);

DCE2_Queue* DCE2_QueueNew(DCE2_QueueDataFree);
DCE2_Ret DCE2_QueueEnqueue(DCE2_Queue*, void*);
void* DCE2_QueueDequeue(DCE2_Queue*);
static inline bool DCE2_QueueIsEmpty(DCE2_Queue*);
void DCE2_QueueEmpty(DCE2_Queue*);
void* DCE2_QueueFirst(DCE2_Queue*);
void* DCE2_QueueNext(DCE2_Queue*);
void DCE2_QueueDestroy(DCE2_Queue*);
void DCE2_QueueRemoveCurrent(DCE2_Queue*);
void* DCE2_QueueLast(DCE2_Queue*);

/********************************************************************
 * Function: DCE2_ListIsEmpty()
 *
 * Determines whether or not the list has any items in it
 * currently.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns:
 *  bool
 *      true if the list has zero nodes in it or the list object
 *          passed in is NULL.
 *      false if the list has one or more nodes in it.
 *
 ********************************************************************/
inline bool DCE2_ListIsEmpty(DCE2_List* list)
{
    if (list == nullptr)
        return true;
    if (list->num_nodes == 0)
        return true;
    return false;
}

/********************************************************************
 * Function: DCE2_QueueIsEmpty()
 *
 * Determines whether or not the queue has any items in it
 * currently.
 *
 ********************************************************************/
inline bool DCE2_QueueIsEmpty(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return true;
    if (queue->num_nodes == 0)
        return true;
    return false;
}

#endif

