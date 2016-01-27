//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "dce2_list.h"
#include "dce2_utils.h"

#include "log/messages.h"
#include "utils/util.h"

/********************************************************************
 * Private function prototyes
 ********************************************************************/
static void DCE2_ListInsertTail(DCE2_List*, DCE2_ListNode*);
static void DCE2_ListInsertHead(DCE2_List*, DCE2_ListNode*);
static void DCE2_ListInsertBefore(DCE2_List*, DCE2_ListNode*, DCE2_ListNode*);

/********************************************************************
 * Function: DCE2_ListNew()
 *
 * Creates and returns a new list object.
 *
 * Arguments:
 *  DCE2_ListType
 *      The type of list this should be - sorted, splayed, etc.
 *  DCE2_ListKeyCompare
 *      The comparison function to call when comparing two keys
 *      for inserting, finding, etc.
 *  DCE2_ListDataFree
 *      An optional function to call to free data in the list.
 *      If NULL is passed in, the user will have to manually free
 *      the data.
 *  DCE2_ListKeyFree
 *      An optional function to call to free keys used in the list.
 *      If NULL is passed in, the user will have to manually free
 *      the keys.
 *  int
 *      Flags that affect processing of the list.
 *      See DCE2_ListFlags for possible combinations.
 *
 * Returns:
 *  DCE2_List *
 *      Pointer to a valid list object.
 *      NULL if an error occurs.
 *
 ********************************************************************/
DCE2_List* DCE2_ListNew(DCE2_ListType type, DCE2_ListKeyCompare kc,
    DCE2_ListDataFree df, DCE2_ListKeyFree kf,
    int flags)
{
    DCE2_List* list;

    /* Must have a key compare function */
    if (kc == nullptr)
        return nullptr;

    list = (DCE2_List*)SnortAlloc(sizeof(DCE2_List));
    if (list == nullptr)
        return nullptr;

    list->type = type;
    list->compare = kc;
    list->data_free = df;
    list->key_free = kf;
    list->flags = flags;

    return list;
}
/********************************************************************
 * Function: DCE2_ListInsert()
 *
 * Adds a new node to the list with the key and data supplied.
 * If no duplicates are allowed in the key is searched for first
 * to see if a node is already present in the list.  If sorted,
 * the node is inserted into the list based on the key compare
 * function associated with the list object.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  void *
 *      Pointer to a key to associate with data.
 *  void *
 *      Pointer to the data to insert into the list.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__DUPLICATE if an entry with the key is already
 *          in the list and no duplicates are allowed.
 *      DCE2_RET__SUCCESS if a new node with key and data is
 *          successfully inserted into the list.
 *      DCE2_RET__ERROR if memory cannot be allocated for the
 *          new node or a NULL list object was passed in.
 *
 ********************************************************************/
DCE2_Ret DCE2_ListInsert(DCE2_List* list, void* key, void* data)
{
    DCE2_ListNode* n;
    DCE2_ListNode* last = nullptr;
    int dup_check = 0;

    if (list == nullptr)
        return DCE2_RET__ERROR;

    if (list->flags & DCE2_LIST_FLAG__NO_DUPS)
    {
        for (last = list->head; last != nullptr; last = last->next)
        {
            int comp = list->compare(key, last->key);
            if (comp == 0)
            {
                /* It's already in the list */
                return DCE2_RET__DUPLICATE;
            }
            else if ((comp < 0) && (list->type == DCE2_LIST_TYPE__SORTED))
            {
                /* Break out here so as to insert after this node since
                 * the list is sorted */
                break;
            }
        }

        dup_check = 1;
    }

    n = (DCE2_ListNode*)SnortAlloc(sizeof(DCE2_ListNode));
    if (n == nullptr)
        return DCE2_RET__ERROR;

    n->key = key;
    n->data = data;

    if ((list->type != DCE2_LIST_TYPE__SORTED) ||
        (list->head == nullptr))
    {
        if (list->flags & DCE2_LIST_FLAG__INS_TAIL)
            DCE2_ListInsertTail(list, n);
        else
            DCE2_ListInsertHead(list, n);
    }
    else if (dup_check)  /* and the list is sorted */
    {
        if (last == nullptr)
            DCE2_ListInsertTail(list, n);
        else
            DCE2_ListInsertBefore(list, n, last);
    }
    else
    {
        DCE2_ListNode* tmp;

        for (tmp = list->head; tmp != nullptr; tmp = tmp->next)
        {
            if (list->compare(key, tmp->key) <= 0)
                break;
        }

        if (tmp == nullptr)
            DCE2_ListInsertTail(list, n);
        else if (tmp == list->head)
            DCE2_ListInsertHead(list, n);
        else
            DCE2_ListInsertBefore(list, n, tmp);
    }

    return DCE2_RET__SUCCESS;
}


/********************************************************************
 * Function: DCE2_ListFirst()
 *
 * Returns a pointer to the data of the first node in the list.
 * Sets a current pointer to the first node in the list for
 * iterating over the list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns:
 *  void *
 *      The data in the first node in the list.
 *      NULL if the list object passed in is NULL, or there are
 *          no items in the list.
 *
 ********************************************************************/
void* DCE2_ListFirst(DCE2_List* list)
{
    if (list == nullptr)
        return nullptr;

    list->current = list->head;
    list->next = nullptr;

    if (list->current != nullptr)
        return list->current->data;

    return nullptr;
}

/********************************************************************
 * Function: DCE2_ListNext()
 *
 * Increments the current pointer in the list to the next node in
 * the list and returns the data associated with it.  This in
 * combination with DCE2_ListFirst is useful in a for loop to
 * iterate over the items in a list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns:
 *  void *
 *      The data in the next node in the list.
 *      NULL if the list object passed in is NULL, or we are at
 *          the end of the list and there are no next nodes.
 *
 ********************************************************************/
void* DCE2_ListNext(DCE2_List* list)
{
    if (list == nullptr)
        return nullptr;

    if (list->next != nullptr)
    {
        list->current = list->next;
        list->next = nullptr;
        return list->current->data;
    }
    else if (list->current != nullptr)
    {
        list->current = list->current->next;
        if (list->current != nullptr)
            return list->current->data;
    }

    return nullptr;
}


/********************************************************************
 * Function: DCE2_ListEmpty()
 *
 * Removes all of the nodes in a list.  Does not delete the list
 * object itself.  Calls data free and key free functions for
 * data and key if they are not NULL.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_ListEmpty(DCE2_List* list)
{
    DCE2_ListNode* n;

    if (list == nullptr)
        return;

    n = list->head;

    while (n != nullptr)
    {
        DCE2_ListNode* tmp = n->next;

        if (list->data_free != nullptr)
            list->data_free(n->data);

        if (list->key_free != nullptr)
            list->key_free(n->key);

        free((void*)n);
        n = tmp;
    }

    list->head = list->tail = list->current = nullptr;
    list->num_nodes = 0;
}

/********************************************************************
 * Function: DCE2_ListDestroy()
 *
 * Destroys the list object and all of the data associated with it.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_ListDestroy(DCE2_List* list)
{
    if (list == nullptr)
        return;

    DCE2_ListEmpty(list);
    free(list);
}

/********************************************************************
 * Function: DCE2_ListInsertTail()
 *
 * Private function for inserting a node at the end of the list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  DCE2_ListNode *
 *      A pointer to the list node to insert.
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_ListInsertTail(DCE2_List* list, DCE2_ListNode* n)
{
    if ((list == nullptr) || (n == nullptr))
    {
        ErrorMessage("%s(%d) List and/or list node passed in was nullptr",
            __FILE__, __LINE__);

        return;
    }

    if (list->tail == nullptr)
    {
        list->tail = list->head = n;
        n->prev = n->next = nullptr;
    }
    else
    {
        n->prev = list->tail;
        n->next = nullptr;
        list->tail->next = n;
        list->tail = n;
    }

    list->num_nodes++;
}

/********************************************************************
 * Function: DCE2_ListInsertHead()
 *
 * Private function for inserting a node at the front of the list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  DCE2_ListNode *
 *      A pointer to the list node to insert.
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_ListInsertHead(DCE2_List* list, DCE2_ListNode* n)
{
    if ((list == nullptr) || (n == nullptr))
    {
        ErrorMessage("%s(%d) List and/or list node passed in was NULL",
            __FILE__, __LINE__);

        return;
    }

    if (list->head == nullptr)
    {
        list->head = list->tail = n;
        n->prev = n->next = nullptr;
    }
    else
    {
        n->prev = nullptr;
        n->next = list->head;
        list->head->prev = n;
        list->head = n;
    }

    list->num_nodes++;
}

/********************************************************************
 * Function: DCE2_ListInsertBefore()
 *
 * Private function for inserting a node before a given node in
 * the list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  DCE2_ListNode *
 *      A pointer to the list node to insert.
 *  DCE2_ListNode *
 *      A pointer to the list node to insert this node before.
 *
 * Returns: None
 *
 ********************************************************************/
static void DCE2_ListInsertBefore(DCE2_List* list, DCE2_ListNode* insert, DCE2_ListNode* front)
{
    if ((list == nullptr) || (insert == nullptr) || (front == nullptr))
    {
        ErrorMessage("%s(%d) List, insert node and/or front node passed in "
            "was NULL", __FILE__, __LINE__);
        return;
    }

    if (front == list->head)
    {
        DCE2_ListInsertHead(list, insert);
    }
    else
    {
        insert->prev = front->prev;
        insert->next = front;
        front->prev->next = insert;
        front->prev = insert;

        list->num_nodes++;
    }
}
