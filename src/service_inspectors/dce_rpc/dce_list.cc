//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_list.h"

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

    list = (DCE2_List*)snort_calloc(sizeof(DCE2_List));

    list->type = type;
    list->compare = kc;
    list->data_free = df;
    list->key_free = kf;
    list->flags = flags;

    return list;
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
        return;


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
        return;   

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
        return;

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
 *      DCE2_RET__ERROR if a NULL list object was passed in.
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

    n = (DCE2_ListNode*)snort_calloc(sizeof(DCE2_ListNode));

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

        snort_free((void*)n);
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
    snort_free(list);
}

/********************************************************************
 * Function: DCE2_ListFind()
 *
 * Trys to find a node in the list using key passed in.  If list
 * is splayed, found node is moved to front of list.  The data
 * associated with the node is returned.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  void *
 *      Pointer to a key.
 *
 * Returns:
 *  void *
 *      If the key is found, the data associated with the node
 *          is returned.
 *      NULL is returned if the item cannot be found given the key.
 *
 ********************************************************************/
void* DCE2_ListFind(DCE2_List* list, void* key)
{
    DCE2_ListNode* n;

    if (list == nullptr)
        return nullptr;

    for (n = list->head; n != nullptr; n = n->next)
    {
        int comp = list->compare(key, n->key);
        if (comp == 0)
        {
            /* Found it, break out */
            break;
        }
        else if ((comp < 0) && (list->type == DCE2_LIST_TYPE__SORTED))
        {
            /* Don't look any more if the list is sorted */
            return nullptr;
        }
    }

    if (n != nullptr)
    {
        /* If list is splayed, move found node to front of list */
        if ((list->type == DCE2_LIST_TYPE__SPLAYED) &&
            (n != list->head))
        {
            n->prev->next = n->next;

            if (n->next != nullptr)
                n->next->prev = n->prev;
            else  /* it's the tail */
                list->tail = n->prev;

            n->prev = nullptr;
            n->next = list->head;
            list->head->prev = n;
            list->head = n;
        }

        return n->data;
    }

    return nullptr;
}

/********************************************************************
 * Function: DCE2_ListFindKey()
 *
 * Trys to find a node in the list using key passed in.  If list
 * is splayed, found node is moved to front of list.  Returns
 * whether or not the key is associated with a node in the list.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  void *
 *      Pointer to a key.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__SUCCESS if the key is found.
 *      DCE2_RET__ERROR if the key is not found.
 *
 ********************************************************************/
DCE2_Ret DCE2_ListFindKey(DCE2_List* list, void* key)
{
    DCE2_ListNode* n;

    if (list == nullptr)
        return DCE2_RET__ERROR;

    for (n = list->head; n != nullptr; n = n->next)
    {
        int comp = list->compare(key, n->key);
        if (comp == 0)
        {
            /* Found it, break out */
            break;
        }
        else if ((comp < 0) && (list->type == DCE2_LIST_TYPE__SORTED))
        {
            /* Don't look any more if the list is sorted */
            return DCE2_RET__ERROR;
        }
    }

    if (n != nullptr)
    {
        /* If list is splayed, move found node to front of list */
        if ((list->type == DCE2_LIST_TYPE__SPLAYED) &&
            (n != list->head))
        {
            n->prev->next = n->next;

            if (n->next != nullptr)
                n->next->prev = n->prev;
            else  /* it's the tail */
                list->tail = n->prev;

            n->prev = nullptr;
            n->next = list->head;
            list->head->prev = n;
            list->head = n;
        }

        return DCE2_RET__SUCCESS;
    }

    return DCE2_RET__ERROR;
}

/********************************************************************
 * Function: DCE2_ListRemove()
 *
 * Removes the node in the list with the specified key.  If
 * data free and key free functions were given with the creation
 * of the list object, they are called with the data and key
 * respectively.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *  void *
 *      Pointer to a key.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__ERROR if a node in the list with the specified
 *          key cannot be found or the list object passed in is NULL.
 *      DCE2_RET__SUCCESS if the node is successfully removed from
 *          the list.
 *
 ********************************************************************/
DCE2_Ret DCE2_ListRemove(DCE2_List* list, void* key)
{
    DCE2_ListNode* n;

    if (list == nullptr)
        return DCE2_RET__ERROR;

    for (n = list->head; n != nullptr; n = n->next)
    {
        int comp = list->compare(key, n->key);
        if (comp == 0)
        {
            /* Found it */
            break;
        }
        else if ((comp < 0) && (list->type == DCE2_LIST_TYPE__SORTED))
        {
            /* Won't find it after this since the list is sorted */
            return DCE2_RET__ERROR;
        }
    }

    if (n == nullptr)
        return DCE2_RET__ERROR;

    if (n == list->head)
        list->head = n->next;
    if (n == list->tail)
        list->tail = n->prev;
    if (n->prev != nullptr)
        n->prev->next = n->next;
    if (n->next != nullptr)
        n->next->prev = n->prev;

    if (list->key_free != nullptr)
        list->key_free(n->key);

    if (list->data_free != nullptr)
        list->data_free(n->data);

    snort_free((void*)n);

    list->num_nodes--;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_ListRemoveCurrent()
 *
 * Removes the current node pointed to in the list.  This is set
 * when a call to DCE2_ListFirst or DCE2_ListNext is called.  For
 * either of these if data is returned and the user want to remove
 * that data from the list, this function should be called.
 * Sets a next pointer, so a next call to DCE2_ListNext will point
 * to the node after the deleted one.
 *
 * Arguments:
 *  DCE2_List *
 *      A pointer to the list object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_ListRemoveCurrent(DCE2_List* list)
{
    if (list == nullptr)
        return;

    if (list->current == nullptr)
        return;

    list->next = list->current->next;
    list->prev = list->current->prev;

    if (list->current == list->head)
        list->head = list->current->next;
    if (list->current == list->tail)
        list->tail = list->current->prev;
    if (list->current->prev != nullptr)
        list->current->prev->next = list->current->next;
    if (list->current->next != nullptr)
        list->current->next->prev = list->current->prev;

    if (list->key_free != nullptr)
        list->key_free(list->current->key);

    if (list->data_free != nullptr)
        list->data_free(list->current->data);

    snort_free((void*)list->current);
    list->current = nullptr;

    list->num_nodes--;
}

/********************************************************************
 * Function: DCE2_QueueNew()
 *
 * Creates and initializes a new queue object.
 *
 * Arguments:
 *  DCE2_QueueDataFree
 *      An optional free function for the data inserted into
 *      the queue.  If NULL is passed in, the user will be
 *      responsible for freeing data left in the queue.
 *
 * Returns:
 *  DCE2_Queue *
 *      Pointer to a new queue object.
 *
 ********************************************************************/
DCE2_Queue* DCE2_QueueNew(DCE2_QueueDataFree df)
{
    DCE2_Queue* queue;

    queue = (DCE2_Queue*)snort_calloc(sizeof(DCE2_Queue));
    queue->data_free = df;

    return queue;
}

/********************************************************************
 * Function: DCE2_QueueEnqueue()
 *
 * Inserts data into the queue.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *  void *
 *      Pointer to the data to insert into the queue.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__ERROR if the queue object passed in is NULL.
 *      DCE2_RET__SUCCESS if the data is successfully added to
 *          the queue.
 *
 ********************************************************************/
DCE2_Ret DCE2_QueueEnqueue(DCE2_Queue* queue, void* data)
{
    DCE2_QueueNode* n;

    if (queue == nullptr)
        return DCE2_RET__ERROR;

    n = (DCE2_QueueNode*)snort_calloc(sizeof(DCE2_QueueNode));
    n->data = data;

    if (queue->tail == nullptr)
    {
        queue->head = queue->tail = n;
        n->next = nullptr;
    }
    else
    {
        queue->tail->next = n;
        n->prev = queue->tail;
        queue->tail = n;
    }

    queue->num_nodes++;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_QueueDequeue()
 *
 * Removes and returns the data in the first node in the queue.
 * Note that the user will have to free the data returned.  The
 * data free function only applies to data that is in the queue
 * when it is emptied or destroyed.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns:
 *  void *
 *      The data in the first node in the queue.
 *      NULL if there are no items in the queue or the queue object
 *          passed in is NULL.
 *
 ********************************************************************/
void* DCE2_QueueDequeue(DCE2_Queue* queue)
{
    DCE2_QueueNode* n;

    if (queue == nullptr)
        return nullptr;

    n = queue->head;

    if (n != nullptr)
    {
        void* data = n->data;

        if (queue->head == queue->tail)
        {
            queue->head = queue->tail = nullptr;
        }
        else
        {
            queue->head->next->prev = nullptr;
            queue->head = queue->head->next;
        }

        snort_free((void*)n);

        queue->num_nodes--;

        return data;
    }

    return nullptr;
}

/********************************************************************
 * Function: DCE2_QueueEmpty()
 *
 * Removes all of the nodes in a queue.  Does not delete the queue
 * object itself.  Calls data free function for data if it is
 * not NULL.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_QueueEmpty(DCE2_Queue* queue)
{
    DCE2_QueueNode* n;

    if (queue == nullptr)
        return;

    n = queue->head;

    while (n != nullptr)
    {
        DCE2_QueueNode* tmp = n->next;

        if (queue->data_free != nullptr)
            queue->data_free(n->data);

        snort_free((void*)n);
        n = tmp;
    }

    queue->head = queue->tail = queue->current = nullptr;
    queue->num_nodes = 0;
}

/********************************************************************
 * Function: DCE2_QueueDestroy()
 *
 * Destroys the queue object and all of the data associated with it.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_QueueDestroy(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return;

    DCE2_QueueEmpty(queue);
    snort_free((void*)queue);
}

/********************************************************************
 * Function: DCE2_QueueFirst()
 *
 * Returns a pointer to the data of the first node in the queue.
 * Sets a current pointer to the first node in the queue for
 * iterating over the queue.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns:
 *  void *
 *      The data in the first node in the queue.
 *      NULL if the queue object passed in is NULL, or there are
 *          no items in the queue.
 *
 ********************************************************************/
void* DCE2_QueueFirst(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return nullptr;

    queue->current = queue->head;
    queue->next = nullptr;

    if (queue->current != nullptr)
        return queue->current->data;

    return nullptr;
}

/********************************************************************
 * Function: DCE2_QueueNext()
 *
 * Increments the current pointer in the queue to the next node in
 * the queue and returns the data associated with it.  This in
 * combination with DCE2_QueueFirst is useful in a for loop to
 * iterate over the items in a queue.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns:
 *  void *
 *      The data in the next node in the queue.
 *      NULL if the queue object passed in is NULL, or we are at
 *          the end of the queue and there are no next nodes.
 *
 ********************************************************************/
void* DCE2_QueueNext(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return nullptr;

    if (queue->next != nullptr)
    {
        queue->current = queue->next;
        queue->next = nullptr;
        return queue->current->data;
    }
    else if (queue->current != nullptr)
    {
        queue->current = queue->current->next;
        if (queue->current != nullptr)
            return queue->current->data;
    }

    return nullptr;
}

/********************************************************************
 * Function: DCE2_QueueRemoveCurrent()
 *
 * Removes the current node pointed to in the queue.  This is set
 * when a call to DCE2_QueueFirst or DCE2_QueueNext is called.  For
 * either of these if data is returned and the user want to remove
 * that data from the queue, this function should be called.
 * Sets a next pointer, so a next call to DCE2_QueueNext will point
 * to the node after the deleted one.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the list object.
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_QueueRemoveCurrent(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return;

    if (queue->current == nullptr)
        return;

    queue->next = queue->current->next;
    queue->prev = queue->current->prev;

    if (queue->current == queue->head)
        queue->head = queue->next;
    if (queue->current == queue->tail)
        queue->tail = queue->prev;
    if (queue->current->prev != nullptr)
        queue->current->prev->next = queue->current->next;
    if (queue->current->next != nullptr)
        queue->current->next->prev = queue->current->prev;

    if (queue->data_free != nullptr)
        queue->data_free(queue->current->data);

    snort_free((void*)queue->current);
    queue->current = nullptr;

    queue->num_nodes--;
}

/********************************************************************
 * Function: DCE2_QueueLast()
 *
 * Returns a pointer to the data of the last node in the queue.
 * Sets a current pointer to the last node in the queue for
 * iterating over the queue backwards.
 *
 * Arguments:
 *  DCE2_Queue *
 *      A pointer to the queue object.
 *
 * Returns:
 *  void *
 *      The data in the last node in the queue.
 *      NULL if the queue object passed in is NULL, or there are
 *          no items in the queue.
 *
 ********************************************************************/
void* DCE2_QueueLast(DCE2_Queue* queue)
{
    if (queue == nullptr)
        return nullptr;

    queue->current = queue->tail;
    queue->prev = nullptr;

    if (queue->current != nullptr)
        return queue->current->data;

    return nullptr;
}

