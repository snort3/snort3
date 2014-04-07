/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "sf_sdlist.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

/* Function: int sf_sdlist_init(sfSDlist *list, void (*destroy)(void *data))
 *
 * Purpose: initialize an dlist
 * Args: list - pointer to a dlist structure
 *       destroy - free function ( use NULL for none )
 * Returns:
 *     1 on failure , 0 on success
 */

int sf_sdlist_init(sfSDList *list, void (*destroy)(void *data))
{
    list->destroy = destroy;
    list->size = 0;
    list->head = NULL;
    list->tail = NULL;

    return 0;
}


/* Function: int sf_sdlist_delete(sfSDList *list)
 *
 * Purpose: delete every item of a list
 * Args: list -> pointer to a dlist structure
 *
 * Returns: 1 on failure , 0 on success
 */
int sf_sdlist_delete(sfSDList *list)
{
    while(list->head != NULL)
    {
        sf_sdlist_remove_next(list, NULL);
    }

    return 0;
}

/*
 * Function: int sf_sdlist_insert_next(sfSDList *list, SDListItem *item,
 *                                    void *data, SDListItem *container)
 *
 * Purpose: insert data in container in the list after the item
 * Args: list - dlist structure
 *       curr - current position in list structure
 *       data - current data to insert
 *       container - place to put the data
 *
 * Returns: 0 on sucess,  1 on failure
 */
int sf_sdlist_insert_next(sfSDList *list, SDListItem *curr, void *data,
                          SDListItem *container)
{
    SDListItem *item = container;

    if(!item) return -1;

    item->data = data;

    if(curr == NULL)
    {
        /* We are inserting at the head of the list HEAD */

        if(list->size == 0)
        {
            list->tail = item;
        }

        item->next = list->head;
        list->head = item;
    }
    else
    {
        if(curr->next == NULL)
        {
            /* TAIL */
            list->tail = item;
        }

        item->next = curr->next;
        curr->next = item;
    }

    item->prev = curr;
    list->size++;
    return 0;
}

int sf_sdlist_append(sfSDList *list, void *data, SDListItem *container)
{
    return sf_sdlist_insert_next(list, list->tail, data, container);
}

int sf_sdlist_remove_next(sfSDList *list, SDListItem *item)
{
    SDListItem *li = NULL;
    void *data;

    if(list->size == 0)
    {
        return -1;
    }

    /* remove the head */
    if(item == NULL)
    {
        li = list->head;
        data = li->data;
        list->head = li->next;
    }
    else
    {
        data = item->data;
        if(item->next == NULL)
        {
            return -1;
        }

        li = item->next;
        item->next = li->next;
        item->prev = li->prev;
    }

    if(li->next != NULL)
    {
        li->next->prev = item;
    }

    if(list->destroy != NULL)
        list->destroy(data);

    list->size--;

    if(list->size == 0) {
        list->tail = NULL;
    }

    return 0;
}


/*
 * Function: int sf_sdlist_remove(sfSDList *list, SDListItem *item)
 *
 * Purpose: remove the item pointed to by item
 * Args: list - list pointer
 *       item - item to unlink from the list
 *
 * Returns: 0 on success , 1 on exception
 *
 */
int sf_sdlist_remove(sfSDList *list, SDListItem *item)
{
    SDListItem *next_item;
    SDListItem *prev_item;

    if(item == NULL)
    {
        return -1;
    }

    next_item = item->next;
    prev_item = item->prev;

    if(next_item != NULL)
    {
        next_item->prev = prev_item;
    } else {
        list->tail = prev_item;
    }

    if(prev_item != NULL)
    {
        prev_item->next = next_item;
    } else {
        /* HEAD */
        list->head = next_item;
    }


    if(list->destroy != NULL)
        list->destroy(item->data);


    list->size--;

    if(list->size == 0)
    {
        list->head = NULL;
        list->tail = NULL;
    }

    return 0;
}

void print_sdlist(sfSDList *a)
{
    SDListItem *li;
    printf("***");
    printf(" size: %d\n", a->size);
    for(li = a->head; li != NULL; li = li->next) {
        printf(" `- %p\n", (void*)li);
    }
}

#ifdef TEST_SDLIST
void bad(void *d) {
    free(d);
    return;
}

int main(void) {
    sfSDList a;

    SDListItem *li;
    SDListItem listpool[1000];

    sf_sdlist_init(&a, &bad);
    if(sf_sdlist_append(&a, (char *) SnortStrdup("hello"), &listpool[0]))
    {
        printf("error appending!\n");
    }

    sf_sdlist_append(&a, (char *)SnortStrdup("goodbye"), &listpool[1]);

    sf_sdlist_insert_next(&a, NULL, (char *)SnortStrdup("woo"), &listpool[2]);

    printf("list size %d\n", a.size);

    for(li = a.head; li != NULL; li = li->next)
    {
        printf("%s\n", (char *) li->data);
    }


    printf("*** removing ***\n");
    sf_sdlist_remove(&a, &listpool[1]);
    printf("list size %d\n", a.size);
    for(li = a.head; li != NULL; li = li->next)
    {
        printf("%s\n", (char *) li->data);
    }

    sf_sdlist_delete(&a);

    printf("list size %d\n", a.size);
    return 0;
}
#endif /* TEST_SDLIST */
