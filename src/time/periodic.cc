/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "periodic.h"

#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "snort_types.h"
#include "util.h"

typedef struct _PeriodicCheckFuncNode
{
    void *arg;
    uint16_t priority;
    uint32_t period;
    uint32_t time_left;
    PeriodicFunc func;
    struct _PeriodicCheckFuncNode *next;

} PeriodicCheckFuncNode;

static PeriodicCheckFuncNode *periodic_check_funcs;

void periodic_register(
    PeriodicFunc periodic_func, void *arg,
    uint16_t priority, uint32_t period )
{
    PeriodicCheckFuncNode **list= &periodic_check_funcs;
    PeriodicCheckFuncNode *node;

    if (list == NULL)
        return;

    node = (PeriodicCheckFuncNode *)SnortAlloc(sizeof(PeriodicCheckFuncNode));

    if (*list == NULL)
    {
        *list = node;
    }
    else
    {
        PeriodicCheckFuncNode *tmp = *list;
        PeriodicCheckFuncNode *last = NULL;

        do
        {
            /* Insert higher priority stuff first.  Lower priority
             * number means higher priority */
            if (priority < tmp->priority)
                break;

            last = tmp;
            tmp = tmp->next;

        } while (tmp != NULL);

        /* Priority higher than first item in list */
        if (last == NULL)
        {
            node->next = tmp;
            *list = node;
        }
        else
        {
            node->next = tmp;
            last->next = node;
        }
    }

    node->func = periodic_func;
    node->arg = arg;
    node->priority = priority;
    node->period = period;
    node->time_left = period;
}

void periodic_release()
{
    PeriodicCheckFuncNode* head = periodic_check_funcs;

    while (head != NULL)
    {
        PeriodicCheckFuncNode* tmp = head->next;
        /* don't free sig->arg, that's free'd by the CleanExit func */
        free(head);
        head = tmp;
    }
    periodic_check_funcs = NULL;
}

void periodic_check()
{
    PeriodicCheckFuncNode* fn = periodic_check_funcs;

    while ( fn )
    {
        if ( !fn->time_left )
        {
            fn->func(fn->arg);
            fn->time_left = fn->period;
        }
        else
            fn->time_left--;

        fn = fn->next;
    }
}

