//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
**  @file       sfeventq.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This provides generic functions for queuing events and
**              inserting the events with a provided function.  All
**              memory management for events is provided here.
**
**
**  The sfeventq functions provide a generic way for handling events,
**  prioritizing those events, and acting on the highest ranked events
**  with a user function.
**
**  Example on using sfeventq:
**
**  1. Initialize event queue
**       sfeventq_init()
**
**  2. Add events to queue
**       sfeventq_event_alloc() allocates the memory for storing the event.
**       sfeventq_add() adds the event and prioritizes the event in the queue.
**       You should only allocate and add one event at a time.  Otherwise,
**       event_alloc() will return null on memory exhaustion.
**
**  3. Event actions
**       sfeventq_action() will call the provided function on the initialized
**       number of events to log.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfeventq.h"

#include <cassert>
#include "utils/util.h"

/*
**  Initialize the event queue.  Provide the max number of nodes that this
**  queue will support, the number of top nodes to log in the queue, and the
**  size of the event structure that the user will fill in.
*/
SF_EVENTQ* sfeventq_new(int max_nodes, int log_nodes, int event_size)
{
    if ((max_nodes <= 0) || (log_nodes <= 0) || (event_size <= 0))
        return nullptr;

    SF_EVENTQ* eq = (SF_EVENTQ*)snort_calloc(sizeof(SF_EVENTQ));

    /* Initialize the memory for the nodes that we are going to use. */
    eq->node_mem = (SF_EVENTQ_NODE*)snort_calloc(max_nodes, sizeof(SF_EVENTQ_NODE));
    eq->event_mem = (char*)snort_calloc(max_nodes + 1, event_size);

    eq->max_nodes = max_nodes;
    eq->log_nodes = log_nodes;
    eq->event_size = event_size;
    eq->cur_nodes = 0;
    eq->cur_events = 0;
    eq->fails = 0;

    eq->reserve_event = (char*)(&eq->event_mem[max_nodes * eq->event_size]);

    return eq;
}

/*
**  Allocate the memory for an event to add to the event queue.  This
**  function is meant to be called first, the event structure filled in,
**  and then added to the queue.  While you can allocate several times before
**  adding to the queue, this is not recommended as you may get a null ptr
**  if you allocate more than the max node number.
**
**  @return  void *
**
**  @retval  null - unable to allocate memory.
**  @retval !null - ptr to memory.
*/
void* sfeventq_event_alloc(SF_EVENTQ* eq)
{
    void* event;

    if (eq->cur_events >= eq->max_nodes)
    {
        if (eq->reserve_event == nullptr)
            return nullptr;

        event = (void*)eq->reserve_event;
        eq->reserve_event = nullptr;

        return event;
    }

    event = (void*)(&eq->event_mem[eq->cur_events * eq->event_size]);

    eq->cur_events++;

    return event;
}

/*
**  Resets the event queue.  We also set the reserve event back
**  to the last event in the queue.
*/
unsigned sfeventq_reset(SF_EVENTQ* eq)
{
    unsigned fails = eq->fails;
    eq->fails = 0;
    eq->head = nullptr;
    eq->cur_nodes = 0;
    eq->cur_events = 0;
    eq->reserve_event = (char*)(&eq->event_mem[eq->max_nodes * eq->event_size]);
    return fails;
}

void sfeventq_free(SF_EVENTQ* eq)
{
    if (eq == nullptr)
        return;

    /* Free the memory for the nodes that were in use. */
    if (eq->node_mem != nullptr)
    {
        snort_free(eq->node_mem);
        eq->node_mem = nullptr;
    }

    if (eq->event_mem != nullptr)
    {
        snort_free(eq->event_mem);
        eq->event_mem = nullptr;
    }

    snort_free(eq);
}

/*
**  This function returns a ptr to the node to use.  We allocate the last
**  event node if we have exhausted the event queue.  Before we allocate
**  the last node, we determine if the incoming event has a higher
**  priority than the last node.  If it does, we allocate the node, otherwise
**  we drop it because it is lower priority.
**
**  If the last node is allocated, we have to point the reserve_event to
**  the allocated event memory, since the reserved_event memory was used
**  for the incoming event.
**
**  @return SF_EVENTQ_NODE *
**
**  @retval null - resource exhaustion and event is lower priority than last node
**  @retval !null - ptr to node memory.
*/
static SF_EVENTQ_NODE* get_eventq_node(SF_EVENTQ* eq, void*)
{
    if (eq->cur_nodes >= eq->max_nodes)
        return nullptr;

    //  We grab the next node from the node memory.
    return &eq->node_mem[eq->cur_nodes++];
}

/*
**  Add this event to the queue using the supplied ordering
**  function.  If the queue is exhausted, then we compare the
**  event to be added with the last event, and decide whether
**  it is a higher priority than the last node.
**
**  @return integer
**
**  @retval -1 add event failed
**  @retval  0 add event succeeded
*/
int sfeventq_add(SF_EVENTQ* eq, void* event)
{
    assert(event);

    /*
    **  If get_eventq_node() returns null, this means that
    **  we have exhausted the eventq and the incoming event
    **  is lower in priority then the last ranked event.
    **  So we just drop it.
    */
    SF_EVENTQ_NODE* node = get_eventq_node(eq, event);

    if ( !node )
    {
        ++eq->fails;
        return -1;
    }

    node->event = event;
    node->next  = nullptr;
    node->prev  = nullptr;

    if (eq->cur_nodes == 1)
    {
        //  This is the first node
        eq->head = eq->last = node;
        return 0;
    }

    //  This means we are the last node.
    node->prev = eq->last;

    eq->last->next = node;
    eq->last = node;

    return 0;
}

/*
**  Call the supplied user action function on the highest priority
**  events.
**
**  @return integer
**
**  @retval -1 action function failed on an event
**  @retval  0 no events logged
**  @retval  1 events logged
*/
int sfeventq_action(SF_EVENTQ* eq, int (* action_func)(void*, void*), void* user)
{
    SF_EVENTQ_NODE* node;
    int logged = 0;

    if (action_func == nullptr)
        return -1;

    if (eq->head == nullptr)
        return 0;

    for (node = eq->head; node != nullptr; node = node->next)
    {
        if (logged >= eq->log_nodes)
            return 1;

        if (action_func(node->event, user))
            return -1;

        logged++;
    }

    return 1;
}

