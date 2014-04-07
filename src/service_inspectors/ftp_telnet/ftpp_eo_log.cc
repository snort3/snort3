/*
 * ftpp_eo_log.c
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Description:
 *
 * This file contains the event output functionality that
 * FTPTelnet uses to log events and data associated with
 * the events.
 *
 * Log events, retrieve events, and select events that HttpInspect
 * generates.
 *
 * Logging Events:
 *   Since the object behind this is no memset()s, we have to rely on the
 *   stack interface to make sure we don't log the same event twice.  So
 *   if there are events in the stack we cycle through to make sure that
 *   there are none available before we add a new event and increment the
 *   stack count.  Then to reset the event queue, we just need to set the
 *   stack count back to zero.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#include <stdlib.h>

#include "ftpp_si.h"
#include "ftpp_eo.h"
#include "ftpp_eo_events.h"
#include "ftpp_return_codes.h"

#include "snort.h"
#include "signature.h"

/*
 * The ftp & telnet events and the priorities are listed here.
 * Any time that a new client event is added, we have to
 * add the event id and the priority here.  If you want to
 * change either of those characteristics, you have to change
 * them here.
 */
// FIXIT this event foo should be eliminated; just use the normal event mechanism (same for HI)
static THREAD_LOCAL FTPP_EVENT_INFO ftp_event_info[FTP_EO_EVENT_NUM] = {
    { FTP_EO_TELNET_CMD,
        FTP_EO_TELNET_CMD_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        FTP_EO_TELNET_CMD_STR },
    { FTP_EO_INVALID_CMD,
        FTP_EO_INVALID_CMD_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        FTP_EO_INVALID_CMD_STR },
    { FTP_EO_PARAMETER_LENGTH_OVERFLOW,
        FTP_EO_PARAMETER_LENGTH_OVERFLOW_SID,
        0,
        FTPP_EO_HIGH_PRIORITY,
        FTP_EO_PARAMETER_LENGTH_OVERFLOW_STR },
    { FTP_EO_MALFORMED_PARAMETER,
        FTP_EO_MALFORMED_PARAMETER_SID,
        0,
        FTPP_EO_HIGH_PRIORITY,
        FTP_EO_MALFORMED_PARAMETER_STR },
    { FTP_EO_PARAMETER_STR_FORMAT,
        FTP_EO_PARAMETER_STR_FORMAT_SID,
        0,
        FTPP_EO_HIGH_PRIORITY,
        FTP_EO_PARAMETER_STR_FORMAT_STR },
    { FTP_EO_RESPONSE_LENGTH_OVERFLOW,
        FTP_EO_RESPONSE_LENGTH_OVERFLOW_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        FTP_EO_RESPONSE_LENGTH_OVERFLOW_STR },
    { FTP_EO_ENCRYPTED,
        FTP_EO_ENCRYPTED_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        FTP_EO_ENCRYPTED_STR },
    { FTP_EO_BOUNCE,
        FTP_EO_BOUNCE_SID,
        0,
        FTPP_EO_MED_PRIORITY,
        FTP_EO_BOUNCE_STR },
    { FTP_EO_EVASIVE_TELNET_CMD,
        FTP_EO_EVASIVE_TELNET_CMD_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        FTP_EO_EVASIVE_TELNET_CMD_STR }

};

static THREAD_LOCAL FTPP_EVENT_INFO telnet_event_info[TELNET_EO_EVENT_NUM] = {
    { TELNET_EO_AYT_OVERFLOW,
            TELNET_EO_AYT_OVERFLOW_SID,
            0,
            FTPP_EO_HIGH_PRIORITY,
            TELNET_EO_AYT_OVERFLOW_STR },
    { TELNET_EO_ENCRYPTED,
        TELNET_EO_ENCRYPTED_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        TELNET_EO_ENCRYPTED_STR },
    { TELNET_EO_SB_NO_SE,
        TELNET_EO_SB_NO_SE_SID,
        0,
        FTPP_EO_LOW_PRIORITY,
        TELNET_EO_SB_NO_SE_STR }

};

static THREAD_LOCAL int log_initialized = 0;

/*
 * Function: ftpp_eo_event_log_init()
 *
 * Purpose: Initialize the event logger.
 *          We need to initialize the event logger for the FTP/Telnet
 *          preprocessor.  Initializes the event info objects and class types.
 *
 * Arguments: None
 *
 * Returns: void
 *
 */
void ftpp_eo_event_log_init(void)
{
    if (!log_initialized)
    {
        // FIXTHIS - ClassTypeLookupByType() called during runtime ...
        ClassType* type = ClassTypeLookupByType(snort_conf, "protocol-command-decode");

        if (type != NULL)
        {
            ftp_event_info[FTP_EO_TELNET_CMD].classification = type->id;
            ftp_event_info[FTP_EO_TELNET_CMD].priority = type->priority;
            ftp_event_info[FTP_EO_INVALID_CMD].classification = type->id;
            ftp_event_info[FTP_EO_INVALID_CMD].priority = type->priority;
            ftp_event_info[FTP_EO_MALFORMED_PARAMETER].classification =
                type->id;
            ftp_event_info[FTP_EO_MALFORMED_PARAMETER].priority =
                type->priority;
            ftp_event_info[FTP_EO_ENCRYPTED].classification = type->id;
            ftp_event_info[FTP_EO_ENCRYPTED].priority = type->priority;
            ftp_event_info[FTP_EO_EVASIVE_TELNET_CMD].classification = type->id;
            ftp_event_info[FTP_EO_EVASIVE_TELNET_CMD].priority = type->priority;
            telnet_event_info[TELNET_EO_ENCRYPTED].classification = type->id;
            telnet_event_info[TELNET_EO_ENCRYPTED].priority = type->priority;
        }

        type = ClassTypeLookupByType(snort_conf, "string-detect");
        if (type != NULL)
        {
            ftp_event_info[FTP_EO_RESPONSE_LENGTH_OVERFLOW].classification =
                type->id;
            ftp_event_info[FTP_EO_RESPONSE_LENGTH_OVERFLOW].priority =
                type->priority;
        }

        type = ClassTypeLookupByType(snort_conf, "policy-violation");
        if (type != NULL)
        {
            ftp_event_info[FTP_EO_BOUNCE].classification = type->id;
            ftp_event_info[FTP_EO_BOUNCE].priority = type->priority;
        }

        type = ClassTypeLookupByType(snort_conf, "attempted-admin");
        if (type != NULL)
        {
            ftp_event_info[FTP_EO_PARAMETER_LENGTH_OVERFLOW].classification =
                type->id;
            ftp_event_info[FTP_EO_PARAMETER_LENGTH_OVERFLOW].priority =
                type->priority;
            ftp_event_info[FTP_EO_PARAMETER_STR_FORMAT].classification =
                type->id;
            ftp_event_info[FTP_EO_PARAMETER_STR_FORMAT].priority =
                type->priority;
            telnet_event_info[TELNET_EO_AYT_OVERFLOW].classification =
                type->id;
            telnet_event_info[TELNET_EO_AYT_OVERFLOW].priority =
                type->priority;
            telnet_event_info[TELNET_EO_SB_NO_SE].classification =
                type->id;
            telnet_event_info[TELNET_EO_SB_NO_SE].priority=
                type->priority;
        }
        log_initialized = 1;
    }
}

/*
 * Function: ftpp_eo_event_log(FTPP_GEN_EVENTS *gen_events,
 *                             FTPP_EVENT_INFO *event_info,
 *                             int iEvent,
 *                             void *data, void (*free_data)(void *) )
 *
 * Purpose: This function logs events during FTPTelnet processing.
 *          The idea behind this event logging is modularity, but at the
 *          same time performance.  We accomplish this utilizing an
 *          optimized stack as an index into the client event array,
 *          instead of walking a list for already logged events.  The
 *          problem here is that we can't just log every event that we've
 *          already seen, because this opens us up to a DOS.  So by using
 *          this method, we can quickly check if an event has already been
 *          logged and deal appropriately.
 *
 * Arguments: gen_events    => pointer to the generic event data
 *            event_info    => pointer to the event info array
 *            iEvent        => index within the event array
 *            data          => pointer to user allocated data
 *            free_data     => pointer to a function to free the user data
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftpp_eo_event_log(FTPP_GEN_EVENTS *gen_events, FTPP_EVENT_INFO *event_info,
                      int iEvent, void *data, void (*free_data)(void *) )
{
    FTPP_EVENT *event;
    int iCtr;
    /*
     * This is where we cycle through the current event stack.  If the event
     * to be logged is already in the queue, then we increment the event
     * count, before returning.  Otherwise, we fall through the loop and
     * set the event before adding it to the queue and incrementing the
     * pointer.
     */
    for(iCtr = 0; iCtr < gen_events->stack_count; iCtr++)
    {
        if(gen_events->stack[iCtr] == iEvent)
        {
            gen_events->events[iEvent].count++;
            return FTPP_SUCCESS;
        }
    }

    /*
     * Initialize the event before putting it in the queue.
     */
    event = &(gen_events->events[iEvent]);
    event->event_info = event_info;
    event->count = 1;
    event->data = data;
    event->free_data = free_data;

    /*
     * We now add the event to the stack.
     */
    gen_events->stack[gen_events->stack_count] = iEvent;
    gen_events->stack_count++;

    return FTPP_SUCCESS;
}

/*
 * Function: telnet_eo_event_log(TELNET_SESSION *session,
 *                               int iEvent,
 *                               void *data, void (*free_data)(void *))
 *
 * Purpose: This function logs events for telnet processing.
 *          It invokes ftpp_eo_event_log using a generic event structure
 *          that contains the telnet specific data.
 *
 * Arguments: session       => pointer to the Telnet session
 *            iEvent        => the event id for the event
 *            data          => pointer to the user data of the event
 *            free_data     => pointer to a function to free the user data
 *
 * Returns: int => return code indicating error or success
 *
 */
int telnet_eo_event_log(TELNET_SESSION *session, int iEvent, void *data,
        void (*free_data)(void *))
{
    int iRet;
    TELNET_EVENTS *telnet_events;
    FTPP_EVENT_INFO *event_info;
    FTPP_GEN_EVENTS gen_events;

    ftpp_eo_event_log_init();

    /*
     * Check the input variables for correctness
     */
    if(!session || (iEvent >= TELNET_EO_EVENT_NUM))
    {
        return FTPP_INVALID_ARG;
    }

    telnet_events = &(session->event_list);
    gen_events.events = (FTPP_EVENT *)&(telnet_events->events);
    gen_events.stack = (int *)&(telnet_events->stack);
    gen_events.stack_count = telnet_events->stack_count;
    event_info = &telnet_event_info[iEvent];

    iRet = ftpp_eo_event_log(&gen_events, event_info, iEvent, data, free_data);

    telnet_events->stack_count = gen_events.stack_count;

    return iRet;
}

/*
 * Function: ftp_eo_event_log(FTP_SESSION *session,
 *                            int iEvent,
 *                            void *data, void (*free_data)(void *))
 *
 * Purpose: This function logs events for ftp processing.
 *          It invokes ftpp_eo_event_log using a generic event structure
 *          that contains the ftp specific data.
 *
 * Arguments: session       => pointer to the FTP session
 *            iEvent        => the event id for the event
 *            data          => pointer to the user data of the event
 *            free_data     => pointer to a function to free the user data
 *
 * Returns: int => return code indicating error or success
 *
 */
int ftp_eo_event_log(FTP_SESSION *session, int iEvent, void *data,
        void (*free_data)(void *))
{
    int iRet;
    FTP_EVENTS *ftp_events;
    FTPP_EVENT_INFO *event_info;
    FTPP_GEN_EVENTS gen_events;

    ftpp_eo_event_log_init();

    /*
     * Check the input variables for correctness
     */
    if(!session || (iEvent >= FTP_EO_EVENT_NUM))
    {
        return FTPP_INVALID_ARG;
    }

    ftp_events = &(session->event_list);
    gen_events.events = (FTPP_EVENT *)&(ftp_events->events);
    gen_events.stack = (int *)&(ftp_events->stack);
    gen_events.stack_count = ftp_events->stack_count;
    event_info = &ftp_event_info[iEvent];

    iRet = ftpp_eo_event_log(&gen_events, event_info, iEvent, data, free_data);

    ftp_events->stack_count = gen_events.stack_count;

    return iRet;
}
