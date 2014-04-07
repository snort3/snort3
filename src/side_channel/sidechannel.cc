/*
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
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2012-2013 Sourcefire, Inc.
 *
 * Author: Michael Altizer <maltizer@sourcefire.com>
 *
 */

#include "sidechannel.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SIDE_CHANNEL
#include <pthread.h>
#include <signal.h>

#include "dmq.h"
#include "rbmq.h"
#include "plugins/sscm_logger.h"
#include "helpers/process.h"

#define DEFAULT_RX_QUEUE_DEPTH      1024
#define DEFAULT_RX_QUEUE_DATA_SIZE  10485760
#define DEFAULT_TX_QUEUE_DEPTH      1024
#define DEFAULT_TX_QUEUE_DATA_SIZE  10485760

#define CONF_SEPARATORS     " \t\n\r,"
#define CONF_RX_QUEUE_DATA_SIZE "rx-queue-data-size"
#define CONF_RX_QUEUE_DEPTH     "rx-queue-depth"
#define CONF_TX_QUEUE_DATA_SIZE "tx-queue-data-size"
#define CONF_TX_QUEUE_DEPTH     "tx-queue-depth"
#define CONF_DISABLE_TX_THREAD  "disable-tx-thread"

#ifdef SC_USE_DMQ
#define RBMQ_Ptr DMQ_Ptr
#define RBMQ_Alloc DMQ_Alloc
#define RBMQ_ReserveMsg DMQ_ReserveMsg
#define RBMQ_CommitReservedMsg DMQ_CommitReservedMsg
#define RBMQ_DiscardReservedMsg DMQ_DiscardReservedMsg
#define RBMQ_CommitExternalMsg DMQ_CommitExternalMsg
#define RBMQ_ReadMsg DMQ_ReadMsg
#define RBMQ_AckMsg DMQ_AckMsg
#define RBMQ_IsEmpty DMQ_IsEmpty
#define RBMQ_Stats DMQ_Stats
#endif

enum ConfState
{
    STATE_START,
    STATE_RX_QUEUE_DATA_SIZE,
    STATE_RX_QUEUE_DEPTH,
    STATE_TX_QUEUE_DATA_SIZE,
    STATE_TX_QUEUE_DEPTH
};

typedef struct _SC_CONFIG
{
    uint32_t rx_queue_max_data_size;
    uint32_t rx_queue_max_depth;
    uint32_t tx_queue_max_data_size;
    uint32_t tx_queue_max_depth;
    bool disable_tx_thread;
    bool enabled;
} SCConfig;

typedef struct _SC_MODULE
{
    struct _SC_MODULE *next;
    char *keyword;
    SCMFunctionBundle funcs;
    bool enabled;
} SCModule;

typedef struct _SC_HANDLER
{
    struct _SC_HANDLER *next;
    uint16_t type;
    SCMProcessMsgFunc processMsgFunc;
    void *data;
} SCHandler;

typedef struct _SC_MESSAGE_QUEUE
{
    RBMQ_Ptr queue;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint32_t max_data_size;
    uint32_t max_depth;
} SCMessageQueue;

static struct {  // FIXIT 1 / process
    uint64_t rx_messages_total;
    uint64_t rx_messages_processed_ib;
    uint64_t rx_messages_processed_oob;
    uint64_t tx_messages_total;
    uint64_t tx_messages_processed;
} Side_Channel_Stats;

static volatile int stop_processing = 0;
static volatile int tx_thread_running = 0;

static pid_t tx_thread_pid;
static pthread_t tx_thread_id;
static pthread_t *p_tx_thread_id;

static SCConfig sc_config;

static SCMessageQueue rx_queue;
static SCMessageQueue tx_queue;

static SCModule *modules;
static SCHandler *rx_handlers;
static SCHandler *tx_handlers;

#ifdef PERF_PROFILING
//static THREAD_LOCAL PreprocStats sideChannelRxPerfStats;  // FIXIT not in use
#endif

void RegisterSideChannelModules(void)
{
    if (!ScSideChannelEnabled())
        return;

    SetupLoggerSCM();
}

void RegisterSideChannelModule(const char *keyword, SCMFunctionBundle *funcs)
{
    SCModule *module, *tmp, *last = NULL;

    if (!ScSideChannelEnabled())
        return;

    if (!keyword)
        FatalError("No keyword given while registering a side channel module!\n");

    if (!funcs)
        FatalError("No function bundle given while registering side channel '%s'!\n", keyword);

    for (tmp = modules; tmp; tmp = tmp->next)
    {
        if (strcasecmp(tmp->keyword, keyword) == 0)
            FatalError("Duplicate side channel keyword: %s\n", keyword);
        last = tmp;
    }
    module = (SCModule*)SnortAlloc(sizeof(SCModule));

    module->next = NULL;
    module->keyword = SnortStrdup(keyword);
    module->funcs = *funcs;
    module->enabled = 0;

    LogMessage("Register SCM '%s' with configFunc=%p, initFunc=%p, postInitFunc=%p, idleFunc=%p, statsFunc=%p, shutdownFunc=%p\n",
            keyword, module->funcs.configFunc, module->funcs.initFunc, module->funcs.postInitFunc,
            module->funcs.idleFunc, module->funcs.statsFunc, module->funcs.shutdownFunc);

    if (last)
        last->next = module;
    else
        modules = module;
}

int ConfigureSideChannelModule(const char *keyword, char *opts)
{
    SCModule *module;

    for (module = modules; module; module = module->next)
    {
        if (strcasecmp(module->keyword, keyword) == 0)
            break;
    }
    if (!module)
        return -ENOENT;

    module->funcs.configFunc(opts);
    module->enabled = 1;

    return 0;
}

static int SCRegisterHandler(SCHandler **handlers, uint16_t type, SCMProcessMsgFunc processMsgFunc, void *data)
{
    SCHandler *handler;

    if (!ScSideChannelEnabled())
        return 0;

    handler = (SCHandler*)SnortAlloc(sizeof(SCHandler));

    handler->next = NULL;
    handler->type = type;
    handler->processMsgFunc = processMsgFunc;
    handler->data = data;

    handler->next = *handlers;
    *handlers = handler;

    return 0;
}

int SideChannelRegisterRXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc, void *data)
{
    return SCRegisterHandler(&rx_handlers, type, processMsgFunc, data);
}

int SideChannelRegisterTXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc, void *data)
{
    return SCRegisterHandler(&tx_handlers, type, processMsgFunc, data);
}

static void SCUnregisterHandler(SCHandler **handlers, uint16_t type, SCMProcessMsgFunc processMsgFunc)
{
    SCHandler *handler, *prev;

    if (!ScSideChannelEnabled())
        return;

    for (prev = NULL, handler = *handlers; handler; prev = handler, handler = handler->next)
    {
        if (handler->type == type && handler->processMsgFunc == processMsgFunc)
            break;
    }

    if (handler)
    {
        if (!prev)
            *handlers = handler->next;
        else
            prev->next = handler->next;

        free(handler);
    }
}

void SideChannelUnregisterRXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc)
{
    SCUnregisterHandler(&rx_handlers, type, processMsgFunc);
}

void SideChannelUnregisterTXHandler(uint16_t type, SCMProcessMsgFunc processMsgFunc)
{
    SCUnregisterHandler(&tx_handlers, type, processMsgFunc);
}

static int SCPreallocMessage(SCMessageQueue *mq, uint32_t length, SCMsgHdr **hdr_ptr, uint8_t **msg_ptr, void **msg_handle)
{
    int rval;

    pthread_mutex_lock(&mq->mutex);
    rval = RBMQ_ReserveMsg(mq->queue, length, (void **) hdr_ptr, msg_ptr, msg_handle);
    pthread_mutex_unlock(&mq->mutex);

    return rval;
}

int SideChannelPreallocMessageRX(uint32_t length, SCMsgHdr **hdr_ptr, uint8_t **msg_ptr, void **msg_handle)
{
    return SCPreallocMessage(&rx_queue, length, hdr_ptr, msg_ptr, msg_handle);
}

int SideChannelPreallocMessageTX(uint32_t length, SCMsgHdr **hdr_ptr, uint8_t **msg_ptr, void **msg_handle)
{
    return SCPreallocMessage(&tx_queue, length, hdr_ptr, msg_ptr, msg_handle);
}

static int SCDiscardMessage(SCMessageQueue *mq, void *msg_handle)
{
    int rval;

    pthread_mutex_lock(&mq->mutex);
    rval = RBMQ_DiscardReservedMsg(mq->queue, msg_handle);
    pthread_mutex_unlock(&mq->mutex);

    return rval;
}

int SideChannelDiscardMessageRX(void *msg_handle)
{
    return SCDiscardMessage(&rx_queue, msg_handle);
}

int SideChannelDiscardMessageTX(void *msg_handle)
{
    return SCDiscardMessage(&tx_queue, msg_handle);
}

static int SCEnqueueMessage(SCMessageQueue *mq, SCMsgHdr *hdr, const uint8_t *msg, uint32_t length, void *msg_handle, SCMQMsgFreeFunc msgFreeFunc)
{
    int rval;

    if (!msg_handle)
    {
        SCMsgHdr *hdr_ptr;
        uint8_t *msg_ptr;

        rval = RBMQ_ReserveMsg(mq->queue, length, (void **) &hdr_ptr, &msg_ptr, &msg_handle);
        if (rval != 0)
        {
            ErrorMessage("%s: Could not reserve message: %d\n", __FUNCTION__, rval);
            return rval;
        }
        memcpy(msg_ptr, msg, length);
        memcpy(hdr_ptr, hdr, sizeof(SCMsgHdr));
        rval = RBMQ_CommitReservedMsg(mq->queue, msg_handle, length, msgFreeFunc);
        if (rval != 0)
        {
            ErrorMessage("%s: Could not commit reserved message: %d\n", __FUNCTION__, rval);
            return rval;
        }
    }
    else
        rval = RBMQ_CommitReservedMsg(mq->queue, msg_handle, length, msgFreeFunc);

    return rval;
}

static inline void SCProcessMessage(SCHandler *handlers, SCMsgHdr *hdr, const uint8_t *msg, uint32_t length)
{
    SCHandler *handler;

    for (handler = handlers; handler; handler = handler->next)
    {
        if (hdr->type == handler->type || handler->type == SC_MSG_TYPE_ANY)
            handler->processMsgFunc(hdr, msg, length);
    }
}

static int SCDrainAndProcess(SCMessageQueue *mq, SCHandler *handlers)
{
    SCHandler *handler;
    SCMsgHdr *hdr;
    uint32_t length;
    const uint8_t *msg;
    void *msg_handle;
    int rval;

    /* Read a message from the queue. */
    pthread_mutex_lock(&mq->mutex);
    rval = RBMQ_ReadMsg(mq->queue, (const void **) &hdr, &msg, &length, &msg_handle);
    pthread_mutex_unlock(&mq->mutex);
    if (rval != 0)
        return 1;

    /* Handle it. */
    SCProcessMessage(handlers, hdr, msg, length);

    /* And, finally, acknowledge it. */
    pthread_mutex_lock(&mq->mutex);
    rval = RBMQ_AckMsg(mq->queue, msg_handle);
    pthread_mutex_unlock(&mq->mutex);
    if (rval != 0)
        WarningMessage("Error ACK'ing message %p!\n", msg_handle);

    return 0;
}

/* Called by an out-of-band thread (probably a Side Channel Module). */
int SideChannelEnqueueMessageRX(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length, void *msg_handle, SCMQMsgFreeFunc msgFreeFunc)
{
    int rval;

    /* 
     * Because the Snort main thread relinquishes control to DAQ_Acquire for up to a second,
     * we potentially need to preempt it and process RX messages as they are being enqueued
     * to avoid backups and overruns.
     * This should be safe since the main thread holds the snort_process_lock mutex while it
     * is not in DAQ_Acquire().
     */
    while (pthread_mutex_trylock(&snort_process_lock) == 0)
    {
        /* If there are no more messages in the RX queue, process the new message without enqueuing it and return. */
        if (SCDrainAndProcess(&rx_queue, rx_handlers) != 0)
        {
            SCProcessMessage(rx_handlers, hdr, msg, length);
            if (msgFreeFunc)
                msgFreeFunc((uint8_t *) msg);
            if (msg_handle)
            {
                pthread_mutex_lock(&rx_queue.mutex);
                RBMQ_DiscardReservedMsg(rx_queue.queue, msg_handle);
                pthread_mutex_unlock(&rx_queue.mutex);
            }
            Side_Channel_Stats.rx_messages_total++;
            Side_Channel_Stats.rx_messages_processed_oob++;

            pthread_mutex_unlock(&snort_process_lock);
            return 0;
        }
        else
            Side_Channel_Stats.rx_messages_processed_oob++;

        pthread_mutex_unlock(&snort_process_lock);
    }

    /* Finally, enqueue the message if we really have to. */
    pthread_mutex_lock(&rx_queue.mutex);
    rval = SCEnqueueMessage(&rx_queue, hdr, msg, length, msg_handle, msgFreeFunc);
    /* TODO: Error check the above call. */
    Side_Channel_Stats.rx_messages_total++;
    pthread_mutex_unlock(&rx_queue.mutex);

    return rval;
}

/* Called in the Snort main thread. */
int SideChannelEnqueueMessageTX(SCMsgHdr *hdr, const uint8_t *msg, uint32_t length, void *msg_handle, SCMQMsgFreeFunc msgFreeFunc)
{
    int rval, empty;

    /* Only bother queuing if the TX thread is running, otherwise just immediately process. */
    if (tx_thread_running)
    {
        pthread_mutex_lock(&tx_queue.mutex);
        empty = RBMQ_IsEmpty(tx_queue.queue);
        rval = SCEnqueueMessage(&tx_queue, hdr, msg, length, msg_handle, msgFreeFunc);
        /* TODO: Error check the above call. */
        Side_Channel_Stats.tx_messages_total++;
        /* If the queue was empty, signal any waiters. */
        if (empty)
            pthread_cond_signal(&tx_queue.cond);
        pthread_mutex_unlock(&tx_queue.mutex);
    }
    else
    {
        SCProcessMessage(tx_handlers, hdr, msg, length);
        Side_Channel_Stats.tx_messages_total++;
        Side_Channel_Stats.tx_messages_processed++;
        if (msgFreeFunc)
            msgFreeFunc((uint8_t *) msg);
        if (msg_handle)
        {
            pthread_mutex_lock(&tx_queue.mutex);
            RBMQ_DiscardReservedMsg(tx_queue.queue, msg_handle);
            pthread_mutex_unlock(&tx_queue.mutex);
        }
        rval = 0;
    }

    return rval;
}

static int SCEnqueueData(SCMessageQueue *mq, SCMsgHdr *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    return RBMQ_CommitExternalMsg(mq->queue, hdr, msg, length, msgFreeFunc);
}

/* Called by an out-of-band thread (probably a Side Channel Module). */
int SideChannelEnqueueDataRX(SCMsgHdr *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    int rval;

    pthread_mutex_lock(&rx_queue.mutex);
    rval = SCEnqueueData(&rx_queue, hdr, msg, length, msgFreeFunc);
    /* TODO: Error check the above call. */
    Side_Channel_Stats.rx_messages_total++;
    pthread_mutex_unlock(&rx_queue.mutex);

    return rval;
}

/* Called in the Snort main thread. */
int SideChannelEnqueueDataTX(SCMsgHdr *hdr, uint8_t *msg, uint32_t length, SCMQMsgFreeFunc msgFreeFunc)
{
    int rval, empty;

    /* Only bother queuing if the TX thread is running, otherwise just immediately process. */
    if (tx_thread_running)
    {
        pthread_mutex_lock(&tx_queue.mutex);
        empty = RBMQ_IsEmpty(tx_queue.queue);
        rval = SCEnqueueData(&tx_queue, hdr, msg, length, msgFreeFunc);
        /* TODO: Error check the above call. */
        Side_Channel_Stats.tx_messages_total++;
        /* If the queue was empty, signal any waiters. */
        if (empty)
            pthread_cond_signal(&tx_queue.cond);
        pthread_mutex_unlock(&tx_queue.mutex);
    }
    else
    {
        SCProcessMessage(tx_handlers, hdr, msg, length);
        Side_Channel_Stats.tx_messages_total++;
        Side_Channel_Stats.tx_messages_processed++;
        msgFreeFunc(msg);
        rval = 0;
    }

    return rval;
}

/* Called in the Snort main thread. */
uint32_t SideChannelDrainRX(unsigned max_msgs)
{
    uint32_t processed = 0;

    if (!ScSideChannelEnabled())
        return 0;

    if (RBMQ_IsEmpty(rx_queue.queue))
        return 0;

    while (!max_msgs || processed < max_msgs)
    {
        if (stop_processing || SCDrainAndProcess(&rx_queue, rx_handlers) != 0)
            break;

        Side_Channel_Stats.rx_messages_processed_ib++;
        processed++;
    }

    return processed;
}

static void *SideChannelThread(void *arg)
{
    struct timespec ts;
    struct timeval tv;
    SCHandler *handler;
    SCModule *module;
    SCMsgHdr *hdr;
    uint32_t length;
    const uint8_t *msg;
    void *msg_handle;
    int rval;

    tx_thread_pid = gettid();
    tx_thread_running = 1;

    pthread_mutex_lock(&tx_queue.mutex);
    while (!stop_processing)
    {
        /* If the message queue is empty, we will stop without unlocking it so we can immediately start a timed wait. */
        while ((rval = RBMQ_ReadMsg(tx_queue.queue, (const void **) &hdr, &msg, &length, &msg_handle)) == 0)
        {
            pthread_mutex_unlock(&tx_queue.mutex);

            for (handler = tx_handlers; handler; handler = handler->next)
            {
                if (hdr->type == handler->type || handler->type == SC_MSG_TYPE_ANY)
                    handler->processMsgFunc(hdr, msg, length);
            }

            pthread_mutex_lock(&tx_queue.mutex);
            rval = RBMQ_AckMsg(tx_queue.queue, msg_handle);
            if (rval != 0)
                WarningMessage("Error ACK'ing message %p!\n", msg_handle);
            /* Again, not unlocking so that we're already locked for the three places we can go
                from here, which are all expecting it (dequeue, timed wait, or done). */

            Side_Channel_Stats.tx_messages_processed++;
            if (stop_processing)
                goto done;
        }
        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec + 10;
        ts.tv_nsec = tv.tv_usec * 1000;
        rval = pthread_cond_timedwait(&tx_queue.cond, &tx_queue.mutex, &ts);
        /* If we timed out waiting for new output messages to process, run the registered idle routines. */
        if (rval == ETIMEDOUT && !stop_processing)
        {
            for (module = modules; module; module = module->next)
            {
                if (module->enabled && module->funcs.idleFunc)
                    module->funcs.idleFunc();
            }
        }
    }
done:
    pthread_mutex_unlock(&tx_queue.mutex);

    LogMessage("Side Channel thread exiting...\n");

    return NULL;
}

static void SCParseConfiguration(SnortConfig *sc, SCConfig *config)
{
    long int value;
    char *token, *argcpy, *endptr;
    enum ConfState confState = STATE_START;

    memset(config, 0, sizeof(SCConfig));

    config->enabled = sc->side_channel_config.enabled;
    if (!config->enabled)
        return;

    config->rx_queue_max_data_size = DEFAULT_RX_QUEUE_DATA_SIZE;
    config->rx_queue_max_depth = DEFAULT_RX_QUEUE_DEPTH;
    config->tx_queue_max_data_size = DEFAULT_TX_QUEUE_DATA_SIZE;
    config->tx_queue_max_depth = DEFAULT_TX_QUEUE_DEPTH;
    config->disable_tx_thread = false;

    if (!sc->side_channel_config.opts)
        return;

    argcpy = sc->side_channel_config.opts;
    char* lasts = "";

    for (token = strtok_r(argcpy, CONF_SEPARATORS, &lasts);
        token;
        token = strtok_r(NULL, CONF_SEPARATORS, &lasts))
    {
        switch (confState)
        {
            case STATE_START:
                if (strcmp(token, CONF_RX_QUEUE_DATA_SIZE) == 0)
                    confState = STATE_RX_QUEUE_DATA_SIZE;
                else if (strcmp(token, CONF_RX_QUEUE_DEPTH) == 0)
                    confState = STATE_RX_QUEUE_DEPTH;
                else if (strcmp(token, CONF_TX_QUEUE_DATA_SIZE) == 0)
                    confState = STATE_TX_QUEUE_DATA_SIZE;
                else if (strcmp(token, CONF_TX_QUEUE_DEPTH) == 0)
                    confState = STATE_TX_QUEUE_DEPTH;
                else if (strcmp(token, CONF_DISABLE_TX_THREAD) == 0)
                    config->disable_tx_thread = true;
                else
                    FatalError("Invalid side channel configuration token: '%s'\n", token);
                break;
            case STATE_RX_QUEUE_DATA_SIZE:
                confState = STATE_START;
                value = SnortStrtoul(token, &endptr, 0);
                if (errno != 0 || *endptr != '\0')
                    FatalError("Invalid argument for side channel RX queue data size: '%s'\n", token);
                config->rx_queue_max_data_size = value;
                break;
            case STATE_RX_QUEUE_DEPTH:
                confState = STATE_START;
                value = SnortStrtoul(token, &endptr, 0);
                if (errno != 0 || *endptr != '\0')
                    FatalError("Invalid argument for side channel RX queue depth: '%s'\n", token);
                config->rx_queue_max_depth = value;
                break;
            case STATE_TX_QUEUE_DATA_SIZE:
                confState = STATE_START;
                value = SnortStrtoul(token, &endptr, 0);
                if (errno != 0 || *endptr != '\0')
                    FatalError("Invalid argument for side channel TX queue data size: '%s'\n", token);
                config->tx_queue_max_data_size = value;
                break;
            case STATE_TX_QUEUE_DEPTH:
                confState = STATE_START;
                value = SnortStrtoul(token, &endptr, 0);
                if (errno != 0 || *endptr != '\0')
                    FatalError("Invalid argument for side channel TX queue depth: '%s'\n", token);
                config->tx_queue_max_depth = value;
                break;
            default:
                break;
        }
    }
}

int SideChannelVerifyConfig(SnortConfig *sc)
{
    SCConfig config;

    SCParseConfiguration(sc, &config);

    return memcmp(&config, &sc_config, sizeof(SCConfig));
}

void SideChannelConfigure(SnortConfig *sc)
{
    if (!sc->side_channel_config.enabled)
        return;

    SCParseConfiguration(sc, &sc_config);

    rx_queue.max_data_size = sc_config.rx_queue_max_data_size;
    rx_queue.max_depth = sc_config.rx_queue_max_depth;
    tx_queue.max_data_size = sc_config.tx_queue_max_data_size;
    tx_queue.max_depth = sc_config.tx_queue_max_depth;

    LogMessage("Side Channel config:\n");
    LogMessage("  RX Queue Max Data Size: %u\n", sc_config.rx_queue_max_data_size);
    LogMessage("  RX Queue Max Depth: %u\n", sc_config.rx_queue_max_depth);
    LogMessage("  TX Queue Max Data Size: %u\n", sc_config.tx_queue_max_data_size);
    LogMessage("  RX Queue Max Depth: %u\n", sc_config.tx_queue_max_depth);
}

void SideChannelInit(void)
{
    SCModule *module;

    if (!ScSideChannelEnabled())
        return;

    pthread_mutex_init(&rx_queue.mutex, NULL);
    pthread_cond_init(&rx_queue.cond, NULL);
    rx_queue.queue = RBMQ_Alloc(rx_queue.max_depth, sizeof(SCMsgHdr), rx_queue.max_data_size);

    pthread_cond_init(&tx_queue.cond, NULL);
    pthread_mutex_init(&tx_queue.mutex, NULL);
    tx_queue.queue = RBMQ_Alloc(tx_queue.max_depth, sizeof(SCMsgHdr), tx_queue.max_data_size);

    for (module = modules; module; module = module->next)
    {
        if (module->enabled && module->funcs.initFunc)
            module->funcs.initFunc();
    }
}

void SideChannelStartTXThread(void)
{
    const struct timespec thread_sleep = { 0, 100 };
    SCModule *module;
    sigset_t mask;
    int found, rval;

    if (!ScSideChannelEnabled())
        return;

    if (sc_config.disable_tx_thread)
        return;

    /* Avoid starting the TX thread if there are no TX handlers or TX idle tasks registered. */
    found = 0;
    for (module = modules; module; module = module->next)
    {
        if (module->enabled && module->funcs.idleFunc)
        {
            found = 1;
            break;
        }
    }
    if (!found && !tx_handlers)
    {
        LogMessage("Not starting unnecessary Side Channel TX thread.\n");
        return;
    }

    /* Spin off the Side Channel handler thread. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGNAL_SNORT_RELOAD);
    sigaddset(&mask, SIGNAL_SNORT_DUMP_STATS);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGNAL_SNORT_ROTATE_STATS);
    sigaddset(&mask, SIGNAL_SNORT_CHILD_READY);
    sigaddset(&mask, SIGNAL_SNORT_READ_ATTR_TBL);
    sigaddset(&mask, SIGVTALRM);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);

    if ((rval = pthread_create(&tx_thread_id, NULL, &SideChannelThread, NULL)) != 0)
    {
        sigemptyset(&mask);
        pthread_sigmask(SIG_SETMASK, &mask, NULL);
        FatalError("Side Channel: Unable to create thread: %s\n", get_error(rval));
    }
    while (!tx_thread_running)
        nanosleep(&thread_sleep, NULL);

    p_tx_thread_id = &tx_thread_id;
    sigemptyset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
    LogMessage("Side Channel TX thread started tid=%p (pid=%u)\n", (void *) tx_thread_id, tx_thread_pid);
}

void SideChannelStopTXThread(void)
{
    int rval;

    if (!ScSideChannelEnabled())
        return;

    if (p_tx_thread_id != NULL)
    {
        stop_processing = 1;
        pthread_mutex_lock(&tx_queue.mutex);
        pthread_cond_signal(&tx_queue.cond);
        pthread_mutex_unlock(&tx_queue.mutex);
        if ((rval = pthread_join(*p_tx_thread_id, NULL)) != 0)
            WarningMessage("Side channel TX thread termination returned an error: %s\n", get_error(rval));
    }
}

int SideChannelPostInit(void)
{
    SCModule *module;

    if (!ScSideChannelEnabled())
        return 0;

    for (module = modules; module; module = module->next)
    {
        if (module->enabled && module->funcs.postInitFunc)
            module->funcs.postInitFunc();
    }

    return 0;
}

void SideChannelStats(const char *separator)
{
    SCModule *module;

    if (!ScSideChannelEnabled())
        return;

    LogMessage("%s\n", separator);
    LogMessage("Side Channel:\n");
    LogMessage("  RX Messages Total:            %" PRIu64 "\n", Side_Channel_Stats.rx_messages_total);
    LogMessage("  RX Messages Processed (IB):   %" PRIu64 "\n", Side_Channel_Stats.rx_messages_processed_ib);
    LogMessage("  RX Messages Processed (OOB):  %" PRIu64 "\n", Side_Channel_Stats.rx_messages_processed_oob);
    LogMessage("  TX Messages Total:            %" PRIu64 "\n", Side_Channel_Stats.tx_messages_total);
    LogMessage("  TX Messages Processed:        %" PRIu64 "\n", Side_Channel_Stats.tx_messages_processed);

    for (module = modules; module; module = module->next)
    {
        if (module->enabled && module->funcs.statsFunc)
        {
            LogMessage("%s\n", separator);
            module->funcs.statsFunc(0);
        }
    }

    LogMessage("  RX Queue Stats:\n");
    RBMQ_Stats(rx_queue.queue, "  ");

    LogMessage("  TX Queue Stats:\n");
    RBMQ_Stats(tx_queue.queue, "  ");
}

void SideChannelCleanUp(void)
{
    SCModule *module;

    if (!ScSideChannelEnabled())
        return;

    while ((module = modules))
    {
        if (module->enabled)
        {
            if (module->funcs.statsFunc)
                module->funcs.statsFunc(1);

            if (module->funcs.shutdownFunc)
                module->funcs.shutdownFunc();
        }
        modules = module->next;
        free(module->keyword);
        free(module);
    }
    pthread_cond_destroy(&tx_queue.cond);
    pthread_mutex_destroy(&tx_queue.mutex);
    pthread_cond_destroy(&rx_queue.cond);
    pthread_mutex_destroy(&rx_queue.mutex);
}

/*
 * WARNING: Messages are being written in and read assuming host byte order.
 */

static inline ssize_t Write(int fd, const void *buf, size_t count)
{
    ssize_t n;
    errno = 0;

    while ((n = write(fd, buf, count)) <= (ssize_t) count)
    {
        if (n == (ssize_t) count)
            return 0;

        if (n > 0)
            count -= n;
        else if (errno != EINTR)
            break;
    }

    return -1;
}

int SideChannelWriteMsgToFile(int fd, SCMsgHdr *hdr, const uint8_t *msg, uint32_t length)
{
    if (Write(fd, &hdr->type, sizeof(hdr->type)) != 0)
        return -1;

    if (Write(fd, &hdr->timestamp, sizeof(hdr->timestamp)) != 0)
        return -1;

    if (Write(fd, &length, sizeof(length)) != 0)
        return -1;

    if (Write(fd, msg, length) != 0)
        return -1;

    return 0;
}

static inline ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t n;
    errno = 0;

    while ((n = read(fd, buf, count)) <= (ssize_t) count)
    {
        if (n == (ssize_t) count)
            return 0;

        if (n > 0)
        {
            count -= n;
            buf = (uint8_t *) buf + n;
        }
        else if (n == 0)
            break;
        else if (errno != EINTR)
        {
            ErrorMessage("Error reading Logger SCM log file: %s (%d)\n", get_error(errno), errno);
            break;
        }
    }
    return -1;
}

int SideChannelReadMsgFromFile(int fd, SCMsgHdr *hdr, uint8_t **msg_ptr, uint32_t *length_ptr)
{
    uint64_t timestamp;
    uint32_t length;
    uint16_t type;
    uint8_t *msg;

    if (Read(fd, &type, sizeof(type)) != 0)
        return -1;

    if (Read(fd, &timestamp, sizeof(timestamp)) != 0)
        return -1;

    if (Read(fd, &length, sizeof(length)) != 0)
        return -1;

    if (length > 0)
    {
        msg = (uint8_t*)SnortAlloc(length);
        if (Read(fd, msg, length) != 0)
        {
            free(msg);
            return -1;
        }
    }
    else
        msg = NULL;

    hdr->type = type;
    hdr->timestamp = timestamp;
    *length_ptr = length;
    *msg_ptr = msg;

    return 0;
}

#endif /* SIDE_CHANNEL */
