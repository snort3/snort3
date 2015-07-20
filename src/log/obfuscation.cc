//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

#include "obfuscation.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern "C" {
#include <daq.h>
}

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "main/thread.h"
#include "utils/snort_bounds.h"
#include "utils/util.h"

#ifdef OBFUSCATION_TEST_STANDALONE
# ifndef OBFUSCATION_TEST
#  define OBFUSCATION_TEST
# endif
static int TraverseReassembled(
    Packet*,
    int (*)(DAQ_PktHdr_t*, uint8_t*, uint8_t*, uint32_t, void*),
    void*
);
#endif

/*******************************************************************************
 * Macros
 ******************************************************************************/
#define OBFUSCATE_ENTRIES         512
#define OBFUSCATE_MAXLEN_ENTRIES    8
#define OBFUSCATE_SLICE_ENTRIES   (OBFUSCATE_ENTRIES - OBFUSCATE_MAXLEN_ENTRIES)

/*******************************************************************************
 * Data structures
 ******************************************************************************/
typedef struct _ObfuscationEntry
{
    Packet* p;
    ob_size_t offset;
    ob_size_t length;
    ob_char_t ob_char;
} ObfuscationEntry;

typedef struct _ObfuscationStruct
{
    int num_entries;
    int num_maxlen_entries;
    int sorted;
    ObfuscationEntry entries[OBFUSCATE_ENTRIES];
    ObfuscationEntry* sort_entries[OBFUSCATE_ENTRIES];
    ObfuscationEntry* maxlen_entries[OBFUSCATE_MAXLEN_ENTRIES];
} ObfuscationStruct;

typedef struct _ObfuscationCallbackData
{
    const Packet* packet;
    ObfuscationCallback user_callback;
    void* user_data;
    int entry_index;
    ob_size_t total_offset;
} ObfuscationCallbackData;

typedef struct _ObfuscationStreamCallbackData
{
    ObfuscationCallbackData* data;
    uint32_t next_seq;
    int last_entry_index;
} ObfuscationStreamCallbackData;

typedef struct _ObfuscatedPayload
{
    uint8_t** payload;
    ob_size_t* payload_len;
    ob_size_t payload_size;
} ObfuscatedPayload;

/*******************************************************************************
 * Globals
 ******************************************************************************/
static THREAD_LOCAL ObfuscationStruct ob_struct;

/*******************************************************************************
 * Private function prototypes
 ******************************************************************************/
static inline int PayloadObfuscationRequired(Packet*);

static inline void SortObfuscationEntries(void);

static inline void SetObfuscationCallbackData(
    ObfuscationCallbackData*, Packet*, ObfuscationCallback, void*);

static ObRet AddObfuscationEntry(Packet*, ob_size_t, ob_size_t, ob_char_t);
static int ObfuscationEntrySort(const void*, const void*);

static ObRet TraverseObfuscationList(ObfuscationCallbackData*,
    const DAQ_PktHdr_t*, const uint8_t*, ob_size_t);

static ObRet GetObfuscatedPayloadCallback(const DAQ_PktHdr_t*,
    const uint8_t*, ob_size_t, ob_char_t, void*);

static void PrintObfuscationEntry(const ObfuscationEntry*, int);

/*******************************************************************************
 * API prototypes
 ******************************************************************************/
static void OB_API_ResetObfuscationEntries(void);
static ObRet OB_API_AddObfuscationEntry(Packet*, ob_size_t,
ob_size_t, ob_char_t);
static int OB_API_PayloadObfuscationRequired(Packet*);
static ObRet OB_API_ObfuscatePacket(Packet*, ObfuscationCallback, void*);
static ObRet OB_API_ObfuscatePacketStreamSegments(Packet*,
ObfuscationCallback, void*);
static ObRet OB_API_GetObfuscatedPayload(Packet*, uint8_t**, ob_size_t*);
static void OB_API_PrintObfuscationEntries(int);

/* API accessor */
ObfuscationApi obfuscationApi =
{
    OB_API_ResetObfuscationEntries,        // resetObfuscationEntries
    OB_API_AddObfuscationEntry,            // addObfuscationEntry
    OB_API_PayloadObfuscationRequired,     // payloadObfuscationRequired
    OB_API_ObfuscatePacket,                // obfuscatePacket
    OB_API_ObfuscatePacketStreamSegments,  // obfuscatePacketStreamSegments
    OB_API_GetObfuscatedPayload,           // getObfuscatedPayload
    OB_API_PrintObfuscationEntries         // printObfuscationEntries
};

ObfuscationApi* obApi = &obfuscationApi;

/*******************************************************************************
 * API Function definitions
 ******************************************************************************/
// resetObfuscationEntries
void OB_API_ResetObfuscationEntries(void)
{
    ob_struct.num_entries = 0;
    ob_struct.num_maxlen_entries = 0;
    ob_struct.sorted = 0;
}

// addObfuscationEntry
static ObRet OB_API_AddObfuscationEntry(Packet* p, ob_size_t offset,
    ob_size_t length, ob_char_t ob_char)
{
    if (p == NULL)
        return OB_RET_ERROR;

    p->packet_flags |= PKT_PAYLOAD_OBFUSCATE;

    return AddObfuscationEntry(p, offset, length, ob_char);
}

// payloadObfuscationRequired
static int OB_API_PayloadObfuscationRequired(Packet* p)
{
    return PayloadObfuscationRequired(p);
}

// obfuscatePacket
static ObRet OB_API_ObfuscatePacket(Packet* p,
    ObfuscationCallback user_callback, void* user_data)
{
    ObfuscationCallbackData callback_data;

    if (!PayloadObfuscationRequired(p))
        return OB_RET_ERROR;

    SortObfuscationEntries();
    SetObfuscationCallbackData(&callback_data, p, user_callback, user_data);

    /* Send header information first - isn't obfuscated */
    if (user_callback(p->pkth, p->pkt, (ob_size_t)(p->data - p->pkt),
        0, user_data) != OB_RET_SUCCESS)
    {
        return OB_RET_ERROR;
    }

    if (TraverseObfuscationList(&callback_data, NULL, p->data,
        (ob_size_t)(p->pkth->caplen - (p->data - p->pkt))) != OB_RET_SUCCESS)
    {
        return OB_RET_ERROR;
    }

    return OB_RET_SUCCESS;
}

// obfuscatePacketStreamSegments
// FIXIT-L traverse_reassembled() deleted
// this should also be deleted if it is no longer needed
static ObRet OB_API_ObfuscatePacketStreamSegments(Packet*,
    ObfuscationCallback, void*)
{
    return OB_RET_ERROR;
}

// getObfuscatedPayload
static ObRet OB_API_GetObfuscatedPayload(Packet* p,
    uint8_t** payload, ob_size_t* payload_len)
{
    ObfuscationCallbackData callback_data;
    ObfuscatedPayload user_data;

    if (!PayloadObfuscationRequired(p))
        return OB_RET_ERROR;

    if ((payload == NULL) || (payload_len == NULL))
        return OB_RET_ERROR;

    *payload = NULL;
    *payload_len = 0;

    user_data.payload = payload;
    user_data.payload_len = payload_len;
    user_data.payload_size = 0;

    SortObfuscationEntries();
    SetObfuscationCallbackData(&callback_data, p,
        GetObfuscatedPayloadCallback, (void*)&user_data);

    if (TraverseObfuscationList(&callback_data, NULL, p->data,
        (ob_size_t)(p->pkth->caplen - (p->data - p->pkt))) != OB_RET_SUCCESS)
    {
        return OB_RET_ERROR;
    }

    return OB_RET_SUCCESS;
}

// printObfuscationEntries
static void OB_API_PrintObfuscationEntries(int sorted)
{
    int i;
    ObfuscationEntry* entry;

    if (sorted)
        SortObfuscationEntries();

    for (i = 0; i < ob_struct.num_entries; i++)
    {
        LogMessage("Entry: %d\n", i);

        if (sorted)
            entry = ob_struct.sort_entries[i];
        else
            entry = &ob_struct.entries[i];

        PrintObfuscationEntry(entry, 2);
    }
}

/*******************************************************************************
 * Private function definitions
 ******************************************************************************/

/*******************************************************************************
 * Function: NumObfuscateMaxLenEntries()
 *
 * Gets the number of current OB_LENGTH_MAX entries that have been added.
 *
 * Arguments
 *  None
 *
 * Returns
 *  The number of current OB_LENGTH_MAX entries.
 *
 ******************************************************************************/
static inline int NumObfuscateMaxLenEntries(void)
{
    return ob_struct.num_maxlen_entries;
}

/*******************************************************************************
 * Function: NumObfuscateSliceEntries()
 *
 * Gets the number of current slice entries that have been added.
 *
 * Arguments
 *  None
 *
 * Returns
 *  The number of current slice entries.
 *
 ******************************************************************************/
static inline int NumObfuscateSliceEntries(void)
{
    return ob_struct.num_entries - ob_struct.num_maxlen_entries;
}

/*******************************************************************************
 * Function: ObfuscationEntryOverflow()
 *
 * Determines whether or not there is enough space in the static entry array to
 * add another obfucation entry.
 *
 * Arguments
 *  ob_size_t
 *   The length of the entry that should be added.  If length is OB_LENGTH_MAX
 *   then the max length array is checked.
 *
 * Returns
 *  OB_RET_SUCCESS  if the entry can be added
 *  OB_RET_OVERFLOW  if there isn't enough space to add another entry
 *
 ******************************************************************************/
static inline ObRet ObfuscationEntryOverflow(ob_size_t length)
{
    if (length == OB_LENGTH_MAX)
    {
        if (NumObfuscateMaxLenEntries() >= OBFUSCATE_MAXLEN_ENTRIES)
            return OB_RET_OVERFLOW;
    }
    else
    {
        if (NumObfuscateSliceEntries() >= OBFUSCATE_SLICE_ENTRIES)
            return OB_RET_OVERFLOW;
    }

    return OB_RET_SUCCESS;
}

/*******************************************************************************
 * Function: PayloadObfuscationRequired()
 *
 * Determines whether or not the packet requires obfuscation.  An obfuscation
 * flag is added to the packet flags when an obfuscation entry is added that
 * is associated with the packet.  If there isn't any data, then it doesn't
 * need obfuscation.
 *
 * Arguments
 *  Packet *p
 *   The Packet to check
 *
 * Returns
 *  0  if obfuscation is not needed.
 *  1  if the packet has been flagged for obfuscation.
 *
 ******************************************************************************/
static inline int PayloadObfuscationRequired(Packet* p)
{
    if ((p == NULL) || (p->pkth == NULL)
        || (p->pkt == NULL) || (p->data == NULL)
        || (p->pkt >= p->data)
        || ((ob_size_t)(p->data - p->pkt) > p->pkth->caplen))
    {
        return 0;
    }

    if (!(p->packet_flags & PKT_PAYLOAD_OBFUSCATE)
        || (ob_struct.num_entries == 0))
    {
        return 0;
    }

    return 1;
}

/*******************************************************************************
 * Function: SetObfuscationEntry()
 *
 * Initializes an obfuscation entry with the passed in values.
 *
 * Arguments
 *  ObfuscationEntry *entry
 *   The obfuscation entry to initialize
 *  Packet *p
 *   The Packet to associate with this entry
 *  ob_size_t offset
 *   The offset into the packet to start obfuscation
 *  ob_size_t length
 *   The amount of data to obfuscate starting from offset
 *  ob_char_t ob_char
 *   The character to use when obfuscating
 *
 * Returns
 *  None
 *
 ******************************************************************************/
static inline void SetObfuscationEntry(ObfuscationEntry* entry,
    Packet* p, ob_size_t offset, ob_size_t length, ob_char_t ob_char)
{
    if (entry == NULL)
        return;

    entry->p = p;
    entry->offset = offset;
    entry->length = length;
    entry->ob_char = ob_char;
}

/*******************************************************************************
 * Function: SetObfuscationCallbackData()
 *
 * Initializes the callback data for use in TraverseObfuscationList.
 *
 * Arguments
 *  ObfuscationCallbackData *callback_data
 *   The callback data struct to initialize
 *  Packet *p
 *   The Packet to associate with this entry
 *  ob_size_t offset
 *   The offset into the packet to start obfuscation
 *  ob_size_t length
 *   The amount of data to obfuscate starting from offset
 *  ob_char_t ob_char
 *   The character to use when obfuscating
 *
 * Returns
 *  None
 *
 ******************************************************************************/
static inline void SetObfuscationCallbackData(
    ObfuscationCallbackData* callback_data, Packet* packet,
    ObfuscationCallback user_callback, void* user_data)
{
    if (callback_data == NULL)
        return;

    callback_data->packet = packet;
    callback_data->user_callback = user_callback;
    callback_data->user_data = user_data;
    callback_data->entry_index = 0;
    callback_data->total_offset = 0;
}

/*******************************************************************************
 * Function: SetObfuscationStreamCallbackData()
 *
 * Initializes the callback data for use in TraverseObfuscationList.
 *
 * Arguments
 *  ObfuscationStreamCallbackData *stream_callback_data
 *   The stream callback data struct to initialize
 *  ObfuscationCallbackData *callback_data
 *   The callback data struct to initialize
 *  Packet *p
 *   The Packet to associate with this entry
 *  ob_size_t offset
 *   The offset into the packet to start obfuscation
 *  ob_size_t length
 *   The amount of data to obfuscate starting from offset
 *  ob_char_t ob_char
 *   The character to use when obfuscating
 *
 * Returns
 *  None
 *
 ******************************************************************************/
#if 0
static inline void SetObfuscationStreamCallbackData(
    ObfuscationStreamCallbackData* stream_callback_data,
    ObfuscationCallbackData* callback_data, Packet* packet,
    ObfuscationCallback user_callback, void* user_data)
{
    if ((stream_callback_data == NULL) || (callback_data == NULL))
        return;

    SetObfuscationCallbackData(callback_data, packet, user_callback, user_data);
    stream_callback_data->data = callback_data;
    stream_callback_data->next_seq = 0;
    stream_callback_data->last_entry_index = 0;
}
#endif

/*******************************************************************************
 * Function: SortObfuscationEntries()
 *
 * Uses qsort to sort the entries that have been added.  Possibly qsort is not
 * the most efficient sort here since, in general, the entries will be added
 * from smallest offset to largest.
 *
 * Arguments
 *  None
 *
 * Returns
 *  None
 *
 ******************************************************************************/
static inline void SortObfuscationEntries(void)
{
    if (!ob_struct.sorted)
    {
        qsort((void*)ob_struct.sort_entries, ob_struct.num_entries,
            sizeof(ObfuscationEntry*), ObfuscationEntrySort);
        ob_struct.sorted = 1;
    }
}

/*******************************************************************************
 * Function: AddObfuscationEntry()
 *
 * Adds an obfuscation entry to the obfuscation list.  OB_LENGTH_MAX entries
 * are first checked to see if there is an entry already associated with
 * the Packet passed in.  If there is, the entry with the lesser of the two
 * offsets is used.
 *
 * Arguments
 *  Packet *p
 *   The Packet to be associated with this entry
 *  ob_size_t offset
 *   The offset into the payload of this packet to start obfuscating
 *  ob_size_t length
 *   The length of the payload starting at offset to obfuscate
 *  ob_char_t
 *   The character to use when obfuscating
 *
 * Returns
 *  OB_RET_SUCCESS  if the entry was successfully added
 *  OB_RET_OVERFLOW  if there is no room left to store the entry
 *
 ******************************************************************************/
static ObRet AddObfuscationEntry(Packet* p, ob_size_t offset,
    ob_size_t length, ob_char_t ob_char)
{
    ObfuscationEntry* entry;
    int entry_index = ob_struct.num_entries;

    if (length == OB_LENGTH_MAX)
    {
        int i;

        /* Check to see if there is an OB_LENGTH_MAX entry already associated
         * with this packet */
        for (i = 0; i < ob_struct.num_maxlen_entries; i++)
        {
            entry = ob_struct.maxlen_entries[i];
            if (entry->p == p)
            {
                /* Already have an entry for this packet.  Use the entry with
                 * the lesser of the two offsets */
                if (offset < entry->offset)
                {
                    entry->offset = offset;
                    entry->ob_char = ob_char;
                }

                return OB_RET_SUCCESS;
            }
        }
    }

    if (ObfuscationEntryOverflow(length) != OB_RET_SUCCESS)
        return OB_RET_OVERFLOW;

    /* Reset sorted since we're adding an entry and the list will need
     * to be sorted again */
    ob_struct.sorted = 0;

    /* Get the entry at the current index */
    entry = &ob_struct.entries[entry_index];
    SetObfuscationEntry(entry, p, offset, length, ob_char);

    ob_struct.sort_entries[entry_index] = entry;
    ob_struct.num_entries++;

    if (length == OB_LENGTH_MAX)
    {
        ob_struct.maxlen_entries[ob_struct.num_maxlen_entries] = entry;
        ob_struct.num_maxlen_entries++;
    }

    return OB_RET_SUCCESS;
}

/*******************************************************************************
 * Function: ObfuscationEntrySort()
 *
 * Sorting callback.  Sorted by offset, then length if the offsets are the same.
 *
 * Arguments
 *  const void *data1
 *   The compare to argument
 *  const void *data2
 *   The argument to compare to the first argument
 *
 * Returns
 *  -1  if the first ObfuscationEntry is considered less than the second
 *   1  if the first ObfuscationEntry is considered greater than the second
 *   0  if both offset and length are equal
 *
 ******************************************************************************/
static int ObfuscationEntrySort(const void* data1, const void* data2)
{
    ObfuscationEntry* ob1 = *((ObfuscationEntry**)data1);
    ObfuscationEntry* ob2 = *((ObfuscationEntry**)data2);

    if (ob1->offset < ob2->offset)
        return -1;
    else if (ob1->offset > ob2->offset)
        return 1;
    else if (ob1->length < ob2->length)
        return -1;
    else if (ob1->length > ob2->length)
        return 1;

    return 0;
}

/*******************************************************************************
 * Function: TraverseObfuscationList()
 *
 * This is the main function for obfuscating a payload or stream segments.
 * It walks through a packet and obfuscation entries, calling the user
 * callback with obfuscated and non-obfuscated instructions.
 *
 * Arguments
 *  ObfuscationCallbackData *data
 *   The state tracking data structure.  Has the packet being obfuscated,
 *   current obfuscation entry and total number of bytes obfuscated thus
 *   far.
 *  DAQ_PktHdr_t *pkth
 *   The pcap header information associated with the payload being
 *   obfuscated.
 *  uint8_t *pkt
 *   The start of the packet including Ethernet headers, etc.
 *  uint8_t *payload
 *   Pointer to the payload data to be obfuscated
 *  ob_size_t
 *   The size of the payload data
 *
 * Returns
 *  OB_RET_SUCCESS  if successfully completed
 *  OB_RET_ERROR  if the user callback doesn't return OB_RET_SUCCESS
 *
 ******************************************************************************/
static ObRet TraverseObfuscationList(ObfuscationCallbackData* data,
    const DAQ_PktHdr_t* pkth, const uint8_t* payload_data,
    ob_size_t payload_size)
{
    int i;
    ob_size_t total_offset = data->total_offset;
    ob_size_t payload_offset = 0;
    const DAQ_PktHdr_t* pkth_tmp = pkth;
#ifdef OBFUSCATION_TEST
    uint8_t print_array[OB_LENGTH_MAX];
    ob_size_t start_total_offset = 0;
    ob_size_t start_payload_offset = 0;
#endif

    if ((payload_data == NULL) || (payload_size == 0))
        return OB_RET_ERROR;

#ifdef OBFUSCATION_TEST
    LogMessage("Payload data: %u bytes\n", payload_size);
    LogMessage("==============================================================="
        "=================\n");
#endif

    /* Start from current saved obfuscation entry index */
    for (i = data->entry_index; i < ob_struct.num_entries; i++)
    {
        /* Get the entry from the sorted array */
        const ObfuscationEntry* entry = ob_struct.sort_entries[i];
        ob_size_t ob_offset = entry->offset;
        ob_size_t ob_length = entry->length;

        /* Make sure it's for the right packet */
        if (entry->p != data->packet)
        {
#ifdef OBFUSCATION_TEST
            LogMessage("flags1: %08x, flags2: %08x\n", entry->p->packet_flags,
                data->packet->packet_flags);
#endif
            continue;
        }

        /* We've already obfuscated this part of the packet payload
         * Account for overflow */
        if (((ob_offset + ob_length) <= total_offset)
            && ((ob_offset + ob_length) > ob_offset))
        {
            continue;
        }

#ifdef OBFUSCATION_TEST
        LogMessage("  Total offset: %u\n\n", total_offset);
        start_total_offset = total_offset;
        start_payload_offset = payload_offset;
#endif

        /* Note the obfuscation offset is only used at this point to determine
         * the amount of data that does not need to be obfuscated up to the
         * offset or the length of what needs to be obfuscated if the offset
         * is less than what's already been logged */

        if (ob_offset > total_offset)
        {
            /* Get the amount of non-obfuscated data - need to log straight
             * packet data up to obfuscation offset */
            ob_size_t length = ob_offset - total_offset;

            /* If there is more length than what's left in the packet,
             * truncate it, do we don't overflow */
            if (length > (payload_size - payload_offset))
                length = payload_size - payload_offset;

            /* Call the user callback and tell it not to obfuscate the data
             * by passing in a non-NULL packet pointer */
            if (data->user_callback(pkth_tmp, payload_data + payload_offset,
                length, 0, data->user_data) != OB_RET_SUCCESS)
            {
                return OB_RET_ERROR;
            }

#ifdef OBFUSCATION_TEST
            SafeMemcpy(print_array + payload_offset, payload_data + payload_offset,
                length, print_array, print_array + sizeof(print_array));
#endif
            /* Only the first payload call sends the pcap_pkthdr */
            pkth_tmp = NULL;

            /* Adjust offsets */
            payload_offset += length;
            total_offset += length;

            /* If there is no more packet data, break out of the loop */
            if (payload_offset == payload_size)
            {
#ifdef OBFUSCATION_TEST
                PrintPacketData(print_array + start_payload_offset, length);
                LogMessage("\n");
#endif
                break;
            }
        }
        else if (ob_offset < total_offset)
        {
            /* If the entries offset is less than the current total offset,
             * decrease the length. */
            ob_length -= (total_offset - ob_offset);
        }

        /* Adjust the amount of data to obfuscate if it exceeds the amount of
         * data left in the packet.  Account for overflow */
        if (((payload_offset + ob_length) > payload_size)
            || ((payload_offset + ob_length) <= payload_offset))
        {
            ob_length = payload_size - payload_offset;
        }

        /* Call the user callback and tell it to obfuscate the data by passing
         * in a NULL packet pointer */
        if (data->user_callback(pkth_tmp, NULL, ob_length,
            entry->ob_char, data->user_data) != OB_RET_SUCCESS)
        {
            return OB_RET_ERROR;
        }

#ifdef OBFUSCATION_TEST
        LogMessage("  Entry: %d\n", i);
        LogMessage("  --------------------------\n");
        PrintObfuscationEntry(entry, 4);
        LogMessage("\n");

        SafeMemset(print_array + payload_offset, entry->ob_char,
            ob_length, print_array, print_array + sizeof(print_array));

        if (ob_length < entry->length)
        {
            if (ob_offset < start_total_offset)
            {
                if (payload_offset + ob_length == payload_size)
                {
                    LogMessage("  Obfuscating beyond already obfuscated "
                        "(%u bytes) and to end of payload: %u bytes\n\n",
                        (start_total_offset - ob_offset), ob_length);
                }
                else
                {
                    LogMessage("  Obfuscating beyond already obfuscated "
                        "(%u bytes): %u bytes\n\n",
                        (start_total_offset - ob_offset), ob_length);
                }
            }
            else
            {
                LogMessage("  Obfuscating to end of payload: "
                    "%u bytes\n\n", ob_length);
            }
        }
        else
        {
            LogMessage("  Obfuscating: %u bytes\n\n", ob_length);
        }

        PrintPacketData(print_array + start_payload_offset,
            (payload_offset - start_payload_offset) + ob_length);

        if (((entry->offset + entry->length) - (total_offset + ob_length)) > 0)
        {
            LogMessage("\n  Remaining amount to obfuscate: %u bytes\n",
                (entry->offset + entry->length) - (total_offset + ob_length));
        }

        LogMessage("\n");
#endif

        /* Only the first payload call sends the pcap_pkthdr */
        pkth_tmp = NULL;

        /* Adjust offsets */
        payload_offset += ob_length;
        total_offset += ob_length;

        /* If there is no more packet data, break out of the loop */
        if (payload_offset == payload_size)
            break;
    }

    /* There's more data in the packet left, meaning we ran out of
     * obfuscation entries */
    if (payload_size > payload_offset)
    {
        ob_size_t length = payload_size - payload_offset;

        /* Call the user callback and tell it not to obfuscate the data
         * by passing in a non-NULL packet pointer */
        if (data->user_callback(pkth_tmp, payload_data + payload_offset,
            length, 0, data->user_data) != OB_RET_SUCCESS)
        {
            return OB_RET_ERROR;
        }

#ifdef OBFUSCATION_TEST
        SafeMemcpy(print_array + payload_offset, payload_data + payload_offset,
            length, print_array, print_array + sizeof(print_array));
#endif

        /* Adjust offsets - don't need to adjust packet offset since
         * we're done with the packet */
        total_offset += length;
    }

#ifdef OBFUSCATION_TEST
    LogMessage("Obfuscated payload\n");
    LogMessage("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        "~~~~~~~~~~\n");
    PrintPacketData(print_array, payload_size);
    LogMessage("\n\n");
#endif

    /* Save these for next time we come in if necessary.  Mainly for
     * traversing stream segments */
    data->entry_index = i;
    data->total_offset = total_offset;

    return OB_RET_SUCCESS;
}

/*******************************************************************************
 * Function: GetObfuscationPayloadCallback()
 *
 * ObfuscationCallback for returning an allocated obfuscated payload.
 *
 * Arguments
 *  DAQ_PktHdr_t *pkth
 *   The pcap header information associated with the payload being
 *   obfuscated.
 *  uint8_t *packet_data
 *   Pointer to the packet data to be obfuscated
 *  ob_char_t ob_char
 *   The obfuscation character
 *  ob_size_t length
 *   The length of the portion of packet payload to use
 *  void *user_data
 *   The ObfuscatedPayload data
 *
 * Returns
 *  OB_RET_ERROR  if copying obfuscation data is not successful
 *  OB_RET_SUCCESS  if successful copying data to payload
 *
 ******************************************************************************/
static ObRet GetObfuscatedPayloadCallback(
    const DAQ_PktHdr_t*, const uint8_t* packet_data,
    ob_size_t length, ob_char_t ob_char, void* user_data)
{
    ObfuscatedPayload* ob_payload = (ObfuscatedPayload*)user_data;
    uint8_t* payload;
    ob_size_t payload_len, payload_size;

    if (ob_payload == NULL)
        return OB_RET_ERROR;

    if ((ob_payload->payload == NULL) || (ob_payload->payload_len == NULL))
        return OB_RET_ERROR;

    payload = *ob_payload->payload;
    payload_len = *ob_payload->payload_len;
    payload_size = ob_payload->payload_size;

    if ((payload_len + length) > payload_size)
    {
        /* Allocate extra so we don't have to reallocate every time in */
        ob_size_t new_size = payload_len + length + 100;
        uint8_t* tmp = (uint8_t*)SnortAlloc(new_size);

        if (payload != NULL)
        {
            if (SafeMemcpy(tmp, payload, payload_len,
                tmp, tmp + new_size) != SAFEMEM_SUCCESS)
            {
                free(tmp);
                free(payload);
                return OB_RET_ERROR;
            }

            free(payload);
        }

        payload_size = new_size;
        ob_payload->payload_size = new_size;

        *ob_payload->payload = tmp;
        payload = tmp;
    }

    if (packet_data != NULL)
    {
        if (SafeMemcpy(payload + payload_len, packet_data, length,
            payload, payload + payload_size) != SAFEMEM_SUCCESS)
        {
            free(payload);
            return OB_RET_ERROR;
        }
    }
    else
    {
        if (SafeMemset(payload + payload_len, (uint8_t)ob_char, length,
            payload, payload + payload_size) != SAFEMEM_SUCCESS)
        {
            free(payload);
            return OB_RET_ERROR;
        }
    }

    *ob_payload->payload_len += length;

    return OB_RET_SUCCESS;
}

/*******************************************************************************
 * Function: PrintObfuscationEntry()
 *
 * Prints an obfuscation entry offsetted with optional leading whitespace.
 *
 * Arguments
 *  const ObfuscationEntry *entry
 *   The entry to print
 *  int leading_whitespace
 *   The amount of whitespace to use before printing a line.
 * Returns
 *  None
 *
 ******************************************************************************/
static void PrintObfuscationEntry(const ObfuscationEntry* entry,
    int leading_space)
{
    if (entry == NULL)
        return;

    LogMessage("%*sPacket: %p\n", leading_space, "", (void*)entry->p);
    LogMessage("%*sOffset: %u\n", leading_space, "", entry->offset);
    LogMessage("%*sLength: %u\n", leading_space, "", entry->length);
    if (isgraph((int)entry->ob_char))
        LogMessage("%*sOb char: \'%c\'\n", leading_space, "", entry->ob_char);
    else
        LogMessage("%*sOb char: 0x%02x\n", leading_space, "", entry->ob_char);
}

/******************************************************************************
 * Testing
 ******************************************************************************/
#ifdef OBFUSCATION_TEST_STANDALONE

#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_ALLOC_SIZE  1024

/* Used for standalone testing */
struct Segment
{
    DAQ_PktHdr_t* pkth;
    uint8_t* data;
    uint16_t size;
    Segment* next;
};

/* Used for standalone testing */
struct ObPacket
{
    Packet p;
    Segment* seglist;
};

static uint8_t* ob_payload = NULL;
static void ObTestAlloc(void**, int, int);
static void CreateObEntries(Packet*, ob_char_t, ob_size_t,
ob_size_t, int, int);
static ObRet ObCallback(DAQ_PktHdr_t*, uint8_t*, ob_char_t,
ob_size_t, void*);
static uint8_t* GetPayloadFromFile(char*, ob_size_t*);

static int TraverseReassembled(Packet* p,
    int (* callback)(DAQ_PktHdr_t*, uint8_t*, void*),
    void* user_data)
{
    ObfuscationCallbackData* callback_data =
        (ObfuscationCallbackData*)user_data;
    int segments = 0;
    Segment* seg;
    ObPacket* op = (ObPacket*)p;

    for (seg = op->seglist; seg != NULL; seg = seg->next)
    {
        if (callback(seg->pkth, seg->data, user_data) != 0)
            return segments;
        segments++;
    }

    return segments;
}

static void ObTestAlloc(void** ptr, int ptr_size, int this_size)
{
    if (ptr == NULL)
        return;

    if (*ptr == NULL)
    {
        *ptr = calloc(1, this_size);
        if (*ptr == NULL)
        {
            fprintf(stderr, "Failed to allocate memory for payload.\n");
            exit(1);
        }
    }
    else
    {
        if (this_size > ptr_size)
        {
            *ptr = realloc(*ptr, this_size);
            if (*ptr == NULL)
            {
                fprintf(stderr, "Failed to allocate memory for payload.\n");
                exit(1);
            }
        }
    }
}

static void CreateObEntries(Packet* p, ob_char_t ob_char,
    ob_size_t ob_offset, ob_size_t ob_length, int reverse, int add_maxlen)
{
    typedef struct _ob_tmp_struct
    { ob_size_t offset; ob_size_t length; } ob_tmp_struct_t;

    ob_size_t offset;
    ob_tmp_struct_t* tmp_struct = NULL;
    int num_tmps = 0;
    int i;

    if (p == NULL)
        return;

    for (offset = (rand() % ob_offset) + 1;
        offset < (p->dsize - ob_offset);
        offset += (rand() % ob_offset) + 1)
    {
        ob_size_t length = rand() % ob_length + 1;

        ObTestAlloc((void**)&tmp_struct, sizeof(ob_tmp_struct_t) * num_tmps,
            sizeof(ob_tmp_struct_t) * (num_tmps + 1));
        tmp_struct[num_tmps].offset = offset;
        tmp_struct[num_tmps].length = length;
        num_tmps++;

        if (add_maxlen && (offset > p->dsize/2))
            obApi->addObfuscationEntry(p, offset, OB_LENGTH_MAX, ob_char);

        if ((offset + length) >= p->dsize)
            break;
    }

    if (reverse)
    {
        for (i = num_tmps - 1; i >= 0; i--)
        {
            obApi->addObfuscationEntry(p, tmp_struct[i].offset,
                tmp_struct[i].length, ob_char);
        }
    }
    else
    {
        for (i = 0; i < num_tmps; i++)
        {
            obApi->addObfuscationEntry(p, tmp_struct[i].offset,
                tmp_struct[i].length, ob_char);
        }
    }
}

static ObRet ObCallback(DAQ_PktHdr_t* pkth, uint8_t* packet_data,
    ob_char_t ob_char, ob_size_t length, void* user_data)
{
    ob_size_t* offset = (ob_size_t*)user_data;

    if (packet_data != NULL)
        memcpy(ob_payload + *offset, packet_data, length);
    else
        memset(ob_payload + *offset, ob_char, length);

    *offset += length;
    return OB_RET_SUCCESS;
}

static uint8_t* GetPayloadFromFile(char* payload_file, ob_size_t* payload_bytes)
{
    uint8_t* payload = NULL;
    FILE* fp;
    ob_size_t bytes;

    if (payload_bytes == NULL)
        return NULL;

    *payload_bytes = 0;

    fp = fopen(payload_file, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Could not open payload file \"%s\": %s\n",
            payload_file, get_error(errno));
        exit(1);
    }

    ObTestAlloc((void**)&payload, 0, PAYLOAD_ALLOC_SIZE);
    while ((bytes = fread(payload + *payload_bytes, sizeof(char),
            PAYLOAD_ALLOC_SIZE, fp)) == PAYLOAD_ALLOC_SIZE)
    {
        ObTestAlloc((void**)&payload, *payload_bytes + bytes,
            *payload_bytes + bytes + bytes);
        *payload_bytes += bytes;
    }

    *payload_bytes += bytes;
    if (*payload_bytes > OB_LENGTH_MAX)
        *payload_bytes = OB_LENGTH_MAX;

    return payload;
}

static uint8_t* GetStaticPayload(ob_char_t ob_char, ob_size_t* payload_bytes)
{
    uint8_t* payload = NULL;
    ob_size_t alloc_size = 1000;
    ob_char_t char1 = 0x00;
    ob_char_t char2 = 0x01;
    ob_char_t c = char1;

    if (c == ob_char)
        c = char2;

    ObTestAlloc((void**)&payload, 0, alloc_size);
    memset(payload, c, alloc_size);

    *payload_bytes = alloc_size;
    return payload;
}

static void SegmentPayload(Packet* p)
{
    ob_size_t length;
    ob_size_t i;
    Segment* last;
    ObPacket* op = (ObPacket*)p;

    for (i = 0; i < p->dsize; i += length)
    {
        Segment* seg = NULL;

        length = rand() % 20 + 1;
        if (i + length > p->dsize)
            length = p->dsize - i;

        ObTestAlloc((void**)&seg, 0, sizeof(Segment));
        ObTestAlloc((void**)&seg->data, 0, length);
        ObTestAlloc((void**)&seg->pkth, 0, sizeof(DAQ_PktHdr_t));

        memcpy(seg->data, p->data + i, length);
        seg->size = length;
        seg->pkth->caplen = length;

        if (op->seglist == NULL)
        {
            op->seglist = seg;
            last = seg;
        }
        else
        {
            last->next = seg;
            last = seg;
        }

        if ((i + length) == p->dsize)
            break;
    }
}

void PrintUsage(char* prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -a (add max length entry)\n");
    fprintf(stderr, "  -c <obfuscation character>\n");
    fprintf(stderr, "  -l <max obfuscation length>\n");
    fprintf(stderr, "  -o <max obfuscation offset>\n");
    fprintf(stderr, "  -p <payload file>\n");
    fprintf(stderr, "  -s (use segmentation)\n");
    fprintf(stderr, "  -r (reverse entries before sorting)\n");
}

int main(int argc, char* argv[])
{
    char c;
    char* payload_file = NULL;
    ob_char_t ob_char = 'X';
    int segment = 0;
    int reverse = 0;
    int add_maxlen = 0;
    ob_size_t ob_offset = 50;
    ob_size_t ob_length = 16;
    uint8_t* payload = NULL;
    ob_size_t payload_bytes = 0;
    ob_size_t offset = 0;
    DAQ_PktHdr_t pkth, * pkthtmp;
    Packet* tmp = PacketManager::encode_new();
    Packet& packet = *tmp;

    while ((c = getopt(argc, argv, "ac:l:o:p:rsh")) != -1)
    {
        switch (c)
        {
        case 'a':
            add_maxlen = 1;
            break;
        case 'c':
            ob_char = (ob_char_t)strtol(optarg, NULL, 0);
            break;
        case 'l':
        {
            int value;
            if (!isdigit(optarg[0]))
            {
                PrintUsage(argv[0]);
                fprintf(stderr, "Obfuscation max length must be a "
                    "positive integer.\n");
                exit(1);
            }
            value = atoi(optarg);
            if (value > UINT16_MAX)
            {
                PrintUsage(argv[0]);
                fprintf(stderr, "Obfuscation max length must be "
                    "less than 65535.\n");
                exit(1);
            }
            ob_length = (ob_size_t)value;
        }
        break;
        case 'o':
        {
            int value;
            if (!isdigit(optarg[0]))
            {
                PrintUsage(argv[0]);
                fprintf(stderr, "Obfuscation offset must be a "
                    "positive integer.\n");
                exit(1);
            }
            value = atoi(optarg);
            if (value > UINT16_MAX)
            {
                PrintUsage(argv[0]);
                fprintf(stderr, "Obfuscation max offset must "
                    "be less than 65535.\n");
                exit(1);
            }
            ob_offset = (ob_size_t)value;
        }
        break;
        case 'p':
            payload_file = strdup(optarg);
            if (payload_file == NULL)
            {
                PrintUsage(argv[0]);
                fprintf(stderr, "Failed to copy payload file.\n");
                exit(1);
            }
            break;
        case 'r':
            reverse = 1;
            break;
        case 's':
            segment = 1;
            break;
        case 'h':
            PrintUsage(argv[0]);
            exit(0);
        default:
            PrintUsage(argv[0]);
            fprintf(stderr, "Invalid option. Use -h for usage.\n");
            exit(1);
        }
    }

    srand(time(NULL));

    if (payload_file != NULL)
    {
        payload = GetPayloadFromFile(payload_file, &payload_bytes);
        if (payload == NULL)
        {
            fprintf(stderr, "Failed to get data from \"%s\"\n", payload_file);
            exit(1);
        }
    }
    else
    {
        payload = GetStaticPayload(ob_char, &payload_bytes);
    }

    ObTestAlloc((void**)&ob_payload, 0, payload_bytes);

    obApi->resetObfuscationEntries();

    packet.reset();
    packet.pseudo_type = 0;
    packet.user_policy_id = 0;
    packet.iplist_id = 0;
    packeet.ps_proto = 0;

    pkthtmp = (DAQ_PktHdr_t*)&packet.pkth;
    pkthtmp = &pkth;
    pkthtmp->caplen = payload_bytes;
    pkthtmp->ts.tv_sec = 0;
    pkthtmp->ts.tv_usec = 0;

    packet.packet_flags |= PKT_PAYLOAD_OBFUSCATE;
    packet.data = payload;
    packet.dsize = payload_bytes;

    CreateObEntries(&packet, ob_char, ob_offset, ob_length,
        reverse, add_maxlen);
    //obApi->printObfuscationEntries();

    if (segment)
    {
        SegmentPayload(&packet);
        if (obApi->payloadObfuscationRequired(&packet))
            obApi->obfuscateStreamSegments(&packet, ObCallback, &offset);
    }
    else
    {
        if (obApi->payloadObfuscationRequired(&packet))
            obApi->obfuscatePayload(&packet, ObCallback, &offset);
    }

    free(payload);
    free(ob_payload);
    if (payload_file != NULL)
        free(payload_file);

    return 0;
}

#endif /* OBFUSCATION_TEST_STANDALONE */

