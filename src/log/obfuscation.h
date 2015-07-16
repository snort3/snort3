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

#ifndef OBFUSCATION_H
#define OBFUSCATION_H

extern "C" {
#include <daq.h>
}
#include "protocols/packet.h"

/*******************************************************************************
 * Macros
 ******************************************************************************/
/* This should be defined to be greater than or equal to the maximum
 * amount of data expected to be obfuscated */
#define OB_LENGTH_MAX  UINT16_MAX

/*******************************************************************************
 * Types
 ******************************************************************************/
typedef uint8_t ob_char_t;
typedef uint16_t ob_size_t;

typedef enum _ObRet
{
    OB_RET_SUCCESS,
    OB_RET_ERROR,
    OB_RET_OVERFLOW
} ObRet;

/*******************************************************************************
 * Callback to use for obfuscating payload or stream segments - see API below.
 *
 * The first chunk of a payload or stream segment whether needing obfuscation
 * or not will pass a valid pcap_pkthdr struct. Subsequent calls will pass NULL
 * for this structure.  This is useful, especially for the stream segment API
 * call to know when a new segment begins.  Any new "payload" will have a valid
 * pcap_pkthdr struct.
 *
 * If the slice sent in has a non-NULL packet data pointer, the data should *NOT*
 * be obfuscated.
 *
 * If the chunk sent in has a NULL packet data pointer, then that chunk of data
 * should be obfuscated with the obfuscation character.
 *
 * The length passed in is the amount of data that should be copied from the
 * packet data pointer or the amount of data that should be written with the
 * obfuscation character.
 *
 * Arguments
 *  DAQ_PktHdr_t *pkth
 *   The pcap header that contains the packet caplen and timestamps
 *  uint8_t *packet_data
 *   A pointer to the current offset into the packet data.  NULL if
 *   obfuscation of the payload slice is required.
 *  ob_char_t ob_char
 *   The obfuscation character to use if packet_data is NULL.
 *  ob_size_t length
 *   The amount of data to be logged or obfuscated.
 *  void *user_data
 *   The user data passed in to the API functions obfuscatePayload() or
 *   obfuscateStreamSegments below.
 *
 * Returns
 *  OB_RET_SUCCESS  if all is good
 *  OB_RET_ERROR  if the rest of the obfuscation should not be done
 *
 ******************************************************************************/
typedef ObRet (* ObfuscationCallback)
(
    const DAQ_PktHdr_t* pkth,
    const uint8_t* packet_data,
    ob_size_t length,
    ob_char_t ob_char,
    void* user_data
);

/*******************************************************************************
 * Obfuscation API
 ******************************************************************************/
typedef struct _ObfuscationApi
{
    /*
     * Resets/clears any entries that have been added
     * Should be done per packet aquisition
     *
     * Arguments
     *  None
     *
     * Returns
     *  None
     */

    void (* resetObfuscationEntries)();

    /*
     * Adds an obfuscation entry to the queue
     *
     * Arguments
     *  Packet *p
     *   The Packet struct that has the payload data that should be obfuscated
     *  ob_size_t offset
     *   The offset from the beginning of the payload to start obfuscation
     *  ob_size_t length
     *   The amount of data to obfuscate
     *  ob_char_t ob_char
     *   The character to use when obfuscating
     *
     * There are two types of entries that can be added.  A slice entry that
     * has an offset and length less than OB_LENGTH_MAX and an entry with
     * length OB_LENGTH_MAX that implies obfuscating from offset to the end
     * of the packet data.
     *
     * NOTE --
     * There is a fixed size of slice entries and OB_LENGTH_MAX entries.
     * If OB_RET_OVERFLOW is returned when attempting to add a slice entry,
     * a second call can be made to add an OB_LENGTH_MAX entry.  Only one
     * OB_LENGTH_MAX entry can be associated with each Packet.  If there is
     * already an OB_LENGTH_MAX entry for the packet, the lower of the two
     * offsets will be used.  Although you should check for OB_RET_OVERFLOW
     * when attempting to add an OB_LENGTH_MAX entry, the fixed size should
     * be more than enough space to store an entry for each possible packet
     * that could be in the system at the time.
     *
     * Returns
     *  OB_RET_SUCCESS on sucess
     *  OB_RET_ERROR  on error
     *  OB_RET_OVERFLOW  if there is no space left to add an entry
     */

    ObRet (* addObfuscationEntry)(Packet* p, ob_size_t offset,
        ob_size_t length, ob_char_t ob_char);

    /*
     * Determines if there are any obfuscation entries associated with
     * the given Packet
     *
     * Arguments
     *  Packet *
     *   The Packet to check
     *
     * Returns
     *  1  if the packet requires obfuscation
     *  0  if it doesn't
     */

    int (* payloadObfuscationRequired)(Packet* p);

    /*
     * Obfuscate the payload associated with the Packet.  Mainly for use by the
     * output system to print or log an obfuscated payload.  The callback will
     * be called for both payload segments that need obfuscation and those that
     * don't.  See comment on ObfuscationCallback above.
     *
     * Arguments
     *  Packet *
     *   The Packet whose payload should be obfuscated
     *  ObfuscationCallback
     *   The function that will be called for each obfuscated and
     *   non-obfuscated segment in the payload
     *  void *
     *   User data that will be passed to the callback
     *
     * Returns
     *  OB_RET_SUCCESS  on sucess
     *  OB_RET_ERROR  on error
     */

    ObRet (* obfuscatePacket)(Packet* p,
        ObfuscationCallback callback, void* user_data);

    /*
     * Obfuscate the stream segments associated with the Packet.  Mainly for use
     * by the output system to print or log the stream segments associated with
     * a Packet that have been marked as needing obfuscation.  The callback will
     * be called for both stream segments that need obfuscation and those that
     * don't.  It will be called for all stream segments.  See comment on
     * ObfuscationCallback above.
     *
     * Arguments
     *  Packet *
     *   The Packet whose stream segments should be obfuscated
     *  ObfuscationCallback
     *   The function that will be called for each obfuscated and
     *   non-obfuscated part of the stream segments.
     *  void *
     *   User data that will be passed to the callback
     *
     * Returns
     *  OB_RET_SUCCESS  on sucess
     *  OB_RET_ERROR  on error
     */

    ObRet (* obfuscatePacketStreamSegments)(Packet* p,
        ObfuscationCallback callback, void* user_data);

    /*
     * Obfuscates the Packet payload and returns payload and payload length
     * in parameters
     *
     * NOTE
     * *payload will be set to NULL, so don't pass in an already
     *      allocated pointer.
     * *payload_len will be zeroed.
     *
     * The payload returned is dynamically allocated and MUST be free'd.
     *
     * Arguments
     *  Packet *
     *   The Packet whose payload should be obfuscated
     *  uint8_t **payload
     *   A pointer to a payload pointer so it can be allocated, returned
     *   and accessed.
     *  ob_size_t *payload_len
     *   A pointer to an ob_size_t so the length can be returned.
     *
     * Returns
     *  OB_RET_ERROR  if the payload could not be obfuscated
     *                the pointers to payload and payload_len will not be valid
     *  OB_RET_SUCCESS  if the payload was obfuscated
     *                  the pointers to payload and payload_len will be valid
     */

    ObRet (* getObfuscatedPayload)(Packet* p, uint8_t** payload,
        ob_size_t* payload_len);

    /*
     * Prints the current obfuscation entries.
     *
     * Arguments
     *  int sorted
     *   Print the sorted entries and sort if necessary.
     *
     * Returns
     *  None
     */

    void (* printObfuscationEntries)(int sorted);
} ObfuscationApi;

/* For access when including header */
extern ObfuscationApi* obApi;

#endif

