//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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
// gtp_parser.cc author Hui Cao <hcao@sourcefire.com>

// parses gtp control messages

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gtp_parser.h"

#include <arpa/inet.h>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"

#include "gtp.h"
#include "gtp_inspect.h"
#include "gtp_module.h"

#pragma pack(1)
static inline void alert(int sid)
{
    DetectionEngine::queue_event(GID_GTP, sid);
    gtp_stats.events++;
}

/* GTP basic Header  */
struct GTP_C_Hdr
{
    uint8_t flag;               /* flag: version (bit 6-8), PT (5), E (3), S (2), PN (1) */
    uint8_t type;               /* message type */
    uint16_t length;            /* length */
};

struct GTP_C_Hdr_v0
{
    GTP_C_Hdr hdr;
    uint16_t sequence_num;
    uint16_t flow_lable;
    uint64_t tid;
};

/* GTP Information element Header  */
struct GTP_IE_Hdr
{
    uint8_t type;
    uint16_t length;            /* length */
};
#pragma pack()

#define GTP_HEADER_LEN_V0       (20)
#define GTP_HEADER_LEN_V1       (12)
#define GTP_HEADER_LEN_V2       (8)
#define GTP_HEADER_LEN_EPC_V2   (12)
#define GTP_LENGTH_OFFSET_V0    (GTP_HEADER_LEN_V0)
#define GTP_LENGTH_OFFSET_V1    (8)
#define GTP_LENGTH_OFFSET_V2    (4)

#define GTP_MIN_HEADER_LEN      (8)

#ifdef DEBUG_MSGS
/*Display the content*/
static void convertToHex(char* output, int outputSize, const uint8_t* input, int inputSize)
{
    int i = 0;
    int length;
    int numBytesInLine = 0;
    int totalBytes = outputSize;
    char* buf_ptr = output;

    while ((i < inputSize)&&(totalBytes > 0))
    {
        length = snprintf(buf_ptr, totalBytes, "%.2x ", (uint8_t)input[i]);
        buf_ptr += length;
        totalBytes -= length;
        if (totalBytes < 0)
            break;
        numBytesInLine += length;

        if (numBytesInLine > 80)
        {
            snprintf(buf_ptr++, totalBytes, "\n");
            totalBytes--;
            numBytesInLine = 0;
        }
        i++;
    }
}

/* Display the information elements*/
static void printInfoElements(GTP_IEData* info_elements, GTPMsg* msg)
{
    int i;

    for (i=0; i < MAX_GTP_IE_CODE + 1; i++)
    {
        char buf[STD_BUF];
        if (info_elements[i].msg_id == msg->msg_id)
        {
            convertToHex( (char*)buf, sizeof(buf),
                msg->gtp_header + info_elements[i].shift, info_elements[i].length);
            DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Info type: %.3d, content: %s\n", i, buf); );
        }
    }
}
#endif

static int gtp_processInfoElements(
    const GTPConfig& config, GTPMsg* msg, const uint8_t* buff, uint16_t len)
{
    uint8_t* start;
    uint8_t type;
    int32_t unprocessed_len;
    uint8_t previous_type;

    DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Information elements: length: %d\n", len); );

    start = (uint8_t*)buff;
    previous_type = (uint8_t)*start;
    unprocessed_len = len;

    while ( unprocessed_len > 0)
    {
        type =  *start;

        if (previous_type  >  type)
            alert(GTP_EVENT_OUT_OF_ORDER_IE);

        const GTP_InfoElement* ie = &config.infov[msg->version][type];
        uint16_t length;

        if ( NULL == ie )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_GTP, "Unsupported Information elements!\n"); );
            gtp_stats.unknownIEs++;
            return false;
        }

        /*For fixed length, use the table*/
        if (ie->length)
        {
            length = ie->length;
        }
        else /*For variable length, use the length field*/
        {
            GTP_IE_Hdr* ieHdr;
            /*check the length before reading*/
            if (sizeof(*ieHdr) > (unsigned)unprocessed_len)
            {
                alert(GTP_EVENT_BAD_IE_LEN);
                return false;
            }
            ieHdr = (GTP_IE_Hdr*)start;
            length = ntohs(ieHdr->length);
            /*Check the length */
            if (length > UINT16_MAX - GTP_MIN_HEADER_LEN - sizeof(*ieHdr))
            {
                alert(GTP_EVENT_BAD_IE_LEN);
                return false;
            }

            if (msg->version == 2)
                length += 4;
            else
                length += 3;
        }

        if (length > unprocessed_len )
        {
            alert(GTP_EVENT_BAD_IE_LEN);
            return false;
        }

        /*Combine the same information element type into one buffer*/
        if ((previous_type == type) && (msg->info_elements[type].msg_id == msg->msg_id))
        {
            msg->info_elements[type].length += length;
        }
        else
        {
            msg->info_elements[type].length = length;
            msg->info_elements[type].shift = start - msg->gtp_header;
            msg->info_elements[type].msg_id = msg->msg_id;
        }

        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "GTP information element: %s(%d), length: %d\n",
            ie->name.c_str(), type, length));
        start += length;
        unprocessed_len -= length;
        previous_type = type;
    }
    DEBUG_WRAP(printInfoElements(msg->info_elements, msg); );
    return true;
}

/********************************************************************
 * Function: gtp_parse_v0()
 *
 * process the GTP v0 message.
 *
 * Arguments:
 *  GTPMsg *   - gtp message
 *  char* buff - start of the gtp message buffer
 *  uint16_t   - length of the message
 *
 * Returns:
 *  false
 *  true
 *          Bits
 *Octets  8   7   6   5   4   3   2   1
 *1       Version     PT  1   1   1   SNN
 *2       Message Type
 *3-4     Length
 *5-6     Sequence Number
 *7-8     Flow Label
 *9       SNDCP N-PDULLC Number
 *10      Spare ‘ 1 1 1 1 1 1 1 1 ‘
 *11      Spare ‘ 1 1 1 1 1 1 1 1 ‘
 *12      Spare ‘ 1 1 1 1 1 1 1 1 ‘
 *13-20   TID
 *
 ********************************************************************/

static int gtp_parse_v0(GTPMsg* msg, const uint8_t* buff, uint16_t gtp_len)
{
    GTP_C_Hdr* hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_GTP, "This is a GTP v0 packet.\n"); );

    hdr = (GTP_C_Hdr*)buff;

    msg->header_len = GTP_HEADER_LEN_V0;

    /*Check the length field. */
    if (gtp_len != ((unsigned int)ntohs(hdr->length) + GTP_LENGTH_OFFSET_V0))
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Calculated length %d != %d in header.\n",
            gtp_len - GTP_LENGTH_OFFSET_V0, ntohs(hdr->length)); );
        alert(GTP_EVENT_BAD_MSG_LEN);
        return false;
    }

    return true;
}

/********************************************************************
 * Function: gtp_parse_v1()
 *
 * process the GTP v1 message.
 *
 * Arguments:
 *  GTPMsg *   - gtp message
 *  char* buff - start of the gtp message buffer
 *  uint16_t   - length of the message
 *
 * Returns:
 *  false
 *  true
 *
 * Octets  8   7   6   5   4   3   2   1
 * 1       Version     PT  (*) E   S   PN
 * 2       Message Type
 * 3       Length (1st Octet)
 * 4       Length (2nd Octet)
 * 5       Tunnel Endpoint Identifier (1st Octet)
 * 6       Tunnel Endpoint Identifier (2nd Octet)
 * 7       Tunnel Endpoint Identifier (3rd Octet)
 * 8       Tunnel Endpoint Identifier (4th Octet)
 * 9       Sequence Number (1st Octet)
 * 10      Sequence Number (2nd Octet)
 * 11      N-PDU Number
 * 12      Next Extension Header Type
 ********************************************************************/
static int gtp_parse_v1(GTPMsg* msg, const uint8_t* buff, uint16_t gtp_len)
{
    uint8_t next_hdr_type;
    GTP_C_Hdr* hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_GTP, "This ia a GTP v1 packet.\n"); );

    hdr = (GTP_C_Hdr*)buff;

    /*Check the length based on optional fields and extension header*/
    if (hdr->flag & 0x07)
    {
        msg->header_len = GTP_HEADER_LEN_V1;
        /*Check optional fields*/
        if (gtp_len < msg->header_len)
        {
            alert(GTP_EVENT_BAD_MSG_LEN);
            return false;
        }

        next_hdr_type = *(buff + msg->header_len - 1);

        /*Check extension headers*/
        while (next_hdr_type)
        {
            uint16_t ext_header_len;

            /*check length before reading data, at lease 4 bytes per extension header*/
            if (gtp_len < msg->header_len + 4)
            {
                alert(GTP_EVENT_BAD_MSG_LEN);
                return false;
            }

            ext_header_len = *(buff + msg->header_len);

            if (!ext_header_len)
            {
                alert(GTP_EVENT_BAD_MSG_LEN);
                return false;
            }

            /*Extension header length is a unit of 4 octets*/
            msg->header_len += ext_header_len*4;

            /*check length before reading data*/
            if (gtp_len < msg->header_len)
            {
                alert(GTP_EVENT_BAD_MSG_LEN);
                return false;
            }
            next_hdr_type = *(buff + msg->header_len - 1);
        }
    }
    else
        msg->header_len = GTP_HEADER_LEN_V1;

    /*Check the length field. */
    if (gtp_len != ((unsigned int)ntohs(hdr->length) + GTP_LENGTH_OFFSET_V1))
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Calculated length %d != %d in header.\n",
            gtp_len - GTP_LENGTH_OFFSET_V1, ntohs(hdr->length)); );
        alert(GTP_EVENT_BAD_MSG_LEN);
        return false;
    }

    return true;
}

/********************************************************************
 * Function: gtp_parse_v2()
 *
 * process the GTP v2 message.
 *
 * Arguments:
 *  GTPMsg *   - gtp message
 *  char* buff - start of the gtp message buffer
 *  uint16_t   - length of the message
 *
 * Returns:
 *  false
 *  true
 *
 *Octets      8   7   6   5   4   3      2      1
 *1           Version     P   T   Spare  Spare  Spare
 *2           Message Type
 *3           Message Length (1st Octet)
 *4           Message Length (2nd Octet)
 *m to k(m+3) If T flag is set to 1, then TEID shall be placed into octets 5-8.
 *            Otherwise, TEID field is not present at all.
 *n to (n+2)  Sequence Number
 *(n+3)       Spare
 ********************************************************************/
static int gtp_parse_v2(GTPMsg* msg, const uint8_t* buff, uint16_t gtp_len)
{
    GTP_C_Hdr* hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_GTP, "This ia a GTP v2 packet.\n"); );

    hdr = (GTP_C_Hdr*)buff;

    if (hdr->flag & 0x8)
        msg->header_len = GTP_HEADER_LEN_EPC_V2;
    else
        msg->header_len = GTP_HEADER_LEN_V2;

    /*Check the length field. */
    if (gtp_len != ((unsigned int)ntohs(hdr->length) + GTP_LENGTH_OFFSET_V2))
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Calculated length %d != %d in header.\n",
            gtp_len - GTP_LENGTH_OFFSET_V2, ntohs(hdr->length)); );
        alert(GTP_EVENT_BAD_MSG_LEN);
        return false;
    }

    return true;
}

/********************************************************************
 * Function: gtp_parse()
 *
 * The main entry for parser: process the gtp messages.
 *
 * Arguments:
 *  GTPMsg *   - gtp message
 *  char* buff - start of the gtp message buffer
 *  uint16_t   - length of the message
 *
 * Returns:
 *  false
 *  true
 ********************************************************************/
int gtp_parse(const GTPConfig& config, GTPMsg* msg, const uint8_t* buff, uint16_t gtp_len)
{
    DEBUG_WRAP(DebugMessage(DEBUG_GTP, "Start parsing...\n"));

    /*Check the length*/
    DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Basic header length: %d\n", GTP_MIN_HEADER_LEN));
    if (gtp_len < GTP_MIN_HEADER_LEN)
        return false;

    /*The first 3 bits are version number*/
    GTP_C_Hdr* hdr = (GTP_C_Hdr*)buff;
    msg->version = (hdr->flag & 0xE0) >> 5;
    msg->msg_type = hdr->type;
    msg->gtp_header = (uint8_t*)buff;

    if (msg->version > MAX_GTP_VERSION_CODE)
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Unsupported GTP version: %d!\n",msg->version); );
        return false;
    }
    /*Check whether this is GTP or GTP', Exit if GTP'*/
    if (!(hdr->flag & 0x10))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_GTP, "Unsupported GTP'!\n"); );
        return false;
    }

    const GTP_MsgType* msgType = &config.msgv[msg->version][msg->msg_type];

    if ( NULL == msgType )
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "Unsupported GTP message type: %d!\n",msg->msg_type); );
        gtp_stats.unknownTypes++;
        return false;
    }
    else
    {
        DEBUG_WRAP(DebugFormat(DEBUG_GTP, "GTP version: %d, message type: %s(%d)\n",
            msg->version, msgType->name.c_str(), msg->msg_type));
    }

    // FIXIT-L need to implement stats retrieval from module
    //gtp_stats.messages[msg->version][msg->msg_type]++;

    /* We only care about control types*/
    if ( hdr->type == 255)
        return false;

    bool status = true;

    switch (msg->version)
    {
    case 0: /*GTP v0*/
        status = gtp_parse_v0(msg, buff, gtp_len);
        break;

    case 1: /*GTP v1*/
        status = gtp_parse_v1(msg, buff, gtp_len);
        break;

    case 2: /*GTP v2 */
        status = gtp_parse_v2(msg, buff, gtp_len);
        break;

    default:
        DEBUG_WRAP(DebugMessage(DEBUG_GTP, "Unknown protocol version.\n"); );
        return false;
    }

    /*Parse information elements*/
    if ((msg->header_len < gtp_len)&& (true == status))
    {
        msg->info_elements = get_infos();
        buff += msg->header_len;
        status = gtp_processInfoElements(
            config, msg, buff, (uint16_t)(gtp_len - msg->header_len));
    }
    return status;
}

