/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
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

/* unified2.c
 * Adam Keeton
 *
 * 09/26/06
 * This file is litterally unified.c converted to write unified2
 *
 */

#include "loggers/unified2_common.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <string>

#include "framework/logger.h"
#include "framework/module.h"
#include "decode.h" /* for struct in6_addr -- maybe move to snort_types.h? */
#include "snort_types.h"
#include "main/analyzer.h"
#include "decode.h"
#include "rules.h"
#include "treenodes.h"
#include "util.h"
#include "parser.h"
#include "snort_debug.h"
#include "mstring.h"
#include "event.h"
#include "snort_debug.h"
#include "snort_bounds.h"
#include "obfuscation.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "detection_util.h"
#include "detect.h"
#include "snort.h"
#include "stream/stream_api.h"

using namespace std;

/* ------------------ Data structures --------------------------*/
typedef struct _Unified2Config
{
    string base_filename;
    unsigned int limit;
    int nostamp;
    int mpls_event_types;
    int vlan_event_types;
} Unified2Config;

typedef struct _Unified2LogCallbackData
{
    Serial_Unified2Packet *logheader;
    Unified2Config *config;
    Event *event;
    uint32_t num_bytes;

} Unified2LogCallbackData;

struct U2
{
    int base_proto;
    uint32_t timestamp;
    char filepath[STD_BUF];
    FILE* stream;
    unsigned int current;
};

/* -------------------- Global Variables ----------------------*/

static THREAD_LOCAL U2 u2;

/* Used for buffering header and payload of unified records so only one
 * write is necessary. */
constexpr unsigned u2_buf_sz = 
    sizeof(Serial_Unified2_Header) + sizeof(Unified2IDSEventIPv6) + IP_MAXPACKET;

// TBD - is performance any better if these buffers are off the heap?
static THREAD_LOCAL uint8_t write_pkt_buffer[u2_buf_sz];

#define write_pkt_end (write_pkt_buffer + u2_buf_sz)

#define MAX_XDATA_WRITE_BUF_LEN (MAX_XFF_WRITE_BUF_LENGTH - \
        sizeof(struct in6_addr) + DECODE_BLEN)

/* This buffer is used in lieu of the underlying default stream buf to
 * prevent flushing in the middle of a record.  Every write is force
 * flushed to disk immediately after the entire record is written so
 * spoolers get an entire record */

/* use the size of the buffer we copy record data into */
static THREAD_LOCAL char io_buffer[u2_buf_sz];

/* -------------------- Local Functions -----------------------*/

/* Unified2 Output functions */
static void Unified2InitFile(Unified2Config *);
static inline void Unified2RotateFile(Unified2Config *);
static void _Unified2LogPacketAlert(Packet *, const char *, Unified2Config *, Event *);
static void _Unified2LogStreamAlert(Packet *, const char *, Unified2Config *, Event *);
static int Unified2LogStreamCallback(DAQ_PktHdr_t *, uint8_t *, void *);
static void Unified2Write(uint8_t *, uint32_t, Unified2Config *);

static void _AlertIP4_v2(Packet *, const char*, Unified2Config*, Event *);
static void _AlertIP6_v2(Packet *, const char*, Unified2Config*, Event *);

static ObRet Unified2LogObfuscationCallback(const DAQ_PktHdr_t *pkth,
        const uint8_t *packet_data, ob_size_t length, ob_char_t ob_char, void *userdata);

static void AlertExtraData(Flow*, void *data, LogFunction *log_funcs, uint32_t max_count, uint32_t xtradata_mask, uint32_t event_id, uint32_t event_second);

#define U2_PACKET_FLAG 1
/* Obsolete flag as UI wont check the impact_flag field anymore.*/
#define U2_FLAG_BLOCKED 0x20
/* New flags to set the pad field (corresponds to blocked column in UI) with packet action*/
#define U2_BLOCKED_FLAG_BLOCKED 0x01
#define U2_BLOCKED_FLAG_WDROP 0x02

/*
 * Function: Unified2InitFile()
 *
 * Purpose: Initialize the unified2 ouput file
 *
 * Arguments: config => pointer to the plugin's reference data struct
 *
 * Returns: void function
 */
static void Unified2InitFile(Unified2Config *config)
{
    char filepath[STD_BUF];
    char *fname_ptr;

    if (config == NULL)
    {
        FatalError("%s(%d) Could not initialize unified2 file: Unified2 "
                   "configuration data is NULL.\n", __FILE__, __LINE__);
    }

    u2.timestamp = (uint32_t)time(NULL);

    if (!config->nostamp)
    {
        if (SnortSnprintf(filepath, sizeof(filepath), "%s.%u",
                          u2.filepath, u2.timestamp) != SNORT_SNPRINTF_SUCCESS)
        {
            FatalError("%s(%d) Failed to copy unified2 file path.\n",
                       __FILE__, __LINE__);
        }

        fname_ptr = filepath;
    }
    else
    {
        fname_ptr = u2.filepath;
    }

    // FIXIT should use open() instead of fopen()
    if ((u2.stream = fopen(fname_ptr, "wb")) == NULL)
    {
        FatalError("%s(%d) Could not open %s: %s\n",
                   __FILE__, __LINE__, fname_ptr, get_error(errno));
    }

    /* Set buffer to size of record buffer so the system doesn't flush
     * part of a record if it's greater than BUFSIZ */
    if (setvbuf(u2.stream, io_buffer, _IOFBF, sizeof(io_buffer)) != 0)
    {
        ErrorMessage("%s(%d) Could not set I/O buffer: %s. "
                     "Using system default.\n",
                     __FILE__, __LINE__, get_error(errno));
    }

    /* If test mode, close and delete the file */
    if (ScTestMode())  // FIXIT eliminate test check; should always remove if empty
    {
        fclose(u2.stream);
        u2.stream = NULL;
        if (unlink(fname_ptr) == -1)
        {
            ErrorMessage("%s(%d) Running in test mode so we want to remove "
                         "test unified2 file. Could not unlink file \"%s\": %s\n",
                         __FILE__, __LINE__, fname_ptr, get_error(errno));
        }
    }
}

static inline void Unified2RotateFile(Unified2Config *config)
{
    fclose(u2.stream);
    u2.current = 0;
    Unified2InitFile(config);
}

static void _AlertIP4_v2(Packet *p, const char*, Unified2Config *config, Event *event)
{
    Serial_Unified2_Header hdr;
    Unified2IDSEvent alertdata;
    uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Unified2IDSEvent);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_info->generator);
    alertdata.signature_id = htonl(event->sig_info->id);
    alertdata.signature_revision = htonl(event->sig_info->rev);
    alertdata.classification_id = htonl(event->sig_info->class_id);
    alertdata.priority_id = htonl(event->sig_info->priority);

    if(p)
    {
        if ( Active_PacketWasDropped() )
        {
            if (DAQ_GetInterfaceMode(p->pkth) == DAQ_MODE_INLINE)
            {
                alertdata.impact_flag = U2_FLAG_BLOCKED;
                alertdata.blocked = U2_BLOCKED_FLAG_BLOCKED;
            }
            else
            {
                // Set would be dropped if not inline interface
                alertdata.blocked = U2_BLOCKED_FLAG_WDROP;
            }
        }
        else if ( Active_PacketWouldBeDropped() )
        {
            alertdata.blocked = U2_BLOCKED_FLAG_WDROP;
        }

        if(IPH_IS_VALID(p))
        {
            alertdata.ip_source = p->iph->ip_src.s_addr;
            alertdata.ip_destination = p->iph->ip_dst.s_addr;
            alertdata.protocol = GetEventProto(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (!IsPortscanPacket(p))
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }

            if((p->mpls) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->mplsHdr.label);
            }
            if(config->vlan_event_types)
            {
                if(p->vh)
                {
                    alertdata.vlanId = htons(VTH_VLAN(p->vh));
                }

                alertdata.pad2 = htons(p->user_policy_id);
            }

        }
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2IDSEvent));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_VLAN);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
                   &alertdata, sizeof(Unified2IDSEvent),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2IDSEvent. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer, write_len, config);
}

static void _AlertIP6_v2(Packet *p, const char*, Unified2Config *config, Event *event)
{
    Serial_Unified2_Header hdr;
    Unified2IDSEventIPv6 alertdata;
    uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Unified2IDSEventIPv6);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_info->generator);
    alertdata.signature_id = htonl(event->sig_info->id);
    alertdata.signature_revision = htonl(event->sig_info->rev);
    alertdata.classification_id = htonl(event->sig_info->class_id);
    alertdata.priority_id = htonl(event->sig_info->priority);

    if(p)
    {
        if ( Active_PacketWasDropped() )
        {
            if (DAQ_GetInterfaceMode(p->pkth) == DAQ_MODE_INLINE)
            {
                alertdata.impact_flag = U2_FLAG_BLOCKED;
                alertdata.blocked = U2_BLOCKED_FLAG_BLOCKED;
            }
            else
            {
                // Set would be dropped if not inline interface
                alertdata.blocked = U2_BLOCKED_FLAG_WDROP;
            }
        }
        else if ( Active_PacketWouldBeDropped() )
        {
            alertdata.blocked = U2_BLOCKED_FLAG_WDROP;
        }

        if(IPH_IS_VALID(p))
        {
            snort_ip_p ip;

            ip = GET_SRC_IP(p);
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;

            ip = GET_DST_IP(p);
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;

            alertdata.protocol = GetEventProto(p);

            if ((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else if (!IsPortscanPacket(p))
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }

            if((p->mpls) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->mplsHdr.label);
            }
            if(config->vlan_event_types)
            {
                if(p->vh)
                {
                    alertdata.vlanId = htons(VTH_VLAN(p->vh));
                }

                alertdata.pad2 = htons(p->user_policy_id);
            }
        }
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2IDSEventIPv6));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_VLAN);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
                   &alertdata, sizeof(Unified2IDSEventIPv6),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2IDSEventIPv6. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_pkt_buffer, write_len, config);
}

void _WriteExtraData(Unified2Config *config, uint32_t event_id, uint32_t event_second, uint8_t *buffer, uint32_t len, uint32_t type )
{

    Serial_Unified2_Header hdr;
    SerialUnified2ExtraData alertdata;
    Unified2ExtraDataHdr alertHdr;
    uint8_t write_buffer[MAX_XDATA_WRITE_BUF_LEN];
    uint8_t *write_end = NULL;
    uint8_t *ptr = NULL;


    uint32_t write_len;

    write_len = sizeof(Serial_Unified2_Header) + sizeof(Unified2ExtraDataHdr);

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event_id);
    alertdata.event_second = htonl(event_second);
    alertdata.data_type = htonl(EVENT_DATA_TYPE_BLOB);

    alertdata.type = htonl(type);
    alertdata.blob_length = htonl(sizeof(alertdata.data_type) +
                sizeof(alertdata.blob_length) + len);


    write_len = write_len + sizeof(alertdata) + len;
    alertHdr.event_type = htonl(EVENT_TYPE_EXTRA_DATA);
    alertHdr.event_length = htonl(write_len - sizeof(Serial_Unified2_Header));


    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(write_len - sizeof(Serial_Unified2_Header));
    hdr.type = htonl(UNIFIED2_EXTRA_DATA);

    write_end = write_buffer + sizeof(write_buffer);


    ptr = write_buffer;

    if (SafeMemcpy(ptr, &hdr, sizeof(hdr),
                   write_buffer, write_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    ptr = ptr +  sizeof(hdr);

    if (SafeMemcpy(ptr, &alertHdr, sizeof(alertHdr),
                   write_buffer, write_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Unified2ExtraDataHdr. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    ptr = ptr + sizeof(alertHdr);

    if (SafeMemcpy(ptr, &alertdata, sizeof(alertdata),
                   write_buffer, write_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy SerialUnified2ExtraData. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    ptr = ptr + sizeof(alertdata);

    if (SafeMemcpy(ptr, buffer, len,
                write_buffer, write_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Gzip Decompressed Buffer. "
                "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    Unified2Write(write_buffer, write_len, config);
}

static void AlertExtraData(
    Flow* flow, void *data,
    LogFunction *log_funcs, uint32_t max_count,
    uint32_t xtradata_mask,
    uint32_t event_id, uint32_t event_second)
{
    Unified2Config *config = (Unified2Config *)data;
    uint32_t xid;

    if((config == NULL) || !xtradata_mask || !event_second)
        return;

    xid = ffs(xtradata_mask);

    while ( xid && (xid <= max_count) )
    {
        uint32_t len = 0;
        uint32_t type = 0;
        uint8_t *write_buffer;

        if ( log_funcs[xid-1](flow, &write_buffer, &len, &type) && (len > 0) )
        {
            _WriteExtraData(config, event_id, event_second, write_buffer, len, type);
        }
        xtradata_mask ^= BIT(xid);
        xid = ffs(xtradata_mask);
    }
}

static void _Unified2LogPacketAlert(
    Packet *p, const char*, Unified2Config *config, Event *event)
{
    Serial_Unified2_Header hdr;
    Serial_Unified2Packet logheader;
    uint32_t pkt_length = 0;
    uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Serial_Unified2Packet) - 4;

    logheader.sensor_id = 0;
    logheader.linktype = u2.base_proto;

    if (event != NULL)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n"));
    }
    else
    {
        logheader.event_id = 0;
        logheader.event_second = 0;
    }

    if ((p != NULL) && (p->pkt != NULL) && (p->pkth != NULL)
            && obApi->payloadObfuscationRequired(p))
    {
        Unified2LogCallbackData unifiedData;

        unifiedData.logheader = &logheader;
        unifiedData.config = config;
        unifiedData.event = event;
        unifiedData.num_bytes = 0;

        if (obApi->obfuscatePacket(p, Unified2LogObfuscationCallback,
                (void *)&unifiedData) == OB_RET_SUCCESS)
        {
            /* Write the last record */
            if (unifiedData.num_bytes != 0)
                Unified2Write(write_pkt_buffer, unifiedData.num_bytes, config);
            return;
        }
    }

    if(p && p->pkt && p->pkth)
    {
        logheader.packet_second = htonl((uint32_t)p->pkth->ts.tv_sec);
        logheader.packet_microsecond = htonl((uint32_t)p->pkth->ts.tv_usec);
        logheader.packet_length = htonl(p->pkth->caplen);

        pkt_length = p->pkth->caplen;
        write_len += pkt_length;
    }
    else
    {
        logheader.packet_second = 0;
        logheader.packet_microsecond = 0;
        logheader.packet_length = 0;
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Serial_Unified2Packet) - 4 + pkt_length);
    hdr.type = htonl(UNIFIED2_PACKET);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
                   &logheader, sizeof(Serial_Unified2Packet) - 4,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2Packet. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return;
    }

    if (pkt_length != 0)
    {
        if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header) +
                       sizeof(Serial_Unified2Packet) - 4,
                       p->pkt, pkt_length,
                       write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to copy packet data. "
                         "Not writing unified2 event.\n", __FILE__, __LINE__);
            return;
        }
    }

    Unified2Write(write_pkt_buffer, write_len, config);
}

/**
 * Callback for the Stream reassembler to log packets
 *
 */
static int Unified2LogStreamCallback(DAQ_PktHdr_t *pkth,
                                     uint8_t *packet_data, void *userdata)
{
    Unified2LogCallbackData *unifiedData = (Unified2LogCallbackData *)userdata;
    Serial_Unified2_Header hdr;
    uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Serial_Unified2Packet) - 4;

    if (!userdata || !pkth || !packet_data)
        return -1;

    write_len += pkth->caplen;

    if ( unifiedData->config->limit &&
        (u2.current + write_len) > unifiedData->config->limit )
        Unified2RotateFile(unifiedData->config);

    hdr.type = htonl(UNIFIED2_PACKET);
    hdr.length = htonl(sizeof(Serial_Unified2Packet) - 4 + pkth->caplen);

    /* Event data will already be set */

    unifiedData->logheader->packet_second = htonl((uint32_t)pkth->ts.tv_sec);
    unifiedData->logheader->packet_microsecond = htonl((uint32_t)pkth->ts.tv_usec);
    unifiedData->logheader->packet_length = htonl(pkth->caplen);

    if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
                   unifiedData->logheader, sizeof(Serial_Unified2Packet) - 4,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy Serial_Unified2Packet. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header) +
                   sizeof(Serial_Unified2Packet) - 4,
                   packet_data, pkth->caplen,
                   write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
    {
        ErrorMessage("%s(%d) Failed to copy packet data. "
                     "Not writing unified2 event.\n", __FILE__, __LINE__);
        return -1;
    }

    Unified2Write(write_pkt_buffer, write_len, unifiedData->config);

    return 0;
}

static ObRet Unified2LogObfuscationCallback(const DAQ_PktHdr_t *pkth,
        const uint8_t *packet_data, ob_size_t length,
        ob_char_t ob_char, void *userdata)
{
    Unified2LogCallbackData *unifiedData = (Unified2LogCallbackData *)userdata;

    if (userdata == NULL)
        return OB_RET_ERROR;

    if (pkth != NULL)
    {
        Serial_Unified2_Header hdr;
        uint32_t record_len = (pkth->caplen + sizeof(Serial_Unified2_Header)
                + (sizeof(Serial_Unified2Packet) - 4));

        /* Write the last buffer if present.  Want to write an entire record
         * at a time in case of failures, we don't corrupt the log file. */
        if (unifiedData->num_bytes != 0)
            Unified2Write(write_pkt_buffer, unifiedData->num_bytes, unifiedData->config);

        if ((write_pkt_buffer + record_len) > write_pkt_end)
        {
            ErrorMessage("%s(%d) Too much data. Not writing unified2 event.\n",
                    __FILE__, __LINE__);
            return OB_RET_ERROR;
        }

        if ( unifiedData->config->limit &&
            (u2.current + record_len) > unifiedData->config->limit )
            Unified2RotateFile(unifiedData->config);

        hdr.type = htonl(UNIFIED2_PACKET);
        hdr.length = htonl((sizeof(Serial_Unified2Packet) - 4) + pkth->caplen);

        /* Event data will already be set */

        unifiedData->logheader->packet_second = htonl((uint32_t)pkth->ts.tv_sec);
        unifiedData->logheader->packet_microsecond = htonl((uint32_t)pkth->ts.tv_usec);
        unifiedData->logheader->packet_length = htonl(pkth->caplen);

        if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
                    write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to copy Serial_Unified2_Header. "
                    "Not writing unified2 event.\n", __FILE__, __LINE__);
            return OB_RET_ERROR;
        }

        if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
                    unifiedData->logheader, sizeof(Serial_Unified2Packet) - 4,
                    write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to copy Serial_Unified2Packet. "
                    "Not writing unified2 event.\n", __FILE__, __LINE__);
            return OB_RET_ERROR;
        }

        /* Reset this for the new record */
        unifiedData->num_bytes = (record_len - pkth->caplen);
    }

    if (packet_data != NULL)
    {
        if (SafeMemcpy(write_pkt_buffer + unifiedData->num_bytes,
                    packet_data, (size_t)length,
                    write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to copy packet data "
                    "Not writing unified2 event.\n", __FILE__, __LINE__);
            return OB_RET_ERROR;
        }
    }
    else
    {
        if (SafeMemset(write_pkt_buffer + unifiedData->num_bytes,
                    (uint8_t)ob_char, (size_t)length,
                    write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
        {
            ErrorMessage("%s(%d) Failed to obfuscate packet data "
                    "Not writing unified2 event.\n", __FILE__, __LINE__);
            return OB_RET_ERROR;
        }
    }

    unifiedData->num_bytes += length;

    return OB_RET_SUCCESS;
}


/**
 * Log a set of packets stored in the stream reassembler
 *
 */
static void _Unified2LogStreamAlert(
    Packet *p, const char*, Unified2Config *config, Event *event)
{
    Unified2LogCallbackData unifiedData;
    Serial_Unified2Packet logheader;

    logheader.sensor_id = 0;
    logheader.linktype = u2.base_proto;

    /* setup the event header */
    if (event != NULL)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);
    }
    else
    {
        logheader.event_id = 0;
        logheader.event_second = 0;
    }

    /* queue up the stream for logging */
    unifiedData.logheader = &logheader;
    unifiedData.config = config;
    unifiedData.event = event;
    unifiedData.num_bytes = 0;

    if ((p != NULL) && (p->pkt != NULL) && (p->pkth != NULL)
            && obApi->payloadObfuscationRequired(p))
    {
        if (obApi->obfuscatePacketStreamSegments(p, Unified2LogObfuscationCallback,
                (void *)&unifiedData) == OB_RET_SUCCESS)
        {
            /* Write the last record */
            if (unifiedData.num_bytes != 0)
                Unified2Write(write_pkt_buffer, unifiedData.num_bytes, config);
            return;
        }

        /* Reset since we failed */
        unifiedData.num_bytes = 0;
    }

    if (!p)
        return;

    stream.traverse_reassembled(p, Unified2LogStreamCallback, &unifiedData);
}

/******************************************************************************
 * Function: Unified2Write()
 *
 * Main function for writing to the unified2 file.
 *
 * For low level I/O errors, the current unified2 file is closed and a new
 * one created and a write to the new unified2 file is done.  It was found
 * that when writing to an NFS mounted share that is using a soft mount option,
 * writes sometimes fail and leave the unified2 file corrupted.  If the write
 * to the newly created unified2 file fails, Snort will fatal error.
 *
 * In the case of interrupt errors, the write is retried, but only for a
 * finite number of times.
 *
 * All other errors are treated as non-recoverable and Snort will fatal error.
 *
 * Upon successful completion of write, the length of the data written is
 * added to the current amount of total data written thus far to the
 * unified2 file.
 *
 * Arguments
 *  uint8_t *
 *      The buffer containing the data to write
 *  uint32_t
 *      The length of the data to write
 *  Unified2Config *
 *      A pointer to the unified2 configuration data
 *
 * Returns: None
 *
 ******************************************************************************/
static void Unified2Write(uint8_t *buf, uint32_t buf_len, Unified2Config *config)
{
    size_t fwcount = 0;
    int ffstatus = 0;

    /* Nothing to write or nothing to write to */
    if ((buf == NULL) || (config == NULL) || (u2.stream == NULL))
        return;

    /* Don't use fsync().  It is a total performance killer */
    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) != 1) ||
        ((ffstatus = fflush(u2.stream)) != 0))
    {
        /* errno is saved just to avoid other intervening calls
         * (e.g. ErrorMessage) potentially reseting it to something else. */
        int error = errno;
        int max_retries = 3;

        /* On iterations other than the first, the only non-zero error will be
         * EINTR or interrupt.  Only iterate a maximum of max_retries times so
         * there is no chance of infinite looping if for some reason the write
         * is constantly interrupted */
        while ((error != 0) && (max_retries != 0))
        {
            if (config->nostamp)
            {
                ErrorMessage("%s(%d) Failed to write to unified2 file (%s): %s\n",
                             __FILE__, __LINE__, u2.filepath, get_error(error));
            }
            else
            {
                ErrorMessage("%s(%d) Failed to write to unified2 file (%s.%u): %s\n",
                             __FILE__, __LINE__, u2.filepath,
                             u2.timestamp, get_error(error));
            }

            while ((error == EINTR) && (max_retries != 0))
            {
                max_retries--;

                /* Supposedly an interrupt can only occur before anything
                 * has been written.  Try again */
                ErrorMessage("%s(%d) Got interrupt. Retry write to unified2 "
                             "file.\n", __FILE__, __LINE__);

                if (fwcount != 1)
                {
                    /* fwrite() failed.  Redo fwrite and fflush */
                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) == 1) &&
                        ((ffstatus = fflush(u2.stream)) == 0))
                    {
                        ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                     __FILE__, __LINE__);
                        error = 0;
                        break;
                    }
                }
                else if ((ffstatus = fflush(u2.stream)) == 0)
                {
                    ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                 __FILE__, __LINE__);
                    error = 0;
                    break;
                }

                error = errno;

                ErrorMessage("%s(%d) Retrying write to unified2 file failed.\n",
                             __FILE__, __LINE__);
            }

            /* If we've reached the maximum number of interrupt retries,
             * just bail out of the main while loop */
            if (max_retries == 0)
                continue;

            switch (error)
            {
                case 0:
                    break;

                case EIO:
                    ErrorMessage("%s(%d) Unified2 file is possibly corrupt. "
                                 "Closing this unified2 file and creating "
                                 "a new one.\n", __FILE__, __LINE__);

                    Unified2RotateFile(config);

                    if (config->nostamp)
                    {
                        ErrorMessage("%s(%d) New unified2 file: %s\n",
                                     __FILE__, __LINE__, u2.filepath);
                    }
                    else
                    {
                        ErrorMessage("%s(%d) New unified2 file: %s.%u\n",
                                     __FILE__, __LINE__,
                                     u2.filepath, u2.timestamp);
                    }

                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) == 1) &&
                        ((ffstatus = fflush(u2.stream)) == 0))
                    {
                        ErrorMessage("%s(%d) Write to unified2 file succeeded!\n",
                                     __FILE__, __LINE__);
                        error = 0;
                        break;
                    }

                    error = errno;

                    /* Loop again if interrupt */
                    if (error == EINTR)
                        break;

                    /* Write out error message again, then fall through and fatal */
                    if (config->nostamp)
                    {
                        ErrorMessage("%s(%d) Failed to write to unified2 file (%s): %s\n",
                                     __FILE__, __LINE__, u2.filepath, get_error(error));
                    }
                    else
                    {
                        ErrorMessage("%s(%d) Failed to write to unified2 file (%s.%u): %s\n",
                                     __FILE__, __LINE__, u2.filepath,
                                     u2.timestamp, get_error(error));
                    }

                    /* Fall through */

                case EAGAIN:  /* We're not in non-blocking mode */
                case EBADF:
                case EFAULT:
                case EFBIG:
                case EINVAL:
                case ENOSPC:
                case EPIPE:
                default:
                    FatalError("%s(%d) Cannot write to device.\n", __FILE__, __LINE__);
            }
        }

        if ((max_retries == 0) && (error != 0))
        {
            FatalError("%s(%d) Maximum number of interrupts exceeded. "
                       "Cannot write to device.\n", __FILE__, __LINE__);
        }
    }

    u2.current += buf_len;
}

//-------------------------------------------------------------------------
// unified2 module
//-------------------------------------------------------------------------

static const Parameter u2_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, "unified2.log",
      "name of alert file" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "bytes | KB | MB | GB" },

    { "nostamp", Parameter::PT_BOOL, nullptr, "true",
      "append file creation time to name (in Unix Epoch format)" },

    { "mpls_event_types", Parameter::PT_BOOL, nullptr, "false",
      "include mpls labels in events" },

    { "vlan_event_types", Parameter::PT_BOOL, nullptr, "false",
      "include vlan IDs in events" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class U2Module : public Module
{
public:
    U2Module() : Module("unified2", u2_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

public:
    string file;
    unsigned limit;
    unsigned units;
    bool nostamp;
    bool mpls;
    bool vlan;
};

bool U2Module::set(const char*, Value& v, SnortConfig*)
{
   if ( v.is("file") )
        file = v.get_string();

    else if ( v.is("limit") )
        limit = v.get_long();

    else if ( v.is("units") )
        units = v.get_long();

    else if ( v.is("nostamp") )
        nostamp = v.get_bool();

    else if ( v.is("mpls_event_types") )
        mpls = v.get_bool();

    else if ( v.is("vlan_event_types") )
        vlan = v.get_bool();

    else
        return false;

    return true;
}

bool U2Module::begin(const char*, int, SnortConfig*)
{
    file = "unified2.log";
    limit = 0;
    units = 0;
    nostamp = ScNoOutputTimestamp();
    mpls = vlan = false;
    return true;
}

bool U2Module::end(const char*, int, SnortConfig*)
{
    while ( units-- )
        limit *= 1024;

    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class U2Logger : public Logger {
public:
    U2Logger(U2Module*);
    ~U2Logger();

    void open();
    void close();

    void alert(Packet*, const char* msg, Event*);
    void log(Packet*, const char* msg, Event*);

private:
    Unified2Config config;
};

U2Logger::U2Logger(U2Module* m)
{
    config.base_filename = m->file;
    config.limit = m->limit;
    config.nostamp = m->nostamp;
    config.mpls_event_types = m->mpls;
    config.vlan_event_types = m->vlan;
}

U2Logger::~U2Logger()
{ }

void U2Logger::open()
{
    int status;

    std::string name;
    get_instance_file(name, config.base_filename.c_str());

    status = SnortSnprintf(
        u2.filepath, sizeof(u2.filepath), "%s", name.c_str());

    if (status != SNORT_SNPRINTF_SUCCESS)
    {
        FatalError("%s(%d) Failed to copy unified2 file name\n",
                   __FILE__, __LINE__);
    }
    u2.base_proto = htonl(DAQ_GetBaseProtocol());

    Unified2InitFile(&config);

    stream.reg_xtra_data_log(AlertExtraData, &config);
}

void U2Logger::close()
{
    if ( u2.stream )
        fclose(u2.stream);
}

void U2Logger::alert(Packet *p, const char *msg, Event *event)
{
    if(IS_IP4(p))
    {
        _AlertIP4_v2(p, msg, &config, event);
    }
    else
    {
        _AlertIP6_v2(p, msg, &config, event);

        if(ScLogIPv6Extra() && IS_IP6(p))
        {
            snort_ip_p ip = GET_SRC_IP(p);
            _WriteExtraData(&config, event->event_id, event->ref_time.tv_sec,
                &ip->ip8[0], sizeof(struct in6_addr),  EVENT_INFO_IPV6_SRC);
            ip = GET_DST_IP(p);
            _WriteExtraData(&config, event->event_id, event->ref_time.tv_sec,
                &ip->ip8[0], sizeof(struct in6_addr),  EVENT_INFO_IPV6_DST);
        }
    }

    if ( p->flow )
        stream.update_session_alert(
            p->flow, p, event->sig_info->generator, event->sig_info->id,
            event->event_id, event->ref_time.tv_sec);

    if ( p->xtradata_mask )
    {
        LogFunction *log_funcs;
        uint32_t max_count = stream.get_xtra_data_map(&log_funcs);

        if ( max_count > 0 )
            AlertExtraData(
                p->flow, &config, log_funcs, max_count, p->xtradata_mask,
                event->event_id, event->ref_time.tv_sec);
    }
}

void U2Logger::log(Packet *p, const char *msg, Event *event)
{
    if(p)
    {
        if ( p->packet_flags & PKT_REBUILT_STREAM )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG,
                        "[*] Reassembled packet, dumping stream packets\n"););
            _Unified2LogStreamAlert(p, msg, &config, event);
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "[*] Logging unified 2 packets...\n"););
            _Unified2LogPacketAlert(p, msg, &config, event);
        }
   }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new U2Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* u2_ctor(SnortConfig*, Module* mod)
{ return new U2Logger((U2Module*)mod); }

static void u2_dtor(Logger* p)
{ delete p; }

static LogApi u2_api
{
    {
        PT_LOGGER,
        "unified2",
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG | OUTPUT_TYPE_FLAG__ALERT,
    u2_ctor,
    u2_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &u2_api.base,
    nullptr
};
#else
const BaseApi* eh_unified2 = &u2_api.base;
#endif

