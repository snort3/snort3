//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/detection_util.h"
#include "detection/detect.h"
#include "parser/parser.h"
#include "events/event.h"
#include "utils/util.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "stream/stream_api.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"
#include "protocols/icmp4.h"
#include "log/obfuscator.h"
#include "utils/safec.h"

using namespace std;

#define S_NAME "unified2"
#define F_NAME S_NAME ".log"

/* ------------------ Data structures --------------------------*/
typedef struct _Unified2Config
{
    unsigned int limit;
    int nostamp;
    int mpls_event_types;
    int vlan_event_types;
} Unified2Config;

typedef struct _Unified2LogCallbackData
{
    Serial_Unified2Packet* logheader;
    Unified2Config* config;
    Event* event;
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

#define MAX_XDATA_WRITE_BUF_LEN \
    (MAX_XFF_WRITE_BUF_LENGTH - \
    sizeof(struct in6_addr) + DECODE_BLEN)

/* This buffer is used in lieu of the underlying default stream buf to
 * prevent flushing in the middle of a record.  Every write is force
 * flushed to disk immediately after the entire record is written so
 * spoolers get an entire record */

/* use the size of the buffer we copy record data into */
static THREAD_LOCAL char io_buffer[u2_buf_sz];

/* -------------------- Local Functions -----------------------*/

/* Unified2 Output functions */
static void Unified2InitFile(Unified2Config*);
static inline void Unified2RotateFile(Unified2Config*);
static void _Unified2LogPacketAlert(Packet*, const char*, Unified2Config*, Event*);
static void Unified2Write(uint8_t*, uint32_t, Unified2Config*);

static void _AlertIP4_v2(Packet*, const char*, Unified2Config*, Event*);
static void _AlertIP6_v2(Packet*, const char*, Unified2Config*, Event*);

static void AlertExtraData(Flow*, void* data, LogFunction* log_funcs, uint32_t max_count, uint32_t
    xtradata_mask, uint32_t event_id, uint32_t event_second);

#define U2_PACKET_FLAG 1
/* Obsolete flag as UI wont check the impact_flag field anymore.*/
#define U2_FLAG_BLOCKED 0x20
/* New flags to set the pad field (corresponds to blocked column in UI) with packet action*/
#define U2_BLOCKED_FLAG_ALLOW 0x00
#define U2_BLOCKED_FLAG_BLOCK 0x01
#define U2_BLOCKED_FLAG_WOULD 0x02
#define U2_BLOCKED_FLAG_CANT  0x03

static int s_blocked_flag[] =
{
    U2_BLOCKED_FLAG_ALLOW,
    U2_BLOCKED_FLAG_CANT,
    U2_BLOCKED_FLAG_WOULD,
    U2_BLOCKED_FLAG_BLOCK,
};

static int GetU2Flags(const Packet*, uint8_t* pimpact)
{
    Active::ActiveStatus dispos = Active::get_status();

    if ( dispos > Active::AST_ALLOW )
        *pimpact = U2_FLAG_BLOCKED;

    return s_blocked_flag[dispos];
}

/*
 * Function: Unified2InitFile()
 *
 * Purpose: Initialize the unified2 output file
 *
 * Arguments: config => pointer to the plugin's reference data struct
 *
 * Returns: void function
 */
static void Unified2InitFile(Unified2Config* config)
{
    char filepath[STD_BUF];
    char* fname_ptr;

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

    // FIXIT-P should use open() instead of fopen()
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
    if (SnortConfig::test_mode())  // FIXIT-L eliminate test check; should always remove if empty
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

static inline void Unified2RotateFile(Unified2Config* config)
{
    fclose(u2.stream);
    u2.current = 0;
    Unified2InitFile(config);
}

static void _AlertIP4_v2(Packet* p, const char*, Unified2Config* config, Event* event)
{
    Serial_Unified2_Header hdr;
    Unified2IDSEvent alertdata;
    uint32_t write_len = sizeof(hdr) + sizeof(alertdata);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_info->generator);
    alertdata.signature_id = htonl(event->sig_info->id);
    alertdata.signature_revision = htonl(event->sig_info->rev);
    alertdata.classification_id = htonl(event->sig_info->class_id);
    alertdata.priority_id = htonl(event->sig_info->priority);

    if (p)
    {
        alertdata.blocked = GetU2Flags(p, &alertdata.impact_flag);

        if (p->has_ip())
        {
            const ip::IP4Hdr* const iph = p->ptrs.ip_api.get_ip4h();
            alertdata.ip_source = iph->get_src();
            alertdata.ip_destination = iph->get_dst();

            if (p->is_portscan())
            {
                alertdata.ip_proto = p->ps_proto;
            }
            else
            {
                alertdata.ip_proto = p->get_ip_proto_next();

                if ( p->type() == PktType::ICMP)
                {
                    // If PktType == ICMP, icmph is set
                    alertdata.sport_itype = htons(p->ptrs.icmph->type);
                    alertdata.dport_icode = htons(p->ptrs.icmph->code);
                }
                else if (!p->is_portscan())
                {
                    alertdata.sport_itype = htons(p->ptrs.sp);
                    alertdata.dport_icode = htons(p->ptrs.dp);
                }
            }

            if ((p->proto_bits & PROTO_BIT__MPLS) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->ptrs.mplsHdr.label);
            }
            if (config->vlan_event_types)
            {
                if (p->proto_bits & PROTO_BIT__VLAN)
                {
                    alertdata.vlanId = htons(layer::get_vlan_layer(p)->vid());
                }

                alertdata.pad2 = htons(p->user_policy_id);
            }
        }
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(alertdata));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_VLAN);

    memcpy_s(write_pkt_buffer, sizeof(write_pkt_buffer), &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, sizeof(write_pkt_buffer) - offset, &alertdata, sizeof(alertdata));

    Unified2Write(write_pkt_buffer, write_len, config);
}

static void _AlertIP6_v2(Packet* p, const char*, Unified2Config* config, Event* event)
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

    if (p)
    {
        alertdata.blocked = GetU2Flags(p, &alertdata.impact_flag);

        if(p->ptrs.ip_api.is_ip())
        {
            const sfip_t* ip;

            ip = p->ptrs.ip_api.get_src();
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;

            ip = p->ptrs.ip_api.get_dst();
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;

            if (p->is_portscan())
            {
                alertdata.ip_proto = p->ps_proto;
            }
            else
            {
                alertdata.ip_proto = p->get_ip_proto_next();

                if ( p->type() == PktType::ICMP)
                {
                    // If PktType == ICMP, icmph is set
                    alertdata.sport_itype = htons(p->ptrs.icmph->type);
                    alertdata.dport_icode = htons(p->ptrs.icmph->code);
                }
                else if (!p->is_portscan())
                {
                    alertdata.sport_itype = htons(p->ptrs.sp);
                    alertdata.dport_icode = htons(p->ptrs.dp);
                }
            }

            if ((p->proto_bits & PROTO_BIT__MPLS) && (config->mpls_event_types))
            {
                alertdata.mpls_label = htonl(p->ptrs.mplsHdr.label);
            }
            if (config->vlan_event_types)
            {
                if (p->proto_bits & PROTO_BIT__VLAN)
                {
                    alertdata.vlanId = htons(layer::get_vlan_layer(p)->vid());
                }

                alertdata.pad2 = htons(p->user_policy_id);
            }
        }
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2IDSEventIPv6));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_VLAN);

    memcpy_s(write_pkt_buffer, sizeof(write_pkt_buffer), &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, sizeof(write_pkt_buffer) - offset,
        &alertdata, sizeof(alertdata));

    Unified2Write(write_pkt_buffer, write_len, config);
}

static void _WriteExtraData(Unified2Config* config,
    uint32_t event_id,
    uint32_t event_second,
    const uint8_t* buffer,
    uint32_t len,
    uint32_t type)
{
    Serial_Unified2_Header hdr;
    SerialUnified2ExtraData alertdata;
    Unified2ExtraDataHdr alertHdr;
    uint8_t write_buffer[MAX_XDATA_WRITE_BUF_LEN];
    uint8_t* ptr = NULL;

    uint32_t write_len = sizeof(hdr) + sizeof(alertHdr);

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event_id);
    alertdata.event_second = htonl(event_second);
    alertdata.data_type = htonl(EVENT_DATA_TYPE_BLOB);

    alertdata.type = htonl(type);
    alertdata.blob_length = htonl(sizeof(alertdata.data_type) +
        sizeof(alertdata.blob_length) + len);

    write_len = write_len + sizeof(alertdata) + len;
    alertHdr.event_type = htonl(EVENT_TYPE_EXTRA_DATA);
    alertHdr.event_length = htonl(write_len - sizeof(hdr));

    if (write_len > sizeof(write_buffer))
        return;

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(write_len - sizeof(hdr));
    hdr.type = htonl(UNIFIED2_EXTRA_DATA);

    ptr = write_buffer;

    memcpy_s(ptr, sizeof(write_buffer), &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(ptr + offset, sizeof(write_buffer) - offset, &alertHdr, sizeof(alertHdr));

    offset += sizeof(alertHdr);

    memcpy_s(ptr + offset, sizeof(write_buffer) - offset, &alertdata, sizeof(alertdata));

    offset += sizeof(alertdata);

    memcpy_s(ptr + offset, sizeof(write_buffer) - offset, buffer, len);

    Unified2Write(write_buffer, write_len, config);
}

static void AlertExtraData(
    Flow* flow, void* data,
    LogFunction* log_funcs, uint32_t max_count,
    uint32_t xtradata_mask,
    uint32_t event_id, uint32_t event_second)
{
    Unified2Config* config = (Unified2Config*)data;
    uint32_t xid;

    if ((config == NULL) || !xtradata_mask || !event_second)
        return;

    xid = ffs(xtradata_mask);

    while ( xid && (xid <= max_count) )
    {
        uint32_t len = 0;
        uint32_t type = 0;
        uint8_t* write_buffer;

        if ( log_funcs[xid-1](flow, &write_buffer, &len, &type) && (len > 0) )
        {
            _WriteExtraData(config, event_id, event_second, write_buffer, len, type);
        }
        xtradata_mask ^= BIT(xid);
        xid = ffs(xtradata_mask);
    }
}

static void _Unified2LogPacketAlert(
    Packet* p, const char*, Unified2Config* config, Event* event)
{
    Serial_Unified2_Header hdr;
    Serial_Unified2Packet logheader;
    uint32_t pkt_length = 0;
    uint32_t write_len = sizeof(hdr) + sizeof(Serial_Unified2Packet) - 4;

    logheader.sensor_id = 0;
    logheader.linktype = u2.base_proto;

    if (event != NULL)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);

        DebugMessage(DEBUG_LOG, "------------\n");
    }
    else
    {
        logheader.event_id = 0;
        logheader.event_second = 0;
    }

    if ( p and p->pkth )
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

    memcpy_s(write_pkt_buffer, sizeof(write_pkt_buffer), &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, sizeof(write_pkt_buffer) - offset,
        &logheader, sizeof(logheader) - 4);

    offset += sizeof(logheader) - 4;

    if (pkt_length != 0)
    {
        if (pkt_length > sizeof(write_pkt_buffer) - offset)
            return;

        uint8_t *start = write_pkt_buffer + offset;

        memcpy_s(start, sizeof(write_pkt_buffer) - offset,
            p->is_data() ? p->data : p->pkt, pkt_length);

        if ( p->obfuscator )
        {
            off_t off = p->data - p->pkt;

            if ( !p->is_data() )
                off = 0;

            for ( const auto& b : *p->obfuscator )
                memset(&start[ off + b.offset ], '.', b.length);
        }
    }

    Unified2Write(write_pkt_buffer, write_len, config);
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
static void Unified2Write(uint8_t* buf, uint32_t buf_len, Unified2Config* config)
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
                        ErrorMessage("%s(%d) Write to unified2 file succeeded\n",
                            __FILE__, __LINE__);
                        error = 0;
                        break;
                    }
                }
                else if ((ffstatus = fflush(u2.stream)) == 0)
                {
                    ErrorMessage("%s(%d) Write to unified2 file succeeded\n",
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
                    ErrorMessage("%s(%d) Write to unified2 file succeeded\n",
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

            case EAGAIN:      /* We're not in non-blocking mode */
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

static const Parameter s_params[] =
{
    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "limit multiplier" },

    { "nostamp", Parameter::PT_BOOL, nullptr, "true",
      "append file creation time to name (in Unix Epoch format)" },

    { "mpls_event_types", Parameter::PT_BOOL, nullptr, "false",
      "include mpls labels in events" },

    { "vlan_event_types", Parameter::PT_BOOL, nullptr, "false",
      "include vlan IDs in events" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event and packet in unified2 format file"

class U2Module : public Module
{
public:
    U2Module() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    unsigned limit;
    unsigned units;
    bool nostamp;
    bool mpls;
    bool vlan;
};

bool U2Module::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("limit") )
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
    limit = 0;
    units = 0;
    nostamp = SnortConfig::output_no_timestamp();
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

class U2Logger : public Logger
{
public:
    U2Logger(U2Module*);
    ~U2Logger();

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;
    void log(Packet*, const char* msg, Event*) override;

private:
    Unified2Config config;
};

U2Logger::U2Logger(U2Module* m)
{
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
    get_instance_file(name, F_NAME);

    status = SnortSnprintf(
        u2.filepath, sizeof(u2.filepath), "%s", name.c_str());

    if (status != SNORT_SNPRINTF_SUCCESS)
    {
        FatalError("%s(%d) Failed to copy unified2 file name\n",
            __FILE__, __LINE__);
    }
    u2.base_proto = htonl(SFDAQ::get_base_protocol());

    Unified2InitFile(&config);

    stream.reg_xtra_data_log(AlertExtraData, &config);
}

void U2Logger::close()
{
    if ( u2.stream )
        fclose(u2.stream);
}

void U2Logger::alert(Packet* p, const char* msg, Event* event)
{
    if (p->ptrs.ip_api.is_ip6())
    {
        _AlertIP6_v2(p, msg, &config, event);

        // FIXIT-M delete ip6 extra data; support ip6 normally
        if (SnortConfig::get_log_ip6_extra() && p->ptrs.ip_api.is_ip6())
        {
            const sfip_t* ip = p->ptrs.ip_api.get_src();
            _WriteExtraData(&config, event->event_id, event->ref_time.tv_sec,
                &ip->ip8[0], sizeof(struct in6_addr),  EVENT_INFO_IPV6_SRC);
            ip = p->ptrs.ip_api.get_dst();
            _WriteExtraData(&config, event->event_id, event->ref_time.tv_sec,
                &ip->ip8[0], sizeof(struct in6_addr),  EVENT_INFO_IPV6_DST);
        }
    }
    else // ip4 or data
    {
        _AlertIP4_v2(p, msg, &config, event);
    }

    if ( p->flow )
        stream.update_session_alert(
            p->flow, p, event->sig_info->generator, event->sig_info->id,
            event->event_id, event->ref_time.tv_sec);

    if ( p->xtradata_mask )
    {
        LogFunction* log_funcs;
        uint32_t max_count = stream.get_xtra_data_map(&log_funcs);

        if ( max_count > 0 )
            AlertExtraData(
                p->flow, &config, log_funcs, max_count, p->xtradata_mask,
                event->event_id, event->ref_time.tv_sec);
    }
}

void U2Logger::log(Packet* p, const char* msg, Event* event)
{
    if (p)
    {
        if ( (p->packet_flags & PKT_REBUILT_STREAM) and !p->is_data() )
        {
            DebugMessage(DEBUG_LOG,
                "[*] Reassembled packet, dumping stream packets\n");
            // FIXIT-H replace with reassembled stream data and
            // optionally the first captured packet
            //_Unified2LogStreamAlert(p, msg, &config, event);
        }
        else
        {
            DebugMessage(DEBUG_LOG, "[*] Logging unified 2 packets...\n");
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
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
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

