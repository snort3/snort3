//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
 * This file is literally unified.c converted to write unified2
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "detection/signature.h"
#include "detection/detection_util.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/messages.h"
#include "log/obfuscator.h"
#include "log/unified2.h"
#include "log/u2_packet.h"
#include "main/snort_config.h"
#include "network_inspectors/appid/appid_api.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"
#include "stream/stream.h"
#include "utils/safec.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;
using namespace std;

#define S_NAME "unified2"
#define F_NAME S_NAME ".log"

/* ------------------ Data structures --------------------------*/

struct Unified2Config
{
    unsigned int limit;
    int nostamp;
    bool legacy_events;
};

struct U2
{
    FILE* stream;
    unsigned int current;
    int base_proto;
    uint32_t timestamp;
    char filepath[STD_BUF];
};

/* -------------------- Global Variables ----------------------*/

static THREAD_LOCAL U2 u2;

/* Used for buffering header and payload of unified records so only one
 * write is necessary. */
constexpr unsigned u2_buf_sz =
    sizeof(Serial_Unified2_Header) + sizeof(Unified2Event) + IP_MAXPACKET;

static THREAD_LOCAL uint8_t* write_pkt_buffer = nullptr;

#define MAX_XDATA_WRITE_BUF_LEN \
    (MAX_XFF_WRITE_BUF_LENGTH - \
    sizeof(struct in6_addr) + DECODE_BLEN)

/* This buffer is used in lieu of the underlying default stream buf to
 * prevent flushing in the middle of a record.  Every write is force
 * flushed to disk immediately after the entire record is written so
 * spoolers get an entire record */

/* use the size of the buffer we copy record data into */
static THREAD_LOCAL char* io_buffer = nullptr;

/* -------------------- Local Functions -----------------------*/

static void Unified2Write(uint8_t*, uint32_t, Unified2Config*);

static void Unified2InitFile(Unified2Config* config)
{
    assert(config);

    char filepath[STD_BUF];
    char* fname_ptr;

    u2.timestamp = (uint32_t)time(nullptr);

    if (!config->nostamp)
    {
        if (SnortSnprintf(filepath, sizeof(filepath), "%s.%u",
            u2.filepath, u2.timestamp) != SNORT_SNPRINTF_SUCCESS)
        {
            FatalError("unified2 failed to copy file path.\n");
        }

        fname_ptr = filepath;
    }
    else
    {
        fname_ptr = u2.filepath;
    }

    if ((u2.stream = fopen(fname_ptr, "wb")) == nullptr)
    {
        FatalError("unified2 could not open %s: %s\n", fname_ptr, get_error(errno));
    }

    /* Set buffer to size of record buffer so the system doesn't flush
     * part of a record if it's greater than BUFSIZ */
    if (setvbuf(u2.stream, io_buffer, _IOFBF, u2_buf_sz) != 0)
    {
        ErrorMessage("unified2 could not set I/O buffer: %s. "
            "Using system default.\n", get_error(errno));
    }
}

static inline void Unified2RotateFile(Unified2Config* config)
{
    fclose(u2.stream);
    u2.current = 0;
    Unified2InitFile(config);
}

static inline unsigned get_version(const SfIp& addr)
{
    uint16_t family = addr.get_family();
    return (family == AF_INET) ? 0x4 : (family == AF_INET6 ? 0x6 : 0x0);
}

static inline void copy_addr(const SfIp& src, const SfIp& dst, Unified2Event& e)
{
    COPY4(e.pkt_src_ip, src.get_ip6_ptr());
    COPY4(e.pkt_dst_ip, dst.get_ip6_ptr());
    e.pkt_ip_ver = (get_version(src) << 4) | get_version(dst);
}

static void alert_event(Packet* p, const char*, Unified2Config* config, const Event* event)
{
    Unified2Event u2_event;
    memset(&u2_event, 0, sizeof(u2_event));

    u2_event.snort_id = 0;  // FIXIT-H define / use

    u2_event.event_id = htonl(event->event_id);
    u2_event.event_second = htonl(event->ref_time.tv_sec);
    u2_event.event_microsecond = htonl(event->ref_time.tv_usec);

    u2_event.rule_gid = htonl(event->sig_info->gid);
    u2_event.rule_sid = htonl(event->sig_info->sid);
    u2_event.rule_rev = htonl(event->sig_info->rev);
    u2_event.rule_class = htonl(event->sig_info->class_id);
    u2_event.rule_priority = htonl(event->sig_info->priority);

    if ( p )
    {
        u2_event.policy_id_detect = htonl(p->user_ips_policy_id);
        u2_event.policy_id_inspect = htonl(p->user_inspection_policy_id);
        u2_event.policy_id_context = htonl(p->user_network_policy_id);

        if ( p->ptrs.ip_api.is_ip() )
            copy_addr(*p->ptrs.ip_api.get_src(), *p->ptrs.ip_api.get_dst(), u2_event);

        else if (p->flow)
        {
            if (p->is_from_client())
                copy_addr(p->flow->client_ip, p->flow->server_ip, u2_event);
            else
                copy_addr(p->flow->server_ip, p->flow->client_ip, u2_event);
        }

        if ( p->type() == PktType::ICMP)
        {
            // If PktType == ICMP, icmph is set
            u2_event.pkt_src_port_itype = htons(p->ptrs.icmph->type);
            u2_event.pkt_dst_port_icode = htons(p->ptrs.icmph->code);
        }
        else
        {
            u2_event.pkt_src_port_itype = htons(p->ptrs.sp);
            u2_event.pkt_dst_port_icode = htons(p->ptrs.dp);
        }

        if ( p->proto_bits & PROTO_BIT__MPLS )
            u2_event.pkt_mpls_label = htonl(p->ptrs.mplsHdr.label);

        if ( p->proto_bits & PROTO_BIT__VLAN )
            u2_event.pkt_vlan_id = htons(layer::get_vlan_layer(p)->vid());

        u2_event.pkt_ip_proto = (uint8_t)p->get_ip_proto_next();

        const char* app_name = p->flow ?
            appid_api.get_application_name(*p->flow, p->is_from_client()) : nullptr;

        if ( app_name )
            memcpy_s(u2_event.app_name, sizeof(u2_event.app_name),
                app_name, strlen(app_name) + 1);
    }

    u2_event.snort_status = Active::get_status();
    u2_event.snort_action = Active::get_action();

    Serial_Unified2_Header hdr;
    uint32_t write_len = sizeof(hdr) + sizeof(u2_event);

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2Event));
    hdr.type = htonl(UNIFIED2_EVENT3);

    memcpy_s(write_pkt_buffer, u2_buf_sz, &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, u2_buf_sz - offset, &u2_event, sizeof(u2_event));

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
    uint8_t* ptr = nullptr;

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

    if ((config == nullptr) || !xtradata_mask || !event_second)
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
    Packet* p, const char*, Unified2Config* config, const Event* event,
    unsigned u2_type, U2PseudoHeader* u2h = nullptr)
{
    Serial_Unified2_Header hdr;
    Serial_Unified2Packet logheader;

    uint32_t pkt_length = 0;
    uint32_t write_len = sizeof(hdr) + sizeof(Serial_Unified2Packet) - 4;
    unsigned u2h_len = u2h ? u2h->get_size() : 0;

    logheader.sensor_id = 0;
    logheader.linktype = u2.base_proto;

    if (event != nullptr)
    {
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);
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
        pkt_length = ( p->is_rebuilt() ) ? p->dsize : p->pkth->caplen;
        logheader.packet_length = htonl(pkt_length + u2h_len);
        write_len += pkt_length + u2h_len;
    }
    else
    {
        logheader.packet_second = 0;
        logheader.packet_microsecond = 0;
        logheader.packet_length = 0;
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Serial_Unified2Packet) - 4 + pkt_length + u2h_len);
    hdr.type = htonl(u2_type);

    memcpy_s(write_pkt_buffer, u2_buf_sz, &hdr, sizeof(hdr));
    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, u2_buf_sz - offset, &logheader, sizeof(logheader) - 4);
    offset += sizeof(logheader) - 4;

    if ( u2h_len > 0 )
    {
        assert(u2_buf_sz - offset > u2h_len);
        memcpy_s(write_pkt_buffer + offset, u2_buf_sz - offset, u2h->get_data(), u2h_len);
        offset += u2h_len;
    }

    if (pkt_length != 0)
    {
        if (pkt_length > u2_buf_sz - offset)
            return;

        uint8_t *start = write_pkt_buffer + offset;

        memcpy_s(start, u2_buf_sz - offset, p->is_data() ? p->data : p->pkt, pkt_length);

        if ( p->obfuscator )
        {
            off_t off = p->data - p->pkt;

            if ( p->is_data() )
                off = 0;

            for ( const auto& b : *p->obfuscator )
                memset(&start[ off + b.offset ], p->obfuscator->get_mask_char(), b.length);
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
    if ((buf == nullptr) || (config == nullptr) || (u2.stream == nullptr))
        return;

    /* Don't use fsync().  It is a total performance killer */
    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) != 1) ||
        ((ffstatus = fflush(u2.stream)) != 0))
    {
        /* errno is saved just to avoid other intervening calls
         * (e.g. ErrorMessage) potentially resetting it to something else. */
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
                ErrorMessage("unified2 failed to write to file (%s): %s\n",
                    u2.filepath, get_error(error));
            }
            else
            {
                ErrorMessage("unified2 failed to write to file (%s.%u): %s\n",
                    u2.filepath, u2.timestamp, get_error(error));
            }

            while ((error == EINTR) && (max_retries != 0))
            {
                max_retries--;

                /* Supposedly an interrupt can only occur before anything
                 * has been written.  Try again */
                if (fwcount != 1)
                {
                    /* fwrite() failed.  Redo fwrite and fflush */
                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) == 1) &&
                        ((ffstatus = fflush(u2.stream)) == 0))
                    {
                        error = 0;
                        break;
                    }
                }
                else if ((ffstatus = fflush(u2.stream)) == 0)
                {
                    error = 0;
                    break;
                }

                error = errno;
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
                ErrorMessage("unified2 file is possibly corrupt. "
                    "Closing this unified2 file and creating a new one.\n");

                Unified2RotateFile(config);

                if (config->nostamp)
                {
                    ErrorMessage("unified2 rotated file: %s\n", u2.filepath);
                }
                else
                {
                    ErrorMessage("unified2 rotated file: %s.%u\n", u2.filepath, u2.timestamp);
                }

                if (((fwcount = fwrite(buf, (size_t)buf_len, 1, u2.stream)) == 1) &&
                    ((ffstatus = fflush(u2.stream)) == 0))
                {
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
                    ErrorMessage("unified2 failed to write to file (%s): %s\n",
                        u2.filepath, get_error(error));
                }
                else
                {
                    ErrorMessage("unified2 failed to write to file (%s.%u): %s\n",
                        u2.filepath, u2.timestamp, get_error(error));
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
                FatalError("unified2 cannot write to device.\n");
            }
        }

        if ((max_retries == 0) && (error != 0))
        {
            FatalError("unified2 cannot write to device. "
                "Maximum number of interrupts exceeded.\n");
        }
    }

    u2.current += buf_len;
}

//--------------------------------------------------------------------------
// legacy event support
// FIXIT-L encode pseudo packets for buffers and extra data for out of date
//         barnyard2
//--------------------------------------------------------------------------

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

static void _AlertIP4_v2(Packet* p, const char*, Unified2Config* config, const Event* event)
{
    Serial_Unified2_Header hdr;
    Unified2IDSEvent alertdata;
    uint32_t write_len = sizeof(hdr) + sizeof(alertdata);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_info->gid);
    alertdata.signature_id = htonl(event->sig_info->sid);
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
        }
        else if (p->flow)
        {
            if (p->is_from_client())
            {
                alertdata.ip_source = *(p->flow->client_ip.get_ip4_ptr());
                alertdata.ip_destination = *(p->flow->server_ip.get_ip4_ptr());
            }
            else
            {
                alertdata.ip_source = *(p->flow->server_ip.get_ip4_ptr());
                alertdata.ip_destination = *(p->flow->client_ip.get_ip4_ptr());
            }
        }

        alertdata.ip_proto = p->get_ip_proto_next();

        if ( p->type() == PktType::ICMP)
        {
            // If PktType == ICMP, icmph is set
            alertdata.sport_itype = htons(p->ptrs.icmph->type);
            alertdata.dport_icode = htons(p->ptrs.icmph->code);
        }

        alertdata.sport_itype = htons(p->ptrs.sp);
        alertdata.dport_icode = htons(p->ptrs.dp);

        if ( p->proto_bits & PROTO_BIT__MPLS )
            alertdata.mpls_label = htonl(p->ptrs.mplsHdr.label);

        if (p->proto_bits & PROTO_BIT__VLAN)
            alertdata.vlanId = htons(layer::get_vlan_layer(p)->vid());

        alertdata.pad2 = htons((uint16_t)p->user_ips_policy_id);

        const char* app_name = p->flow ?
            appid_api.get_application_name(*p->flow, p->is_from_client()) : nullptr;

        if ( app_name )
            memcpy_s(alertdata.app_name, sizeof(alertdata.app_name),
                app_name, strlen(app_name) + 1);
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(alertdata));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_VLAN);

    memcpy_s(write_pkt_buffer, u2_buf_sz, &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, u2_buf_sz - offset, &alertdata, sizeof(alertdata));

    Unified2Write(write_pkt_buffer, write_len, config);
}

static void _AlertIP6_v2(Packet* p, const char*, Unified2Config* config, const Event* event)
{
    Serial_Unified2_Header hdr;
    Unified2IDSEventIPv6 alertdata;
    uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Unified2IDSEventIPv6);

    memset(&alertdata, 0, sizeof(alertdata));

    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_info->gid);
    alertdata.signature_id = htonl(event->sig_info->sid);
    alertdata.signature_revision = htonl(event->sig_info->rev);
    alertdata.classification_id = htonl(event->sig_info->class_id);
    alertdata.priority_id = htonl(event->sig_info->priority);

    if (p)
    {
        alertdata.blocked = GetU2Flags(p, &alertdata.impact_flag);

        if(p->ptrs.ip_api.is_ip())
        {
            const SfIp* ip;
            ip = p->ptrs.ip_api.get_src();
            alertdata.ip_source = *(const struct in6_addr*)ip->get_ip6_ptr();
            ip = p->ptrs.ip_api.get_dst();
            alertdata.ip_destination = *(const struct in6_addr*)ip->get_ip6_ptr();
        }
        else if (p->flow)
        {
            if (p->is_from_client())
            {
                alertdata.ip_source = *(const struct in6_addr*)p->flow->client_ip.get_ip6_ptr();
                alertdata.ip_destination = *(const struct in6_addr*)p->flow->server_ip.get_ip6_ptr();
            }
            else
            {
                alertdata.ip_source = *(const struct in6_addr*)p->flow->server_ip.get_ip6_ptr();
                alertdata.ip_destination = *(const struct in6_addr*)p->flow->client_ip.get_ip6_ptr();
            }
        }

        alertdata.ip_proto = p->get_ip_proto_next();

        if ( p->type() == PktType::ICMP)
        {
            // If PktType == ICMP, icmph is set
            alertdata.sport_itype = htons(p->ptrs.icmph->type);
            alertdata.dport_icode = htons(p->ptrs.icmph->code);
        }

        alertdata.sport_itype = htons(p->ptrs.sp);
        alertdata.dport_icode = htons(p->ptrs.dp);

        if ( p->proto_bits & PROTO_BIT__MPLS )
            alertdata.mpls_label = htonl(p->ptrs.mplsHdr.label);

        if (p->proto_bits & PROTO_BIT__VLAN)
            alertdata.vlanId = htons(layer::get_vlan_layer(p)->vid());

        alertdata.pad2 = htons((uint16_t)p->user_ips_policy_id);

        const char* app_name = p->flow ?
            appid_api.get_application_name(*p->flow, p->is_from_client()) : nullptr;

        if ( app_name )
            memcpy_s(alertdata.app_name, sizeof(alertdata.app_name),
                app_name, strlen(app_name) + 1);
    }

    if ( config->limit && (u2.current + write_len) > config->limit )
        Unified2RotateFile(config);

    hdr.length = htonl(sizeof(Unified2IDSEventIPv6));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_VLAN);

    memcpy_s(write_pkt_buffer, u2_buf_sz, &hdr, sizeof(hdr));

    size_t offset = sizeof(hdr);

    memcpy_s(write_pkt_buffer + offset, u2_buf_sz - offset, &alertdata, sizeof(alertdata));

    Unified2Write(write_pkt_buffer, write_len, config);
}

//-------------------------------------------------------------------------
// unified2 module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "legacy_events", Parameter::PT_BOOL, nullptr, "false",
      "generate Snort 2.X style events for barnyard2 compatibility" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "nostamp", Parameter::PT_BOOL, nullptr, "true",
      "append file creation time to name (in Unix Epoch format)" },

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

    Usage get_usage() const override
    { return CONTEXT; }

public:
    unsigned limit;
    bool nostamp;
    bool legacy_events;
};

bool U2Module::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else if ( v.is("nostamp") )
        nostamp = v.get_bool();

    else if ( v.is("legacy_events") )
        legacy_events = v.get_bool();

    else
        return false;

    return true;
}

bool U2Module::begin(const char*, int, SnortConfig*)
{
    limit = 0;
    nostamp = SnortConfig::output_no_timestamp();
    legacy_events = false;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class U2Logger : public Logger
{
public:
    U2Logger(U2Module*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;
    void log(Packet*, const char* msg, Event*) override;

private:
    // alert_legacy() and friends retain compatibility with barnyard2
    void alert_legacy(Packet*, const char* msg, const Event&);

private:
    Unified2Config config;
};

U2Logger::U2Logger(U2Module* m)
{
    config.limit = m->limit;
    config.nostamp = m->nostamp;
    config.legacy_events = m->legacy_events;
}


void U2Logger::open()
{
    int status;

    std::string name;
    get_instance_file(name, F_NAME);

    status = SnortSnprintf(
        u2.filepath, sizeof(u2.filepath), "%s", name.c_str());

    if (status != SNORT_SNPRINTF_SUCCESS)
    {
        FatalError("unified2 failed to copy file name\n");
    }
    u2.base_proto = htonl(SFDAQ::get_base_protocol());

    write_pkt_buffer = new uint8_t[u2_buf_sz];
    io_buffer = new char[u2_buf_sz];

    Unified2InitFile(&config);

    Stream::reg_xtra_data_log(AlertExtraData, &config);
}

void U2Logger::close()
{
    if ( u2.stream )
        fclose(u2.stream);

    delete[] write_pkt_buffer;
    delete[] io_buffer;

    write_pkt_buffer = nullptr;
    io_buffer = nullptr;
}

void U2Logger::alert_legacy(Packet* p, const char* msg, const Event& event)
{
    if (p->ptrs.ip_api.is_ip6())
    {
        _AlertIP6_v2(p, msg, &config, &event);

        if (p->ptrs.ip_api.is_ip6())
        {
            const SfIp* ip = p->ptrs.ip_api.get_src();
            _WriteExtraData(&config, event.event_id, event.ref_time.tv_sec,
                (const uint8_t*) ip->get_ip6_ptr(), sizeof(struct in6_addr), EVENT_INFO_IPV6_SRC);
            ip = p->ptrs.ip_api.get_dst();
            _WriteExtraData(&config, event.event_id, event.ref_time.tv_sec,
                (const uint8_t*) ip->get_ip6_ptr(), sizeof(struct in6_addr), EVENT_INFO_IPV6_DST);
        }
    }
    else // ip4 or data
    {
        _AlertIP4_v2(p, msg, &config, &event);
    }

    if ( p->flow )
        Stream::update_flow_alert(
            p->flow, p, event.sig_info->gid, event.sig_info->sid,
            event.event_id, event.ref_time.tv_sec);

    if ( p->xtradata_mask )
    {
        LogFunction* log_funcs;
        uint32_t max_count = Stream::get_xtra_data_map(log_funcs);

        if ( max_count > 0 )
            AlertExtraData(
                p->flow, &config, log_funcs, max_count, p->xtradata_mask,
                event.event_id, event.ref_time.tv_sec);
    }
}

void U2Logger::alert(Packet* p, const char* msg, const Event& event)
{
    if ( config.legacy_events )
    {
        alert_legacy(p, msg, event);
        return;
    }
    alert_event(p, msg, &config, &event);

    if ( p->flow )
        Stream::update_flow_alert(
            p->flow, p, event.sig_info->gid, event.sig_info->sid,
            event.event_id, event.ref_time.tv_sec);

    if ( p->xtradata_mask )
    {
        LogFunction* log_funcs;
        uint32_t max_count = Stream::get_xtra_data_map(log_funcs);

        if ( max_count > 0 )
            AlertExtraData(
                p->flow, &config, log_funcs, max_count, p->xtradata_mask,
                event.event_id, event.ref_time.tv_sec);
    }
}

void U2Logger::log(Packet* p, const char* msg, Event* event)
{
    assert(p);

    // FIXIT-L convert to packet method
    if ( !p->is_cooked() or p->pseudo_type == PSEUDO_PKT_IP )
        _Unified2LogPacketAlert(p, msg, &config, event, UNIFIED2_PACKET);

    else if ( !config.legacy_events )
        _Unified2LogPacketAlert(p, msg, &config, event, UNIFIED2_BUFFER);

    else
    {
        U2PseudoHeader u2h(p);
        _Unified2LogPacketAlert(p, msg, &config, event, UNIFIED2_PACKET, &u2h);
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
#else
const BaseApi* eh_unified2[] =
#endif
{
    &u2_api.base,
    nullptr
};

