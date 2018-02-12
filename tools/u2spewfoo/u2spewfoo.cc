//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// u2spewfoo.cc author Adam Keeton

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "u2_common.h"

static long s_pos = 0, s_off = 0;

#define TO_IP(x) x >> 24, ((x) >> 16)& 0xff, ((x) >> 8)& 0xff, (x)& 0xff

static u2iterator* new_iterator(char* filename)
{
    FILE* f = fopen(filename, "rb");
    u2iterator* ret;

    if (!f)
    {
        printf("ERROR: Failed to open file: %s\n\tErrno: %s\n",
            filename, strerror(errno));
        return nullptr;
    }

    ret = (u2iterator*)malloc(sizeof(u2iterator));

    if (!ret)
    {
        printf("ERROR: Failed to initialize iterator\n");
        fclose(f);
        return nullptr;
    }

    ret->file = f;
    ret->filename = strdup(filename);
    if (!ret->filename )
    {
        printf("ERROR: Failed to initialize iterator for %s\n", filename);
        free(ret);
        fclose(f);
        return nullptr;
    }
    return ret;
}

static inline void free_iterator(u2iterator* it)
{
    if (it->file)
        fclose(it->file);
    if (it->filename)
        free(it->filename);
    if (it)
        free(it);
}

static bool get_record(u2iterator* it, u2record* record)
{
    uint32_t bytes_read;
    uint8_t* tmp;

    if (!it || !it->file)
        return false;

    /* check if the log was rotated */
    if (feof(it->file))
    {
        /* Get next timestamped file? */
        puts("Hit the EOF .. and this is not being handled yet.");
        return false;
    }

    if ( s_off )
    {
        if ( fseek(it->file, s_pos+s_off, SEEK_SET) )
        {
            puts("Unable to SEEK on current file .. and this is not being handled yet.");
            return false;
        }
        s_off = 0;
    }

    /* read type and length */
    bytes_read = fread(record, 1, sizeof(uint32_t) * 2, it->file);
    /* But they're in network order! */
    record->type= ntohl(record->type);
    record->length= ntohl(record->length);

    //if(record->type == UNIFIED2_PACKET) record->length+=4;

    if (bytes_read == 0)
        /* EOF */
        return false;

    if (bytes_read != sizeof(uint32_t)*2)
    {
        puts("ERROR: Failed to read record metadata.");
        printf("\tRead %u of %lu bytes\n", bytes_read, (unsigned long)sizeof(uint32_t)*2);
        return false;
    }

    s_pos = ftell(it->file);

    tmp = (uint8_t*)realloc(record->data, record->length);

    if (!tmp)
    {
        puts("ERROR: Failed to allocate record memory.");
        free(record->data);
        record->data = nullptr;
        return false;
    }

    record->data = tmp;

    bytes_read = fread(record->data, 1, record->length, it->file);

    if (bytes_read != record->length)
    {
        puts("ERROR: Failed to read all record data.");
        printf("\tRead %u of %u bytes\n", bytes_read, record->length);

        if ( record->type != UNIFIED2_PACKET ||
            bytes_read < ntohl(((Serial_Unified2Packet*)record->data)->packet_length)
            )
            return false;

        clearerr(it->file);
    }

    return true;
}

static void extradata_dump(u2record* record)
{
    uint8_t* field, * data;
    int i;
    int len = 0;
    SerialUnified2ExtraData event;
    Unified2ExtraDataHdr eventHdr;
    uint32_t ip;
    char ip6buf[INET6_ADDRSTRLEN+1];
    struct in6_addr ipAddr;

    memcpy(&eventHdr, record->data, sizeof(Unified2ExtraDataHdr));

    memcpy(&event, record->data + sizeof(Unified2ExtraDataHdr), sizeof(SerialUnified2ExtraData));

    /* network to host ordering */
    field = (uint8_t*)&eventHdr;
    for (i=0; i<2; i++, field+=4)
    {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = (uint8_t*)&event;
    for (i=0; i<6; i++, field+=4)
    {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    printf("\n(ExtraDataHdr)\n"
        "\tevent type: %u\tevent length: %u\n",
        eventHdr.event_type, eventHdr.event_length);

    printf("\n(ExtraData)\n"
        "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
        "\ttype: %u\tdatatype: %u\tbloblength: %u\t",
        event.sensor_id, event.event_id,
        event.event_second, event.type,
        event.data_type, event.blob_length);

    len = event.blob_length - sizeof(event.blob_length) - sizeof(event.data_type);

    switch (event.type)
    {
    case EVENT_INFO_XFF_IPV4:
        memcpy(&ip, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData),
            sizeof(uint32_t));
        ip = ntohl(ip);
        printf("Original Client IP: %u.%u.%u.%u\n", TO_IP(ip));
        break;

    case EVENT_INFO_XFF_IPV6:
        memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) +
            sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
        printf("Original Client IP: %s\n", ip6buf);
        break;

    case EVENT_INFO_GZIP_DATA:
        printf("GZIP Decompressed Data: %.*s\n",
            len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_JSNORM_DATA:
        printf("Normalized JavaScript Data: %.*s\n",
            len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_SMTP_FILENAME:
        printf("SMTP Attachment Filename: %.*s\n",
            len,record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_SMTP_MAILFROM:
        printf("SMTP MAIL FROM Addresses: %.*s\n",
            len,record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_SMTP_RCPTTO:
        printf("SMTP RCPT TO Addresses: %.*s\n",
            len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_SMTP_EMAIL_HDRS:
        printf("SMTP EMAIL HEADERS: \n%.*s\n",
            len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_HTTP_URI:
        printf("HTTP URI: %.*s\n",
            len, record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData));
        break;

    case EVENT_INFO_HTTP_HOSTNAME:
        printf("HTTP Hostname: ");
        data = record->data + sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData);
        for (i=0; i < len; i++)
        {
            if (iscntrl(data[i]))
                printf("%c",'.');
            else
                printf("%c",data[i]);
        }
        printf("\n");
        break;

    case EVENT_INFO_IPV6_SRC:
        memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) +
            sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
        printf("IPv6 Source Address: %s\n", ip6buf);
        break;

    case EVENT_INFO_IPV6_DST:
        memcpy(&ipAddr, record->data + sizeof(Unified2ExtraDataHdr) +
            sizeof(SerialUnified2ExtraData), sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &ipAddr, ip6buf, INET6_ADDRSTRLEN);
        printf("IPv6 Destination Address: %s\n", ip6buf);
        break;

    default:
        break;
    }
}

static const char* lookup(const char* list[], unsigned size, unsigned idx)
{
    if ( idx < size )
        return list[idx];

    static char buf[8];
    snprintf(buf, sizeof(buf), "%u", idx);
    return buf;
}

static const char* get_status(uint8_t stat)
{
    const char* stats[] = { "allow", "can't", "would", "force" };
    return lookup(stats, sizeof(stats)/sizeof(stats[0]), stat);
}

static const char* get_action(uint8_t act)
{
    const char* acts[] = { "pass", "dtop", "block", "reset" };
    return lookup(acts, sizeof(acts)/sizeof(acts[0]), act);
}

static void print_addr_port(
    const char* which, unsigned af, const uint32_t* addr, uint16_t port)
{
    uint16_t fam = (af == 0x4) ? AF_INET : AF_INET6;
    unsigned idx = (fam == AF_INET) ? 3 : 0;

    char ip_buf[INET6_ADDRSTRLEN+1];
    inet_ntop(fam, addr+idx, ip_buf, sizeof(ip_buf));

    printf("\t%s IP: %s\tPort: %hu\n", which, ip_buf, htons(port));
}

static void event3_dump(u2record* record)
{
    Unified2Event event;
    memcpy(&event, record->data, sizeof(event));

    printf("%s", "\n(Event)\n");

    printf("\tSnort ID: %u\tEvent ID: %u\tSeconds: %u.%06u\n",
        htonl(event.snort_id), htonl(event.event_id),
        htonl(event.event_second), htonl(event.event_microsecond));

    printf(
        "\tPolicy ID:\tContext: %u\tInspect: %u\tDetect: %u\n",
        htonl(event.policy_id_context), htonl(event.policy_id_inspect),
        htonl(event.policy_id_detect));

    printf(
        "\tRule %u:%u:%u\tClass: %u\tPriority: %u\n",
        htonl(event.rule_gid), htonl(event.rule_sid), htonl(event.rule_rev),
        htonl(event.rule_class), htonl(event.rule_priority));

    printf(
        "\tMPLS Label: %u\tVLAN ID: %hu\tIP Version: 0x%hhX\tIP Proto: %hhu\n",
        htonl(event.pkt_mpls_label), htons(event.pkt_vlan_id),
        event.pkt_ip_ver, event.pkt_ip_proto);

    print_addr_port("Src", event.pkt_ip_ver >> 4, event.pkt_src_ip, event.pkt_src_port_itype);
    print_addr_port("Dst", event.pkt_ip_ver & 0xF, event.pkt_dst_ip, event.pkt_dst_port_icode);

    printf("\tApp Name: %s\n", event.app_name[0] ? event.app_name : "none");

    printf(
        "\tStatus: %s\tAction: %s\n",
        get_status(event.snort_status), get_action(event.snort_action));
}

static void event2_dump(u2record* record)
{
    uint8_t* field;
    int i;

    Unified2IDSEvent event;

    memcpy(&event, record->data, sizeof(event));

    /* network to host ordering
       In the event structure, only the last 40 bits are not 32 bit fields
       The first 11 fields need to be converted */
    field = (uint8_t*)&event;
    for (i=0; i<11; i++, field+=4)
    {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    field +=6;
    *(uint32_t*)field = ntohl(*(uint32_t*)field); /* mpls_label */
    field += 4;
    /* policy_id and vlanid */
    for (i=0; i<2; i++, field+=2)
    {
        *(uint16_t*)field = ntohs(*(uint16_t*)field);
    }
    /* done changing the network ordering */

    printf("\n(Event)\n"
        "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
        "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
        "\tpriority: %u\tip source: %u.%u.%u.%u\tip destination: %u.%u.%u.%u\n"
        "\tsrc port: %hu\tdest port: %hu\tip_proto: %hhu\timpact_flag: %hhu\tblocked: %hhu\n"
        "\tmpls label: %u\tvlan id: %hu\tpolicy id: %hu\tappid: %s\n",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, TO_IP(event.ip_source),
        TO_IP(event.ip_destination), event.sport_itype,
        event.dport_icode, to_utype(event.ip_proto),
        event.impact_flag, event.blocked,
        event.mpls_label, event.vlanId, event.pad2, event.app_name);
}

static void event2_6_dump(u2record* record)
{
    uint8_t* field;
    int i;
    char ip6buf[INET6_ADDRSTRLEN+1];
    Unified2IDSEventIPv6 event;

    memcpy(&event, record->data, sizeof(event));

    /* network to host ordering
       In the event structure, only the last 40 bits are not 32 bit fields
       The first fields need to be converted */
    field = (uint8_t*)&event;
    for (i=0; i<9; i++, field+=4)
    {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    field +=6;
    *(uint32_t*)field = ntohl(*(uint32_t*)field); /* mpls_label */
    field += 4;
    /* policy_id and vlanid */
    for (i=0; i<2; i++, field+=2)
    {
        *(uint16_t*)field = ntohs(*(uint16_t*)field);
    }
    /* done changing the network ordering */

    inet_ntop(AF_INET6, &event.ip_source, ip6buf, INET6_ADDRSTRLEN);

    printf("\n(IPv6 Event)\n"
        "\tsensor id: %u\tevent id: %u\tevent second: %u\tevent microsecond: %u\n"
        "\tsig id: %u\tgen id: %u\trevision: %u\t classification: %u\n"
        "\tpriority: %u\tip source: %s\t",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, ip6buf);

    inet_ntop(AF_INET6, &event.ip_destination, ip6buf, INET6_ADDRSTRLEN);
    printf("ip destination: %s\n"
        "\tsrc port: %hu\tdest port: %hu\tip_proto: %hhu\timpact_flag: %hhu\tblocked: %hhu\n"
        "\tmpls label: %u\tvlan id: %hu\tpolicy id: %hu\tappid: %s\n",
        ip6buf, event.sport_itype,
        event.dport_icode, to_utype(event.ip_proto),
        event.impact_flag, event.blocked,
        event.mpls_label, event.vlanId, event.pad2, event.app_name);
}

#define LOG_CHARS 16

static void LogBuffer(const uint8_t* p, unsigned n)
{
    char hex[(3*LOG_CHARS)+1];
    char txt[LOG_CHARS+1];
    unsigned odx = 0, idx = 0, at = 0;

    for ( idx = 0; idx < n; idx++)
    {
        uint8_t byte = p[idx];
        sprintf(hex + 3*odx, "%2.02X ", byte);
        txt[odx++] = isprint(byte) ? byte : '.';

        if ( odx == LOG_CHARS )
        {
            txt[odx] = hex[3*odx] = '\0';
            printf("[%5u] %s %s\n", at, hex, txt);
            at = idx + 1;
            odx = 0;
        }
    }
    if ( odx )
    {
        txt[odx] = hex[3*odx] = '\0';
        printf("[%5u] %-48.48s %s\n", at, hex, txt);
    }
}

static void packet_dump(u2record* record)
{
    uint32_t counter;
    uint8_t* field;

    unsigned offset = sizeof(Serial_Unified2Packet)-4;
    unsigned reclen = record->length - offset;

    Serial_Unified2Packet packet;
    memcpy(&packet, record->data, offset);

    /* network to host ordering
       The first 7 fields need to be converted */
    field = (uint8_t*)&packet;
    for (counter=0; counter<7; counter++, field+=4)
    {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }
    /* done changing from network ordering */

    if (record->type == UNIFIED2_PACKET)
        printf("\nPacket\n"
            "\tsensor id: %u\tevent id: %u\tevent second: %u\n"
            "\tpacket second: %u\tpacket microsecond: %u\n"
            "\tlinktype: %u\tpacket_length: %u\n",
            packet.sensor_id, packet.event_id, packet.event_second,
            packet.packet_second, packet.packet_microsecond, packet.linktype,
            packet.packet_length);
    else
        printf("\nBuffer\n"
            "\tsensor_id: %u\tevent_id: %u\tevent_second: %u\n"
            "\tpacket_second: %u\tpacket_microsecond: %u\n"
            "\tpacket_length: %u\n",
            packet.sensor_id, packet.event_id, packet.event_second,
            packet.packet_second, packet.packet_microsecond, packet.packet_length);

    if ( record->length <= offset )
        return;

    if ( packet.packet_length != reclen )
    {
        printf("ERROR: logged %u but packet_length = %u\n",
            record->length-offset, packet.packet_length);

        if ( packet.packet_length < reclen )
        {
            reclen = packet.packet_length;
            s_off = reclen + offset;
        }
    }
    LogBuffer(record->data+offset, reclen);
}

static int u2dump(char* file)
{
    u2record record;
    u2iterator* it = new_iterator(file);

    memset(&record, 0, sizeof(record));

    if (!it)
    {
        printf("ERROR: failed to create new iterator with file: %s\n", file);
        return -1;
    }

    while ( get_record(it, &record) )
    {
        if ( record.type == UNIFIED2_EVENT3 and record.length == sizeof(Unified2Event) )
            event3_dump(&record);

        else if ( (record.type == UNIFIED2_PACKET) or (record.type == UNIFIED2_BUFFER) )
            packet_dump(&record);

        else if (record.type == UNIFIED2_EXTRA_DATA)
            extradata_dump(&record);

        // deprecated
        else if ( record.type == UNIFIED2_IDS_EVENT_VLAN and
            record.length == sizeof(Unified2IDSEvent) )
        {
            event2_dump(&record);
        }
        else if ( record.type == UNIFIED2_IDS_EVENT_IPV6_VLAN and
            record.length == sizeof(Unified2IDSEventIPv6) )
        {
            event2_6_dump(&record);
        }
        else
        {
            printf("WARNING: skipping unknown record (%u) or bad length (%u)\n",
                record.type, record.length);
        }
    }

    free_iterator(it);

    if (record.data)
        free(record.data);

    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        puts("usage: u2eventdump <file>");
        return 1;
    }

    return u2dump(argv[1]);
}

