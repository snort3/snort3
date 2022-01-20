/*--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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
*/
/* daq_hext.c author Russ Combs <rucombs@cisco.com> */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "daq_user.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <daq_module_api.h>

#define DAQ_MOD_VERSION 1
#define DAQ_NAME "hext"
#define DAQ_TYPE (DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_MULTI_INSTANCE)

#define HEXT_DEFAULT_POOL_SIZE 16
#define DEF_BUF_SZ 16384
#define MAX_LINE_SZ  128

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _hext_msg_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    DAQ_FlowStats_t flowstats;
    DAQ_UsrHdr_t pci;
    uint8_t* data;
    struct _hext_msg_desc* next;
} HextMsgDesc;

typedef struct
{
    HextMsgDesc* pool;
    HextMsgDesc* freelist;
    DAQ_MsgPoolInfo_t info;
} HextMsgPool;

typedef struct
{
    /* Configuration */
    char* filename;
    unsigned snaplen;
    int dlt;

    /* State */
    DAQ_ModuleInstance_h modinst;
    HextMsgPool pool;
    FILE* fp;
    volatile bool interrupted;

    bool sof;
    bool eof;

    DAQ_UsrHdr_t pci;
    DAQ_UsrHdr_t cfg;

    DAQ_Stats_t stats;
} HextContext;

static DAQ_VariableDesc_t hext_variable_descriptions[] = {
    { "dlt", "Data link type to report to the application instead of DLT_USER (integer)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------
// utility functions
//-------------------------------------------------------------------------

static void destroy_message_pool(HextContext* hc)
{
    HextMsgPool* pool = &hc->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].data);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_message_pool(HextContext* hc, unsigned size)
{
    HextMsgPool* pool = &hc->pool;
    pool->pool = calloc(sizeof(HextMsgDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(hc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(HextMsgDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(HextMsgDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        HextMsgDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(hc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(hc->modinst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, hc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += hc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->address_space_id = 0;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->flags = 0;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->owner = hc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static void set_c2s(HextContext* hc, int c2s)
{
    if (c2s)
    {
        hc->pci = hc->cfg;
    }
    else
    {
        hc->pci.src_addr = hc->cfg.dst_addr;
        hc->pci.dst_addr = hc->cfg.src_addr;
        hc->pci.src_port = hc->cfg.dst_port;
        hc->pci.dst_port = hc->cfg.src_port;
        hc->pci.flags &= ~DAQ_USR_FLAG_TO_SERVER;
    }
}

static void parse_host(const char* s, uint32_t* addr, uint16_t* port)
{
    char buf[32];  // oversize so pton() errors out if too long
    unsigned c = 0;

    while (isspace(*s))
        s++;

    while (*s && !isspace(*s) && c < sizeof(buf))
        buf[c++] = *s++;

    if (c == sizeof(buf))
        --c;

    buf[c] = '\0';

    inet_pton(AF_INET, buf, addr);
    *port = atoi(s);
}

static void parse_pci(HextContext* hc, const char* s)
{
    parse_host(s, &hc->pci.src_addr, &hc->pci.src_port);

    s = strstr(s, "->");

    if (!s)
        return;

    parse_host(s+2, &hc->pci.dst_addr, &hc->pci.dst_port);

    // hack until client / server is resolved:
    if (hc->pci.src_port >= hc->pci.dst_port)
        hc->pci.flags |= DAQ_USR_FLAG_TO_SERVER;
    else
        hc->pci.flags &= ~DAQ_USR_FLAG_TO_SERVER;
}

static bool is_ipv4(char const* src)
{
    struct in6_addr temp;
    if (inet_pton(AF_INET, src, &temp) == 1)
        return true;
    else if (inet_pton(AF_INET6, src, &temp) == 1)
        return false;

    return false;
}

static void IpAddr(uint32_t* addr, char const* ip)
{
    if (is_ipv4(ip))
    {
        addr[0] = 0;
        addr[1] = 0;
        addr[2] = htonl(0xffff);
        inet_pton(AF_INET, ip, &addr[3]);
    }
    else
        inet_pton(AF_INET6, ip, addr);
}

static bool parse_flowstats(DAQ_MsgType type, const char* line, HextMsgDesc *desc)
{
#define FLOWSTATS_FORMAT \
    "%" SCNi16 " "  /* ingress_group */  \
    "%" SCNi16 " "  /* egress_group */   \
    "%" SCNi32 " "  /* ingress_intf */   \
    "%" SCNi32 " "  /* egress_intf */    \
    "%s "           /* srcAddr */       \
    "%" SCNu16 " "  /* initiator_port */ \
    "%s "           /* dstAddr */       \
    "%" SCNu16 " "  /* responder_port */ \
    "%" SCNu32 " "  /* opaque */        \
    "%" SCNu64 " "  /* initiator_pkts */ \
    "%" SCNu64 " "  /* responder_pkts */ \
    "%" SCNu64 " "  /* initiator_pkts_dropped */  \
    "%" SCNu64 " "  /* responder_pkts_dropped */  \
    "%" SCNu64 " "  /* initiator_bytes_dropped */ \
    "%" SCNu64 " "  /* responder_bytes_dropped */ \
    "%" SCNu8  " "  /* is_qos_applied_on_src_intf */ \
    "%" SCNu32 " "  /* sof_timestamp.tv_sec */  \
    "%" SCNu32 " "  /* eof_timestamp.tv_sec */  \
    "%" SCNu16 " "  /* vlan_tag */      \
    "%" SCNu16 " "  /* address_space_id */  \
    "%" SCNu8  " "  /* protocol */ \
    "%" SCNu8       /* flags */
#define FLOWSTATS_ITEMS 22
    DAQ_FlowStats_t* f = &desc->flowstats;
    char srcaddr[INET6_ADDRSTRLEN], dstaddr[INET6_ADDRSTRLEN];
    uint32_t sof_sec, eof_sec;
    int rval = sscanf(line, FLOWSTATS_FORMAT, &f->ingress_group, &f->egress_group, &f->ingress_intf,
            &f->egress_intf, srcaddr, &f->initiator_port, dstaddr, &f->responder_port, &f->opaque,
            &f->initiator_pkts, &f->responder_pkts, &f->initiator_pkts_dropped, &f->responder_pkts_dropped,
            &f->initiator_bytes_dropped, &f->responder_bytes_dropped, &f->is_qos_applied_on_src_intf,
            &sof_sec, &eof_sec, &f->vlan_tag, &f->address_space_id,
            &f->protocol, &f->flags);
    if (rval != FLOWSTATS_ITEMS)
        return false;

    f->sof_timestamp.tv_sec = sof_sec;
    f->eof_timestamp.tv_sec = eof_sec;

    desc->msg.type = type;
    desc->msg.hdr_len = sizeof(desc->flowstats);
    desc->msg.hdr = &desc->flowstats;
    desc->msg.data_len = 0;
    desc->msg.data = NULL;

    IpAddr((uint32_t*)&f->initiator_ip, srcaddr);
    f->initiator_port = htons(f->initiator_port);
    IpAddr((uint32_t*)&f->responder_ip, dstaddr);
    f->responder_port = htons(f->responder_port);
    f->sof_timestamp.tv_usec = 0;
    f->eof_timestamp.tv_usec = 0;
    if (f->vlan_tag == 0)
        f->vlan_tag = 0xfff;

    return true;
}

static uint8_t xlat(char c)
{
    switch (c)
    {
    case 'r': return '\r';
    case 'n': return '\n';
    case 't': return '\t';
    case '\\': return '\\';
    }
    return c;
}

static int unescape(char c, char* u)
{
    static int esc = 0;
    if (!esc && c == '\\')
    {
        esc = 1;
        return 0;
    }
    else if (esc)
    {
        esc = 0;
        *u = xlat(c);
    }
    else
        *u = c;

    return 1;
}

//-------------------------------------------------------------------------
// parsing functions
//-------------------------------------------------------------------------
// all commands start with $
// $packet <addr> <port> -> <addr> <port>
// $packet -> client
// $packet -> server
// $client <addr> <port>
// $server <addr> <port>
static bool parse_command(HextContext* hc, const char* s, HextMsgDesc *desc)
{
    bool msg = false;

    if (!strncmp(s, "packet -> client", 16))
        set_c2s(hc, 0);

    else if (!strncmp(s, "packet -> server", 16))
        set_c2s(hc, 1);

    else if (!strncmp(s, "packet ", 7))
        parse_pci(hc, s+7);

    else if (!strncmp(s, "client ", 7))
        parse_host(s+7, &hc->cfg.src_addr, &hc->cfg.src_port);

    else if (!strncmp(s, "server ", 7))
        parse_host(s+7, &hc->cfg.dst_addr, &hc->cfg.dst_port);

    else if (!strncmp(s, "sof ", 4))
        msg = parse_flowstats(DAQ_MSG_TYPE_SOF, s+4, desc);

    else if (!strncmp(s, "eof ", 4))
        msg = parse_flowstats(DAQ_MSG_TYPE_EOF, s+4, desc);

    return msg;
}

// load quoted string data into buffer up to snaplen
static void parse_string(HextContext* hc, char* s, HextMsgDesc *desc)
{
    char t;

    while (*s && *s != '"' && desc->msg.data_len < hc->snaplen)
    {
        if (unescape(*s++, &t))
            desc->data[desc->msg.data_len++] = t;
    }
    desc->pkthdr.pktlen = desc->msg.data_len;
}

// load hex data into buffer up to snaplen
static void parse_hex(HextContext* hc, char* s, HextMsgDesc *desc)
{
    char* t = s;
    long x = strtol(t, &s, 16);

    while (*s && s != t && desc->msg.data_len  < hc->snaplen)
    {
        desc->data[desc->msg.data_len++] = (uint8_t) x;
        x = strtol(t=s, &s, 16);
    }
    desc->pkthdr.pktlen = desc->msg.data_len;
}

static void init_packet_message(HextContext* hc, HextMsgDesc* desc)
{
    DAQ_PktHdr_t *pkthdr = &desc->pkthdr;

    desc->msg.type = DAQ_MSG_TYPE_PACKET;
    desc->msg.hdr_len = sizeof(*pkthdr);
    desc->msg.hdr = pkthdr;
    desc->msg.data_len = 0;
    desc->msg.data = desc->data;

    struct timeval t;
    gettimeofday(&t, NULL);

    pkthdr->ts.tv_sec = t.tv_sec;
    pkthdr->ts.tv_usec = t.tv_usec;

    desc->pci = hc->pci;
    if (hc->sof)
    {
        desc->pci.flags |= DAQ_USR_FLAG_START_FLOW;
        hc->sof = false;
    }
}

static bool parse(HextContext* hc, char* line, HextMsgDesc* desc)
{
    char* s = line;
    bool got_msg = false;

    while (isspace(*s))
        s++;

    // Force a flush of the current packet message if we hit a blank line or command
    switch (*s)
    {
    case '\0':
        if (desc->msg.data)
            got_msg = true;
        break;

    case '#':
        break;

    case '$':
        // Do not reset the line buffer so that we can parse the command the next time through
        if (desc->msg.data)
            return true;

        got_msg = parse_command(hc, s+1, desc);
        break;

    case '"':
        if (!desc->msg.data)
            init_packet_message(hc, desc);
        parse_string(hc, s+1, desc);
        break;

    case 'x':
        if (!desc->msg.data)
            init_packet_message(hc, desc);
        parse_hex(hc, s+1, desc);
        break;
    }
    line[0] = '\0';
    return got_msg;
}

static DAQ_RecvStatus hext_read_message(HextContext* hc, HextMsgDesc* desc)
{
    char line[MAX_LINE_SZ];
    char* s = NULL;

    desc->msg.data = NULL;
    line[0] = '\0';
    while (line[0] != '\0' || (s = fgets(line, sizeof(line), hc->fp)) != NULL)
    {
        // FIXIT-L Currently no error checking, just ignores bad lines
        if (parse(hc, line, desc))
            break;
    }

    if (!s)
    {
        if (feof(hc->fp))
        {
            // If there is still pending data in a packet message, mark it as End of Flow and flush it
            // Otherwise, create an empty packet message to convey the End of Flow
            // FIXIT-M - Make this actually the case, for now Snort can't handle data on packets marked EoF
            /*
            if (!hc->eof)
            {
                if (!desc->msg.data)
                    init_packet_message(hc, desc);
                desc->pci.flags |= DAQ_USR_FLAG_END_FLOW;
                hc->eof = true;
                return DAQ_RSTAT_OK;
            }
            */
            if (desc->msg.data)
                return DAQ_RSTAT_OK;
            if (!hc->eof)
            {
                init_packet_message(hc, desc);
                desc->pci.flags |= DAQ_USR_FLAG_END_FLOW;
                hc->eof = true;
                return DAQ_RSTAT_OK;
            }
            return DAQ_RSTAT_EOF;
        }

        if (ferror(hc->fp))
        {
            char error_msg[1024] = {0};
            if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
                SET_ERROR(hc->modinst, "%s: can't read from file (%s)\n", DAQ_NAME, error_msg);
            else
                SET_ERROR(hc->modinst, "%s: can't read from file: %d\n", DAQ_NAME, errno);
            return DAQ_RSTAT_ERROR;
        }
    }

    return DAQ_RSTAT_OK;
}

//-------------------------------------------------------------------------
// file functions
//-------------------------------------------------------------------------

static int hext_setup(HextContext* hc)
{
    if (!strcmp(hc->filename, "tty"))
    {
        hc->fp = stdin;
    }
    else if (!(hc->fp = fopen(hc->filename, "r")))
    {
        char error_msg[1024] = {0};
        if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
            SET_ERROR(hc->modinst, "%s: can't open file (%s)\n", DAQ_NAME, error_msg);
        else
            SET_ERROR(hc->modinst, "%s: can't open file: %d\n", DAQ_NAME, errno);
        return -1;
    }
    parse_host("192.168.1.2 12345", &hc->cfg.src_addr, &hc->cfg.src_port);
    parse_host("10.1.2.3 80", &hc->cfg.dst_addr, &hc->cfg.dst_port);

    hc->cfg.ip_proto = hc->pci.ip_proto = IPPROTO_TCP;
    hc->cfg.flags = hc->pci.flags = DAQ_USR_FLAG_TO_SERVER;
    hc->sof = true;
    hc->eof = false;

    return 0;
}


//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static int hext_daq_module_load(const DAQ_BaseAPI_t* base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int hext_daq_get_variable_descs(const DAQ_VariableDesc_t** var_desc_table)
{
    *var_desc_table = hext_variable_descriptions;

    return sizeof(hext_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int hext_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void** ctxt_ptr)
{
    HextContext* hc;
    int rval = DAQ_ERROR;

    hc = calloc(1, sizeof(*hc));
    if (!hc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new Hext context!", DAQ_NAME);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    hc->modinst = modinst;

    hc->snaplen = daq_base_api.config_get_snaplen(modcfg) ? daq_base_api.config_get_snaplen(modcfg) : DEF_BUF_SZ;
    hc->dlt = DLT_USER;

    const char* varKey, * varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        /* Retrieve the requested buffer size (default = 0) */
        if (!strcmp(varKey, "dlt"))
            hc->dlt = strtol(varValue, NULL, 10);
        else
        {
            SET_ERROR(modinst, "%s: Unknown variable name: '%s'", DAQ_NAME, varKey);
            rval = DAQ_ERROR_INVAL;
            goto err;
        }

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    const char* filename = daq_base_api.config_get_input(modcfg);
    if (filename)
    {
        if (!(hc->filename = strdup(filename)))
        {
            SET_ERROR(modinst, "%s: Couldn't allocate memory for the filename!", DAQ_NAME);
            rval = DAQ_ERROR_NOMEM;
            goto err;
        }
    }

    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    rval = create_message_pool(hc, pool_size ? pool_size : HEXT_DEFAULT_POOL_SIZE);
    if (rval != DAQ_SUCCESS)
        goto err;

    *ctxt_ptr = hc;

    return DAQ_SUCCESS;

err:
    if (hc)
    {
        if (hc->filename)
            free(hc->filename);
        destroy_message_pool(hc);
        free(hc);
    }
    return rval;
}

static void hext_daq_destroy(void* handle)
{
    HextContext* hc = (HextContext*) handle;

    if (hc->filename)
        free(hc->filename);
    destroy_message_pool(hc);
    free(hc);
}

static int hext_daq_start(void* handle)
{
    HextContext* hc = (HextContext*) handle;

    if (hext_setup(hc))
        return DAQ_ERROR;

    return DAQ_SUCCESS;
}

static int hext_daq_interrupt(void* handle)
{
    HextContext* hc = (HextContext*) handle;
    hc->interrupted = true;
    return DAQ_SUCCESS;
}

static int hext_daq_stop(void* handle)
{
    HextContext* hc = (HextContext*) handle;

    if (hc->fp != stdin)
        fclose(hc->fp);

    hc->fp = NULL;

    return DAQ_SUCCESS;
}

static int hext_daq_ioctl(void* handle, DAQ_IoctlCmd cmd, void* arg, size_t arglen)
{
    (void) handle;

    if (cmd == DIOCTL_QUERY_USR_PCI)
    {
        if (arglen != sizeof(DIOCTL_QueryUsrPCI))
            return DAQ_ERROR_INVAL;
        DIOCTL_QueryUsrPCI* qup = (DIOCTL_QueryUsrPCI*) arg;
        if (!qup->msg)
            return DAQ_ERROR_INVAL;
        HextMsgDesc* desc = (HextMsgDesc*) qup->msg->priv;
        qup->pci = &desc->pci;
        return DAQ_SUCCESS;
    }
    return DAQ_ERROR_NOTSUP;
}

static int hext_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    HextContext* hc = (HextContext*) handle;
    memcpy(stats, &hc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void hext_daq_reset_stats(void* handle)
{
    HextContext* hc = (HextContext*) handle;
    memset(&hc->stats, 0, sizeof(hc->stats));
}

static int hext_daq_get_snaplen (void* handle)
{
    HextContext* hc = (HextContext*) handle;
    return hc->snaplen;
}

static uint32_t hext_daq_get_capabilities(void* handle)
{
    (void) handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_INTERRUPT | DAQ_CAPA_UNPRIV_START;
}

static int hext_daq_get_datalink_type(void* handle)
{
    HextContext* hc = (HextContext*) handle;
    return hc->dlt;
}

static unsigned hext_daq_msg_receive(void* handle, const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat)
{
    HextContext* hc = (HextContext*) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    unsigned idx = 0;

    while (idx < max_recv)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (hc->interrupted)
        {
            hc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* Make sure that we have a message descriptor available to populate. */
        HextMsgDesc* desc = hc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        /* Attempt to read a message into the descriptor. */
        status = hext_read_message(hc, desc);
        if (status != DAQ_RSTAT_OK)
            break;

        /* Last, but not least, extract this descriptor from the free list and
           place the message in the return vector. */
        hc->pool.freelist = desc->next;
        desc->next = NULL;
        hc->pool.info.available--;
        msgs[idx] = &desc->msg;

        idx++;
    }

    *rstat = status;

    return idx;
}

static int hext_daq_msg_finalize(void* handle, const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    HextContext* hc = (HextContext*) handle;
    HextMsgDesc* desc = (HextMsgDesc *) msg->priv;

    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    hc->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = hc->pool.freelist;
    hc->pool.freelist = desc;
    hc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int hext_daq_get_msg_pool_info(void* handle, DAQ_MsgPoolInfo_t* info)
{
    HextContext* hc = (HextContext*) handle;

    *info = hc->pool.info;

    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t hext_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_MOD_VERSION,
    /* .name = */ DAQ_NAME,
    /* .type = */ DAQ_TYPE,
    /* .load = */ hext_daq_module_load,
    /* .unload = */ NULL,
    /* .get_variable_descs = */ hext_daq_get_variable_descs,
    /* .instantiate = */ hext_daq_instantiate,
    /* .destroy = */ hext_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ hext_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ hext_daq_interrupt,
    /* .stop = */ hext_daq_stop,
    /* .ioctl = */ hext_daq_ioctl,
    /* .get_stats = */ hext_daq_get_stats,
    /* .reset_stats = */ hext_daq_reset_stats,
    /* .get_snaplen = */ hext_daq_get_snaplen,
    /* .get_capabilities = */ hext_daq_get_capabilities,
    /* .get_datalink_type = */ hext_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ hext_daq_msg_receive,
    /* .msg_finalize = */ hext_daq_msg_finalize,
    /* .get_msg_pool_info = */ hext_daq_get_msg_pool_info,
};

