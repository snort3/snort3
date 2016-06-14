#include <stdio.h>
#include "session_file.h"

static void sessionFileAdd(void* session, SessionFileData* data);
static SessionFileData* sessionFileFind(void* session);
static void sessionDataDump(FILE* file, SessionControlBlock* scb);
static void packetDataDump(FILE* file, uint32_t packetCount, Packet* pkt);
static void sessionDataRead(FILE* file, SessionControlBlock* scb);
static int packetDataRead(FILE* file, Packet* pkt, HttpParsedHeaders** pHttpHeader);
static void readHttpHeaderItem(FILE* file, HEADER_LOCATION* headerLocation);

static SFXHASH* sessionFiles = nullptr;

void sessionFileInit(void)
{
    sessionFiles = sfxhash_new(2048,
        sizeof(void*),
        sizeof(SessionFileData),
        0,
        0,
        nullptr,
        nullptr,
        0);
}

void sessionFileFini(void)
{
    SFXHASH_NODE* node;
    SessionFileData* data;

    for (node = sfxhash_findfirst(sessionFiles);
        node;
        node = sfxhash_findnext(sessionFiles))
    {
        data = (SessionFileData*)node->data;
        fclose(data->file);
    }

    sfxhash_delete(sessionFiles);
    sessionFiles = nullptr;
}

FILE* sessionFileProcess(Packet* pkt)
{
    static uint32_t packetCount = 0;
    static uint32_t sessionCount = 0;
    SessionFileData* pSessionFileData;
    SessionFileData sessionFileData;
    SessionControlBlock* scb = (SessionControlBlock*)pkt->stream_session;

    packetCount++;

    if (!scb)
    {
        printf("Ignoring packet %d\n", packetCount);
        return nullptr;
    }

    pSessionFileData = sessionFileFind(scb);

    if (!pSessionFileData)
    {
        pSessionFileData = &sessionFileData;

        sessionCount++;
        sprintf(pSessionFileData->fileName, "session%d.ssn", sessionCount);
        pSessionFileData->file = fopen(pSessionFileData->fileName, "w");
        pSessionFileData->packetCount = 1;

        sessionFileAdd(scb, pSessionFileData);
    }
    else
    {
        pSessionFileData->packetCount++;
    }

    sessionDataDump(pSessionFileData->file, scb);

    packetDataDump(pSessionFileData->file, pSessionFileData->packetCount, pkt);

    return pSessionFileData->file;
}

void sessionFileProcessHttp(Packet* pkt, HttpParsedHeaders* headers)
{
    FILE* file = sessionFileProcess(pkt);

    if (file == nullptr)
        return;

    if (headers->host.len > 0)
    {
        fprintf(file, "    %u %d ", PACKET_HTTP_HOST, headers->host.len);
        fwrite(headers->host.start, 1, headers->host.len, file);
    }
    if (headers->url.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_URL, headers->url.len);
        fwrite(headers->url.start, 1, headers->url.len, file);
    }
    if (headers->method.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_METHOD, headers->method.len);
        fwrite(headers->method.start, 1, headers->method.len, file);
    }
    if (headers->userAgent.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_USER_AGENT, headers->userAgent.len);
        fwrite(headers->userAgent.start, 1, headers->userAgent.len, file);
    }
    if (headers->referer.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_REFERER, headers->referer.len);
        fwrite(headers->referer.start, 1, headers->referer.len, file);
    }
    if (headers->via.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_VIA, headers->via.len);
        fwrite(headers->via.start, 1, headers->via.len, file);
    }
    if (headers->responseCode.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_RESPONSE_CODE, headers->responseCode.len);
        fwrite(headers->responseCode.start, 1, headers->responseCode.len, file);
    }
    if (headers->server.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_SERVER, headers->server.len);
        fwrite(headers->server.start, 1, headers->server.len, file);
    }
    if (headers->xWorkingWith.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_X_WORKING_WITH, headers->xWorkingWith.len);
        fwrite(headers->xWorkingWith.start, 1, headers->xWorkingWith.len, file);
    }
    if (headers->contentType.len > 0)
    {
        fprintf(file, "\n    %u %d ", PACKET_HTTP_CONTENT_TYPE, headers->contentType.len);
        fwrite(headers->contentType.start, 1, headers->contentType.len, file);
    }
    fprintf(file, "\n");
}

void sessionFileReadSession(FILE* file, SessionControlBlock* scb)
{
    char buf[16];

    while (true)
    {
        fscanf(file, "%s\n", buf);

        if (strcmp(buf, "Session:") == 0)
        {
            sessionDataRead(file, scb);
            return;
        }
    }
}

int sessionFileReadPacket(FILE* file, Packet* pkt, HttpParsedHeaders** pHttpHeader)
{
    char buf[16];

    while (true)
    {
        fscanf(file, "%s\n", buf);

        if (strncmp(buf, "Packet", 6) == 0)
        {
            fgets(buf, 16, file);
            return packetDataRead(file, pkt, pHttpHeader);
        }
    }
}

static void sessionFileAdd(void* session, SessionFileData* data)
{
    sfxhash_add(sessionFiles, &session, data);
}

static SessionFileData* sessionFileFind(void* session)
{
    return (SessionFileData*)sfxhash_find(sessionFiles, &session);
}

static void sessionDataDump(FILE* file, SessionControlBlock* scb)
{
    fprintf(file, "Session:\n");
    fprintf(file, "    %u %08X %08X %08X %08X\n", SESSION_CLIENT_IP_IA32,
        scb->client_ip.ia32[0],
        scb->client_ip.ia32[1],
        scb->client_ip.ia32[2],
        scb->client_ip.ia32[3]);
    fprintf(file, "    %u %u\n", SESSION_CLIENT_PORT, scb->client_port);
    fprintf(file, "    %u %u\n", SESSION_HA_STATE_SESSION_FLAGS, scb->ha_state.session_flags);
}

static void packetDataDump(FILE* file, uint32_t packetCount, Packet* pkt)
{
    fprintf(file, "Packet %d:\n", packetCount);

    if (pkt->pkt_header)
    {
        fprintf(file, "    %u %u\n", PACKET_PKT_HEADER_TS_TV_SEC, (unsigned
            int)pkt->pkt_header->ts.tv_sec);
        fprintf(file, "    %u %d\n", PACKET_PKT_HEADER_INGRESS_GROUP,
            pkt->pkt_header->ingress_group);
        fprintf(file, "    %u %u\n", PACKET_PKT_HEADER_PKTLEN, pkt->pkt_header->pktlen);
    }

    if (pkt->tcp_header)
    {
        fprintf(file, "    %u %u\n", PACKET_TCP_HEADER_SOURCE_PORT, pkt->tcp_header->source_port);
        fprintf(file, "    %u %u\n", PACKET_TCP_HEADER_FLAGS, pkt->tcp_header->flags);
    }

    if (pkt->udp_header)
    {
        fprintf(file, "    %u %u\n", PACKET_UDP_HEADER_SOURCE_PORT, pkt->udp_header->source_port);
    }

    if (pkt->is_ip4())
    {
        fprintf(file, "    %u %08X %08X %08X %08X\n", PACKET_IP4H_IP_ADDRS_IP_SRC_IA32,
            pkt->ip4h->ip_addrs->ip_src.ia32[0],
            pkt->ip4h->ip_addrs->ip_src.ia32[1],
            pkt->ip4h->ip_addrs->ip_src.ia32[2],
            pkt->ip4h->ip_addrs->ip_src.ia32[3]);
        fprintf(file, "    %u %u\n", PACKET_IP4H_IP_ADDRS_IP_SRC_FAMILY,
            pkt->ip4h->ip_addrs->ip_src.family);
        fprintf(file, "    %u %08X %08X %08X %08X\n", PACKET_IP4H_IP_ADDRS_IP_DST_IA32,
            pkt->ip4h->ip_addrs->ip_dst.ia32[0],
            pkt->ip4h->ip_addrs->ip_dst.ia32[1],
            pkt->ip4h->ip_addrs->ip_dst.ia32[2],
            pkt->ip4h->ip_addrs->ip_dst.ia32[3]);
        fprintf(file, "    %u %u\n", PACKET_IP4H_IP_ADDRS_IP_DST_FAMILY,
            pkt->ip4h->ip_addrs->ip_dst.family);
        fprintf(file, "    %u %u\n", PACKET_IP4H_IP_PROTO, pkt->ip4h->ip_proto);
    }

    if (pkt->ip6h)
    {
        fprintf(file, "    %u %08X %08X %08X %08X\n", PACKET_IP6H_IP_ADDRS_IP_SRC_IA32,
            pkt->ip6h->ip_addrs->ip_src.ia32[0],
            pkt->ip6h->ip_addrs->ip_src.ia32[1],
            pkt->ip6h->ip_addrs->ip_src.ia32[2],
            pkt->ip6h->ip_addrs->ip_src.ia32[3]);
        fprintf(file, "    %u %u\n", PACKET_IP6H_IP_ADDRS_IP_SRC_FAMILY,
            pkt->ip6h->ip_addrs->ip_src.family);
        fprintf(file, "    %u %08X %08X %08X %08X\n", PACKET_IP6H_IP_ADDRS_IP_DST_IA32,
            pkt->ip6h->ip_addrs->ip_dst.ia32[0],
            pkt->ip6h->ip_addrs->ip_dst.ia32[1],
            pkt->ip6h->ip_addrs->ip_dst.ia32[2],
            pkt->ip6h->ip_addrs->ip_dst.ia32[3]);
        fprintf(file, "    %u %u\n", PACKET_IP6H_IP_ADDRS_IP_DST_FAMILY,
            pkt->ip6h->ip_addrs->ip_dst.family);
    }

    fprintf(file, "    %u %u\n", PACKET_FAMILY, pkt->family);
    fprintf(file, "    %u %08X\n", PACKET_FLAGS, pkt->flags);
    fprintf(file, "    %u %u\n", PACKET_SRC_PORT, pkt->src_port);
    fprintf(file, "    %u %u\n", PACKET_DST_PORT, pkt->dst_port);
    if (pkt->payload_size)
    {
        fprintf(file, "    %u %u ", PACKET_PAYLOAD, pkt->payload_size);
        fwrite(pkt->payload, 1, pkt->payload_size, file);
        fprintf(file, "\n");
    }
}

void sessionDataRead(FILE* file, SessionControlBlock* scb)
{
    int match;
    uint32_t type;

    while (true)
    {
        match = fscanf(file, "%u", &type);

        if ((match == EOF) || (match == 0))
            return;

        switch (type)
        {
        case SESSION_CLIENT_IP_IA32:
            fscanf(file, "%x", &scb->client_ip.ia32[0]);
            fscanf(file, "%x", &scb->client_ip.ia32[1]);
            fscanf(file, "%x", &scb->client_ip.ia32[2]);
            fscanf(file, "%x\n", &scb->client_ip.ia32[3]);
            break;
        case SESSION_CLIENT_PORT:
            fscanf(file, "%u\n", (unsigned int*)&scb->client_port);
            break;
        case SESSION_HA_STATE_SESSION_FLAGS:
            fscanf(file, "%u\n", &scb->ha_state.session_flags);
            break;
        default:
            printf("Unknown session field\n");
            break;
        }
    }
}

// FIXIT - M Must check to ensure memory allocated by snort_calloc's below is freed when
// the tests complete
static int packetDataRead(FILE* file, Packet* pkt, HttpParsedHeaders** pHttpHeader)
{
    static SFDAQ_PktHdr_t pkt_header = { 0 };
    static TCPHeader tcp_header = { 0 };
    static UDPHeader udp_header = { 0 };
    static IP4Hdr ip4h = { 0 };
    static IP6Hdr ip6h = { 0 };
    static IPAddresses ip4_addrs = { 0 };
    static IPAddresses ip6_addrs = { 0 };
    int match;
    uint32_t type;

    memset(&pkt_header, 0, sizeof(pkt_header));
    memset(&tcp_header, 0, sizeof(tcp_header));
    memset(&udp_header, 0, sizeof(udp_header));
    memset(&ip4h, 0, sizeof(ip4h));
    memset(&ip6h, 0, sizeof(ip6h));
    memset(&ip4_addrs, 0, sizeof(ip4_addrs));
    memset(&ip6_addrs, 0, sizeof(ip6_addrs));

    while (true)
    {
        match = fscanf(file, "%u", &type);

        if (match == EOF)
            return -1;
        if (match == 0)
            return 0;

        switch (type)
        {
        case PACKET_PKT_HEADER_TS_TV_SEC:
            pkt->pkt_header = &pkt_header;
            fscanf(file, "%u\n", (unsigned int*)&pkt_header.ts.tv_sec);
            break;
        case PACKET_PKT_HEADER_INGRESS_GROUP:
            pkt->pkt_header = &pkt_header;
            fscanf(file, "%u\n",  &pkt_header.ingress_group);
            break;
        case PACKET_PKT_HEADER_PKTLEN:
            pkt->pkt_header = &pkt_header;
            fscanf(file, "%u\n", &pkt_header.pktlen);
            break;
        case PACKET_TCP_HEADER_SOURCE_PORT:
            pkt->tcp_header = &tcp_header;
            fscanf(file, "%u\n", (unsigned int*)&tcp_header.source_port);
            break;
        case PACKET_TCP_HEADER_FLAGS:
            pkt->tcp_header = &tcp_header;
            fscanf(file, "%u\n", (unsigned int*)&tcp_header.flags);
            break;
        case PACKET_UDP_HEADER_SOURCE_PORT:
            pkt->udp_header = &udp_header;
            fscanf(file, "%u\n", (unsigned int*)&udp_header.source_port);
            break;
        case PACKET_IP4H_IP_ADDRS_IP_SRC_IA32:
            ip4h.ip_addrs = &ip4_addrs;
            pkt->ip4h = &ip4h;

            fscanf(file, "%x", &ip4_addrs.ip_src.ia32[0]);
            fscanf(file, "%x", &ip4_addrs.ip_src.ia32[1]);
            fscanf(file, "%x", &ip4_addrs.ip_src.ia32[2]);
            fscanf(file, "%x\n", &ip4_addrs.ip_src.ia32[3]);
            break;
        case PACKET_IP4H_IP_ADDRS_IP_SRC_FAMILY:
            ip4h.ip_addrs = &ip4_addrs;
            pkt->ip4h = &ip4h;

            fscanf(file, "%u\n", (unsigned int*)&ip4_addrs.ip_src.family);
            break;
        case PACKET_IP4H_IP_ADDRS_IP_DST_IA32:
            ip4h.ip_addrs = &ip4_addrs;
            pkt->ip4h = &ip4h;

            fscanf(file, "%x", &ip4_addrs.ip_dst.ia32[0]);
            fscanf(file, "%x", &ip4_addrs.ip_dst.ia32[1]);
            fscanf(file, "%x", &ip4_addrs.ip_dst.ia32[2]);
            fscanf(file, "%x\n", &ip4_addrs.ip_dst.ia32[3]);
            break;
        case PACKET_IP4H_IP_ADDRS_IP_DST_FAMILY:
            ip4h.ip_addrs = &ip4_addrs;
            pkt->ip4h = &ip4h;

            fscanf(file, "%u\n", (unsigned int*)&ip4_addrs.ip_dst.family);
            break;
        case PACKET_IP4H_IP_PROTO:
            ip4h.ip_addrs = &ip4_addrs;
            pkt->ip4h = &ip4h;

            fscanf(file, "%u\n", (unsigned int*)&ip4h.ip_proto);
            break;
        case PACKET_IP6H_IP_ADDRS_IP_SRC_IA32:
            ip6h.ip_addrs = &ip6_addrs;
            pkt->ip6h = &ip6h;

            fscanf(file, "%x", &ip6_addrs.ip_src.ia32[0]);
            fscanf(file, "%x", &ip6_addrs.ip_src.ia32[1]);
            fscanf(file, "%x", &ip6_addrs.ip_src.ia32[2]);
            fscanf(file, "%x\n", &ip6_addrs.ip_src.ia32[3]);
            break;
        case PACKET_IP6H_IP_ADDRS_IP_SRC_FAMILY:
            ip6h.ip_addrs = &ip6_addrs;
            pkt->ip6h = &ip6h;

            fscanf(file, "%u\n", (unsigned int*)&ip6_addrs.ip_src.family);
            break;
        case PACKET_IP6H_IP_ADDRS_IP_DST_IA32:
            ip6h.ip_addrs = &ip6_addrs;
            pkt->ip6h = &ip6h;

            fscanf(file, "%x", &ip6_addrs.ip_dst.ia32[0]);
            fscanf(file, "%x", &ip6_addrs.ip_dst.ia32[1]);
            fscanf(file, "%x", &ip6_addrs.ip_dst.ia32[2]);
            fscanf(file, "%x\n", &ip6_addrs.ip_dst.ia32[3]);
            break;
        case PACKET_IP6H_IP_ADDRS_IP_DST_FAMILY:
            ip6h.ip_addrs = &ip6_addrs;
            pkt->ip6h = &ip6h;

            fscanf(file, "%u\n", (unsigned int*)&ip6_addrs.ip_dst.family);
            break;
        case PACKET_FAMILY:
            fscanf(file, "%u\n", &pkt->family);
            break;
        case PACKET_FLAGS:
            fscanf(file, "%x\n", &pkt->flags);
            break;
        case PACKET_SRC_PORT:
            fscanf(file, "%u\n", (unsigned int*)&pkt->src_port);
            break;
        case PACKET_DST_PORT:
            fscanf(file, "%u\n", (unsigned int*)&pkt->dst_port);
            break;
        case PACKET_PAYLOAD:
            fscanf(file, "%u", (unsigned int*)&pkt->payload_size);
            fgetc(file);
            pkt->payload = snort_calloc(sizeof(char)* pkt->payload_size);
            fread((uint8_t*)pkt->payload, 1, pkt->payload_size, file);
            break;
        case PACKET_HTTP_HOST:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->host);
            break;
        case PACKET_HTTP_URL:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->url);
            break;
        case PACKET_HTTP_METHOD:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->method);
            break;
        case PACKET_HTTP_USER_AGENT:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->userAgent);
            break;
        case PACKET_HTTP_REFERER:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->referer);
            break;
        case PACKET_HTTP_VIA:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->via);
            break;
        case PACKET_HTTP_RESPONSE_CODE:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->responseCode);
            break;
        case PACKET_HTTP_SERVER:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->server);
            break;
        case PACKET_HTTP_X_WORKING_WITH:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->xWorkingWith);
            break;
        case PACKET_HTTP_CONTENT_TYPE:
            if (!(*pHttpHeader))
                *pHttpHeader = snort_calloc(sizeof(HttpParsedHeaders));
            readHttpHeaderItem(file, &(*pHttpHeader)->contentType);
            break;
        default:
            printf("Unknown packet field\n");
            break;
        }
    }
}

static void readHttpHeaderItem(FILE* file, HEADER_LOCATION* headerLocation)
{
    uint8_t* start;

    fscanf(file, "%u", &headerLocation->len);
    start = snort_calloc(headerLocation->len + 1);
    fgetc(file);
    fread(start, 1, headerLocation->len, file);
    start[headerLocation->len] = '\0';
    headerLocation->start = start;
}

