//#include <stdarg.h>
#include "external_apis.h"
#include "session_file.h"
#include "appid_flow_data.h"

#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"

AppIdData* pAppIdData = nullptr;

/***********************************************************
 * Local functions
 **********************************************************/
static void determinePacketDirection(Packet* p, uint16_t p_port, uint16_t scb_port, int is_sport)
{
    if (is_sport)
        p->packet_flags |= (p_port == scb_port) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
    else
        p->packet_flags |= (p_port == scb_port) ? PKT_FROM_SERVER : PKT_FROM_CLIENT;
}

static void setPacketDirectionFlag(Packet* p, SessionControlBlock* session)
{
    if (p->is_ip4())
    {
        if (sfip_fast_eq4(p->ptrs.ip_api.get_src(), &session->client_ip))
        {
            if (p->is_tcp())
                determinePacketDirection(p, p->ptrs.tcph->src_port(), session->client_port, true);
            else if (p->is_udp())
                determinePacketDirection(p, p->ptrs.udph->src_port(), session->client_port, true);
            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
        else if (sfip_fast_eq4(p->ptrs.ip_api.get_dst(), &session->client_ip))
        {
            if (p->is_tcp())
                determinePacketDirection(p, p->ptrs.tcph->dst_port(), session->client_port, false);
            else if (p->is_udp())
                determinePacketDirection(p, p->ptrs.udph->dst_port(), session->client_port, false);
            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
    }
    else
    {
        if (sfip_fast_eq6(p->ptrs.ip_api.get_src(), &session->client_ip))
        {
            if (p->is_tcp())
                determinePacketDirection(p, p->ptrs.tcph->src_port(), session->client_port, true);
            else if (p->is_udp())
                determinePacketDirection(p, p->ptrs.udph->src_port(), session->client_port, true);
            else
                p->packet_flags |= PKT_FROM_CLIENT;
        }
        else if (sfip_fast_eq6(p->ptrs.ip_api.get_dst(), &session->client_ip))
        {
            if (p->is_tcp())
                determinePacketDirection(p, p->ptrs.tcph->dst_port(), session->client_port, false);
            else if (p->is_udp())
                determinePacketDirection(p, p->ptrs.udph->dst_port(), session->client_port, false);
            else
                p->packet_flags |= PKT_FROM_SERVER;
        }
    }
}

NORETURN void FatalError(const char* format,...)
{
    va_list arg;

    printf("FATAL ERROR: ");

    va_start (arg, format);
    vfprintf (stdout, format, arg);
    va_end (arg);
    fflush(stdout);

    exit(-1);
}

void LogMessage(const char* format,...)
{
    va_list arg;

    printf("LOG MESSAGE: ");

    va_start (arg, format);
    vfprintf (stdout, format, arg);
    va_end (arg);
    fflush(stdout);
}

/***********************************************************
 * _dpd APIs
 **********************************************************/
void logMsg(const char* format, ...)
{
    va_list arg;

    printf("LOG: ");

    va_start (arg, format);
    vfprintf (stdout, format, arg);
    va_end (arg);
    fflush(stdout);
}

void errMsg(const char* format, ...)
{
    va_list arg;

    printf("ERROR: ");

    va_start (arg, format);
    vfprintf (stdout, format, arg);
    va_end (arg);
    fflush(stdout);
}

void debugMsg(uint64_t, const char* format, ...)
{
    va_list arg;

    printf("DEBUG: ");

    va_start (arg, format);
    vfprintf (stdout, format, arg);
    va_end (arg);
    fflush(stdout);
}

int16_t addProtocolReference(const char*)
{
    return 0;
}

void* addPreproc(struct _SnortConfig*, void (*)(void*, void*), uint16_t, uint32_t, uint32_t)
{
    return nullptr;
}

tSfPolicyId getParserPolicy(struct _SnortConfig*)
{
    return 0;
}

tSfPolicyId getDefaultPolicy(void)
{
    return 1;
}

bool isAppIdRequired(void)
{
    return false;
}

uint32_t getSnortInstance(void)
{
    return 0;
}

int16_t findProtocolReference(const char*)
{
    return 0;
}

/***********************************************************
 * Session APIs
 **********************************************************/
void enable_preproc_all_ports(struct _SnortConfig*, uint32_t, uint32_t)
{
}

void* get_application_data(void*, uint32_t)
{
    return pAppIdData;
}

int set_application_data(void*, uint32_t, AppIdData* data, StreamAppDataFree)
{
    pAppIdData = data;

    return 0;
}

uint32_t get_packet_direction(Packet* p)
{
    if ((p == nullptr) || (p->flow == nullptr))
        return 0;

    setPacketDirectionFlag(p, p->flow);

    return (p->packet_flags & (PKT_FROM_SERVER | PKT_FROM_CLIENT));
}

uint32_t get_session_flags(void* ssnptr)
{
    SessionControlBlock* scb = (SessionControlBlock*)ssnptr;
    return scb->ha_state.session_flags;
}

sfaddr_t* get_session_ip_address(void* scbptr, uint32_t direction)
{
    SessionControlBlock* scb = (SessionControlBlock*)scbptr;

    if (scb != nullptr)
    {
        switch (direction)
        {
        case SSN_DIR_FROM_SERVER:
            return (sfaddr_t*)(&(scb)->server_ip);

        case SSN_DIR_FROM_CLIENT:
            return (sfaddr_t*)(&(scb)->client_ip);

        default:
            break;
        }
    }

    return nullptr;
}

bool is_session_decrypted(void*)
{
    return true;
}

void set_application_id(void*, int16_t, int16_t, int16_t, int16_t)
{
}

bool is_session_http2(void*)
{
    return false;
}

int16_t get_application_protocol_id(void*)
{
    return 0;
}

char** get_http_xff_precedence(void*, uint32_t, int*)
{
    return nullptr;
}

