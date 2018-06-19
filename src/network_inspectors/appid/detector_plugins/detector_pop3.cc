//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// detector_pop3.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_pop3.h"

#include <array>

#include "app_info_table.h"

using namespace snort;

enum POP3ClientState
{
    POP3_CLIENT_STATE_AUTH,     // POP3 - AUTHORIZATION state
    POP3_CLIENT_STATE_TRANS,    // POP3 - TRANSACTION state
    POP3_CLIENT_STATE_STLS_CMD  // POP3 - AUTHORIZATION hybrid state (probable POP3S)
};

struct ClientPOP3Data
{
    int auth;
    char* username;
    POP3ClientState state;
    int detected;
    int got_user;
};

static const uint8_t APOP[] = "APOP ";
static const uint8_t DELE[] = "DELE ";
static const uint8_t LISTC[] = "LIST ";
static const uint8_t LISTEOC[] = "LIST\x00d\x00a";
static const uint8_t LISTEOC2[] = "LIST\x00a";
static const uint8_t NOOP[] = "NOOP\x00d\x00a";
static const uint8_t NOOP2[] = "NOOP\x00a";
static const uint8_t QUIT[] = "QUIT\x00d\x00a";
static const uint8_t QUIT2[] = "QUIT\x00a";
static const uint8_t RETR[] = "RETR ";
static const uint8_t STAT[] = "STAT\x00d\x00a";
static const uint8_t STAT2[] = "STAT\x00a";
static const uint8_t RSET[] = "RSET\x00d\x00a";
static const uint8_t RSET2[] = "RSET\x00a";
static const uint8_t TOP[] = "TOP ";
static const uint8_t UIDL[] = "UIDL ";
static const uint8_t UIDLEOC[] = "UIDL\x00d\x00a";
static const uint8_t UIDLEOC2[] = "UIDL\x00a";
static const uint8_t USER[] = "USER ";
static const uint8_t PASS[] = "PASS ";
static const uint8_t CAPA[] = "CAPA\x00d\x00a";
static const uint8_t CAPA2[] = "CAPA\x00a";
static const uint8_t AUTH[] = "AUTH ";
static const uint8_t AUTHEOC[] = "AUTH\x00d\x00a";
static const uint8_t AUTHEOC2[] = "AUTH\x00a";
static const uint8_t AUTHEOC3[] = "AUTH \x00d\x00a";
static const uint8_t AUTHEOC4[] = "AUTH \x00a";
static const uint8_t STLSEOC[] = "STLS\x00d\x00a";
static const uint8_t STLSEOC2[] = "STLS\x00a";

enum Client_App_Pattern_Index
{
    /* order MUST correspond to that in tcp_patterns */
    PATTERN_USER,
    PATTERN_PASS,
    PATTERN_APOP,
    PATTERN_AUTH,
    PATTERN_AUTHEOC,
    PATTERN_AUTHEOC2,
    PATTERN_AUTHEOC3,
    PATTERN_AUTHEOC4,
    PATTERN_STLSEOC,
    PATTERN_STLSEOC2,
    PATTERN_POP3_OTHER // always last
};

static const unsigned POP3_PORT = 110;
static const unsigned POP3_COUNT_THRESHOLD = 4;

static const char POP3_OK[] = "+OK";
static const char POP3_ERR[] = "-ERR";
static const char POP3_TERM[] = ".\x00D\x00A";

enum POP3State
{
    POP3_STATE_CONNECT,
    POP3_STATE_RESPONSE,
    POP3_STATE_CONTINUE
};

static const unsigned MAX_VERSION_SIZE = 64;
struct ServicePOP3Data
{
    POP3State state;
    unsigned count;
    const char* vendor;
    char version[MAX_VERSION_SIZE];
    snort::AppIdServiceSubtype* subtype;
    int error;
};

struct POP3DetectorData
{
    ClientPOP3Data client;
    ServicePOP3Data server;
    int need_continue;
};

static Pop3ClientDetector* pop3_client_detector;
static Pop3ServiceDetector* pop3_service_detector;

static AppIdFlowContentPattern pop3_client_patterns[] =
{
    { USER, sizeof(USER)-1,         0, 1, 0 },
    { PASS, sizeof(PASS)-1,         0, 1, 0 },
    { APOP, sizeof(APOP)-1,         0, 1, 0 },
    { AUTH, sizeof(AUTH)-1,         0, 1, 0 },
    { AUTHEOC, sizeof(AUTHEOC)-1,   0, 1, 0 },
    { AUTHEOC2, sizeof(AUTHEOC2)-1, 0, 1, 0 },
    { AUTHEOC3, sizeof(AUTHEOC3)-1, 0, 1, 0 },
    { AUTHEOC4, sizeof(AUTHEOC4)-1, 0, 1, 0 },
    { STLSEOC, sizeof(STLSEOC)-1,   0, 1, 0 },
    { STLSEOC2, sizeof(STLSEOC2)-1, 0, 1, 0 },
    /* These are represented by index >= PATTERN_POP3_OTHER */
    { DELE, sizeof(DELE)-1,         0, 1, 0 },
    { LISTC, sizeof(LISTC)-1,       0, 1, 0 },
    { LISTEOC, sizeof(LISTEOC)-1,   0, 1, 0 },
    { LISTEOC2, sizeof(LISTEOC2)-1, 0, 1, 0 },
    { NOOP, sizeof(NOOP)-1,         0, 1, 0 },
    { NOOP2, sizeof(NOOP2)-1,       0, 1, 0 },
    { QUIT, sizeof(QUIT)-1,         0, 1, 0 },
    { QUIT2, sizeof(QUIT2)-1,       0, 1, 0 },
    { RETR, sizeof(RETR)-1,         0, 1, 0 },
    { STAT, sizeof(STAT)-1,         0, 1, 0 },
    { STAT2, sizeof(STAT2)-1,       0, 1, 0 },
    { RSET, sizeof(RSET)-1,         0, 1, 0 },
    { RSET2, sizeof(RSET2)-1,       0, 1, 0 },
    { TOP, sizeof(TOP)-1,           0, 1, 0 },
    { UIDL, sizeof(UIDL)-1,         0, 1, 0 },
    { UIDLEOC, sizeof(UIDLEOC)-1,   0, 1, 0 },
    { UIDLEOC2, sizeof(UIDLEOC2)-1, 0, 1, 0 },
    { CAPA, sizeof(CAPA)-1,         0, 1, 0 },
    { CAPA2, sizeof(CAPA2)-1,       0, 1, 0 },
};
static const uint32_t num_pop3_client_patterns = sizeof(pop3_client_patterns) /
    sizeof(*pop3_client_patterns);

// each entry in this array corresponds to the entry in the pop3_client_patterns array
// above and indicates if the pattern is the end of a protocol command
static std::array<bool, num_pop3_client_patterns> eoc =
{
    { false, false, false, false, true, true, true, true, true,
      true, false, false, true, true, true, true, true, true, false, true, true, true, true,
      false, false, true, true, true, true }
};

static const char ven_cppop[] = "cppop";
static const char ven_cc[] = "Cubic Circle";
static const char ven_im[] = "InterMail";
static const char ver_cc[] = "'s v";
static const char ven_po[] = "Post.Office";
static const char ver_po[] = " v";
static const char ver_po2[] = " release ";
static const char sub_po[] = " with ";
static const char subver_po[] = " version ";

Pop3ClientDetector::Pop3ClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "pop3";
    proto = IpProtocol::TCP;
    provides_user = true;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns.assign(pop3_client_patterns, pop3_client_patterns + num_pop3_client_patterns);

    appid_registry =
    {
        { APP_ID_POP3, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
        { APP_ID_POP3S, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER }
    };

    pop3_client_detector = this;
    handler->register_detector(name, this, proto);
}

Pop3ClientDetector::~Pop3ClientDetector()
{
    if (cmd_matcher)
        delete cmd_matcher;
}

void Pop3ClientDetector::do_custom_init()
{
    cmd_matcher = new snort::SearchTool("ac_full", true);

    if ( !tcp_patterns.empty() )
    {
        unsigned index = 0;

        for (auto& pat : tcp_patterns)
        {
            cmd_matcher->add(pat.pattern, pat.length, index++);
            if (pat.length > longest_pattern)
                longest_pattern = pat.length;
        }
    }
    cmd_matcher->prep();
}

static int pop3_pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    unsigned long idx = (unsigned long)id;
    if ( (int)pop3_client_patterns[idx].length != match_end_pos )
        return 0;

    unsigned long* pat_idx = (unsigned long*)data;
    *pat_idx = (unsigned long)id;
    return 1;
}

static void pop3_free_state(void* data)
{
    POP3DetectorData* dd = (POP3DetectorData*)data;
    if (dd)
    {
        ServicePOP3Data* sd = &dd->server;
        while (sd->subtype)
        {
            snort::AppIdServiceSubtype* sub = sd->subtype;
            sd->subtype = sub->next;
            if (sub->service)
                snort_free((void*)sub->service);
            if (sub->version)
                snort_free((void*)sub->version);
            snort_free(sub);
        }
        ClientPOP3Data* cd = &dd->client;
        if (cd->username)
            snort_free(cd->username);
        snort_free(dd);
    }
}

static int pop3_check_line(const uint8_t** data, const uint8_t* end)
{
    /* Line in the form (textCRLF) */
    for (; (*data)<end; (*data)++)
    {
        if (**data == 0x0D)
        {
            (*data)++;
            if (*data < end && **data == 0x0A)
            {
                (*data)++;
                return 0;
            }
            return -1;
        }
        else if (!isprint(**data))
            return -1;
    }
    return 1;
}

static int pop3_server_validate(POP3DetectorData* dd, const uint8_t* data, uint16_t size,
    AppIdSession& asd, int server)
{
    ServicePOP3Data* pd = &dd->server;
    const uint8_t* begin = nullptr;

    const uint8_t* end = data + size;
    char* v_end = pd->version + MAX_VERSION_SIZE - 1;
    switch (pd->state)
    {
    case POP3_STATE_CONNECT:
        pd->state = POP3_STATE_RESPONSE;
        begin = data;
        // fallthrough

    case POP3_STATE_RESPONSE:
        if (!begin && data[0] == '+' && data[1] == ' ')
        {
            data += 2;
            if (pop3_check_line(&data, end))
                return -1;
            if (data != end)
                return -1;
            return 0;
        }
        if (size < sizeof(POP3_ERR))
            return -1;

        if (!strncmp((const char*)data, POP3_OK, sizeof(POP3_OK)-1))
        {
            data += sizeof(POP3_OK) - 1;
            pd->error = 0;
        }
        else if (!strncmp((const char*)data, POP3_ERR, sizeof(POP3_ERR)-1))
        {
            begin = nullptr;
            data += sizeof(POP3_ERR) - 1;
            pd->error = 1;
        }
        else
            return -1;
        if (pop3_check_line(&data, end) < 0)
            return -1;
        if (dd->client.state == POP3_CLIENT_STATE_STLS_CMD)
        {
            if (pd->error)
            {
                // We failed to transition to POP3S - fall back to normal POP3 state, AUTHORIZATION
                dd->client.state = POP3_CLIENT_STATE_AUTH;
            }
            else
            {
                // we are potentially overriding the APP_ID_POP3 assessment that was made earlier.
                asd.set_session_flags(APPID_SESSION_ENCRYPTED);
                asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                pop3_client_detector->add_app(asd, APP_ID_POP3S, APP_ID_POP3S, nullptr);
            }
        }
        else if (dd->client.username) // possible only with non-TLS auth, therefore APP_ID_POP3
        {
            if (pd->error)
            {
                pop3_service_detector->add_user(asd, dd->client.username, APP_ID_POP3, false);
                snort_free(dd->client.username);
                dd->client.username = nullptr;
            }
            else
            {
                pop3_service_detector->add_user(asd, dd->client.username, APP_ID_POP3, true);
                snort_free(dd->client.username);
                dd->client.username = nullptr;
                dd->need_continue = 0;
                asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                dd->client.got_user = 1;
                if (dd->client.detected)
                    asd.set_client_detected();
            }
        }
        if (server && begin)
        {
            const uint8_t* p;
            char* v;
            const uint8_t* line_end = &data[-1];
            unsigned len = line_end - begin;
            if (( p = service_strstr(begin, len, (const unsigned char*)ven_cppop, sizeof(ven_cppop)-1)) )
            {
                pd->vendor = ven_cppop;
                p += (sizeof(ven_cppop) - 1);
                if (*p == ' ')
                {
                    p++;
                    v = pd->version;
                    for (; p < line_end && *p && *p != ']'; p++)
                    {
                        if (v < v_end)
                        {
                            *v = *p;
                            v++;
                        }
                    }
                    if (p < line_end && *p)
                        *v = 0;
                    else
                        pd->version[0] = 0;
                }
            }
            else if ((p=service_strstr(begin, len, (const unsigned char*)ven_cc, sizeof(ven_cc)-1)))
            {
                pd->vendor = ven_cc;
                p += (sizeof(ven_cc) - 1);
                if (line_end-p >= (int)sizeof(ver_cc)-1 && memcmp(p, ver_cc, sizeof(ver_cc)-1) ==
                    0)
                {
                    p += sizeof(ver_cc) - 1;
                    v = pd->version;
                    for (; p < line_end && *p && *p != ' '; p++)
                    {
                        if (v < v_end)
                        {
                            *v = *p;
                            v++;
                        }
                    }
                    if (p < line_end && *p)
                        *v = 0;
                    else
                        pd->version[0] = 0;
                }
            }
            else if (service_strstr(begin, len, (const unsigned char*)ven_im, sizeof(ven_im)-1))
                pd->vendor = ven_im;
            else if ((p=service_strstr(begin, len, (const unsigned char*)ven_po, sizeof(ven_po)-1)))
            {
                snort::AppIdServiceSubtype* sub;

                pd->vendor = ven_po;
                p += (sizeof(ven_po) - 1);
                if (line_end-p < (int)sizeof(ver_po)-1 || memcmp(p, ver_po, sizeof(ver_po)-1) != 0)
                    goto ven_ver_done;
                p += sizeof(ver_po) - 1;
                const uint8_t* ver = p;
                for (; p < line_end && *p && *p != ' '; p++)
                    ;
                if (p == ver || p >= line_end || !(*p))
                    goto ven_ver_done;
                if (line_end-p < (int)sizeof(ver_po2)-1 || memcmp(p, ver_po2, sizeof(ver_po2)-1) !=
                    0)
                {
                    /* Does not have release */
                    v = pd->version;
                    for (; ver < p && *ver; ver++)
                    {
                        if (v < v_end)
                        {
                            *v = *ver;
                            v++;
                        }
                        else
                            break;
                    }
                    *v = 0;
                    goto ven_ver_done;
                }
                /* Move past release and look for number followed by a space */
                const uint8_t* p2 = p + sizeof(ver_po2) - 1;
                const uint8_t* rel = p2;
                for (; p2 < line_end && *p2 && *p2 != ' '; p2++)
                    ;
                if (p2 >= line_end || p2 == rel || !(*p2))
                {
                    v = pd->version;
                    for (; ver < p && *ver; ver++)
                    {
                        if (v < v_end)
                        {
                            *v = *ver;
                            v++;
                        }
                        else
                            break;
                    }
                    *v = 0;
                    goto ven_ver_done;
                }
                v = pd->version;
                for (; ver < p2 && *ver; ver++)
                {
                    if (v < v_end)
                    {
                        *v = *ver;
                        v++;
                    }
                    else
                        break;
                }
                *v = 0;
                if (line_end-p2 < (int)sizeof(sub_po)-1 || memcmp(p2, sub_po, sizeof(sub_po)-1) !=
                    0)
                    goto ven_ver_done;
                const uint8_t* s = p2 + (sizeof(sub_po) - 1);
                for (p=s; p < line_end && *p && *p != ' '; p++)
                    ;
                if (p == s || p >= line_end || !(*p))
                    goto ven_ver_done;
                sub = (snort::AppIdServiceSubtype*)snort_calloc(sizeof(snort::AppIdServiceSubtype));
                unsigned sub_len;

                sub_len = p - s;
                sub->service = (const char*)snort_calloc(sub_len+1);
                memcpy(const_cast<char*>(sub->service), s, sub_len);
                (const_cast<char*>(sub->service))[sub_len] = 0;
                sub->next = pd->subtype;
                pd->subtype = sub;
                if (line_end-p > (int)sizeof(subver_po)-1
                    && memcmp(p, subver_po, sizeof(subver_po)-1) == 0)
                {
                    s = p + (sizeof(subver_po) - 1);
                    for (p=s; p < line_end && *p && *p != ' '; p++)
                        ;
                    if (p != s && p < line_end && *p)
                    {
                        sub_len = p - s;
                        sub->version = (const char*)snort_calloc(sub_len+1);
                        memcpy(const_cast<char*>(sub->version), s, sub_len);
                        (const_cast<char*>(sub->version))[sub_len] = 0;
                    }
                }
            }
ven_ver_done:;
        }
        if (data >= end)
        {
            pd->count++;
            return 0;
        }
        pd->state = POP3_STATE_CONTINUE;
        // fallthrough

    case POP3_STATE_CONTINUE:
        while (data < end)
        {
            if ((end-data) == (sizeof(POP3_TERM)-1) &&
                !strncmp((const char*)data, POP3_TERM, sizeof(POP3_TERM)-1))
            {
                pd->count++;
                pd->state = POP3_STATE_RESPONSE;
                return 0;
            }
            if (pop3_check_line(&data, end) < 0)
                return -1;
        }
        return 0;
    }
    return 0;
}

POP3DetectorData* Pop3ClientDetector::get_common_data(AppIdSession& asd)
{
    POP3DetectorData* dd = (POP3DetectorData*)data_get(asd);
    if (!dd)
    {
        dd = (POP3DetectorData*)snort_calloc(sizeof(POP3DetectorData));
        data_add(asd, dd, &pop3_free_state);
        dd->server.state = POP3_STATE_CONNECT;
        dd->client.state = POP3_CLIENT_STATE_AUTH;
        dd->need_continue = 1;
        asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return dd;
}

int Pop3ClientDetector::validate(AppIdDiscoveryArgs& args)
{
    const uint8_t* s = args.data;
    const uint8_t* end = (args.data + args.size);
    unsigned length;

    if (!args.size)
        return APPID_INPROCESS;

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    POP3DetectorData* dd = get_common_data(args.asd);
    ClientPOP3Data* fd = &dd->client;

    if (args.dir == APP_ID_FROM_RESPONDER)
    {
        if (pop3_server_validate(dd, args.data, args.size, args.asd, 0))
            args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
        return APPID_INPROCESS;
    }

    while ((length = (end - s)))
    {
        unsigned long pattern_index;
        AppIdFlowContentPattern* cmd = nullptr;

        pattern_index = num_pop3_client_patterns;
        cmd_matcher->find_all((const char*)s, (length > longest_pattern ? longest_pattern : length),
            &pop3_pattern_match, false, (void*)&pattern_index);

        if (pattern_index < num_pop3_client_patterns)
            cmd = &tcp_patterns[pattern_index];
        if (!cmd)
        {
            dd->need_continue = 0;
            args.asd.set_client_detected();
            return APPID_SUCCESS;
        }
        s += cmd->length;
        switch (fd->state)
        {
        case POP3_CLIENT_STATE_STLS_CMD:
            /* We failed to transition to POP3S - fall back to normal POP3 AUTHORIZATION state */
            fd->state = POP3_CLIENT_STATE_AUTH;
            // fallthrough

        case POP3_CLIENT_STATE_AUTH:
            switch (pattern_index)
            {
            case PATTERN_STLSEOC:
            case PATTERN_STLSEOC2:
            {
                /* If the STLS command succeeds we will be in a TLS negotiation state.
                   Wait for the "+OK" from the server using this STLS hybrid state. */
                fd->state = POP3_CLIENT_STATE_STLS_CMD;
                /* skip extra CRLFs */
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
            }
            break;
            case PATTERN_APOP:
            case PATTERN_USER:
            {
                char username[((255 - (sizeof(USER) - 1)) - 2) + 1];
                char* p = username;
                char* p_end = p + sizeof(username) - 1;
                int found_tick = 0;

                for (; s < end && p < p_end; s++)
                {
                    if (isalnum(*s) || *s == '.' || *s == '@' || *s == '-' || *s == '_')
                    {
                        if (!found_tick)
                        {
                            *p = *s;
                            p++;
                        }
                    }
                    else if (*s == '`')
                        found_tick = 1;
                    else if (*s == '\r' || *s == '\n' || *s == ' ')     // test for space for APOP
                                                                        // case
                    {
                        *p = 0;
                        if (username[0])
                        {
                            if (fd->username)
                                snort_free(fd->username);
                            fd->username = snort_strdup(username);
                        }
                        break;
                    }
                    else
                        break;
                }
                if (pattern_index == PATTERN_APOP)
                {
                    /* the APOP command contains the user AND the equivalent of a password. */
                    fd->state = POP3_CLIENT_STATE_TRANS;
                }
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
            }
            break;

            case PATTERN_AUTH:
                /* the AUTH<space> command, containing a parameter implies non-TLS security
                   negotiation */
                fd->state = POP3_CLIENT_STATE_TRANS; // look ahead for normal POP3 commands
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
                // fallthrough
                // for the empty-line skip

            case PATTERN_AUTHEOC:  // used with subsequent CAPA; no state change;
            case PATTERN_AUTHEOC2:
            case PATTERN_AUTHEOC3: // AUTH<space> with nothing after, Mircosoft ext., is query-only
            // behavior; no state change;
            case PATTERN_AUTHEOC4:
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
                break;

            case PATTERN_PASS:
                if (fd->got_user)
                {
                    fd->state = POP3_CLIENT_STATE_TRANS;
                    for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                        ;
                    for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                        ;
                    break;
                }
            // fallthrough
            // we are not changing to TRANSACTION state, yet
            default:
            {
                if (!eoc[pattern_index])
                    for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                        ;
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
            }
            break;
            } // end of switch(pattern_index)
            break;

        case POP3_CLIENT_STATE_TRANS:
            if (pattern_index >= PATTERN_POP3_OTHER)
            {
                // Still in non-secure mode and received a TRANSACTION-state command: POP3 found
                add_app(args.asd, APP_ID_POP3, APP_ID_POP3, nullptr);
                fd->detected = 1;
            }
            else
            {
                // ignore AUTHORIZATION-state commands while in TRANSACTION state
            }
            if (!eoc[pattern_index])
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
            for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                ;
            break;
        }
    }
    return APPID_INPROCESS;
}

Pop3ServiceDetector::Pop3ServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "pop3";
    proto = IpProtocol::TCP;
    provides_user = true;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)POP3_OK, sizeof(POP3_OK)-1, 0, 0, 0 },
        { (const uint8_t*)POP3_ERR, sizeof(POP3_ERR)-1, 0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_POP3, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
        { APP_ID_POP3S, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER }
    };

    service_ports =
    {
        { POP3_PORT, IpProtocol::TCP, false }
    };

    pop3_service_detector = this;
    handler->register_detector(name, this, proto);
}


int Pop3ServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    POP3DetectorData* dd;
    ServicePOP3Data* pd;

    if (!args.size)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    dd = pop3_client_detector->get_common_data(args.asd);
    pd = &dd->server;

    // server side is seeing packets so no need for client side to process them
    args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);

    if (dd->need_continue)
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
    else
    {
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        if (args.asd.is_service_detected())
            return APPID_SUCCESS;
    }

    if (!pop3_server_validate(dd, args.data, args.size, args.asd, 1))
    {
        if (pd->count >= POP3_COUNT_THRESHOLD
            && !args.asd.is_service_detected())
        {
            add_service_consume_subtype(args.asd, args.pkt, args.dir,
                dd->client.state == POP3_CLIENT_STATE_STLS_CMD ? APP_ID_POP3S : APP_ID_POP3,
                pd->vendor, pd->version[0] ? pd->version : nullptr, pd->subtype);
            pd->subtype = nullptr;
            return APPID_SUCCESS;
        }
    }
    else if (!args.asd.is_service_detected())
    {
        fail_service(args.asd, args.pkt, args.dir);
        return APPID_NOMATCH;
    }
    else
    {
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_SUCCESS;
    }

inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;
}

