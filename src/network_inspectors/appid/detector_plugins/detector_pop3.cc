//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "app_info_table.h"
#include "application_ids.h"
#include "client_plugins/client_app_api.h"
#include "detector_plugins/detector_api.h"
#include "service_plugins/service_api.h"
#include "service_plugins/service_util.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "search_engines/search_tool.h"
#include "utils/util.h"

/*#define DEBUG_POP3  1 */

struct POP3_CLIENT_APP_CONFIG
{
    int enabled;
};

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
    int set_flags;
    int detected;
    int got_user;
};

// static const unsigned MIN_POP3_CMDS = 3;

// FIXIT-L THREAD_LOCAL?
static POP3_CLIENT_APP_CONFIG pop3_config;

static CLIENT_APP_RETCODE pop3_ca_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static void pop3_ca_clean(const CleanClientAppAPI* const clean_api);
static CLIENT_APP_RETCODE pop3_ca_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData,
    const AppIdConfig* pConfig);

static RNAClientAppModule client_app_mod =
{
    "POP3",
    IpProtocol::TCP,
    &pop3_ca_init,
    &pop3_ca_clean,
    &pop3_ca_validate,
    1,
    nullptr,
    nullptr,
    0,
    nullptr,
    1,
    0
};

struct Client_App_Pattern
{
    const uint8_t* pattern;
    unsigned length;
    int eoc;
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
    /* order MUST correspond to that in the array, patterns[], below */
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

static Client_App_Pattern patterns[] =
{
    { USER, sizeof(USER)-1, 0 },
    { PASS, sizeof(PASS)-1, 0 },
    { APOP, sizeof(APOP)-1, 0 },
    { AUTH, sizeof(AUTH)-1, 0 },
    { AUTHEOC, sizeof(AUTHEOC)-1, 1 },
    { AUTHEOC2, sizeof(AUTHEOC2)-1, 1 },
    { AUTHEOC3, sizeof(AUTHEOC3)-1, 1 },
    { AUTHEOC4, sizeof(AUTHEOC4)-1, 1 },
    { STLSEOC, sizeof(STLSEOC)-1, 1 },
    { STLSEOC2, sizeof(STLSEOC2)-1, 1 },
    /* These are represented by index >= PATTERN_POP3_OTHER */
    { DELE, sizeof(DELE)-1, 0 },
    { LISTC, sizeof(LISTC)-1, 0 },
    { LISTEOC, sizeof(LISTEOC)-1, 1 },
    { LISTEOC2, sizeof(LISTEOC2)-1, 1 },
    { NOOP, sizeof(NOOP)-1, 1 },
    { NOOP2, sizeof(NOOP2)-1, 1 },
    { QUIT, sizeof(QUIT)-1, 1 },
    { QUIT2, sizeof(QUIT2)-1, 1 },
    { RETR, sizeof(RETR)-1, 0 },
    { STAT, sizeof(STAT)-1, 1 },
    { STAT2, sizeof(STAT2)-1, 1 },
    { RSET, sizeof(RSET)-1, 1 },
    { RSET2, sizeof(RSET2)-1, 1 },
    { TOP, sizeof(TOP)-1, 0 },
    { UIDL, sizeof(UIDL)-1, 0 },
    { UIDLEOC, sizeof(UIDLEOC)-1, 1 },
    { UIDLEOC2, sizeof(UIDLEOC2)-1, 1 },
    { CAPA, sizeof(CAPA)-1, 1 },
    { CAPA2, sizeof(CAPA2)-1, 1 },
};

// FIXIT-L THREAD_LOCAL?
static size_t longest_pattern;

static const unsigned POP3_PORT = 110;

static const unsigned POP3_COUNT_THRESHOLD = 4;

static const char* const POP3_OK = "+OK";
static const char* const POP3_ERR = "-ERR";
static const char* const POP3_TERM = ".\x00D\x00A";

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
    RNAServiceSubtype* subtype;
    int error;
};

static int pop3_init(const IniServiceAPI* const init_api);
static int pop3_validate(ServiceValidationArgs* args);

static RNAServiceElement svc_element =
{
    nullptr,
    &pop3_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "pop3"
};

static RNAServiceValidationPort pp[] =
{
    { &pop3_validate, POP3_PORT, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

static RNAServiceValidationModule service_mod =
{
    "POP3",
    &pop3_init,
    pp,
    nullptr,
    nullptr,
    1,
    nullptr,
    0
};

struct POP3DetectorData
{
    ClientPOP3Data client;
    ServicePOP3Data server;
    int need_continue;
};

SO_PUBLIC RNADetectorValidationModule pop3_detector_mod =
{
    &service_mod,
    &client_app_mod,
    nullptr,
    0,
    nullptr
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_POP3, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    { APP_ID_POP3S, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER }
};

static CLIENT_APP_RETCODE pop3_ca_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;
    RNAClientAppModuleConfigItem* item;
    SearchTool* cmd_matcher = new SearchTool("ac_full");

    for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
    {
        cmd_matcher->add(patterns[i].pattern, patterns[i].length, &patterns[i]);
        if (patterns[i].length > longest_pattern)
            longest_pattern = patterns[i].length;
    }
    cmd_matcher->prep();

    init_api->pAppidConfig->add_generic_config_element(client_app_mod.name, cmd_matcher);

    pop3_config.enabled = 1;

    if (config)
    {
        SF_LNODE* iter = nullptr;

        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &iter);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&iter))
        {
            DebugFormat(DEBUG_INSPECTOR,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
            {
                pop3_config.enabled = atoi(item->value);
            }
        }
    }

    if (pop3_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_INSPECTOR,"registering pattern: %s\n",
            		(const char*)patterns[i].pattern);
            init_api->RegisterPatternNoCase(&pop3_ca_validate, IpProtocol::TCP,
                patterns[i].pattern,
                patterns[i].length, 0, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&pop3_ca_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

static int pop3_init(const IniServiceAPI* const init_api)
{
    init_api->RegisterPatternUser(&pop3_validate, IpProtocol::TCP, (uint8_t*)POP3_OK,
        sizeof(POP3_OK)-1, 0, "pop3", init_api->pAppidConfig);
    init_api->RegisterPatternUser(&pop3_validate, IpProtocol::TCP, (uint8_t*)POP3_ERR,
        sizeof(POP3_ERR)-1, 0, "pop3", init_api->pAppidConfig);

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_INSPECTOR,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&pop3_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }
    return 0;
}

static void pop3_ca_clean(const CleanClientAppAPI* const clean_api)
{
    SearchTool* cmd_matcher =
        (SearchTool*)clean_api->pAppidConfig->find_generic_config_element(client_app_mod.name);
    if (cmd_matcher)
        delete cmd_matcher;
    clean_api->pAppidConfig->remove_generic_config_element(client_app_mod.name);
}

static int pop3_pattern_match(void* id, void*, int index, void* data, void*)
{
    Client_App_Pattern** pcmd;
    unsigned long idx = (unsigned long)id;

    if (index)
        return 0;
    pcmd = (Client_App_Pattern**)data;
    *pcmd = &patterns[idx];
    return 1;
}

static void pop3_free_state(void* data)
{
    POP3DetectorData* dd = (POP3DetectorData*)data;
    ClientPOP3Data* cd;
    ServicePOP3Data* sd;
    RNAServiceSubtype* sub;

    if (dd)
    {
        sd = &dd->server;
        while (sd->subtype)
        {
            sub = sd->subtype;
            sd->subtype = sub->next;
            if (sub->service)
                snort_free((void*)sub->service);
            if (sub->version)
                snort_free((void*)sub->version);
            snort_free(sub);
        }
        cd = &dd->client;
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
    AppIdData* flowp, int server)
{
    static const char ven_cppop[] = "cppop";
    static const char ven_cc[] = "Cubic Circle";
    static const char ven_im[] = "InterMail";
    static const char ver_cc[] = "'s v";
    static const char ven_po[] = "Post.Office";
    static const char ver_po[] = " v";
    static const char ver_po2[] = " release ";
    static const char sub_po[] = " with ";
    static const char subver_po[] = " version ";
    ServicePOP3Data* pd = &dd->server;
    const uint8_t* begin = nullptr;
    const uint8_t* end;
    const uint8_t* line_end;
    const uint8_t* p;
    const uint8_t* p2;
    const uint8_t* ver;
    const uint8_t* rel;
    const uint8_t* s;
    unsigned len;
    char* v;
    char* v_end;

    end = data + size;
    v_end = pd->version;
    v_end += MAX_VERSION_SIZE - 1;
    switch (pd->state)
    {
    case POP3_STATE_CONNECT:
        pd->state = POP3_STATE_RESPONSE;
        begin = data;
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

        if (!strncmp((char*)data, POP3_OK, sizeof(POP3_OK)-1))
        {
            data += sizeof(POP3_OK) - 1;
            pd->error = 0;
        }
        else if (!strncmp((char*)data, POP3_ERR, sizeof(POP3_ERR)-1))
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
                /* We failed to transition to POP3S - fall back to normal POP3 state, AUTHORIZATION
                   */
                dd->client.state = POP3_CLIENT_STATE_AUTH;
            }
            else
            {
                setAppIdFlag(flowp, APPID_SESSION_ENCRYPTED);
                clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                /* we are potentially overriding the APP_ID_POP3 assessment that was made earlier.
                   */
                client_app_mod.api->add_app(flowp, APP_ID_POP3S, APP_ID_POP3S, nullptr); // sets
                                                                                         // APPID_SESSION_CLIENT_DETECTED
            }
        }
        else if (dd->client.username) // possible only with non-TLS authentication therefor:
                                      // APP_ID_POP3
        {
            if (pd->error)
            {
                service_mod.api->add_user(flowp, dd->client.username, APP_ID_POP3, 0);
                snort_free(dd->client.username);
                dd->client.username = nullptr;
            }
            else
            {
                service_mod.api->add_user(flowp, dd->client.username, APP_ID_POP3, 1);
                snort_free(dd->client.username);
                dd->client.username = nullptr;
                dd->need_continue = 0;
                clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                dd->client.got_user = 1;
                if (dd->client.detected)
                    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
            }
        }
        if (server && begin)
        {
            line_end = &data[-1];
            len = line_end - begin;
            if ((p=service_strstr(begin, len, (unsigned char*)ven_cppop, sizeof(ven_cppop)-1)))
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
            else if ((p=service_strstr(begin, len, (unsigned char*)ven_cc, sizeof(ven_cc)-1)))
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
            else if (service_strstr(begin, len, (unsigned char*)ven_im, sizeof(ven_im)-1))
                pd->vendor = ven_im;
            else if ((p=service_strstr(begin, len, (unsigned char*)ven_po, sizeof(ven_po)-1)))
            {
                RNAServiceSubtype* sub;

                pd->vendor = ven_po;
                p += (sizeof(ven_po) - 1);
                if (line_end-p < (int)sizeof(ver_po)-1 || memcmp(p, ver_po, sizeof(ver_po)-1) != 0)
                    goto ven_ver_done;
                p += sizeof(ver_po) - 1;
                ver = p;
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
                p2 = p + sizeof(ver_po2) - 1;
                rel = p2;
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
                s = p2 + (sizeof(sub_po) - 1);
                for (p=s; p < line_end && *p && *p != ' '; p++)
                    ;
                if (p == s || p >= line_end || !(*p))
                    goto ven_ver_done;
                sub = (RNAServiceSubtype*)snort_calloc(sizeof(RNAServiceSubtype));
                unsigned sub_len;

                sub_len = p - s;
                sub->service = (const char*)snort_calloc(sub_len+1);
                memcpy((char*)sub->service, s, sub_len);
                ((char*)sub->service)[sub_len] = 0;
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
                        memcpy((char*)sub->version, s, sub_len);
                        ((char*)sub->version)[sub_len] = 0;
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
    /* Fall through */

    case POP3_STATE_CONTINUE:
        while (data < end)
        {
            if ((end-data) == (sizeof(POP3_TERM)-1) &&
                !strncmp((char*)data, POP3_TERM, sizeof(POP3_TERM)-1))
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

static CLIENT_APP_RETCODE pop3_ca_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet*, struct Detector*, const AppIdConfig* pConfig)
{
    const uint8_t* s = data;
    const uint8_t* end = (data + size);
    unsigned length;
    Client_App_Pattern* cmd;
    POP3DetectorData* dd;
    ClientPOP3Data* fd;

    if (!size)
        return CLIENT_APP_INPROCESS;

#ifdef APP_ID_USES_REASSEMBLED
    pop3_detector_mod.streamAPI->response_flush_stream(pkt);
#endif

    dd = (POP3DetectorData*)pop3_detector_mod.api->data_get(flowp,
        pop3_detector_mod.flow_data_index);
    if (!dd)
    {
        dd = (POP3DetectorData*)snort_calloc(sizeof(POP3DetectorData));
        pop3_detector_mod.api->data_add(flowp, dd,
            pop3_detector_mod.flow_data_index, &pop3_free_state);
        dd->server.state = POP3_STATE_CONNECT;
        fd = &dd->client;
        fd->state = POP3_CLIENT_STATE_AUTH;
    }
    else
        fd = &dd->client;

    if (!fd->set_flags)
    {
        dd->need_continue = 1;
        fd->set_flags = 1;
        setAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    if (dir == APP_ID_FROM_RESPONDER)
    {
#ifdef DEBUG_POP3
        DebugFormat(DEBUG_INSPECTOR,"%p Calling server\n",flowp);
        DumpHex(SF_DEBUG_FILE, data, size);
#endif

        if (pop3_server_validate(dd, data, size, flowp, 0))
            clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
        return CLIENT_APP_INPROCESS;
    }

#ifdef DEBUG_POP3
    DebugFormat(DEBUG_INSPECTOR,"%p Client\n",flowp);
    DumpHex(SF_DEBUG_FILE, data, size);
#endif

    while ((length = (end - s)))
    {
        unsigned pattern_index;
        SearchTool* cmd_matcher =
            (SearchTool*)((AppIdConfig*)pConfig)->find_generic_config_element(client_app_mod.name);

        cmd = nullptr;
        cmd_matcher->find_all((char*)s, (length > longest_pattern ? longest_pattern : length),
            &pop3_pattern_match, false, (void*)&cmd);

        if (!cmd)
        {
            dd->need_continue = 0;
            setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
            return CLIENT_APP_SUCCESS;
        }
        s += cmd->length;

        pattern_index = cmd - patterns; // diff of ptr into array and its base addr is the
                                        // corresponding index.
        switch (fd->state)
        {
        case POP3_CLIENT_STATE_STLS_CMD:
            /* We failed to transition to POP3S - fall back to normal POP3 AUTHORIZATION state */
            fd->state = POP3_CLIENT_STATE_AUTH;
        // fall through

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
            // having skipped to the end of the line, fall through for the empty-line skip

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
            // fall through because we are not changing to TRANSACTION state, yet
            default:
            {
                if (!cmd->eoc)
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
                /* We stayed in non-secure mode and received a TRANSACTION-state command: POP3
                   found */
                client_app_mod.api->add_app(flowp, APP_ID_POP3, APP_ID_POP3, nullptr); // sets
                                                                                       // APPID_SESSION_CLIENT_DETECTED
                fd->detected = 1;
            }
            else
            {
                // ignore AUTHORIZATION-state commands while in TRANSACTION state
            }
            if (!cmd->eoc)
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
            for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                ;
            break;
        }
    }
    return CLIENT_APP_INPROCESS;
}

static int pop3_validate(ServiceValidationArgs* args)
{
    POP3DetectorData* dd;
    ServicePOP3Data* pd;
    AppIdData* flowp = args->flowp;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!size)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    pop3_detector_mod.streamAPI->response_flush_stream(pkt);
#endif

    if (dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

#ifdef DEBUG_POP3
    DebugFormat(DEBUG_INSPECTOR,"%p Dir %d\n",flowp, dir);
    DumpHex(SF_DEBUG_FILE, data, size);
#endif

    dd = (POP3DetectorData*)pop3_detector_mod.api->data_get(flowp,
        pop3_detector_mod.flow_data_index);
    if (!dd)
    {
        dd = (POP3DetectorData*)snort_calloc(sizeof(POP3DetectorData));
        pop3_detector_mod.api->data_add(flowp, dd,
            pop3_detector_mod.flow_data_index, &pop3_free_state);
        dd->client.state = POP3_CLIENT_STATE_AUTH;
        pd = &dd->server;
        pd->state = POP3_STATE_CONNECT;
    }
    else
        pd = &dd->server;

    if (dd->need_continue)
        setAppIdFlag(flowp, APPID_SESSION_CONTINUE);
    else
    {
        clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        if (getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
            return SERVICE_SUCCESS;
    }

    if (!pop3_server_validate(dd, data, size, flowp, 1))
    {
        if (pd->count >= POP3_COUNT_THRESHOLD && !getAppIdFlag(flowp,
            APPID_SESSION_SERVICE_DETECTED))
        {
            service_mod.api->add_service_consume_subtype(flowp, pkt, dir, &svc_element,
                dd->client.state == POP3_CLIENT_STATE_STLS_CMD ? APP_ID_POP3S : APP_ID_POP3,
                pd->vendor,
                pd->version[0] ? pd->version : nullptr, pd->subtype);
            pd->subtype = nullptr;
            return SERVICE_SUCCESS;
        }
    }
    else if (!getAppIdFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
    {
        service_mod.api->fail_service(flowp, pkt, dir, &svc_element,
            service_mod.flow_data_index, args->pConfig);
        return SERVICE_NOMATCH;
    }
    else
    {
        clearAppIdFlag(flowp, APPID_SESSION_CONTINUE);
        return SERVICE_SUCCESS;
    }

inprocess:;
    service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;
}

