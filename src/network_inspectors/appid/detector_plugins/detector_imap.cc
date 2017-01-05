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

// detector_imap.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_api.h"

#include "main/snort_debug.h"
#include "search_engines/search_tool.h"

#include "app_info_table.h"
#include "appid_module.h"
#include "client_plugins/client_app_api.h"
#include "service_plugins/service_api.h"

static const unsigned IMAP_USER_NAME_MAX_LEN = 32;
static const unsigned IMAP_TAG_MAX_LEN = 6;
static const unsigned MIN_CMDS = 3;

static const char NO_LOGIN[] = " Login failed.";

struct CLIENT_APP_CONFIG
{
    int enabled;
};

enum IMAPClientState
{
    IMAP_CLIENT_STATE_NON_AUTH,         // IMAP - Non-Authenticated state
    IMAP_CLIENT_STATE_AUTH,             // IMAP - Authenticated state
    IMAP_CLIENT_STATE_AUTHENTICATE_CMD, // IMAP - authentication-in-progress state
    IMAP_CLIENT_STATE_STARTTLS_CMD,     // IMAP - authentication-in-progress state (probable IMAPS)
};

struct ClientAppData
{
    IMAPClientState state;
    unsigned count;
    int detected;
    int got_user;
    int auth;
    int set_flags;
    char username[IMAP_USER_NAME_MAX_LEN+1];
    char imapCmdTag[IMAP_TAG_MAX_LEN+1];
};

static CLIENT_APP_CONFIG ca_config;

static CLIENT_APP_RETCODE init(const InitClientAppAPI* const init_api, SF_LIST* config);
static void clean();
static CLIENT_APP_RETCODE validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector* userData);

static RNAClientAppModule client_app_mod =
{
    "IMAP",
    IpProtocol::TCP,
    &init,
    &clean,
    &validate,
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

static const uint8_t CAPA[] = "CAPABILITY\x00d\x00a";
static const uint8_t CAPA2[] = "CAPABILITY\x00a";
static const uint8_t NOOP[] = "NOOP\x00d\x00a";
static const uint8_t NOOP2[] = "NOOP\x00a";
static const uint8_t LOGOUT[] = "LOGOUT\x00d\x00a";
static const uint8_t LOGOUT2[] = "LOGOUT\x00a";
static const uint8_t AUTHENTICATE[] = "AUTHENTICATE ";
static const uint8_t LOGIN[] = "LOGIN ";
static const uint8_t SELECT[] = "SELECT ";
/*static const uint8_t EXAMINE[] = "EXAMINE "; */
static const uint8_t CREATE[] = "CREATE ";
static const uint8_t DELETE[] = "DELETE ";
static const uint8_t RENAME[] = "RENAME ";
static const uint8_t SUBSCRIBE[] = "SUBSCRIBE ";
static const uint8_t UNSUBSCRIBE[] = "UNSUBSCRIBE ";
static const uint8_t LISTC[] = "LIST ";
static const uint8_t LSUB[] = "LSUB ";
static const uint8_t APPEND[] = "APPEND ";
static const uint8_t CHECK[] = "CHECK\x00d\x00a";
static const uint8_t CHECK2[] = "CHECK\x00a";
static const uint8_t CLOSE[] = "CLOSE\x00d\x00a";
static const uint8_t CLOSE2[] = "CLOSE\x00a";
static const uint8_t EXPUNGE[] = "EXPUNGE\x00d\x00a";
static const uint8_t EXPUNGE2[] = "EXPUNGE\x00a";
static const uint8_t SEARCH[] = "SEARCH ";
static const uint8_t FETCH[] = "FETCH ";
static const uint8_t PARTIAL[] = "PARTIAL ";
static const uint8_t STORE[] = "STORE ";
static const uint8_t COPY[] = "COPY ";
static const uint8_t UID[] = "UID ";
static const uint8_t STARTTLS[] = "STARTTLS\x00d\x00a";
static const uint8_t STARTTLS2[] = "STARTTLS\x00a";

enum Client_App_Pattern_Index
{
    /* order MUST correspond to that in the array, patterns[], below */
    PATTERN_LOGIN,
    PATTERN_AUTHENTICATE,
    PATTERN_STARTTLS,
    PATTERN_STARTTLS2,
    PATTERN_IMAP_OTHER // always last
};

static Client_App_Pattern patterns[] =
{
    { LOGIN, sizeof(LOGIN)-1, 0 },
    { AUTHENTICATE, sizeof(AUTHENTICATE)-1, 0 },
    { STARTTLS, sizeof(STARTTLS)-1, 1 },
    { STARTTLS2, sizeof(STARTTLS2)-1, 1 },
    /* These are represented by index >= PATTERN_IMAP_OTHER */
    { CAPA, sizeof(CAPA)-1, 1 },
    { CAPA2, sizeof(CAPA2)-1, 1 },
    { NOOP, sizeof(NOOP)-1, 1 },
    { NOOP2, sizeof(NOOP2)-1, 1 },
    { LOGOUT, sizeof(LOGOUT)-1, 1 },
    { LOGOUT2, sizeof(LOGOUT2)-1, 1 },
    { SELECT, sizeof(SELECT)-1, 0 },
    { CREATE, sizeof(CREATE)-1, 0 },
    { DELETE, sizeof(DELETE)-1, 0 },
    { RENAME, sizeof(RENAME)-1, 0 },
    { SUBSCRIBE, sizeof(SUBSCRIBE)-1, 0 },
    { UNSUBSCRIBE, sizeof(UNSUBSCRIBE)-1, 0 },
    { LISTC, sizeof(LISTC)-1, 0 },
    { LSUB, sizeof(LSUB)-1, 0 },
    { APPEND, sizeof(APPEND)-1, 0 },
    { CHECK, sizeof(CHECK)-1, 1 },
    { CHECK2, sizeof(CHECK2)-1, 1 },
    { CLOSE, sizeof(CLOSE)-1, 1 },
    { CLOSE2, sizeof(CLOSE2)-1, 1 },
    { EXPUNGE, sizeof(EXPUNGE)-1, 1 },
    { EXPUNGE2, sizeof(EXPUNGE2)-1, 1 },
    { SEARCH, sizeof(SEARCH)-1, 0 },
    { FETCH, sizeof(FETCH)-1, 0 },
    { PARTIAL, sizeof(PARTIAL)-1, 0 },
    { STORE, sizeof(STORE)-1, 0 },
    { COPY, sizeof(COPY)-1, 0 },
    { UID, sizeof(UID)-1, 0 },
};

static size_t longest_pattern;
static const unsigned IMAP_PORT = 143;
static const unsigned IMAP_COUNT_THRESHOLD = 2;
static const char OK[] = "OK";
static const char BAD[] = "BAD";
static const char NO[] = "NO";

#define IMAP_FLAG_ALNUM         0x01
#define IMAP_FLAG_FIRST_PACKET  0x02
#define IMAP_FLAG_RESULT_OK     0x04
#define IMAP_FLAG_RESULT_NO     0x08
#define IMAP_FLAG_RESULT_BAD    0x10
#define IMAP_FLAG_RESULT_ALL    (IMAP_FLAG_RESULT_OK | IMAP_FLAG_RESULT_NO | IMAP_FLAG_RESULT_BAD)

// static const unsigned IMAP_MAX_BANNER = 192;

enum IMAPState
{
    IMAP_STATE_BEGIN,
    IMAP_STATE_BANNER_SPACE,
    IMAP_STATE_BANNER_OK,
    IMAP_STATE_BANNER_WHITE_SPACE,
    IMAP_STATE_BANNER,
    IMAP_STATE_MID_LINE,
    IMAP_STATE_MID_ALNUM,
    IMAP_STATE_ALNUM_CODE,
    IMAP_STATE_ALNUM_CODE_TERM,
    IMAP_STATE_MID_OK,
    IMAP_STATE_MID_NO,
    IMAP_STATE_MID_BAD,
    IMAP_STATE_MID_TERM,
    IMAP_STATE_MID_OK_LOGIN,
    IMAP_STATE_MID_NO_LOGIN,
    IMAP_STATE_ALNUM_TAG
};

struct ServiceIMAPData
{
    IMAPState state;
    unsigned pos;
    unsigned flags;
    unsigned count;
    unsigned parens;
    char tagValue[IMAP_TAG_MAX_LEN+1];
};

static int imap_init(const InitServiceAPI* const init_api);
static int imap_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &imap_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "imap",
};

static const RNAServiceValidationPort pp[] =
{
    { &imap_validate, IMAP_PORT, IpProtocol::TCP, 0 },
    { &imap_validate, 220, IpProtocol::TCP, 0 },
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

static RNAServiceValidationModule service_mod =
{
    "IMAP",
    &imap_init,
    pp,
    nullptr,
    nullptr,
    1,
    nullptr,
    0
};

static const char IMAP_PATTERN[] = "* OK";

struct DetectorData
{
    ClientAppData client;
    ServiceIMAPData server;
    int need_continue;
};

SO_PUBLIC RNADetectorValidationModule imap_detector_mod =
{
    &service_mod,
    &client_app_mod,
    nullptr,
    0,
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_IMAP, APPINFO_FLAG_CLIENT_USER },
    { APP_ID_IMAPS, APPINFO_FLAG_CLIENT_USER }
};

static CLIENT_APP_RETCODE init(const InitClientAppAPI* const init_api, SF_LIST* config)
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

    AppidConfigElement::add_generic_config_element(client_app_mod.name, cmd_matcher);

    ca_config.enabled = 1;

    if (config)
    {
        SF_LNODE* cursor = nullptr;
        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
        {
            DebugFormat(DEBUG_LOG,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
                ca_config.enabled = atoi(item->value);
        }
    }

    if (ca_config.enabled)
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            DebugFormat(DEBUG_LOG,"registering pattern: %s\n",(const char*)patterns[i].pattern);
            init_api->RegisterPatternNoCase(&validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, -1);
        }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&validate, appIdRegistry[j].appId, appIdRegistry[j].additionalInfo);
    }

    return CLIENT_APP_SUCCESS;
}

static int imap_init(const InitServiceAPI* const init_api)
{
    init_api->RegisterPatternUser(&imap_validate, IpProtocol::TCP, (uint8_t*)IMAP_PATTERN,
        sizeof(IMAP_PATTERN)-1, 0, "imap");

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&imap_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo);
    }

    return 0;
}

static void clean()
{
    SearchTool* cmd_matcher =
        (SearchTool*)AppidConfigElement::find_generic_config_element(client_app_mod.name);
    if (cmd_matcher)
        delete cmd_matcher;

    AppidConfigElement::remove_generic_config_element(client_app_mod.name);
}

static int pattern_match(void* id, void*, int index, void* data, void*)
{
    Client_App_Pattern** pcmd = (Client_App_Pattern**)data;
    unsigned long idx = (unsigned long)id;

    if (index)
        return 0;
    pcmd = (Client_App_Pattern**)data;
    *pcmd = &patterns[idx];
    return 1;
}

static inline int isImapTagChar(uint8_t tag)
{
    /* Per RFC 3501
       tag char's cannot consist of ", %, { */
    if ((tag == 0x7B) || (tag == 0x22) || (tag == 0x25))
        return 0;

    /* Alpha Numeric's */
    if (isalnum(tag) /* valid tag chars: 0-9, A-Z, a-z */
        || (tag >=0x2C && tag <=0x2F)     /* valid tag chars: , - . / */
        || (tag >=0x5D && tag <= 0x60)     /* valid tag chars: ] ^ _ ` */
        || (tag >= 0x21 && tag <= 0x27)     /* valid tag chars: ! # $ & , */
        /* 0x22 " and 0x25 % invalid as above */
        || (tag >= 0x3a && tag <= 0x40)     /*valid tag chars: : ; < = > ? @ */
        || (tag == 0x5b)     /*valid tag chars: [ */
        || (tag >= 0x7c && tag <= 0x7e)     /* valid tag chars: | } ~ */
        )
        return 1;

    return 0;
}

static int imap_server_validate(DetectorData* dd, const uint8_t* data, uint16_t size,
    AppIdSession* asd)
{
    const uint8_t* end = data + size;
    ServiceIMAPData* id = &dd->server;

    id->flags &= ~IMAP_FLAG_RESULT_ALL;  // flags will tell us OK vs. NO vs. BAD

    for (; data < end; data++)
    {
        switch (id->state)
        {
        case IMAP_STATE_BEGIN:
            if (id->flags & IMAP_FLAG_FIRST_PACKET)
            {
                id->flags &= ~IMAP_FLAG_FIRST_PACKET;
                if (*data == '*')
                {
                    id->state = IMAP_STATE_BANNER_SPACE;
                    break;
                }
            }
            if (*data == '+' || *data == '*')
            {
                id->state = IMAP_STATE_MID_LINE;
                id->flags &= ~IMAP_FLAG_ALNUM;
            }
            else if (isImapTagChar(*data))
            {
                id->flags |= IMAP_FLAG_ALNUM;
                id->tagValue[0] = *data;
                id->pos = 1;
                id->state = IMAP_STATE_ALNUM_TAG;
            }
            else
                return -1;
            break;
        case IMAP_STATE_BANNER_SPACE:
            if (*data == ' ')
            {
                id->state = IMAP_STATE_BANNER_OK;
                id->pos = 0;
            }
            else
                id->state = IMAP_STATE_MID_LINE;
            break;
        case IMAP_STATE_BANNER_OK:
            if (*data == OK[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(OK)-1)
                    id->state = IMAP_STATE_BANNER_WHITE_SPACE;
            }
            else
                id->state = IMAP_STATE_MID_LINE;
            break;
        case IMAP_STATE_BANNER_WHITE_SPACE:
            if (*data==' ' || *data=='\t')
                break;
            else if (*data == 0x0D)
                id->state = IMAP_STATE_MID_TERM;
            else if (*data == 0x0A)
                id->state = IMAP_STATE_BEGIN;
            else if (!isprint(*data))
                return -1;
            else
                id->state = IMAP_STATE_BANNER;
            break;
        case IMAP_STATE_BANNER:
            if (*data == 0x0D)
                id->state = IMAP_STATE_MID_TERM;
            else if (*data == 0x0A)
                id->state = IMAP_STATE_BEGIN;
            else if (!isprint(*data))
                return -1;
            break;
        case IMAP_STATE_MID_LINE:
            if (*data == 0x0D)
            {
                if (!id->parens)
                    id->state = IMAP_STATE_MID_TERM;
            }
            else if (*data == 0x0A)
            {
                if (!id->parens)
                {
                    id->state = IMAP_STATE_BEGIN;
                    if (id->flags & IMAP_FLAG_ALNUM)
                        id->count++;
                }
            }
            else if (*data == '(')
                id->parens++;
            else if (*data == ')')
            {
                if (id->parens)
                    id->parens--;
            }
            else if (!isprint(*data) && *data != 0x09)
                return -1;
            break;
        case IMAP_STATE_MID_TERM:
            if (*data == 0x0A)
            {
                id->state = IMAP_STATE_BEGIN;
                if (id->flags & IMAP_FLAG_ALNUM)
                    id->count++;
            }
            else
                return -1;
            break;
        case IMAP_STATE_MID_ALNUM:
            if (*data == ' ')
                id->state = IMAP_STATE_ALNUM_CODE;
            else
                return -1;
            break;
        case IMAP_STATE_ALNUM_TAG:
            if ((id->pos < (sizeof(id->tagValue)-1))
                && (isImapTagChar(*data)))
            {
                id->tagValue[id->pos] = *data;
            }
            else
            {
                id->tagValue[id->pos] = '\0';
                id->state = IMAP_STATE_ALNUM_CODE;
            }
            break;

        case IMAP_STATE_ALNUM_CODE:
            if (*data == OK[0])
            {
                id->state = IMAP_STATE_MID_OK;
                id->pos = 1;
            }
            else if (*data == NO[0])
            {
                id->state = IMAP_STATE_MID_NO;
                id->pos = 1;
            }
            else if (*data == BAD[0])
            {
                id->state = IMAP_STATE_MID_BAD;
                id->pos = 1;
            }
            else
                return -1;
            break;
        case IMAP_STATE_MID_OK:
            if (*data == OK[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(OK)-1)
                {
                    id->pos = 0;
                    id->state = IMAP_STATE_MID_OK_LOGIN;
                    if (!strcasecmp(id->tagValue, dd->client.imapCmdTag))
                    {
                        dd->client.imapCmdTag[0] = '\0';
                        id->flags |= IMAP_FLAG_RESULT_OK;
                    }
                }
            }
            else
                return -1;
            break;

        case IMAP_STATE_MID_OK_LOGIN:
            // add user successful - note: use  of LOGIN cmd implies no  IMAPS
            if ((id->flags & IMAP_FLAG_RESULT_OK) && dd->client.username[0])
                service_mod.api->add_user(asd, dd->client.username, APP_ID_IMAP, 1);

            id->state = IMAP_STATE_MID_LINE;
            break;
        case IMAP_STATE_MID_NO:
            if (*data == NO[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(NO)-1)
                {
                    id->pos = 0;
                    id->state = IMAP_STATE_MID_NO_LOGIN;
                    if (!strcasecmp(id->tagValue, dd->client.imapCmdTag))
                    {
                        dd->client.imapCmdTag[0] = '\0';
                        id->flags |= IMAP_FLAG_RESULT_NO;
                    }
                }
            }
            else
                return -1;
            break;
        case IMAP_STATE_MID_NO_LOGIN:
            if (*data == NO_LOGIN[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(NO_LOGIN)-1)
                {
                    id->state = IMAP_STATE_ALNUM_CODE_TERM;
                    // add user login failed - note: use  of LOGIN cmd implies no  IMAPS
                    if ((id->flags & IMAP_FLAG_RESULT_NO) && dd->client.username[0])
                        service_mod.api->add_user(asd, dd->client.username, APP_ID_IMAP, 0);
                }
            }
            else
                id->state = IMAP_STATE_MID_LINE;
            break;

        case IMAP_STATE_MID_BAD:
            if (*data == BAD[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(BAD)-1)
                {
                    id->state = IMAP_STATE_ALNUM_CODE_TERM;
                    if (!strcasecmp(id->tagValue, dd->client.imapCmdTag))
                    {
                        dd->client.imapCmdTag[0] = '\0';
                        id->flags |= IMAP_FLAG_RESULT_BAD;
                    }
                }
            }
            else
                return -1;
            break;
        case IMAP_STATE_ALNUM_CODE_TERM:
            if (*data == 0x0D)
                id->state = IMAP_STATE_MID_TERM;
            else if (*data == 0x0A)
            {
                id->state = IMAP_STATE_BEGIN;
                id->count++;
            }
            else if (*data == ' ')
                id->state = IMAP_STATE_MID_LINE;
            else
                return -1;
            break;
        }
    }

    if (dd->client.state == IMAP_CLIENT_STATE_STARTTLS_CMD)
    {
        if (id->flags & IMAP_FLAG_RESULT_OK)
        {
            client_app_mod.api->add_app(asd, APP_ID_IMAPS, APP_ID_IMAPS, nullptr);
            asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
        }
        else
            dd->client.state = IMAP_CLIENT_STATE_NON_AUTH;
    }
    else if (dd->client.state == IMAP_CLIENT_STATE_AUTHENTICATE_CMD)
    {
    	// stop discarding intervening command packets (part of the authenticate)
        dd->client.auth = 0;
        dd->client.state = (id->flags & IMAP_FLAG_RESULT_OK) ?
            IMAP_CLIENT_STATE_AUTH : IMAP_CLIENT_STATE_NON_AUTH;
    }

    return 0;
}

static CLIENT_APP_RETCODE validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet*, Detector*)
{
    const uint8_t* s = data;
    const uint8_t* end = (data + size);
    unsigned length;
    Client_App_Pattern* cmd = nullptr;
    DetectorData* dd;
    ClientAppData* fd;
    char tag[IMAP_TAG_MAX_LEN+1] = { 0 };
    SearchTool* cmd_matcher =
        (SearchTool*)AppidConfigElement::find_generic_config_element(client_app_mod.name);

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (!size)
        return CLIENT_APP_INPROCESS;

    dd = (DetectorData*)imap_detector_mod.api->data_get(asd, imap_detector_mod.flow_data_index);
    if (!dd)
    {
        dd = (DetectorData*)snort_calloc(sizeof(DetectorData));
        imap_detector_mod.api->data_add(asd, dd, imap_detector_mod.flow_data_index, &snort_free);
        dd->server.flags = IMAP_FLAG_FIRST_PACKET;
        fd = &dd->client;
    }
    else
        fd = &dd->client;

    if (!fd->set_flags)
    {
        dd->need_continue = 1;
        fd->set_flags = 1;
        asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    if (dir == APP_ID_FROM_RESPONDER)
    {
        if (imap_server_validate(dd, data, size, asd))
            asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
        return CLIENT_APP_INPROCESS;
    }

    while ((length = (end - s)) > 0)
    {
        unsigned pattern_index;
        if (fd->auth)
        {
            /* authentication exchange in progress ignore all client-side
               packets until server-side OK/BAD/NO received */
            for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                ;
            for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                ;
            continue;
        }

        {
            /*processing tags */
            char* p = tag;
            char* p_end = p + sizeof(tag) - 1;
            for (; (s < end) && isImapTagChar(*s); s++)
            {
                if (p < p_end)
                {
                    *p++ = *s;
                }
            }
            for (; (s < end) && !isspace(*s); s++)
                ;
            *p = '\0';
        }

        if (end == s || !isblank(*s))
        {
            dd->need_continue = 0;
            asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
            asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return CLIENT_APP_SUCCESS;
        }
        for (; (s < end) && isblank(*s); s++)
            ;

        /*s is now at command beginning */
        if ((length = (end - s)) <= 0)
        {
            dd->need_continue = 0;
            asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
            asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return CLIENT_APP_SUCCESS;
        }
        cmd = nullptr;
        cmd_matcher->find_all((char*)s, (length > longest_pattern ? longest_pattern : length),
            &pattern_match, false, (void*)&cmd);

        if (!cmd)
        {
            if ( (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') )
            {
                // Command was not in the recognized list. Keep searching.
                return CLIENT_APP_INPROCESS;
            }
            else
            {
                // IMAP commands are English words, or at least start with X.
                return CLIENT_APP_ENULL; // anything but CLIENT_APP_SUCCESS or CLIENT_APP_INPROCESS
            }
        }
        s += cmd->length;

        pattern_index = cmd - patterns; // diff of ptr into array and its base addr is the
                                        // corresponding index.
        switch (fd->state)
        {
        case IMAP_CLIENT_STATE_AUTHENTICATE_CMD:
        case IMAP_CLIENT_STATE_STARTTLS_CMD:
            /* The command we received was rejected by the server side -
               fall back to normal IMAP Non-Authorized state */
            fd->state = IMAP_CLIENT_STATE_NON_AUTH;
        // fall through

        case IMAP_CLIENT_STATE_NON_AUTH:
            switch (pattern_index)
            {
            case PATTERN_LOGIN:
                strncpy(fd->imapCmdTag, tag, sizeof(fd->imapCmdTag));
                {
                    char* p = fd->username;
                    char* p_end = p + sizeof(fd->username) - 1;
                    int found_tick = 0;

                    if (*s == '"')
                    {
                        s++;
                        for (; s < end && p < p_end; s++)
                        {
                            if (*s == '"')
                            {
                                fd->count++;
                                if (fd->count == MIN_CMDS)
                                {
                                    client_app_mod.api->add_app(asd, APP_ID_IMAP, APP_ID_IMAP,
                                        nullptr);
                                    fd->detected = 1;
                                    if (fd->got_user)
                                    {
                                        asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                                        asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                                    }
                                    fd->state = IMAP_CLIENT_STATE_AUTH;
                                }
                                *p = 0;
                                fd->got_user = 1;
                                break;
                            }
                            else if (isalnum(*s) || *s == '.' || *s == '@' || *s == '-' || *s ==
                                '_' || *s == '`' || *s == ' ')
                            {
                                *p = *s;
                                p++;
                            }
                            else
                                break;
                        }
                    }
                    else
                    {
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
                            else if (*s == ' ')
                            {
                                fd->count++;
                                if (fd->count == MIN_CMDS)
                                {
                                    client_app_mod.api->add_app(asd, APP_ID_IMAP, APP_ID_IMAP,
                                        nullptr);
                                    fd->detected = 1;
                                    if (fd->got_user)
                                    {
                                        asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                                        asd->clear_session_flags(
                                        		APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                                    }
                                }
                                *p = 0;
                                fd->got_user = 1;
                                break;
                            }
                            else
                                break;
                        }
                    }
                    for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                        ;
                    for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                        ;
                }
                break;

            case PATTERN_STARTTLS:
            case PATTERN_STARTTLS2:
                strncpy(fd->imapCmdTag, tag, sizeof(fd->imapCmdTag));
                fd->state = IMAP_CLIENT_STATE_STARTTLS_CMD;
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;                                                 // all we need because
                                                                      // cmd->eoc == 1
                /* No other commands will be coming until the result from this one. */
                break;

            case PATTERN_AUTHENTICATE:
                strncpy(fd->imapCmdTag, tag, sizeof(fd->imapCmdTag));
                fd->auth = 1; // gobble additional client packets until the server OK/BAD/NO
                              // response
                fd->state = IMAP_CLIENT_STATE_AUTHENTICATE_CMD;
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
                break;

            default:
            {
                fd->count++;
                if (fd->count == MIN_CMDS)
                {
                    client_app_mod.api->add_app(asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                    fd->detected = 1;
                    if (fd->got_user)
                    {
                        asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                        asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                    }
                }
                if (!cmd->eoc)
                    for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                        ;
                for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                    ;
            }
            break;
            }
            break;
        case IMAP_CLIENT_STATE_AUTH:
        {
            fd->count++;
            if (fd->count == MIN_CMDS)
            {
                client_app_mod.api->add_app(asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                fd->detected = 1;
                if (fd->got_user)
                {
                    asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
                    asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                }
            }
            if (!cmd->eoc)
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
            for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                ;
        }
        break;
        } // end switch(fd->state)
    } // end 'while'
    return CLIENT_APP_INPROCESS;
}

static int imap_validate(ServiceValidationArgs* args)
{
    DetectorData* dd;
    ServiceIMAPData* id;
    AppIdSession* asd = args->asd;
    const uint8_t* data = args->data;
    uint16_t size = args->size;

    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (!size)
        goto inprocess;

    dd = (DetectorData*)imap_detector_mod.api->data_get(asd, imap_detector_mod.flow_data_index);
    if (!dd)
    {
        dd = (DetectorData*)snort_calloc(sizeof(DetectorData));
        imap_detector_mod.api->data_add(asd, dd, imap_detector_mod.flow_data_index, &snort_free);
        id = &dd->server;
        id->state = IMAP_STATE_BEGIN;
        id->flags = IMAP_FLAG_FIRST_PACKET;
    }
    else
        id = &dd->server;

    // server side is seeing packets so no need for client side to process them
    asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);

    if (dd->need_continue)
        asd->set_session_flags(APPID_SESSION_CONTINUE);
    else
    {
        asd->clear_session_flags(APPID_SESSION_CONTINUE);
        if (asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
        {
            appid_stats.imap_flows++;
            return SERVICE_SUCCESS;
        }
    }

    if (!imap_server_validate(dd, data, size, asd))
    {
        if ((id->flags & IMAP_FLAG_RESULT_OK) &&
                dd->client.state == IMAP_CLIENT_STATE_STARTTLS_CMD)
        {
            /* IMAP server response to STARTTLS command from client was OK */
            service_mod.api->add_service(asd, args->pkt, args->dir, &svc_element,
                APP_ID_IMAPS, nullptr, nullptr, nullptr);
            appid_stats.imaps_flows++;
            return SERVICE_SUCCESS;
        }

        if (id->count >= IMAP_COUNT_THRESHOLD &&
                !asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
        {
            service_mod.api->add_service(asd, args->pkt, args->dir, &svc_element,
                APP_ID_IMAP, nullptr, nullptr, nullptr);
            appid_stats.imap_flows++;
            return SERVICE_SUCCESS;
        }
    }
    else if (!asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
    {
        service_mod.api->fail_service(asd, args->pkt, args->dir, &svc_element,
            service_mod.flow_data_index);
        return SERVICE_NOMATCH;
    }
    else
    {
        asd->clear_session_flags(APPID_SESSION_CONTINUE);
        return SERVICE_SUCCESS;
    }

inprocess:
    service_mod.api->service_inprocess(asd, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;
}

