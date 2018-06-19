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

// detector_imap.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_imap.h"

#include <array>

#include "app_info_table.h"
#include "search_engines/search_tool.h"
#include "utils/util.h"

static const unsigned IMAP_USER_NAME_MAX_LEN = 32;
static const unsigned IMAP_TAG_MAX_LEN = 6;
static const unsigned MIN_CMDS = 3;

static const char NO_LOGIN[] = " Login failed.";

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

static const char IMAP_PATTERN[] = "* OK";

enum IMAPClientState
{
    IMAP_CLIENT_STATE_NON_AUTH,         // IMAP - Non-Authenticated state
    IMAP_CLIENT_STATE_AUTH,             // IMAP - Authenticated state
    IMAP_CLIENT_STATE_AUTHENTICATE_CMD, // IMAP - authentication-in-progress state
    IMAP_CLIENT_STATE_STARTTLS_CMD,     // IMAP - authentication-in-progress state (probable IMAPS)
};

enum Client_App_Pattern_Index
{
    /* order MUST correspond to that in the array, patterns[], below */
    PATTERN_LOGIN,
    PATTERN_AUTHENTICATE,
    PATTERN_STARTTLS,
    PATTERN_STARTTLS2,
    PATTERN_IMAP_OTHER // always last
};

struct ImapClientData
{
    IMAPClientState state;
    unsigned count;
    int detected;
    int got_user;
    int auth;
    char username[IMAP_USER_NAME_MAX_LEN+1];
    char imapCmdTag[IMAP_TAG_MAX_LEN+1];
};

struct ImapServiceData
{
    IMAPState state;
    unsigned pos;
    unsigned flags;
    unsigned count;
    unsigned parens;
    char tagValue[IMAP_TAG_MAX_LEN+1];
};

struct ImapDetectorData
{
    ImapClientData client;
    ImapServiceData server;
    int need_continue;
};

static ImapClientDetector* imap_client_detector;

static int isImapTagChar(uint8_t tag)
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

static int imap_server_validate(ImapDetectorData* dd, const uint8_t* data, uint16_t size,
    AppIdSession& asd, AppIdDetector* detector)
{
    const uint8_t* end = data + size;
    ImapServiceData* id = &dd->server;

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
                if (id->pos >= sizeof(OK) - 1)
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
            if ((id->pos < (sizeof(id->tagValue) - 1))
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
                if (id->pos >= sizeof(OK) - 1)
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
                detector->add_user(asd, dd->client.username, APP_ID_IMAP, true);

            id->state = IMAP_STATE_MID_LINE;
            break;
        case IMAP_STATE_MID_NO:
            if (*data == NO[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(NO) - 1)
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
                if (id->pos >= sizeof(NO_LOGIN) - 1)
                {
                    id->state = IMAP_STATE_ALNUM_CODE_TERM;
                    // add user login failed - note: use  of LOGIN cmd implies no  IMAPS
                    if ((id->flags & IMAP_FLAG_RESULT_NO) && dd->client.username[0])
                        detector->add_user(asd, dd->client.username, APP_ID_IMAP, false);
                }
            }
            else
                id->state = IMAP_STATE_MID_LINE;
            break;

        case IMAP_STATE_MID_BAD:
            if (*data == BAD[id->pos])
            {
                id->pos++;
                if (id->pos >= sizeof(BAD) - 1)
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
            // FIXIT-L - this may be called from server side
            //add_app(asd, APP_ID_IMAPS, APP_ID_IMAPS, nullptr);
            asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
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

static AppIdFlowContentPattern imap_client_patterns[] =
{
    { LOGIN, sizeof(LOGIN) - 1, -1, 1, 0 },
    { AUTHENTICATE, sizeof(AUTHENTICATE) - 1, -1, 1, 0 },
    { STARTTLS, sizeof(STARTTLS) - 1, -1, 1, 0 },
    { STARTTLS2, sizeof(STARTTLS2) - 1, -1, 1, 0 },
    /* These are represented by index >= PATTERN_IMAP_OTHER */
    { CAPA, sizeof(CAPA) - 1, -1, 1, 0 },
    { CAPA2, sizeof(CAPA2) - 1, -1, 1, 0 },
    { NOOP, sizeof(NOOP) - 1, -1, 1, 0 },
    { NOOP2, sizeof(NOOP2) - 1, -1, 1, 0 },
    { LOGOUT, sizeof(LOGOUT) - 1, -1, 1, 0 },
    { LOGOUT2, sizeof(LOGOUT2) - 1, -1, 1, 0 },
    { SELECT, sizeof(SELECT) - 1, -1, 1, 0 },
    { CREATE, sizeof(CREATE) - 1, -1, 1, 0 },
    { DELETE, sizeof(DELETE) - 1, -1, 1, 0 },
    { RENAME, sizeof(RENAME) - 1, -1, 1, 0 },
    { SUBSCRIBE, sizeof(SUBSCRIBE) - 1, -1, 1, 0 },
    { UNSUBSCRIBE, sizeof(UNSUBSCRIBE) - 1, -1, 1, 0 },
    { LISTC, sizeof(LISTC) - 1, -1, 1, 0 },
    { LSUB, sizeof(LSUB) - 1, -1, 1, 0 },
    { APPEND, sizeof(APPEND) - 1, -1, 1, 0 },
    { CHECK, sizeof(CHECK) - 1, -1, 1, 0 },
    { CHECK2, sizeof(CHECK2) - 1, -1, 1, 0 },
    { CLOSE, sizeof(CLOSE) - 1, -1, 1, 0 },
    { CLOSE2, sizeof(CLOSE2) - 1, -1, 1, 0 },
    { EXPUNGE, sizeof(EXPUNGE) - 1, -1, 1, 0 },
    { EXPUNGE2, sizeof(EXPUNGE2) - 1, -1, 1, 0 },
    { SEARCH, sizeof(SEARCH) - 1, -1, 1, 0 },
    { FETCH, sizeof(FETCH) - 1, -1, 1, 0 },
    { PARTIAL, sizeof(PARTIAL) - 1, -1, 1, 0 },
    { STORE, sizeof(STORE) - 1, -1, 1, 0 },
    { COPY, sizeof(COPY) - 1, -1, 1, 0 },
    { UID, sizeof(UID) - 1, -1, 1, 0 },
};
static const uint32_t num_imap_client_patterns = sizeof(imap_client_patterns) /
    sizeof(*imap_client_patterns);

// each entry in this array corresponds to the entry in the imap_client_patterns array
// above and indicates if the pattern is the end of a protocol command
static std::array<bool, num_imap_client_patterns> eoc =
{
    { false, false, true, true, true, true, true, true, true, true, false, false,
      false, false, false, false, false, false, false, true, true, true, true, true, true,
      false, false, false, false, false, false }
};

ImapClientDetector::ImapClientDetector(ClientDiscovery* cdm)
{
    imap_client_detector = this;
    handler = cdm;
    name = "IMAP";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns.assign(imap_client_patterns, imap_client_patterns + num_imap_client_patterns);

    appid_registry =
    {
        { APP_ID_IMAP, APPINFO_FLAG_CLIENT_USER },
        { APP_ID_IMAPS, APPINFO_FLAG_CLIENT_USER }
    };

    handler->register_detector(name, this, proto);
}

ImapClientDetector::~ImapClientDetector()
{
    if (cmd_matcher)
        delete cmd_matcher;
}

void ImapClientDetector::do_custom_init()
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

static int pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    unsigned long idx = (unsigned long)id;
    if ( (int)imap_client_patterns[idx].length != match_end_pos )
        return 0;

    unsigned long* pat_idx = (unsigned long*)data;
    *pat_idx = (unsigned long)id;
    return 1;
}

ImapDetectorData* ImapClientDetector::get_common_data(AppIdSession& asd)
{
    ImapDetectorData* dd = (ImapDetectorData*)data_get(asd);
    if (!dd)
    {
        dd = (ImapDetectorData*)snort_calloc(sizeof(ImapDetectorData));
        data_add(asd, dd, &snort_free);
        dd->server.state = IMAP_STATE_BEGIN;
        dd->server.flags = IMAP_FLAG_FIRST_PACKET;
        dd->need_continue = 1;
        asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return dd;
}

int ImapClientDetector::validate(AppIdDiscoveryArgs& args)
{
    const uint8_t* s = args.data;
    const uint8_t* end = (args.data + args.size);
    unsigned length;
    AppIdFlowContentPattern* cmd = nullptr;
    char tag[IMAP_TAG_MAX_LEN + 1] = { 0 };

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (!args.size)
        return APPID_INPROCESS;

    ImapDetectorData* dd = get_common_data(args.asd);
    ImapClientData* fd = &dd->client;

    if (args.dir == APP_ID_FROM_RESPONDER)
    {
        if (imap_server_validate(dd, args.data, args.size, args.asd, this))
            args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
        return APPID_INPROCESS;
    }

    while ((length = (end - s)) > 0)
    {
        unsigned long pattern_index;
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
            args.asd.set_client_detected();
            args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return APPID_SUCCESS;
        }
        for (; (s < end) && isblank(*s); s++)
            ;

        /*s is now at command beginning */
        if (s >= end)
        {
            dd->need_continue = 0;
            args.asd.set_client_detected();
            args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
            return APPID_SUCCESS;
        }
        cmd = nullptr;
        pattern_index = num_imap_client_patterns;
        length = end - s;
        cmd_matcher->find_all((const char*)s, (length > longest_pattern ? longest_pattern : length),
            &pattern_match, false, (void*)&pattern_index);

        if (pattern_index < num_imap_client_patterns)
            cmd = &tcp_patterns[pattern_index];
        if (!cmd)
        {
            if ( (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') )
            {
                // Command was not in the recognized list. Keep searching.
                return APPID_INPROCESS;
            }
            else
            {
                // IMAP commands are English words, or at least start with X.
                return APPID_ENULL; // anything but CLIENT_APP_SUCCESS or CLIENT_APP_INPROCESS
            }
        }

        s += cmd->length;
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
                                    add_app(args.asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                                    fd->detected = 1;
                                    if (fd->got_user)
                                    {
                                        args.asd.set_client_detected();
                                        args.asd.clear_session_flags(
                                            APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
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
                        bool found_tick = false;

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
                                found_tick = true;
                            else if (*s == ' ')
                            {
                                fd->count++;
                                if (fd->count == MIN_CMDS)
                                {
                                    add_app(args.asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                                    fd->detected = 1;
                                    if (fd->got_user)
                                    {
                                        args.asd.set_client_detected();
                                        args.asd.clear_session_flags(
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
                    ;                            // all we need because cmd->eoc == 1
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
                    add_app(args.asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                    fd->detected = 1;
                    if (fd->got_user)
                    {
                        args.asd.set_client_detected();
                        args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                    }
                }
                if (!eoc[pattern_index])
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
                add_app(args.asd, APP_ID_IMAP, APP_ID_IMAP, nullptr);
                fd->detected = 1;
                if (fd->got_user)
                {
                    args.asd.set_client_detected();
                    args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                }
            }
            if (!eoc[pattern_index])
                for (; (s < end) && *s != '\r' && *s != '\n'; s++)
                    ;
            for (; (s < end) && (*s == '\r' || *s == '\n'); s++)
                ;
        }
        break;
        } // end switch(fd->state)
    } // end 'while'

    return APPID_INPROCESS;
}

ImapServiceDetector::ImapServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "IMAP";
    proto = IpProtocol::TCP;
    provides_user = true;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)IMAP_PATTERN, sizeof(IMAP_PATTERN) - 1, 0, 0, 0 }
    };

    appid_registry =
    {
        { APP_ID_IMAP, APPINFO_FLAG_CLIENT_USER },
        { APP_ID_IMAPS, APPINFO_FLAG_CLIENT_USER }
    };

    service_ports =
    {
        { IMAP_PORT, IpProtocol::TCP, false },
        { 220, IpProtocol::TCP, false },
    };

    handler->register_detector(name, this, proto);
}


int ImapServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ImapDetectorData* dd;
    ImapServiceData* id;

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

#ifdef APP_ID_USES_REASSEMBLED
    Stream::flush_response_flush(pkt);
#endif

    if (!args.size)
        goto inprocess;

    dd = imap_client_detector->get_common_data(args.asd);
    id = &dd->server;

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

    if (!imap_server_validate(dd, args.data, args.size, args.asd, this))
    {
        if ((id->flags & IMAP_FLAG_RESULT_OK) &&
            dd->client.state == IMAP_CLIENT_STATE_STARTTLS_CMD)
            return add_service(args.asd, args.pkt, args.dir, APP_ID_IMAPS);

        if (id->count >= IMAP_COUNT_THRESHOLD && !args.asd.is_service_detected())
            return add_service(args.asd, args.pkt, args.dir, APP_ID_IMAP);
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

