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

// client_app_smtp.cc author Sourcefire Inc.

#include "client_app_smtp.h"

#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_api.h"
#include "application_ids.h"

#define  UNIT_TESTING 0

#if UNIT_TESTING
#include "fw_appid.h"
#endif

enum SMTPState
{
    SMTP_STATE_NONE,
    SMTP_STATE_HELO,
    SMTP_STATE_MAIL_FROM,
    SMTP_STATE_RCPT_TO,
    SMTP_STATE_DATA,
    SMTP_STATE_MESSAGE,
    SMTP_STATE_GET_PRODUCT_VERSION,
    SMTP_STATE_SKIP_LINE,
    SMTP_STATE_CONNECTION_ERROR,
    SMTP_STATE_STARTTLS
};

#define MAX_VERSION_SIZE    64
#define MAX_HEADER_LINE_SIZE 1024

#if UNIT_TESTING
char* stateName [] =
{
    "SMTP_STATE_NONE",
    "SMTP_STATE_HELO",
    "SMTP_STATE_MAIL_FROM",
    "SMTP_STATE_RCPT_TO",
    "SMTP_STATE_DATA",
    "SMTP_STATE_MESSAGE",
    "SMTP_STATE_GET_PRODUCT_VERSION",
    "SMTP_STATE_SKIP_LINE",
    "SMTP_STATE_CONNECTION_ERROR",
    "SMTP_STATE_STARTTLS"
};
#endif

/* flag values for ClientSMTPData */
#define CLIENT_FLAG_STARTTLS_SENT   0x01
#define CLIENT_FLAG_SMTPS           0x02

#define MAX_VERSION_SIZE    64
struct ClientSMTPData
{
    int flags;
    SMTPState state;
    SMTPState nextstate;
    uint8_t version[MAX_VERSION_SIZE];
    unsigned pos;
    uint8_t* headerline;
};

struct SMTP_CLIENT_APP_CONFIG
{
    int enabled;
};

THREAD_LOCAL SMTP_CLIENT_APP_CONFIG smtp_config;

static CLIENT_APP_RETCODE smtp_init(const IniClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE smtp_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector* userData, const AppIdConfig* pConfig);

SO_PUBLIC RNAClientAppModule smtp_client_mod =
{
    "SMTP",                 // name
    IpProtocol::TCP,            // proto
    &smtp_init,             // init
    nullptr,                // clean
    &smtp_validate,         // validate
    1,                      // minimum_matches
    nullptr,                // api
    nullptr,                // userData
    0,                      // precedence
    nullptr,                // finalize,
    1,                      // provides_user
    0                       // flow_data_index
};

struct Client_App_Pattern
{
    const u_int8_t* pattern;
    unsigned length;
    int index;
    unsigned appId;
};

#define HELO "HELO "
#define EHLO "EHLO "
#define MAILFROM "MAIL FROM:"
#define RCPTTO "RCPT TO:"
#define DATA "DATA"
#define RSET "RSET"
#define AUTH "AUTH PLAIN"
#define STARTTLS "STARTTLS"

#define STARTTLS_COMMAND_SUCCESS "220 "

#define MICROSOFT "Microsoft "
#define OUTLOOK "Outlook"
#define EXPRESS "Express "
#define IMO "IMO, "

#define XMAILER "X-Mailer: "
#define USERAGENT "User-Agent: "

static const uint8_t APP_SMTP_OUTLOOK[] = "Microsoft Outlook";
static const uint8_t APP_SMTP_OUTLOOK_EXPRESS[] = "Microsoft Outlook Express ";
static const uint8_t APP_SMTP_IMO[] = "IMO, ";
static const uint8_t APP_SMTP_EVOLUTION[] = "Ximian Evolution ";
static const uint8_t APP_SMTP_LOTUSNOTES[] =  "Lotus Notes ";
static const uint8_t APP_SMTP_APPLEMAIL[] =  "Apple Mail (";
static const uint8_t APP_SMTP_EUDORA[] =  "QUALCOMM Windows Eudora Version ";
static const uint8_t APP_SMTP_EUDORAPRO[] =  "Windows Eudora Pro Version ";
static const uint8_t APP_SMTP_AOL[] =  "AOL ";
static const uint8_t APP_SMTP_MUTT[] =  "Mutt/";
static const uint8_t APP_SMTP_KMAIL[] =  "KMail/";
static const uint8_t APP_SMTP_MTHUNDERBIRD[] =  "Mozilla Thunderbird ";
static const uint8_t APP_SMTP_THUNDERBIRD[] =  "Thunderbird ";
static const uint8_t APP_SMTP_MOZILLA[] = "Mozilla";
static const uint8_t APP_SMTP_THUNDERBIRD_SHORT[] = "Thunderbird/";

static Client_App_Pattern patterns[] =
{
    { (uint8_t*)HELO, sizeof(HELO)-1, 0, APP_ID_SMTP },
    { (uint8_t*)EHLO, sizeof(EHLO)-1, 0, APP_ID_SMTP },
    { APP_SMTP_OUTLOOK,         sizeof(APP_SMTP_OUTLOOK)-1,        -1, APP_ID_OUTLOOK },
    { APP_SMTP_OUTLOOK_EXPRESS, sizeof(APP_SMTP_OUTLOOK_EXPRESS)-1,-1, APP_ID_OUTLOOK_EXPRESS },
    { APP_SMTP_IMO,             sizeof(APP_SMTP_IMO)-1,            -1, APP_ID_SMTP_IMO },
    { APP_SMTP_EVOLUTION,       sizeof(APP_SMTP_EVOLUTION)-1,      -1, APP_ID_EVOLUTION },
    { APP_SMTP_LOTUSNOTES,      sizeof(APP_SMTP_LOTUSNOTES)-1,     -1, APP_ID_LOTUS_NOTES },
    { APP_SMTP_APPLEMAIL,       sizeof(APP_SMTP_APPLEMAIL)-1,      -1, APP_ID_APPLE_EMAIL },
    { APP_SMTP_EUDORA,          sizeof(APP_SMTP_EUDORA)-1,         -1, APP_ID_EUDORA },
    { APP_SMTP_EUDORAPRO,       sizeof(APP_SMTP_EUDORAPRO)-1,      -1, APP_ID_EUDORA_PRO },
    { APP_SMTP_AOL,             sizeof(APP_SMTP_AOL)-1,            -1, APP_ID_AOL_EMAIL },
    { APP_SMTP_MUTT,            sizeof(APP_SMTP_MUTT)-1,           -1, APP_ID_MUTT },
    { APP_SMTP_KMAIL,           sizeof(APP_SMTP_KMAIL)-1,          -1, APP_ID_KMAIL },
    { APP_SMTP_MTHUNDERBIRD,    sizeof(APP_SMTP_MTHUNDERBIRD)-1,   -1, APP_ID_THUNDERBIRD },
    { APP_SMTP_THUNDERBIRD,     sizeof(APP_SMTP_THUNDERBIRD)-1,    -1, APP_ID_THUNDERBIRD },
};

static AppRegistryEntry appIdRegistry[] =
{
    { APP_ID_THUNDERBIRD, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_OUTLOOK, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_KMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_EUDORA_PRO, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_EVOLUTION, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_SMTP_IMO, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_EUDORA, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_LOTUS_NOTES, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_APPLE_EMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_AOL_EMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_MUTT, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_SMTP, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_OUTLOOK_EXPRESS, APPINFO_FLAG_CLIENT_ADDITIONAL },
    { APP_ID_SMTPS, APPINFO_FLAG_CLIENT_ADDITIONAL }
};

static CLIENT_APP_RETCODE smtp_init(const IniClientAppAPI* const init_api, SF_LIST* config)
{
    unsigned i;

    smtp_config.enabled = 1;

    if (config)
    {
        SF_LNODE* cursor;
        RNAClientAppModuleConfigItem* item;

        for (item = (RNAClientAppModuleConfigItem*)sflist_first(config, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
        {
            DebugFormat(DEBUG_LOG,"Processing %s: %s\n",item->name, item->value);
            if (strcasecmp(item->name, "enabled") == 0)
            {
                smtp_config.enabled = atoi(item->value);
            }
        }
    }

    if (smtp_config.enabled)
    {
        for (i=0; i < sizeof(patterns)/sizeof(*patterns); i++)
        {
            init_api->RegisterPattern(&smtp_validate, IpProtocol::TCP, patterns[i].pattern,
                patterns[i].length, patterns[i].index, init_api->pAppidConfig);
        }
    }

    unsigned j;
    for (j=0; j < sizeof(appIdRegistry)/sizeof(*appIdRegistry); j++)
    {
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[j].appId);
        init_api->RegisterAppId(&smtp_validate, appIdRegistry[j].appId,
            appIdRegistry[j].additionalInfo, init_api->pAppidConfig);
    }

    return CLIENT_APP_SUCCESS;
}

static int ExtractVersion(ClientSMTPData* const fd, const uint8_t* product,
    const uint8_t* data, AppIdData* flowp, Packet*)
{
    const u_int8_t* p;
    u_int8_t* v;
    u_int8_t* v_end;
    unsigned len;
    unsigned sublen;
    AppId appId = (fd->flags & CLIENT_FLAG_SMTPS) ?  APP_ID_SMTPS : APP_ID_SMTP;

    v_end = fd->version;
    v_end += MAX_VERSION_SIZE - 1;
    len = data - product;
    if (len >= sizeof(MICROSOFT) && memcmp(product, MICROSOFT, sizeof(MICROSOFT)-1) == 0)
    {
        p = product + sizeof(MICROSOFT) - 1;

        if (data-p >= (int)sizeof(OUTLOOK) && memcmp(p, OUTLOOK, sizeof(OUTLOOK)-1) == 0)
        {
            p += sizeof(OUTLOOK) - 1;
            if (p >= data)
                return 1;
            if (*p == ',')
            {
                p++;
                if (p >= data || *p != ' ')
                    return 1;
                p++;
                if (p >= data || isspace(*p))
                    return 1;
                for (v=fd->version; v<v_end && p < data; v++,p++)
                {
                    *v = *p;
                }
                *v = 0;
                smtp_client_mod.api->add_app(flowp, appId, APP_ID_OUTLOOK, (char*)fd->version);
                return 0;
            }
            else if (*p == ' ')
            {
                p++;
                if (data-p >= (int)sizeof(EXPRESS) && memcmp(p, EXPRESS, sizeof(EXPRESS)-1) == 0)
                {
                    p += sizeof(EXPRESS) - 1;
                    if (p >= data || isspace(*p))
                        return 1;
                    for (v=fd->version; v<v_end && p < data; v++,p++)
                    {
                        *v = *p;
                    }
                    *v = 0;
                    smtp_client_mod.api->add_app(flowp, appId, APP_ID_OUTLOOK_EXPRESS,
                        (char*)fd->version);
                    return 0;
                }
                else if (data-p >= (int)sizeof(IMO) && memcmp(p, IMO, sizeof(IMO)-1) == 0)
                {
                    p += sizeof(IMO) - 1;
                    if (p >= data)
                        return 1;
                    for (v=fd->version; v<v_end && p < data; v++,p++)
                    {
                        *v = *p;
                    }
                    *v = 0;
                    smtp_client_mod.api->add_app(flowp, appId, APP_ID_OUTLOOK, (char*)fd->version);
                    return 0;
                }
            }
        }
    }
    else if (len >= sizeof(APP_SMTP_EVOLUTION) && memcmp(product, APP_SMTP_EVOLUTION,
        sizeof(APP_SMTP_EVOLUTION)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_EVOLUTION) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_EVOLUTION, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_LOTUSNOTES) && memcmp(product, APP_SMTP_LOTUSNOTES,
        sizeof(APP_SMTP_LOTUSNOTES)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_LOTUSNOTES) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_LOTUS_NOTES, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_APPLEMAIL) && memcmp(product, APP_SMTP_APPLEMAIL,
        sizeof(APP_SMTP_APPLEMAIL)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_APPLEMAIL) - 1;
        if (p >= data || *(data - 1) != ')' || *p == ')' || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data-1; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_APPLE_EMAIL, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_EUDORA) && memcmp(product, APP_SMTP_EUDORA,
        sizeof(APP_SMTP_EUDORA)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_EUDORA) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_EUDORA, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_EUDORAPRO) && memcmp(product, APP_SMTP_EUDORAPRO,
        sizeof(APP_SMTP_EUDORAPRO)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_EUDORAPRO) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_EUDORA_PRO, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_AOL) && memcmp(product, APP_SMTP_AOL, sizeof(APP_SMTP_AOL)-
        1) == 0)
    {
        p = product + sizeof(APP_SMTP_AOL) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_AOL_EMAIL, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_MUTT) && memcmp(product, APP_SMTP_MUTT, sizeof(APP_SMTP_MUTT)-
        1) == 0)
    {
        p = product + sizeof(APP_SMTP_MUTT) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_MUTT, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_KMAIL) && memcmp(product, APP_SMTP_KMAIL,
        sizeof(APP_SMTP_KMAIL)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_KMAIL) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, appId /*KMAIL_ID*/, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_THUNDERBIRD) && memcmp(product, APP_SMTP_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_THUNDERBIRD) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_THUNDERBIRD, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_MTHUNDERBIRD) && memcmp(product, APP_SMTP_MTHUNDERBIRD,
        sizeof(APP_SMTP_MTHUNDERBIRD)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_MTHUNDERBIRD) - 1;
        if (p >= data || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(flowp, appId, APP_ID_THUNDERBIRD, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_MOZILLA) && memcmp(product, APP_SMTP_MOZILLA,
        sizeof(APP_SMTP_MOZILLA)-1) == 0)
    {
        for (p = product + sizeof(APP_SMTP_MOZILLA) - 1; p < data; p++)
        {
            if (*p == 'T')
            {
                sublen = data - p;
                if (sublen >= sizeof(APP_SMTP_THUNDERBIRD_SHORT) && memcmp(p,
                    APP_SMTP_THUNDERBIRD_SHORT, sizeof(APP_SMTP_THUNDERBIRD_SHORT)-1) == 0)
                {
                    p = p + sizeof(APP_SMTP_THUNDERBIRD_SHORT) - 1;
                    for (v=fd->version; v<v_end && p < data; p++)
                    {
                        if (*p == 0x0A || *p == 0x0D || !isprint(*p))
                            break;
                        *v = *p;
                        v++;
                    }
                    *v = 0;
                    smtp_client_mod.api->add_app(flowp, appId, APP_ID_THUNDERBIRD,
                        (char*)fd->version);
                    return 0;
                }
            }
        }
    }

    return 1;
}

static void freeData(void* data)
{
    ClientSMTPData* fd = (ClientSMTPData*)data;
    snort_free(fd->headerline);
    snort_free(fd);
}

static CLIENT_APP_RETCODE smtp_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdData* flowp, Packet* pkt, struct Detector*, const AppIdConfig*)
{
    ClientSMTPData* fd;
    const uint8_t* end;
#if UNIT_TESTING
    SMTPState currState = SMTP_STATE_NONE;
#endif

    fd = (ClientSMTPData*)smtp_client_mod.api->data_get(flowp, smtp_client_mod.flow_data_index);
    if (!fd)
    {
        fd = (ClientSMTPData*)snort_calloc(sizeof(ClientSMTPData));
        if (!fd)
            return CLIENT_APP_ENOMEM;
        if (smtp_client_mod.api->data_add(flowp, fd, smtp_client_mod.flow_data_index, &freeData))
        {
            snort_free(fd);
            return CLIENT_APP_ENOMEM;
        }
        fd->state = SMTP_STATE_HELO;
    }

    if (dir != APP_ID_FROM_INITIATOR)
    {
        if ( (fd->flags & CLIENT_FLAG_STARTTLS_SENT) &&
            !memcmp(data,STARTTLS_COMMAND_SUCCESS,sizeof(STARTTLS_COMMAND_SUCCESS)-1) )
        {
            fd->flags &= ~(CLIENT_FLAG_STARTTLS_SENT);
            fd->flags |= CLIENT_FLAG_SMTPS;
            clearAppIdFlag(flowp, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS); // we no longer need
                                                                             // to examine the
                                                                             // response.
            if (!getAppIdFlag(flowp, APPID_SESSION_DECRYPTED))
            {
                /* Because we can't see any further info without decryption we settle for
                   plain APP_ID_SMTPS instead of perhaps finding data that would make calling
                   ExtractVersion() worthwhile, So set the appid and call it good. */
                smtp_client_mod.api->add_app(flowp, APP_ID_SMTPS, APP_ID_SMTPS, nullptr);
                goto done;
            }
        }
        return CLIENT_APP_INPROCESS;
    }
    if (getAppIdFlag(flowp, APPID_SESSION_ENCRYPTED))
    {
        if (!getAppIdFlag(flowp, APPID_SESSION_DECRYPTED))
            return CLIENT_APP_INPROCESS;
    }

    for (end = data + size; data < end; data++)
    {
#if UNIT_TESTING
        if (app_id_debug_session_flag && currState != fd->state)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_APPID, "AppIdDbg %s SMTP client state %s\n",
                app_id_debug_session, stateName[fd->state]); );
            currState = fd->state;
        }
#endif
        switch (fd->state)
        {
        case SMTP_STATE_HELO:
            if (*data == HELO[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(HELO))
                {
                    fd->pos = 0;
                    fd->nextstate = SMTP_STATE_MAIL_FROM;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else if (*data == EHLO[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(EHLO))
                {
                    fd->pos = 0;
                    fd->nextstate = SMTP_STATE_MAIL_FROM;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else
                goto done;
            break;

        case SMTP_STATE_MAIL_FROM:
            if (*data == MAILFROM[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(MAILFROM))
                {
                    fd->pos = 0;
                    fd->nextstate = SMTP_STATE_RCPT_TO;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else if (*data == RSET[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(RSET))
                {
                    fd->pos = 0;
                    fd->nextstate = fd->state;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else if (*data == AUTH[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(AUTH))
                {
                    fd->pos = 0;
                    fd->nextstate = fd->state;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else if (*data == STARTTLS[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(STARTTLS))
                {
                    fd->flags |= CLIENT_FLAG_STARTTLS_SENT;
                    fd->pos = 0;
                    fd->nextstate = fd->state;
                    fd->state = SMTP_STATE_SKIP_LINE;
                    setAppIdFlag(flowp, APPID_SESSION_ENCRYPTED);
                }
            }
            else
                goto done;
            break;

        case SMTP_STATE_RCPT_TO:
            if (*data == RCPTTO[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(RCPTTO))
                {
                    fd->pos = 0;
                    fd->nextstate = SMTP_STATE_DATA;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else
                goto done;
            break;

        case SMTP_STATE_DATA:
            if (*data == DATA[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(DATA))
                {
                    fd->pos = 0;
                    fd->nextstate = SMTP_STATE_MESSAGE;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            else if (*data == RCPTTO[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(RCPTTO))
                {
                    fd->pos = 0;
                    fd->nextstate = fd->state;
                    fd->state = SMTP_STATE_SKIP_LINE;
                }
            }
            break;

        case SMTP_STATE_MESSAGE:
            if (*data == '.')
            {
                unsigned len = end - data;
                if (len == 0 ||
                    (len >= 1 && data[1] == 0x0A) ||
                    (len >= 2 && data[1] == 0x0D && data[2] == 0x0A))
                {
                    AppId appId = (fd->flags & CLIENT_FLAG_SMTPS) ?  APP_ID_SMTPS : APP_ID_SMTP;
                    smtp_client_mod.api->add_app(flowp, appId, appId, nullptr);
                    goto done;
                }
            }
            else if (*data == XMAILER[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(XMAILER))
                {
                    fd->pos = 0;
                    fd->state = SMTP_STATE_GET_PRODUCT_VERSION;
                }
            }
            else if (*data == USERAGENT[fd->pos])
            {
                fd->pos++;
                if (fd->pos == strlen(USERAGENT))
                {
                    fd->pos = 0;
                    fd->state = SMTP_STATE_GET_PRODUCT_VERSION;
                }
            }
            else if (!isprint(*data) && *data != 0x09)
                goto done;
            else
            {
                fd->pos = 0;
                fd->nextstate = fd->state;
                fd->state = SMTP_STATE_SKIP_LINE;
            }
            break;

        case SMTP_STATE_GET_PRODUCT_VERSION:
            if (*data == 0x0D)
            {
                if (fd->headerline && fd->pos)
                {
                    ExtractVersion(fd, fd->headerline, fd->headerline + fd->pos, flowp, pkt);
                    snort_free(fd->headerline);
                    fd->headerline = nullptr;
                }
                goto done;
            }
            else if (!isprint(*data))
            {
                snort_free(fd->headerline);
                fd->headerline = nullptr;
                goto done;
            }
            else
            {
                if (!fd->headerline)
                {
                    if (!(fd->headerline = (uint8_t*)snort_calloc(MAX_HEADER_LINE_SIZE)))
                        goto done;
                }

                if (fd->pos < (MAX_HEADER_LINE_SIZE-1))
                    fd->headerline[fd->pos++] = *data;
            }
            break;

        case SMTP_STATE_SKIP_LINE:
            if (*data == 0x0A)
            {
                fd->pos = 0;
                fd->state = fd->nextstate;
                fd->nextstate = SMTP_STATE_NONE;
            }
            else if (!(*data == 0x0D || isprint(*data)))
                goto done;
            break;

        default:
            goto done;
        }
    }
    return CLIENT_APP_INPROCESS;

done:
    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

