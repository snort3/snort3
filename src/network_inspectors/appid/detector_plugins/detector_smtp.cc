/*
** Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include "detector_smtp.h"

#include "main/snort_debug.h"
#include "utils/util.h"
#include "utils/sflsq.h"

#include "application_ids.h"
#include "detector_api.h"
#include "client_plugins/client_app_api.h"
#include "service_plugins/service_util.h"
#include "app_info_table.h"
#include "appid_api.h"
#include "appid_module.h"

enum SMTPClientState
{
    SMTP_CLIENT_STATE_NONE,
    SMTP_CLIENT_STATE_HELO,
    SMTP_CLIENT_STATE_MAIL_FROM,
    SMTP_CLIENT_STATE_RCPT_TO,
    SMTP_CLIENT_STATE_DATA,
    SMTP_CLIENT_STATE_MESSAGE,
    SMTP_CLIENT_STATE_GET_PRODUCT_VERSION,
    SMTP_CLIENT_STATE_SKIP_LINE,
    SMTP_CLIENT_STATE_CONNECTION_ERROR,
    SMTP_CLIENT_STATE_STARTTLS
};

#define MAX_HEADER_LINE_SIZE 1024

#ifdef UNIT_TESTING
char* stateName [] =
{
    "SMTP_CLIENT_STATE_NONE",
    "SMTP_CLIENT_STATE_HELO",
    "SMTP_CLIENT_STATE_MAIL_FROM",
    "SMTP_CLIENT_STATE_RCPT_TO",
    "SMTP_CLIENT_STATE_DATA",
    "SMTP_CLIENT_STATE_MESSAGE",
    "SMTP_CLIENT_STATE_GET_PRODUCT_VERSION",
    "SMTP_CLIENT_STATE_SKIP_LINE",
    "SMTP_CLIENT_STATE_CONNECTION_ERROR",
    "SMTP_CLIENT_STATE_STARTTLS"
};
#endif

/* flag values for ClientSMTPData */
#define CLIENT_FLAG_STARTTLS_SUCCESS    0x01
#define CLIENT_FLAG_SMTPS               0x02

#define MAX_VERSION_SIZE    64
#define SSL_WAIT_PACKETS    8  // This many un-decrypted packets without a HELO and we quit.

struct ClientSMTPData
{
    int flags;
    SMTPClientState state;
    SMTPClientState nextstate;
    uint8_t version[MAX_VERSION_SIZE];
    unsigned pos;
    uint8_t* headerline;
    int decryption_countdown;
};

struct SMTP_CLIENT_APP_CONFIG
{
    int enabled;
};


THREAD_LOCAL SMTP_CLIENT_APP_CONFIG smtp_config;

static CLIENT_APP_RETCODE smtp_ca_init(const InitClientAppAPI* const init_api, SF_LIST *config);
static CLIENT_APP_RETCODE smtp_ca_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector* userData);

static RNAClientAppModule  smtp_client_mod =
{
    "SMTP",                 // name
    IpProtocol::TCP,            // proto
    &smtp_ca_init,             // init
    nullptr,                // clean
    &smtp_ca_validate,         // validate
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
    const uint8_t* pattern;
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
static const uint8_t APP_SMTP_LOTUS_NOTES[] =  "Lotus Notes ";
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
    {(uint8_t*)HELO, sizeof(HELO)-1, -1, APP_ID_SMTP},
    {(uint8_t*)EHLO, sizeof(EHLO)-1, -1, APP_ID_SMTP},
	{APP_SMTP_OUTLOOK,         sizeof(APP_SMTP_OUTLOOK)-1,        -1, APP_ID_OUTLOOK},
	{APP_SMTP_OUTLOOK_EXPRESS, sizeof(APP_SMTP_OUTLOOK_EXPRESS)-1,-1, APP_ID_OUTLOOK_EXPRESS},
	{APP_SMTP_IMO,             sizeof(APP_SMTP_IMO)-1,            -1, APP_ID_SMTP_IMO},
	{APP_SMTP_EVOLUTION,       sizeof(APP_SMTP_EVOLUTION)-1,      -1, APP_ID_EVOLUTION},
	{APP_SMTP_LOTUS_NOTES,      sizeof(APP_SMTP_LOTUS_NOTES)-1,     -1, APP_ID_LOTUS_NOTES},
	{APP_SMTP_APPLEMAIL,       sizeof(APP_SMTP_APPLEMAIL)-1,      -1, APP_ID_APPLE_EMAIL},
	{APP_SMTP_EUDORA,          sizeof(APP_SMTP_EUDORA)-1,         -1, APP_ID_EUDORA},
	{APP_SMTP_EUDORAPRO,       sizeof(APP_SMTP_EUDORAPRO)-1,      -1, APP_ID_EUDORA_PRO},
	{APP_SMTP_AOL,             sizeof(APP_SMTP_AOL)-1,            -1, APP_ID_AOL_EMAIL},
	{APP_SMTP_MUTT,            sizeof(APP_SMTP_MUTT)-1,           -1, APP_ID_MUTT},
	{APP_SMTP_KMAIL,           sizeof(APP_SMTP_KMAIL)-1,          -1, APP_ID_KMAIL},
	{APP_SMTP_MTHUNDERBIRD,    sizeof(APP_SMTP_MTHUNDERBIRD)-1,   -1, APP_ID_THUNDERBIRD},
	{APP_SMTP_THUNDERBIRD,     sizeof(APP_SMTP_THUNDERBIRD)-1,    -1, APP_ID_THUNDERBIRD},
};

static AppRegistryEntry clientAppIdRegistry[] =
{
    {APP_ID_THUNDERBIRD, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_OUTLOOK, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_KMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_EUDORA_PRO, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_EVOLUTION, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_SMTP_IMO, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_EUDORA, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_LOTUS_NOTES, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_APPLE_EMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_AOL_EMAIL, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_MUTT, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_SMTP, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_OUTLOOK_EXPRESS, APPINFO_FLAG_CLIENT_ADDITIONAL},
    {APP_ID_SMTPS, APPINFO_FLAG_CLIENT_ADDITIONAL}
};

static CLIENT_APP_RETCODE smtp_ca_init(const InitClientAppAPI* const init_api, SF_LIST* config)
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
            init_api->RegisterPattern(&smtp_ca_validate, IpProtocol::TCP, patterns[i].pattern,
                                      patterns[i].length, patterns[i].index);
        }
    }

	unsigned j;
	for (j=0; j < sizeof(clientAppIdRegistry)/sizeof(*clientAppIdRegistry); j++)
	{
	    DebugFormat(DEBUG_LOG,"registering appId: %d\n",clientAppIdRegistry[j].appId);
		init_api->RegisterAppId(&smtp_ca_validate, clientAppIdRegistry[j].appId,
		                        clientAppIdRegistry[j].additionalInfo);
	}

    return CLIENT_APP_SUCCESS;
}

#define SMTP_PORT   25
#define SMTPS_DEPRECATED_PORT   465
#define SMTP_CLOSING_CONN "closing connection\x0d\x0a"

enum SMTPServiceState
{
    SMTP_SERVICE_STATE_CONNECTION,
    SMTP_SERVICE_STATE_HELO,
    SMTP_SERVICE_STATE_TRANSFER,
    SMTP_SERVICE_STATE_CONNECTION_ERROR,
    SMTP_SERVICE_STATE_STARTTLS,
    SMTP_SERVICE_STATE_SSL_HANDSHAKE
};

struct ServiceSMTPData
{
    SMTPServiceState state;
    int code;
    int multiline;
    int set_flags;
    bool detected;
};

#pragma pack(1)

struct ServiceSMTPCode
{
    uint8_t code[3];
    uint8_t sp;
};

#pragma pack()

static int smtp_svc_init(const InitServiceAPI* const init_api);
static int smtp_svc_validate(ServiceValidationArgs* args);

static const RNAServiceElement svc_element =
{
    nullptr,
    &smtp_svc_validate,
    nullptr,
    DETECTOR_TYPE_DECODER,
    1,
    1,
    0,
    "smtp"
};

static RNAServiceValidationPort pp[] =
{
    {&smtp_svc_validate, SMTP_PORT, IpProtocol::TCP, 0},
    {&smtp_svc_validate, SMTPS_DEPRECATED_PORT, IpProtocol::TCP, 0},
    { nullptr, 0, IpProtocol::PROTO_NOT_SET, 0 }
};

static RNAServiceValidationModule smtp_service_mod =
{
    "SMTP",
    &smtp_svc_init,
    pp,
    nullptr,
    nullptr,
    0,
    nullptr,
    0
};

static AppRegistryEntry appIdRegistry[] =
{
    {APP_ID_SMTP,  0},
    {APP_ID_SMTPS, 0}
};

struct SMTPDetectorData
{
    ClientSMTPData client;
    ServiceSMTPData server;
    int need_continue;
    int watch_for_deprecated_port;
};

SO_PUBLIC RNADetectorValidationModule smtp_detector_mod =
{
    &smtp_service_mod,
    &smtp_client_mod,
    nullptr,
    0
};

static int smtp_svc_init(const InitServiceAPI* const init_api)
{
    const char SMTP_PATTERN1[] = "220 ";
    const char SMTP_PATTERN2[] = "220-";
    const char SMTP_PATTERN3[] = "SMTP";
    const char SMTP_PATTERN4[] = "smtp";

    init_api->RegisterPattern(&smtp_svc_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN1,
        sizeof(SMTP_PATTERN1) - 1, 0, "smtp");
    init_api->RegisterPattern(&smtp_svc_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN2,
        sizeof(SMTP_PATTERN2) - 1, 0, "smtp");
    init_api->RegisterPattern(&smtp_svc_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN3,
        sizeof(SMTP_PATTERN3) - 1, -1, "smtp");
    init_api->RegisterPattern(&smtp_svc_validate, IpProtocol::TCP, (uint8_t*)SMTP_PATTERN4,
        sizeof(SMTP_PATTERN4) - 1, -1, "smtp");

	unsigned i;
	for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
	{
        DebugFormat(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
		init_api->RegisterAppId(&smtp_svc_validate, appIdRegistry[i].appId,
		                        appIdRegistry[i].additionalInfo);
	}

    return 0;
}

/*
 *    product - The product data should not include any characters
 *              after the end of the product version (e.g. no CR, LF, etc).
 *    prefix_len - The number of characters that are the prefix to the version,
 *              including the NUL terminating character.
 */
static int extract_version_and_add_client_app(ApplicationId clientId, const int prefix_len,
        const uint8_t* product, const uint8_t* product_end, ClientSMTPData* const client_data,
        AppIdSession* asd, AppId appId, PegCount* stat_counter)
{
    const uint8_t* p;
    uint8_t* v;
    uint8_t* v_end;

    v_end = client_data->version;
    v_end += MAX_VERSION_SIZE - 1;

    //  The prefix_len includes the NUL character, but product does not, so
    //  subtract 1 from length to skip.
    p = product + prefix_len - 1;
    if (p >= product_end || isspace(*p))
        return 1;
    for (v=client_data->version; v<v_end && p < product_end; v++,p++)
    {
        *v = *p;
    }
    *v = 0;
    smtp_client_mod.api->add_app(asd, appId, clientId, (char*)client_data->version);
    (*stat_counter)++;
    return 0;
}


/*
 *  Identify the product and version of the SMTP client.
 *
 *  Returns 0 if a recognized product is found.  Otherwise returns 1.
 */
static int IdentifyClientVersion(ClientSMTPData* const fd, const uint8_t* product,
    const uint8_t* data_end, AppIdSession* asd, Packet*)
{
    const uint8_t* p;
    uint8_t* v;
    uint8_t* v_end;
    unsigned len;
    unsigned sublen;
    AppId appId = (fd->flags & CLIENT_FLAG_SMTPS) ?  APP_ID_SMTPS : APP_ID_SMTP;

    v_end = fd->version;
    v_end += MAX_VERSION_SIZE - 1;
    len = data_end - product;
    if (len >= sizeof(MICROSOFT) && memcmp(product, MICROSOFT, sizeof(MICROSOFT)-1) == 0)
    {
        p = product + sizeof(MICROSOFT) - 1;

        if (data_end-p >= (int)sizeof(OUTLOOK) && memcmp(p, OUTLOOK, sizeof(OUTLOOK)-1) == 0)
        {
            p += sizeof(OUTLOOK) - 1;
            if (p >= data_end)
                return 1;
            if (*p == ',')
            {
                p++;
                if (p >= data_end || *p != ' ')
                    return 1;
                return extract_version_and_add_client_app(APP_ID_OUTLOOK,
                    2, p, data_end, fd, asd, appId,
                    &appid_stats.smtp_microsoft_outlook_clients);
            }
            else if (*p == ' ')
            {
                p++;
                if (data_end-p >= (int)sizeof(EXPRESS) && memcmp(p, EXPRESS, sizeof(EXPRESS)-1) == 0)
                {
                    return extract_version_and_add_client_app(APP_ID_OUTLOOK_EXPRESS,
                        sizeof(EXPRESS), p, data_end, fd, asd, appId,
                        &appid_stats.smtp_microsoft_outlook_express_clients);
                }
                else if (data_end-p >= (int)sizeof(IMO) && memcmp(p, IMO, sizeof(IMO)-1) == 0)
                {
                    return extract_version_and_add_client_app(APP_ID_OUTLOOK,
                        sizeof(IMO), p, data_end, fd, asd, appId,
                        &appid_stats.smtp_microsoft_outlook_imo_clients);
                }
            }
        }
    }
    else if (len >= sizeof(APP_SMTP_EVOLUTION) && memcmp(product, APP_SMTP_EVOLUTION,
        sizeof(APP_SMTP_EVOLUTION)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EVOLUTION,
            sizeof(APP_SMTP_EVOLUTION), product, data_end, fd, asd, appId,
            &appid_stats.smtp_evolution_clients);
    }
    else if (len >= sizeof(APP_SMTP_LOTUS_NOTES) && memcmp(product, APP_SMTP_LOTUS_NOTES,
        sizeof(APP_SMTP_LOTUS_NOTES)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_LOTUS_NOTES,
            sizeof(APP_SMTP_LOTUS_NOTES), product, data_end, fd, asd, appId,
            &appid_stats.smtp_lotus_notes_clients);
    }
    else if (len >= sizeof(APP_SMTP_APPLEMAIL) && memcmp(product, APP_SMTP_APPLEMAIL,
        sizeof(APP_SMTP_APPLEMAIL)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_APPLEMAIL) - 1;
        if (p >= data_end || *(data_end - 1) != ')' || *p == ')' || isspace(*p))
            return 1;
        for (v=fd->version; v<v_end && p < data_end-1; v++,p++)
        {
            *v = *p;
        }
        *v = 0;
        smtp_client_mod.api->add_app(asd, appId, APP_ID_APPLE_EMAIL, (char*)fd->version);
        appid_stats.smtp_applemail_clients++;
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_EUDORA) && memcmp(product, APP_SMTP_EUDORA,
        sizeof(APP_SMTP_EUDORA)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EUDORA,
            sizeof(APP_SMTP_EUDORA), product, data_end, fd, asd, appId,
            &appid_stats.smtp_eudora_clients);
    }
    else if (len >= sizeof(APP_SMTP_EUDORAPRO) && memcmp(product, APP_SMTP_EUDORAPRO,
        sizeof(APP_SMTP_EUDORAPRO)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EUDORA_PRO,
            sizeof(APP_SMTP_EUDORAPRO), product, data_end, fd, asd, appId,
            &appid_stats.smtp_eudora_pro_clients);
    }
    else if (len >= sizeof(APP_SMTP_AOL) && memcmp(product, APP_SMTP_AOL,
        sizeof(APP_SMTP_AOL)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_AOL_EMAIL,
            sizeof(APP_SMTP_AOL), product, data_end, fd, asd, appId,
            &appid_stats.smtp_aol_clients);
    }
    else if (len >= sizeof(APP_SMTP_MUTT) && memcmp(product, APP_SMTP_MUTT,
        sizeof(APP_SMTP_MUTT)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_MUTT,
            sizeof(APP_SMTP_MUTT), product, data_end, fd, asd, appId,
            &appid_stats.smtp_mutt_clients);
    }
    else if (len >= sizeof(APP_SMTP_KMAIL) && memcmp(product, APP_SMTP_KMAIL,
        sizeof(APP_SMTP_KMAIL)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_KMAIL,
            sizeof(APP_SMTP_KMAIL), product, data_end, fd, asd, appId,
            &appid_stats.smtp_kmail_clients);
    }
    else if (len >= sizeof(APP_SMTP_THUNDERBIRD) && memcmp(product, APP_SMTP_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
            sizeof(APP_SMTP_THUNDERBIRD), product, data_end, fd, asd, appId,
            &appid_stats.smtp_thunderbird_clients);
    }
    else if (len >= sizeof(APP_SMTP_MTHUNDERBIRD) && memcmp(product, APP_SMTP_MTHUNDERBIRD,
        sizeof(APP_SMTP_MTHUNDERBIRD)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
            sizeof(APP_SMTP_MTHUNDERBIRD), product, data_end, fd, asd, appId,
            &appid_stats.smtp_thunderbird_clients);
    }
    else if (len >= sizeof(APP_SMTP_MOZILLA) && memcmp(product, APP_SMTP_MOZILLA,
        sizeof(APP_SMTP_MOZILLA)-1) == 0)
    {
        for (p = product + sizeof(APP_SMTP_MOZILLA) - 1; p < data_end; p++)
        {
            if (*p == 'T')
            {
                sublen = data_end - p;
                if (sublen >= sizeof(APP_SMTP_THUNDERBIRD_SHORT) && memcmp(p,
                    APP_SMTP_THUNDERBIRD_SHORT, sizeof(APP_SMTP_THUNDERBIRD_SHORT)-1) == 0)
                {
                    return extract_version_and_add_client_app(
                        APP_ID_THUNDERBIRD, sizeof(APP_SMTP_THUNDERBIRD_SHORT),
                        p, data_end, fd, asd, appId,
                        &appid_stats.smtp_thunderbird_clients);
                }
            }
        }
    }

    return 1;
}


static void smtp_free_state(void *data)
{
    SMTPDetectorData* dd = (SMTPDetectorData*)data;
    ClientSMTPData *cd;

    if (dd)
    {
        cd = &dd->client;
        if (cd->headerline)
            snort_free(cd->headerline);
        snort_free(dd);
    }
}
static inline SMTPDetectorData* smtp_get_SMTPDetectorData(AppIdSession* asd)
{
    SMTPDetectorData* dd = (SMTPDetectorData*)smtp_detector_mod.api->data_get(asd, smtp_detector_mod.flow_data_index);
    if (dd)
        return dd;

    dd = (SMTPDetectorData*)snort_calloc(1, sizeof(*dd));
    if (smtp_detector_mod.api->data_add(asd, dd, smtp_detector_mod.flow_data_index, &smtp_free_state))
    {
        snort_free(dd);
        return nullptr;
    }

    dd->server.state = SMTP_SERVICE_STATE_CONNECTION;
    dd->server.detected = false;
    dd->client.state = SMTP_CLIENT_STATE_HELO;
    dd->need_continue = 1;
    dd->watch_for_deprecated_port = 1;
    asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    return dd;
}

// #define UNIT_TEST_SKIP
static CLIENT_APP_RETCODE smtp_ca_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector*)
{
    SMTPDetectorData* dd;
    ClientSMTPData* fd;
    const uint8_t* end;
    unsigned len;
#ifdef UNIT_TESTING
    SMTPClientState currState = SMTP_CLIENT_STATE_NONE;
#endif

    if (!(dd = smtp_get_SMTPDetectorData(asd)))
        return CLIENT_APP_ENOMEM;

    fd = &dd->client;

    if (dir != APP_ID_FROM_INITIATOR)
        return CLIENT_APP_INPROCESS;

    if (asd->get_session_flags(APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED) == APPID_SESSION_ENCRYPTED)
    {
        if ((fd->flags & CLIENT_FLAG_STARTTLS_SUCCESS))
        {
            fd->decryption_countdown--;
            if (!fd->decryption_countdown)
#ifdef UNIT_TEST_SKIP
            if (asd->session_packet_count == 0)
#endif
            {
                fd->flags |= CLIENT_FLAG_SMTPS; // report as SMTPS
                asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
                /* Because we can't see any further info without decryption we settle for
                   plain APP_ID_SMTPS instead of perhaps finding data that would make calling
                   ExtractVersion() worthwhile, So set the appid and call it good. */
                smtp_client_mod.api->add_app(asd, APP_ID_SMTPS, APP_ID_SMTPS, nullptr);
                goto done;
            }
        }
        return CLIENT_APP_INPROCESS;
    }


    for (end = data + size; data < end; data++)
    {
#ifdef UNIT_TESTING
    if (app_id_debug_session_flag && currState != fd->state)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_APPID, "AppIdDbg %s SMTP client state %s\n", app_id_debug_session, stateName[fd->state]););
        currState = fd->state;
    }
#endif
        len = end - data;
        switch (fd->state)
        {
        case SMTP_CLIENT_STATE_HELO:
            if (len >= (sizeof(HELO)-1) && strncasecmp((const char*)data, HELO, sizeof(HELO)-1) == 0)
            {
                data += (sizeof(HELO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MAIL_FROM;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(EHLO)-1) && strncasecmp((const char*)data, EHLO, sizeof(EHLO)-1) == 0)
            {
                data += (sizeof(EHLO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MAIL_FROM;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else goto done;
            break;

        case SMTP_CLIENT_STATE_MAIL_FROM:
            if (len >= (sizeof(MAILFROM)-1) && strncasecmp((const char*)data, MAILFROM, sizeof(MAILFROM)-1) == 0)
            {
                data += (sizeof(MAILFROM)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_RCPT_TO;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(RSET)-1) && strncasecmp((const char*)data, RSET, sizeof(RSET)-1) == 0)
            {
                data += (sizeof(RSET)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(AUTH)-1) && strncasecmp((const char*)data, AUTH, sizeof(AUTH)-1) == 0)
            {
                data += (sizeof(AUTH)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(STARTTLS)-1) && strncasecmp((const char*)data, STARTTLS, sizeof(STARTTLS)-1) == 0)
            {
                data += (sizeof(STARTTLS)-1)-1;
                dd->server.state = SMTP_SERVICE_STATE_STARTTLS;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else goto done;
            break;
        case SMTP_CLIENT_STATE_RCPT_TO:
            if (len >= (sizeof(RCPTTO)-1) && strncasecmp((const char*)data, RCPTTO, sizeof(RCPTTO)-1) == 0)
            {
                data += (sizeof(RCPTTO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_DATA;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else
                goto done;
            break;

        case SMTP_CLIENT_STATE_DATA:
            if (len >= (sizeof(DATA)-1) && strncasecmp((const char*)data, DATA, sizeof(DATA)-1) == 0)
            {
                data += (sizeof(DATA)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MESSAGE;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(RCPTTO)-1) && strncasecmp((const char*)data, RCPTTO, sizeof(RCPTTO)-1) == 0)
            {
                data += (sizeof(RCPTTO)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            break;
        case SMTP_CLIENT_STATE_MESSAGE:
            if (*data == '.')
            {
                if (len == 0 ||
                    (len >= 1 && data[1] == '\n') ||
                    (len >= 2 && data[1] == '\r' && data[2] == '\n'))
                {
                    smtp_client_mod.api->add_app(asd, APP_ID_SMTP, APP_ID_SMTP, nullptr);
                    goto done;
                }
            }
            else if (len >= (sizeof(XMAILER)-1) && strncasecmp((const char*)data, XMAILER, sizeof(XMAILER)-1) == 0)
            {
                data += (sizeof(XMAILER)-1)-1;
                fd->state = SMTP_CLIENT_STATE_GET_PRODUCT_VERSION;
            }
            else if (len >= (sizeof(USERAGENT)-1) && strncasecmp((const char*)data, USERAGENT, sizeof(USERAGENT)-1) == 0)
            {
                data += (sizeof(USERAGENT)-1)-1;
                fd->state = SMTP_CLIENT_STATE_GET_PRODUCT_VERSION;
            }
            else if (!isprint(*data) && *data != '\t')
                goto done;
            else
            {
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            break;

        case SMTP_CLIENT_STATE_GET_PRODUCT_VERSION:
            if (*data == '\r')
            {
                if (fd->headerline && fd->pos)
                {
                    IdentifyClientVersion(fd, fd->headerline, fd->headerline + fd->pos, asd, pkt);
                    snort_free(fd->headerline);
                    fd->headerline = nullptr;
                    fd->pos = 0;
                }
                goto done;
            }
            else if (!isprint(*data))
            {
                snort_free(fd->headerline);
                fd->headerline = nullptr;
                fd->pos = 0;
                goto done;
            }
            else
            {
                if (!fd->headerline)
                    fd->headerline = (uint8_t*)snort_alloc(MAX_HEADER_LINE_SIZE);

                if (fd->pos < (MAX_HEADER_LINE_SIZE-1))
                    fd->headerline[fd->pos++] = *data;
            }
            break;

        case SMTP_CLIENT_STATE_SKIP_LINE:
            if (*data == '\n')
            {
                fd->pos = 0;
                fd->state = fd->nextstate;
                fd->nextstate = SMTP_CLIENT_STATE_NONE;
            }
            else if (!(*data == '\r' || isprint(*data)))
                goto done;
            break;

        default:
            goto done;
        }
    }
    return CLIENT_APP_INPROCESS;

done:
    dd->need_continue = 0;
    asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    return CLIENT_APP_SUCCESS;
}

static inline int smtp_validate_reply(const uint8_t*data, uint16_t* offset, uint16_t size,
    int* multi, int* code)
{
    const ServiceSMTPCode* code_hdr;
    int tmp;

    // Trim any blank lines (be a little tolerant)
    for (; *offset<size; (*offset)++)
    {
        if (data[*offset] != 0x0D && data[*offset] != 0x0A)
            break;
    }

    if (size - *offset < (int)sizeof(ServiceSMTPCode))
    {
        for (; *offset<size; (*offset)++)
        {
            if (!isspace(data[*offset]))
                return -1;
        }
        return 0;
    }

    code_hdr = (ServiceSMTPCode* )(data + *offset);

    if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
        return -1;
    tmp = (code_hdr->code[0] - '0') * 100;

    if (code_hdr->code[1] < '0' || code_hdr->code[1] > '5')
        return -1;
    tmp += (code_hdr->code[1] - '0') * 10;

    if (!isdigit(code_hdr->code[2]))
        return -1;
    tmp += code_hdr->code[2] - '0';

    if (*multi && tmp != *code)
        return -1;
    *code = tmp;
    if (code_hdr->sp == '-') *multi = 1;
    else if (code_hdr->sp == ' ')
        *multi = 0;
    else
        return -1;

    // We have a valid code, now we need to see if the rest of the line is okay
    *offset += sizeof(ServiceSMTPCode);
    for (; *offset < size; (*offset)++)
    {
        if (data[*offset] == 0x0D)
        {
            (*offset)++;
            if (*offset >= size)
                return -1;
            if (data[*offset] != 0x0A)
                return -1;
        }

        if (data[*offset] == 0x0A)
        {
            if (*multi)
            {
                if ((*offset + 1) >= size)
                    return 0;

                if (size - (*offset + 1) < (int)sizeof(ServiceSMTPCode))
                    return -1;

                code_hdr = (ServiceSMTPCode*)(data + *offset + 1);

                if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
                    return -1;
                tmp = (code_hdr->code[0] - '0') * 100;

                if (code_hdr->code[1] < '1' || code_hdr->code[1] > '5')
                    return -1;
                tmp += (code_hdr->code[1] - '0') * 10;

                if (!isdigit(code_hdr->code[2]))
                    return -1;
                tmp += code_hdr->code[2] - '0';

                if (tmp != *code)
                    return -1;

                if (code_hdr->sp == ' ') *multi = 0;
                else if (code_hdr->sp != '-')
                    return -1;

                *offset += sizeof(ServiceSMTPCode);
            }
            else
            {
                (*offset)++;
                return *code;
            }
        }
        else if (!isprint(data[*offset]))
            return -1;
    }

    return 0;
}

static int smtp_svc_validate(ServiceValidationArgs* args)
{
    SMTPDetectorData* dd;
    ServiceSMTPData* fd;
    AppIdSession* asd = args->asd;
    const uint8_t* data = args->data;
    uint16_t size = args->size;
    uint16_t offset;

    if (!(dd = smtp_get_SMTPDetectorData(asd)))
        return SERVICE_ENOMEM;

    if (!size)
        goto inprocess;

    asd->clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);

    // Whether this is bound for the client detector or not, if client doesn't care
    //  then clear the APPID_SESSION_CONTINUE flag and we will be done sooner.
    if (dd->need_continue == 0)
    {
        dd->need_continue--; // don't come through again.
        asd->clear_session_flags(APPID_SESSION_CONTINUE);
        if (dd->client.flags & CLIENT_FLAG_SMTPS)
        {
            // client side gave up because everything is encrypted.
            smtp_service_mod.api->add_service(asd, args->pkt, args->dir, &svc_element,
                                       APP_ID_SMTPS, nullptr, nullptr, nullptr);
            return SERVICE_SUCCESS;
        }
        else if (asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED))
        {
            // Client made it's decision so we are totally done.
            return SERVICE_SUCCESS;
        }
        // We arrive here because the service side is not done yet.
    }

    if (args->dir != APP_ID_FROM_RESPONDER)
        goto inprocess; // allow client validator to have it's shot.

    if (dd->watch_for_deprecated_port)
    {
        dd->watch_for_deprecated_port = 0;
        // If we have caught a response on port 465 that isn't encrypted+decrypted it isn't SMTP at all.
        // The new IANA assignment for this port is non-SSL and NOT SMTP. Only an old server will survive the test.
        if (args->pkt->ptrs.sp == SMTPS_DEPRECATED_PORT && !asd->get_session_flags(APPID_SESSION_DECRYPTED))
        {
            // This is not an SMTPS port because we have not ALREADY gone through the SSL handshake
            goto fail;
        }
    }

    fd = &dd->server;

    offset = 0;
    while (offset < size)
    {
        if (smtp_validate_reply(data, &offset, size, &fd->multiline, &fd->code) < 0)
        {
            if (!(dd->client.flags & CLIENT_FLAG_STARTTLS_SUCCESS))
                goto fail;
            goto inprocess;
        }
        if (!fd->code) goto inprocess;
        switch (fd->state)
        {
        case SMTP_SERVICE_STATE_CONNECTION:
            switch (fd->code)
            {
            case 220:
                fd->state = SMTP_SERVICE_STATE_HELO;
                break;
            case 421:
                if (service_strstr(data, size, (const uint8_t*)SMTP_CLOSING_CONN, sizeof(SMTP_CLOSING_CONN)-1))
                    goto success;
            case 520:
            case 554:
                fd->state = SMTP_SERVICE_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case SMTP_SERVICE_STATE_HELO:
            switch (fd->code)
            {
            case 250:
                fd->state = SMTP_SERVICE_STATE_TRANSFER;
                break;
            case 500:
            case 501:
            case 504:
                break;
            case 421:
            case 553:
                fd->state = SMTP_SERVICE_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case SMTP_SERVICE_STATE_STARTTLS:
            // success or fail, return client to connection-complete state.
            dd->client.state = SMTP_CLIENT_STATE_HELO;
            fd->state = SMTP_SERVICE_STATE_HELO;
            if (fd->code == 220)
            {
                asd->set_session_flags(APPID_SESSION_ENCRYPTED);
                // Now we wonder if the decryption mechanism is in place, so...
                dd->client.flags |= CLIENT_FLAG_STARTTLS_SUCCESS;
                dd->client.decryption_countdown = SSL_WAIT_PACKETS; // start a countdown
                goto inprocess;
            }
            /* STARTTLS failed. */
            break;
        case SMTP_SERVICE_STATE_TRANSFER:
            goto success;
        case SMTP_SERVICE_STATE_CONNECTION_ERROR:
        default:
            goto fail;
        }
    }

inprocess:
    smtp_service_mod.api->service_inprocess(asd, args->pkt, args->dir, &svc_element);
    return SERVICE_INPROCESS;

success:
    if (dd->need_continue > 0)
        asd->set_session_flags(APPID_SESSION_CONTINUE);

    smtp_service_mod.api->add_service(asd, args->pkt, args->dir, &svc_element,
                                      APP_ID_SMTP, nullptr, nullptr, nullptr);
    if (!fd->detected)
    {
        if(fd->state == SMTP_SERVICE_STATE_STARTTLS)
            appid_stats.smtps_flows++;
        else
            appid_stats.smtp_flows++;
        fd->detected = true;
    }
    return SERVICE_SUCCESS;

fail:
    smtp_service_mod.api->fail_service(asd, args->pkt, args->dir, &svc_element,
                                       smtp_service_mod.flow_data_index);
    return SERVICE_NOMATCH;
}
