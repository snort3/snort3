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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_smtp.h"

#include "application_ids.h"
#include "app_info_table.h"
#include "protocols/packet.h"

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
    SMTP_CLIENT_STATE_STARTTLS,
    SMTP_CLIENT_STATE_LOGIN_USER,
    SMTP_CLIENT_STATE_LOGIN_PASSWORD
};

#define MAX_HEADER_LINE_SIZE 1024

/* flag values for ClientSMTPData */
#define CLIENT_FLAG_STARTTLS_SUCCESS    0x01

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
};

struct SMTPDetectorData
{
    ClientSMTPData client;
    ServiceSMTPData server;
    int need_continue;
};

#define HELO "HELO "
#define EHLO "EHLO "
#define MAILFROM "MAIL FROM:"
#define RCPTTO "RCPT TO:"
#define DATA "DATA"
#define RSET "RSET"
#define AUTH_PLAIN "AUTH PLAIN"
#define AUTH_LOGIN "AUTH LOGIN"
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

static SmtpClientDetector* smtp_client_detector;

SmtpClientDetector::SmtpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SMTP";
    proto = IpProtocol::TCP;
    minimum_matches = 1;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)HELO, sizeof(HELO)-1, -1, 0, APP_ID_SMTP },
        { (const uint8_t*)EHLO, sizeof(EHLO)-1, -1, 0, APP_ID_SMTP },
        { APP_SMTP_OUTLOOK,         sizeof(APP_SMTP_OUTLOOK)-1,        -1, 0, APP_ID_OUTLOOK },
        { APP_SMTP_OUTLOOK_EXPRESS, sizeof(APP_SMTP_OUTLOOK_EXPRESS)-1,-1, 0, APP_ID_OUTLOOK_EXPRESS },
        { APP_SMTP_IMO,             sizeof(APP_SMTP_IMO)-1,            -1, 0, APP_ID_SMTP_IMO },
        { APP_SMTP_EVOLUTION,       sizeof(APP_SMTP_EVOLUTION)-1,      -1, 0, APP_ID_EVOLUTION },
        { APP_SMTP_LOTUS_NOTES,      sizeof(APP_SMTP_LOTUS_NOTES)-1,   -1, 0, APP_ID_LOTUS_NOTES },
        { APP_SMTP_APPLEMAIL,       sizeof(APP_SMTP_APPLEMAIL)-1,      -1, 0, APP_ID_APPLE_EMAIL },
        { APP_SMTP_EUDORA,          sizeof(APP_SMTP_EUDORA)-1,         -1, 0, APP_ID_EUDORA },
        { APP_SMTP_EUDORAPRO,       sizeof(APP_SMTP_EUDORAPRO)-1,      -1, 0, APP_ID_EUDORA_PRO },
        { APP_SMTP_AOL,             sizeof(APP_SMTP_AOL)-1,            -1, 0, APP_ID_AOL_EMAIL },
        { APP_SMTP_MUTT,            sizeof(APP_SMTP_MUTT)-1,           -1, 0, APP_ID_MUTT },
        { APP_SMTP_KMAIL,           sizeof(APP_SMTP_KMAIL)-1,          -1, 0, APP_ID_KMAIL },
        { APP_SMTP_MTHUNDERBIRD,    sizeof(APP_SMTP_MTHUNDERBIRD)-1,   -1, 0, APP_ID_THUNDERBIRD },
        { APP_SMTP_THUNDERBIRD,     sizeof(APP_SMTP_THUNDERBIRD)-1,    -1, 0, APP_ID_THUNDERBIRD },
    };

    appid_registry =
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

    smtp_client_detector = this;
    handler->register_detector(name, this, proto);
}


/*
 *    product - The product data should not include any characters
 *              after the end of the product version (e.g. no CR, LF, etc).
 *    prefix_len - The number of characters that are the prefix to the version,
 *              including the NUL terminating character.
 */
// FIXIT-M - refactor this to reduce the number of function parameters
int SmtpClientDetector::extract_version_and_add_client_app(AppId clientId, const int prefix_len,
    const uint8_t* product, const uint8_t* product_end, ClientSMTPData* const client_data,
    AppIdSession& asd, AppId appId)
{
    uint8_t* v_end = client_data->version + MAX_VERSION_SIZE - 1;

    //  The prefix_len includes the NUL character, but product does not, so
    //  subtract 1 from length to skip.
    const uint8_t* p = product + prefix_len - 1;
    if (p >= product_end || isspace(*p))
        return 1;
    uint8_t* v;
    for (v = client_data->version; v < v_end && p < product_end; v++,p++)
        *v = *p;
    *v = 0;
    add_app(asd, appId, clientId, (char*)client_data->version);
    return 0;
}

/*
 *  Identify the product and version of the SMTP client.
 *
 *  Returns 0 if a recognized product is found.  Otherwise returns 1.
 */
int SmtpClientDetector::identify_client_version(ClientSMTPData* const fd, const uint8_t* product,
    const uint8_t* data_end, AppIdSession& asd, snort::Packet*)
{
    const uint8_t* p;
    AppId appId = APP_ID_SMTP;
    uint8_t* v_end = fd->version + MAX_VERSION_SIZE - 1;
    unsigned len = data_end - product;
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
                    2, p, data_end, fd, asd, appId);
            }
            else if (*p == ' ')
            {
                p++;
                if (data_end-p >= (int)sizeof(EXPRESS) && memcmp(p, EXPRESS, sizeof(EXPRESS)-1) == 0)
                {
                    return extract_version_and_add_client_app(APP_ID_OUTLOOK_EXPRESS,
                        sizeof(EXPRESS), p, data_end, fd, asd, appId);
                }
                else if (data_end-p >= (int)sizeof(IMO) && memcmp(p, IMO, sizeof(IMO)-1) == 0)
                {
                    return extract_version_and_add_client_app(APP_ID_OUTLOOK,
                        sizeof(IMO), p, data_end, fd, asd, appId);
                }
            }
        }
    }
    else if (len >= sizeof(APP_SMTP_EVOLUTION) && memcmp(product, APP_SMTP_EVOLUTION,
        sizeof(APP_SMTP_EVOLUTION)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EVOLUTION,
            sizeof(APP_SMTP_EVOLUTION), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_LOTUS_NOTES) && memcmp(product, APP_SMTP_LOTUS_NOTES,
        sizeof(APP_SMTP_LOTUS_NOTES)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_LOTUS_NOTES,
            sizeof(APP_SMTP_LOTUS_NOTES), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_APPLEMAIL) && memcmp(product, APP_SMTP_APPLEMAIL,
        sizeof(APP_SMTP_APPLEMAIL)-1) == 0)
    {
        p = product + sizeof(APP_SMTP_APPLEMAIL) - 1;
        if (p >= data_end || *(data_end - 1) != ')' || *p == ')' || isspace(*p))
            return 1;

        uint8_t* v;
        for (v = fd->version; v < v_end && p < data_end - 1; v++,p++)
        {
            *v = *p;
        }
        *v = 0;

        add_app(asd, appId, APP_ID_APPLE_EMAIL, (char*)fd->version);
        return 0;
    }
    else if (len >= sizeof(APP_SMTP_EUDORA) && memcmp(product, APP_SMTP_EUDORA,
        sizeof(APP_SMTP_EUDORA)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EUDORA,
            sizeof(APP_SMTP_EUDORA), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_EUDORAPRO) && memcmp(product, APP_SMTP_EUDORAPRO,
        sizeof(APP_SMTP_EUDORAPRO)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_EUDORA_PRO,
            sizeof(APP_SMTP_EUDORAPRO), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_AOL) && memcmp(product, APP_SMTP_AOL,
        sizeof(APP_SMTP_AOL)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_AOL_EMAIL,
            sizeof(APP_SMTP_AOL), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_MUTT) && memcmp(product, APP_SMTP_MUTT,
        sizeof(APP_SMTP_MUTT)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_MUTT,
            sizeof(APP_SMTP_MUTT), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_KMAIL) && memcmp(product, APP_SMTP_KMAIL,
        sizeof(APP_SMTP_KMAIL)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_KMAIL,
            sizeof(APP_SMTP_KMAIL), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_THUNDERBIRD) && memcmp(product, APP_SMTP_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
            sizeof(APP_SMTP_THUNDERBIRD), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_MTHUNDERBIRD) && memcmp(product, APP_SMTP_MTHUNDERBIRD,
        sizeof(APP_SMTP_MTHUNDERBIRD)-1) == 0)
    {
        return extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
            sizeof(APP_SMTP_MTHUNDERBIRD), product, data_end, fd, asd, appId);
    }
    else if (len >= sizeof(APP_SMTP_MOZILLA) && memcmp(product, APP_SMTP_MOZILLA,
        sizeof(APP_SMTP_MOZILLA)-1) == 0)
    {
        for (p = product + sizeof(APP_SMTP_MOZILLA) - 1; p < data_end; p++)
        {
            if (*p == 'T')
            {
                unsigned sublen = data_end - p;
                if (sublen >= sizeof(APP_SMTP_THUNDERBIRD_SHORT) && memcmp(p,
                    APP_SMTP_THUNDERBIRD_SHORT, sizeof(APP_SMTP_THUNDERBIRD_SHORT)-1) == 0)
                {
                    return extract_version_and_add_client_app(
                        APP_ID_THUNDERBIRD, sizeof(APP_SMTP_THUNDERBIRD_SHORT),
                        p, data_end, fd, asd, appId);
                }
            }
        }
    }

    return 1;
}

static void smtp_free_state(void* data)
{
    SMTPDetectorData* dd = (SMTPDetectorData*)data;
    if (dd)
    {
        ClientSMTPData* cd = &dd->client;
        if (cd->headerline)
            snort_free(cd->headerline);
        snort_free(dd);
    }
}

SMTPDetectorData* SmtpClientDetector::get_common_data(AppIdSession& asd)
{
    SMTPDetectorData* dd = (SMTPDetectorData*)data_get(asd);
    if (!dd)
    {
        dd = (SMTPDetectorData*)snort_calloc(1, sizeof(*dd));
        data_add(asd, dd, &smtp_free_state);
        dd->server.state = SMTP_SERVICE_STATE_CONNECTION;
        dd->client.state = SMTP_CLIENT_STATE_HELO;
        dd->need_continue = 1;
        asd.set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return dd;
}

int SmtpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    SMTPDetectorData* dd = get_common_data(args.asd);

    if ( !dd )
        return APPID_ENOMEM;

    if (args.dir != APP_ID_FROM_INITIATOR)
        return APPID_INPROCESS;

    ClientSMTPData* fd = &dd->client;
    if (args.asd.get_session_flags(APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED) == APPID_SESSION_ENCRYPTED)
    {
        if ((fd->flags & CLIENT_FLAG_STARTTLS_SUCCESS))
        {
            fd->decryption_countdown--;
            if (!fd->decryption_countdown)
            {
                /* Because we can't see any further info without decryption we settle for
                   plain APP_ID_SMTPS instead of perhaps finding data that would make calling
                   ExtractVersion() worthwhile, So set the appid and call it good. */
                add_app(args.asd, APP_ID_SMTPS, APP_ID_SMTPS, nullptr);
                goto done;
            }
        }
        return APPID_INPROCESS;
    }

    for (const uint8_t* end = args.data + args.size; args.data < end; args.data++)
    {
        unsigned len = end - args.data;
        switch (fd->state)
        {
        case SMTP_CLIENT_STATE_HELO:
            if (len >= (sizeof(HELO)-1) && strncasecmp((const char*)args.data, HELO, sizeof(HELO)-1) == 0)
            {
                args.data += (sizeof(HELO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MAIL_FROM;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
                fd->flags &= ~CLIENT_FLAG_STARTTLS_SUCCESS;
            }
            else if (len >= (sizeof(EHLO)-1) && strncasecmp((const char*)args.data, EHLO, sizeof(EHLO)-1) == 0)
            {
                args.data += (sizeof(EHLO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MAIL_FROM;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
                fd->flags &= ~CLIENT_FLAG_STARTTLS_SUCCESS;
            }
            else
                goto done;
            break;

        case SMTP_CLIENT_STATE_MAIL_FROM:
            if (len >= (sizeof(MAILFROM)-1) && strncasecmp((const char*)args.data, MAILFROM, sizeof(MAILFROM)-1) == 0)
            {
                args.data += (sizeof(MAILFROM)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_RCPT_TO;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(RSET)-1) && strncasecmp((const char*)args.data, RSET, sizeof(RSET)-1) == 0)
            {
                args.data += (sizeof(RSET)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(AUTH_PLAIN)-1) && strncasecmp((const char*)args.data, AUTH_PLAIN, sizeof(AUTH_PLAIN)-1) == 0)
            {
                args.data += (sizeof(AUTH_PLAIN)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(AUTH_LOGIN)-1) && strncasecmp((const char*)args.data, AUTH_LOGIN, sizeof(AUTH_LOGIN)-1) == 0)
            {
                args.data += (sizeof(AUTH_LOGIN)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_LOGIN_USER;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(STARTTLS)-1) && strncasecmp((const char*)args.data, STARTTLS, sizeof(STARTTLS)-1) == 0)
            {
                args.data += (sizeof(STARTTLS)-1)-1;
                dd->server.state = SMTP_SERVICE_STATE_STARTTLS;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            /* check for state reversion */
            else if (len >= (sizeof(HELO)-1) && strncasecmp((const char*)args.data, HELO, sizeof(HELO)-1) == 0)
            {
                args.data += (sizeof(HELO)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
                dd->server.state = SMTP_SERVICE_STATE_HELO; // make sure that service side expects
                                                            // the 250
            }
            else if (len >= (sizeof(EHLO)-1) && strncasecmp((const char*)args.data, EHLO, sizeof(EHLO)-1) == 0)
            {
                args.data += (sizeof(EHLO)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
                dd->server.state = SMTP_SERVICE_STATE_HELO; // make sure that service side expects
                                                            // the 250
            }
            else
                goto done;
            break;

        case SMTP_CLIENT_STATE_LOGIN_USER:
        {
            fd->nextstate = SMTP_CLIENT_STATE_LOGIN_PASSWORD;
            fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
        }
        break;

        case SMTP_CLIENT_STATE_LOGIN_PASSWORD:
        {
            fd->nextstate = SMTP_CLIENT_STATE_MAIL_FROM;
            fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
        }
        break;

        case SMTP_CLIENT_STATE_RCPT_TO:
            if (len >= (sizeof(RCPTTO)-1) && strncasecmp((const char*)args.data, RCPTTO, sizeof(RCPTTO)-1) == 0)
            {
                args.data += (sizeof(RCPTTO)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_DATA;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else
                goto done;
            break;

        case SMTP_CLIENT_STATE_DATA:
            if (len >= (sizeof(DATA)-1) && strncasecmp((const char*)args.data, DATA, sizeof(DATA)-1) == 0)
            {
                args.data += (sizeof(DATA)-1)-1;
                fd->nextstate = SMTP_CLIENT_STATE_MESSAGE;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            else if (len >= (sizeof(RCPTTO)-1) && strncasecmp((const char*)args.data, RCPTTO, sizeof(RCPTTO)-1) == 0)
            {
                args.data += (sizeof(RCPTTO)-1)-1;
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            break;
        case SMTP_CLIENT_STATE_MESSAGE:
            if (*args.data == '.')
            {
                if (len == 0 ||
                    (len >= 1 && args.data[1] == '\n') ||
                    (len >= 2 && args.data[1] == '\r' && args.data[2] == '\n'))
                {
                    add_app(args.asd, APP_ID_SMTP, APP_ID_SMTP, nullptr);
                    goto done;
                }
            }
            else if (len >= (sizeof(XMAILER)-1) && strncasecmp((const char*)args.data, XMAILER, sizeof(XMAILER)-1) == 0)
            {
                args.data += (sizeof(XMAILER)-1)-1;
                fd->state = SMTP_CLIENT_STATE_GET_PRODUCT_VERSION;
            }
            else if (len >= (sizeof(USERAGENT)-1) && strncasecmp((const char*)args.data, USERAGENT, sizeof(USERAGENT)-1) == 0)
            {
                args.data += (sizeof(USERAGENT)-1)-1;
                fd->state = SMTP_CLIENT_STATE_GET_PRODUCT_VERSION;
            }
            else if (!isprint(*args.data) && *args.data != '\t')
                goto done;
            else
            {
                fd->nextstate = fd->state;
                fd->state = SMTP_CLIENT_STATE_SKIP_LINE;
            }
            break;

        case SMTP_CLIENT_STATE_GET_PRODUCT_VERSION:
            if (*args.data == '\r')
            {
                if (fd->headerline && fd->pos)
                {
                    identify_client_version(fd, fd->headerline, fd->headerline + fd->pos, args.asd, args.pkt);
                    snort_free(fd->headerline);
                    fd->headerline = nullptr;
                    fd->pos = 0;
                }
                goto done;
            }
            else if (!isprint(*args.data))
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
                    fd->headerline[fd->pos++] = *args.data;
            }
            break;

        case SMTP_CLIENT_STATE_SKIP_LINE:
            if (*args.data == '\n')
            {
                fd->pos = 0;
                fd->state = fd->nextstate;
                fd->nextstate = SMTP_CLIENT_STATE_NONE;
            }
            else if (!(*args.data == '\r' || isprint(*args.data)))
                goto done;
            break;

        default:
            goto done;
        }
    }
    return APPID_INPROCESS;

done:
    dd->need_continue = 0;
    if(args.asd.get_session_flags(APPID_SESSION_SERVICE_DETECTED))
        args.asd.clear_session_flags(APPID_SESSION_CONTINUE | APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    else
        args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS); 
    args.asd.set_client_detected();
    return APPID_SUCCESS;
}

#define SMTP_PORT   25
#define SMTPS_DEPRECATED_PORT   465
#define SMTP_CLOSING_CONN "closing connection\x0d\x0a"

#pragma pack(1)

struct ServiceSMTPCode
{
    uint8_t code[3];
    uint8_t sp;
};

#pragma pack()

const char SMTP_PATTERN1[] = "220 ";
const char SMTP_PATTERN2[] = "220-";
const char SMTP_PATTERN3[] = "SMTP";
const char SMTP_PATTERN4[] = "smtp";

SmtpServiceDetector::SmtpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "smtp";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    tcp_patterns =
    {
        { (const uint8_t*)SMTP_PATTERN1, sizeof(SMTP_PATTERN1) - 1, -1, 0, 0 },
        { (const uint8_t*)SMTP_PATTERN2, sizeof(SMTP_PATTERN2) - 1, -1, 0, 0 },
        { (const uint8_t*)SMTP_PATTERN3, sizeof(SMTP_PATTERN3) - 1, -1, 0, 0 },
        { (const uint8_t*)SMTP_PATTERN4, sizeof(SMTP_PATTERN4) - 1, -1, 0, 0 },
    };

    appid_registry =
    {
        { APP_ID_SMTP,  APPINFO_FLAG_SERVICE_ADDITIONAL },
        { APP_ID_SMTPS, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { SMTP_PORT, IpProtocol::TCP, false },
        { SMTPS_DEPRECATED_PORT, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


static inline int smtp_validate_reply(const uint8_t* data, uint16_t* offset, uint16_t size,
    int* multi, int* code)
{
    // Trim any blank lines (be a little tolerant)
    for (; *offset < size; (*offset)++)
    {
        if (data[*offset] != 0x0D && data[*offset] != 0x0A)
            break;
    }

    if (size - *offset < (int)sizeof(ServiceSMTPCode))
    {
        for (; *offset < size; (*offset)++)
        {
            if (!isspace(data[*offset]))
                return -1;
        }
        return 0;
    }

    const ServiceSMTPCode* code_hdr = (const ServiceSMTPCode* )(data + *offset);

    if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5')
        return -1;
    int tmp = (code_hdr->code[0] - '0') * 100;

    if (code_hdr->code[1] < '0' || code_hdr->code[1] > '5')
        return -1;
    tmp += (code_hdr->code[1] - '0') * 10;

    if (!isdigit(code_hdr->code[2]))
        return -1;
    tmp += code_hdr->code[2] - '0';

    if (*multi && tmp != *code)
        return -1;
    *code = tmp;
    if (code_hdr->sp == '-')
        *multi = 1;
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

                code_hdr = (const ServiceSMTPCode*)(data + *offset + 1);

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

                if (code_hdr->sp == ' ')
                    *multi = 0;
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

int SmtpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    SMTPDetectorData* dd = smtp_client_detector->get_common_data(args.asd);
    if ( !dd )
        return APPID_ENOMEM;

    ServiceSMTPData* fd = &dd->server;
    uint16_t offset = 0;

    if (!args.size)
        goto inprocess;

    args.asd.clear_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);

    if (args.asd.get_session_flags(APPID_SESSION_SERVICE_DETECTED))
    {
        if(!dd->need_continue)
            args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_SUCCESS;
    }

    if (args.dir != APP_ID_FROM_RESPONDER)
        goto inprocess; // allow client validator to have it's shot.

    while (offset < args.size)
    {
        if (smtp_validate_reply(args.data, &offset, args.size, &fd->multiline, &fd->code) < 0)
        {
            if (!(dd->client.flags & CLIENT_FLAG_STARTTLS_SUCCESS))
                goto fail;
            goto inprocess;
        }
        if (!fd->code)
            goto inprocess;
        switch (fd->state)
        {
        case SMTP_SERVICE_STATE_CONNECTION:
            switch (fd->code)
            {
            case 220:
                fd->state = SMTP_SERVICE_STATE_HELO;
                break;
            case 421:
                if (service_strstr(args.data, args.size,
                    (const uint8_t*)SMTP_CLOSING_CONN, sizeof(SMTP_CLOSING_CONN)-1))
                    goto success;
                // fallthrough
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
            case 220:
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
                dd->client.flags |= CLIENT_FLAG_STARTTLS_SUCCESS;
                //FIXIT-M: FIXIT-M: Revisit SSL decryption countdown after isSSLPolicyEnabled() is ported.
                //Can we use Flow::is_proxied() here?
#if 0
                if (_dpd.isSSLPolicyEnabled(NULL))
#endif
                    dd->client.decryption_countdown = SSL_WAIT_PACKETS; // start a countdown
#if 0
                else
                    dd->client.decryption_countdown = 1
#endif

                add_service(args.asd, args.pkt, args.dir,  APP_ID_SMTPS);

                if(dd->need_continue > 0)
                    args.asd.set_session_flags(APPID_SESSION_ENCRYPTED | APPID_SESSION_STICKY_SERVICE | APPID_SESSION_CONTINUE);
                else
                    args.asd.set_session_flags(APPID_SESSION_ENCRYPTED | APPID_SESSION_STICKY_SERVICE);

                return APPID_SUCCESS;
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
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    if (dd->need_continue > 0)
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);

    return add_service(args.asd, args.pkt, args.dir,
        (fd->state == SMTP_SERVICE_STATE_STARTTLS) ? APP_ID_SMTPS : APP_ID_SMTP);

fail:
    fail_service(args.asd, args.pkt, args.dir);
    return APPID_NOMATCH;
}

