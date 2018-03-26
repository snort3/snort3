//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

/* pp_ftp.c
 *
 * Purpose:  FTP sessions contain commands and responses.  Certain
 *           commands are vectors of attack.  This module checks
 *           those FTP client commands and their parameter values, as
 *           well as the server responses per the configuration.
 *
 * Arguments:  None
 *
 * Effect:  Alerts may be raised
 *
 * Comments:
 *
 */

/* your preprocessor header file goes here */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_ftp.h"

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "file_api/file_service.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "ft_main.h"
#include "ftp_bounce_lookup.h"
#include "ftp_cmd_lookup.h"
#include "ftp_module.h"
#include "ftpp_return_codes.h"
#include "pp_telnet.h"

using namespace snort;

#ifndef MAXHOSTNAMELEN /* Why doesn't Windows define this? */
#define MAXHOSTNAMELEN 256
#endif

static THREAD_LOCAL DataBuffer DecodeBuffer;

/*
 * Used to keep track of pipelined commands and the last one
 * that resulted in a
 */
static THREAD_LOCAL int ftp_cmd_pipe_index = 0;

/*
 * Function: getIP959(char **ip_start,
 *                 char *last_char,
 *                 char term_char,
 *                 uint32_t *ipRet,
 *                 uint16_t *portRet)
 *
 * Purpose: Returns a 32bit IP address and port from an RFC 959 FTP-style
 *          string -- ie, a,b,c,d,p1,p2.  Stops checking when term_char
 *          is seen.  Used to get address and port information from FTP
 *          PORT command and server response to PASV command.
 *
 * Arguments ip_start        => Pointer to pointer to the start of string.
 *                              Updated to end of IP address if successful.
 *           last_char       => End of string
 *           term_char       => Character delimiting the end of the address.
 *           ipRet           => Return pointer to 32bit address on success
 *           portRet         => Return pointer to 16bit port on success
 *
 * Returns: int => return code indicating error or success
 */
static int getIP959(
    const char** ip_start, const char* last_char, const char* term_char,
    SfIp* ipRet, uint16_t* portRet
    )
{
    uint32_t ip=0;
    uint16_t port=0;
    int octet=0;
    const char* this_param = *ip_start;
    do
    {
        int value = 0;
        do
        {
            if (!isdigit((int)(*this_param)))
            {
                return FTPP_NON_DIGIT;
            }
            value = value * 10 + (*this_param - '0');
            this_param++;
        }
        while ((this_param < last_char) &&
            (*this_param != ',') &&
            (strchr(term_char, *this_param) == nullptr));
        if (value > 0xFF)
        {
            return FTPP_INVALID_ARG;
        }
        if (octet  < 4)
        {
            ip = (ip << 8) + value;
        }
        else
        {
            port = (port << 8) + value;
        }

        if (strchr(term_char, *this_param) == nullptr)
            this_param++;
        octet++;
    }
    while ((this_param < last_char) && (strchr(term_char, *this_param) == nullptr));

    if (octet != 6)
    {
        return FTPP_MALFORMED_IP_PORT;
    }

    ip = htonl(ip);
    ipRet->set(&ip, AF_INET);
    *portRet = port;
    *ip_start = this_param;

    return FTPP_SUCCESS;
}

/*
 * getIP1639() parses the LPRT command parameters which have this
 * format (ftyp == e_long_host_port):
 *
 *     LPRT af,hal,h1,h2,h3,h4...,pal,p1,p2...
 *     LPRT 4,4,132,235,1,2,2,24,131
 *     LPRT 6,16,16,128,0,...,0,8,128,0,32,12,65,123,2,20,162
 *
 * (The above examples correspond to the EPRT examples below.)
 *
 * af (address family) is the IP version.  h# and p# are in network
 * byte order (high byte first).
 *
 * This function is called for the LPSV response as well, which
 * has this format:
 *
 *    228 <human readable text> (af,hal,h1,h2,h3,h4...,pal,p1,p2...)
 */
static int getIP1639(
    const char** ip_start, const char* last_char, const char*,
    SfIp* ipRet, uint16_t* portRet
    )
{
    char bytes[21];  /* max of 1+5+3 and 1+17+3 */
    const char* tok = *ip_start;
    unsigned nBytes = 0;
    bytes[0] = 0;

    /* first we just try to get a sequence of csv bytes */
    while ( nBytes < sizeof(bytes) && tok < last_char )
    {
        char* endPtr;
        unsigned long val = strtoul(tok, &endPtr, 10);

        if (
            val > 255 || endPtr == tok ||
            ( *endPtr && *endPtr != ',' && endPtr != last_char )
            )
        {
            return FTPP_INVALID_ARG;
        }
        bytes[nBytes++] = (uint8_t)val;
        tok = (endPtr < last_char) ? endPtr + 1 : endPtr;
    }
    *ip_start = tok;

    /* now we check that the we have a valid sequence of
       bytes and convert the address and port accordingly */
    switch ( bytes[0] )
    {
    case 4:
        if ( nBytes != 9 || bytes[1] != 4 || bytes[6] != 2 )
            return FTPP_INVALID_ARG;
        {
            uint32_t ip4_addr = 0;
            int n;
            for ( n = 0; n < 4; n++ )
                ip4_addr = (ip4_addr << 8) | bytes[n+2];
            /* don't call sfip set() on raw bytes
               to avoid possible word alignment issues */
            ip4_addr = htonl(ip4_addr);
            ipRet->set((void*)&ip4_addr, AF_INET);
        }
        *portRet = (bytes[7] << 8) | bytes[8];
        break;

    case 6:
        if ( nBytes != 21 || bytes[1] != 16 || bytes[18] != 2 )
            return FTPP_INVALID_ARG;

        ipRet->set(bytes+2, AF_INET6);
        *portRet = (bytes[19] << 8) | bytes[20];
        break;
    default:
        return FTPP_INVALID_ARG;
    }
    return FTPP_SUCCESS;
}

/*
 * getIP2428() parses the EPRT command parameters which have this
 * format (ftyp == e_extd_host_port):
 *
 *     EPRT |<family>|address|<tcp-port>|
 *     EPRT |1|132.235.1.2|6275|
 *     EPRT |2|1080::8:800:200C:417A|5282|
 *
 * Note that the address family is 1|2 (as in RFC 2428), not 4|6
 * (as in IP version), nor 2|10 (as in AF_INET[6]).
 *
 * This function is called for the EPSV response as well, which
 * has this format (ftyp == e_int):
 *
 *     229 <human readable text> (|||<tcp-port>|)
 *
 * The delimiter may be other than '|' if required to represent
 * the protocol address, but must be between 33-126 inclusive.
 * Other delimiters aren't required for IPv{4,6} but we allow
 * them for flexibility.
 *
 * It is assumed that *ip_start points to the first delimiter in
 * both cases.
 */

/*
 * this copy is unfortunate but inet_pton() doesn't
 * like the delim and the src buf is const so ...
 */
static void CopyField(
    char* buf, const char* tok, int max, const char* end, char delim
    )
{
    int len = end - tok + 1;
    char* s;

    if ( len >= max )
    {
        strncpy(buf, tok, max);
        buf[max-1] = '\0';
    }
    else
    {
        strncpy(buf, tok, len);
        buf[len] = '\0';
    }
    s = strchr(buf, delim);

    if ( s )
        *s = '\0';
    else
        *buf = '\0';
}

static int getIP2428(
    const char** ip_start, const char* last_char, const char*,
    SfIp* ipRet, uint16_t* portRet, FTP_PARAM_TYPE ftyp
    )
{
    const char* tok = *ip_start;
    char delim = *tok;
    int field = 1, fieldMask = 0;
    int family = AF_UNSPEC, port = 0;
    char buf[64];

    ipRet->clear();
    *portRet = 0;

    /* check first delimiter */
    if ( delim < 33 || delim > 126 )
        return FTPP_INVALID_ARG;

    while ( tok && tok < last_char && field < 4 )
    {
        int check = (*++tok != delim) ? field : 0;

        switch ( check )
        {
        case 0:      /* empty */
            break;

        case 1:      /* check family */
            family = atoi(tok);
            if ( family == 1 )
                family = AF_INET;
            else if ( family == 2 )
                family = AF_INET6;
            else
                return FTPP_INVALID_ARG;
            fieldMask |= 1;
            break;

        case 2:      /* check address */
            CopyField(buf, tok, sizeof(buf), last_char, delim);
            if ( ipRet->set(buf) != SFIP_SUCCESS || family != ipRet->get_family() )
                return FTPP_INVALID_ARG;

            fieldMask |= 2;
            break;

        case 3:      /* check port */
            port = atoi(tok);
            if ( port < 0 || port > MAX_PORTS-1 )
                return FTPP_MALFORMED_IP_PORT;
            *portRet = port;
            fieldMask |= 4;
            break;
        }
        /* advance to next field */
        tok = strchr(tok, delim);
        field++;
    }

    if (tok)
    {
        if ( *tok == delim )
            tok++;
        *ip_start = tok;
    }
    else
    {
        *ip_start = last_char;
    }

    if ( ftyp == e_int && fieldMask == 4 )
        /* TBD: do we need to check for bounce if addr present? */
        return FTPP_SUCCESS;

    if ( ftyp == e_extd_host_port && fieldMask == 7 )
        return FTPP_SUCCESS;

    return FTPP_INVALID_ARG;
}

static int getFTPip(
    FTP_PARAM_TYPE ftyp, const char** ip_start, const char* last_char,
    const char* term_char, SfIp* ipRet, uint16_t* portRet
    )
{
    if ( ftyp == e_host_port )
    {
        return getIP959(ip_start, last_char, term_char, ipRet, portRet);
    }
    if ( ftyp == e_long_host_port )
    {
        return getIP1639(ip_start, last_char, term_char, ipRet, portRet);
    }
    return getIP2428(ip_start, last_char, term_char, ipRet, portRet, ftyp);
}

/*
 * Function: validate_date_format(
 *                            FTP_DATE_FMT *ThisFmt,
 *                            char **this_param)
 *
 * Purpose: Recursively determines whether a date matches the
 *          a valid format.
 *
 * Arguments: ThisFmt        => Pointer to the current format
 *            this_param     => Pointer to start of the portion to validate.
 *                              Updated to end of valid section if valid.
 *
 * Returns: int => return code indicating error or success
 *
 */
static int validate_date_format(FTP_DATE_FMT* ThisFmt, const char** this_param)
{
    int valid_string = 0;
    int checked_something_else = 0;
    int checked_next = 0;
    int iRet = FTPP_ALERT;
    const char* curr_ch;
    if (!ThisFmt)
        return FTPP_INVALID_ARG;

    if (!this_param || !(*this_param))
        return FTPP_INVALID_ARG;

    curr_ch = *this_param;
    if (!ThisFmt->empty)
    {
        char* format_char = ThisFmt->format_string;

        do
        {
            switch (*format_char)
            {
            case 'n':
                if (!isdigit((int)(*curr_ch)))
                {
                    /* Return for non-digit */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            case 'C':
                if (!isalpha((int)(*curr_ch)))
                {
                    /* Return for non-char */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            default:
                if (*curr_ch != *format_char)
                {
                    /* Return for non-matching char */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            }
            valid_string = 1;
        }
        while ((*format_char != '\0') && !isspace((int)(*curr_ch)));

        if ((*format_char != '\0') && isspace((int)(*curr_ch)))
        {
            /* Didn't have enough chars to complete this format */
            return FTPP_INVALID_DATE;
        }
    }

    if ((ThisFmt->optional) && !isspace((int)(*curr_ch)))
    {
        const char* tmp_ch = curr_ch;
        iRet = validate_date_format(ThisFmt->optional, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
            curr_ch = tmp_ch;
    }
    if ((ThisFmt->next_a) && !isspace((int)(*curr_ch)))
    {
        const char* tmp_ch = curr_ch;
        checked_something_else = 1;
        iRet = validate_date_format(ThisFmt->next_a, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
        {
            curr_ch = tmp_ch;
        }
        else if (ThisFmt->next_b)
        {
            iRet = validate_date_format(ThisFmt->next_b, &tmp_ch);
            if (iRet == FTPP_SUCCESS)
                curr_ch = tmp_ch;
        }
        if (ThisFmt->next)
        {
            iRet = validate_date_format(ThisFmt->next, &tmp_ch);
            if (iRet == FTPP_SUCCESS)
            {
                curr_ch = tmp_ch;
                checked_next = 1;
            }
        }
        if (iRet == FTPP_SUCCESS)
        {
            *this_param = curr_ch;
            return iRet;
        }
    }
    if ((!checked_next) && (ThisFmt->next))
    {
        const char* tmp_ch = curr_ch;
        checked_something_else = 1;
        iRet = validate_date_format(ThisFmt->next, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
        {
            curr_ch = tmp_ch;
            checked_next = 1;
        }
    }

    if ((isspace((int)(*curr_ch))) && ((!ThisFmt->next) || checked_next))
    {
        *this_param = curr_ch;
        return FTPP_SUCCESS;
    }

    if (valid_string)
    {
        int all_okay = 0;
        if (checked_something_else)
        {
            if (iRet == FTPP_SUCCESS)
                all_okay = 1;
        }
        else
        {
            all_okay = 1;
        }

        if (all_okay)
        {
            *this_param = curr_ch;
            return FTPP_SUCCESS;
        }
    }

    return FTPP_INVALID_DATE;
}

/*
 * Function: validate_param(
 *                            Packet *p
 *                            char *param
 *                            char *end
 *                            FTP_PARAM_FMT *param_format,
 *                            FTP_SESSION *session)
 *
 * Purpose: Validates the current parameter against the format
 *          specified.
 *
 * Arguments: p              => Pointer to the current packet
 *            params_begin   => Pointer to beginning of parameters
 *            params_end     => End of params buffer
 *            param_format   => Parameter format specifier for this command
 *            session        => Pointer to the session info
 *
 * Returns: int => return code indicating error or success
 *
 */
static int validate_param(Packet* p,
    const char* param,
    const char* end,
    FTP_PARAM_FMT* ThisFmt,
    FTP_SESSION* session)
{
    int iRet;
    const char* this_param = param;

    if (param > end)
        return FTPP_ALERT;

    switch (ThisFmt->type)
    {
    case e_head:
        /* shouldn't get here, but just in case
           this hack is because we do get here! */
        this_param--;
        break;
    case e_unrestricted:
        /* strings/filenames only occur as the last param,
         * so move to the end of the param buffer. */
        this_param = end;
        break;
    case e_strformat:
        /* Check for 2 % signs within the parameter for an FTP command
         * 2 % signs is the magic number per existing rules (24 Sep 2004)
         */
#define MAX_PERCENT_SIGNS 2
        {
            int numPercents = 0;
            do
            {
                if (*this_param == '%')
                {
                    numPercents++;
                    if (numPercents >= MAX_PERCENT_SIGNS)
                    {
                        break;
                    }
                }
                this_param++;
            }
            while ((this_param < end) &&
                (*this_param != '\n'));

            if (numPercents >= MAX_PERCENT_SIGNS)
            {
                /* Alert on string format attack in parameter */
                DetectionEngine::queue_event(GID_FTP, FTP_PARAMETER_STR_FORMAT);
                return FTPP_ALERTED;
            }
        }
        break;
    case e_int:
        /* check that this_param is all digits up to next space */
    {
        do
        {
            if (!isdigit((int)(*this_param)))
            {
                /* Alert on non-digit */
                return FTPP_INVALID_PARAM;
            }
            this_param++;
        }
        while ((this_param < end) && (*this_param != ' ') );
    }
    break;
    case e_number:
        /* check that this_param is all digits up to next space
         * and value is between 1 & 255 */
    {
        int iValue = 0;
        do
        {
            if (!isdigit((int)(*this_param)))
            {
                /* Alert on non-digit */
                return FTPP_INVALID_PARAM;
            }
            iValue = iValue * 10 + (*this_param - '0');
            this_param++;
        }
        while ((this_param < end) && (*this_param != ' ') );

        if ((iValue > 255) || (iValue == 0))
            return FTPP_INVALID_PARAM;
    }
    break;
    case e_char:
        /* check that this_param is one of chars specified */
    {
        int bitNum = (*this_param & 0x1f);
        if (!isalpha((int)(*this_param)))
        {
            /* Alert on non-char */
            return FTPP_INVALID_PARAM;
        }
        else
        {
            if (!(ThisFmt->format.chars_allowed & (1 << (bitNum-1))) )
            {
                /* Alert on unexpected char */
                return FTPP_INVALID_PARAM;
            }
        }
        this_param++;     /* should be a space */
    }
    break;
    case e_date:
        /* check that this_param conforms to date specified */
    {
        const char* tmp_ch = this_param;
        iRet = validate_date_format(ThisFmt->format.date_fmt, &tmp_ch);
        if (iRet != FTPP_SUCCESS)
        {
            /* Alert invalid date */
            return FTPP_INVALID_PARAM;
        }
        if (!isspace((int)(*tmp_ch)))
        {
            /* Alert invalid date -- didn't make it to end of parameter.
            Overflow attempt? */
            return FTPP_INVALID_PARAM;
        }
        this_param = tmp_ch;
    }
    break;
    case e_literal:
        /* check that this_param matches the literal specified */
    {
        const char* s = ThisFmt->format.literal;
        size_t n = strlen(s);

        if ( strncmp(this_param, s, n) )
        {
            /* Alert on non-char */
            return FTPP_INVALID_PARAM;
        }
        this_param += n;
    }
    break;
    /* check that this_param is:  */
    case e_host_port:       /* PORT: h1,h2,h3,h4,p1,p2    */
    case e_long_host_port:  /* LPRT: af,hal,h1,h2,h3,h4...,pal,p1,p2... */
    case e_extd_host_port:  /* EPRT: |<af>|<addr>|<port>| */
    {
        SfIp ipAddr;
        uint16_t port=0;

        int ret = getFTPip(
            ThisFmt->type, &this_param, end, " \n", &ipAddr, &port
            );
        switch (ret)
        {
        case FTPP_NON_DIGIT:
            /* Alert on non-digit */
            return FTPP_INVALID_PARAM;
        case FTPP_INVALID_ARG:
            /* Alert on number > 255 */
            return FTPP_INVALID_PARAM;
        case FTPP_MALFORMED_IP_PORT:
            /* Alert on malformed host-port */
            return FTPP_INVALID_PARAM;
        }

        if ( ThisFmt->type == e_extd_host_port && !ipAddr.is_set() )
        {
            // actually, we expect no addr in 229 responses, which is
            // understood to be server address, so we set that here
            ipAddr = *p->ptrs.ip_api.get_src();
        }
        if ( session->client_conf->bounce )
        {
            if (!ipAddr.equals(*p->ptrs.ip_api.get_src()))
            {
                int alert = 1;

                FTP_BOUNCE_TO* BounceTo = ftp_bounce_lookup_find(
                    session->client_conf->bounce_lookup, &ipAddr, &iRet);
                if (BounceTo)
                {
                    if (BounceTo->portlo)
                    {
                        if (BounceTo->porthi)
                        {
                            if ((port >= BounceTo->portlo) &&
                                (port <= BounceTo->porthi))
                                alert = 0;
                        }
                        else
                        {
                            if (port == BounceTo->portlo)
                                alert = 0;
                        }
                    }
                }

                /* Alert on invalid IP address for PORT */
                if (alert)
                {
                    DetectionEngine::queue_event(GID_FTP, FTP_BOUNCE);
                    /* Return here -- because we will likely want to
                     * inspect the data traffic over a bounced data
                     * connection */
                    return FTPP_PORT_ATTACK;
                }
            }
        }

        session->clientIP = ipAddr;
        session->clientPort = port;
        session->data_chan_state |= DATA_CHAN_PORT_CMD_ISSUED;
        if (session->data_chan_state & DATA_CHAN_PASV_CMD_ISSUED)
        {
            /*
             * If there was a PORT command previously in
             * a series of pipelined requests, this
             * cancels it.
             */
            session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
        }

        session->serverIP.clear();
        session->serverPort = 0;
    }
    break;
    }

    ThisFmt->next_param = this_param;

    return FTPP_SUCCESS;
}

/*
 * Function: check_ftp_param_validity(
 *                            Packet *p,
 *                            char *params_begin,
 *                            char *params_end,
 *                            FTP_PARAM_FMT *param_format,
 *                            FTP_SESSION *session)
 *
 * Purpose: Recursively determines whether each of the parameters for
 *          an FTP command are valid.
 *
 * Arguments: p              => Pointer to the current packet
 *            params_begin   => Pointer to beginning of parameters
 *            params_end     => End of params buffer
 *            param_format   => Parameter format specifier for this command
 *            session        => Pointer to the session info
 *
 * Returns: int => return code indicating error or success
 *
 */
static int check_ftp_param_validity(Packet* p,
    const char* params_begin,
    const char* params_end,
    FTP_PARAM_FMT* param_format,
    FTP_SESSION* session)
{
    int iRet = FTPP_ALERT;
    FTP_PARAM_FMT* ThisFmt = param_format;
    FTP_PARAM_FMT* NextFmt;
    const char* this_param = params_begin;

    if (!param_format)
        return FTPP_INVALID_ARG;

    if (!params_begin && !ThisFmt->next_param_fmt && ThisFmt->optional_fmt)
        return FTPP_SUCCESS;  /* no param is allowed in this case */

    if (!params_begin && (ThisFmt->next_param_fmt && ThisFmt->next_param_fmt->type == e_strformat))
        return FTPP_SUCCESS;  /* string format check of non existent param */

    if (!params_begin)
        return FTPP_INVALID_ARG;

    if ((!ThisFmt->next_param_fmt) && (params_begin >= params_end))
        return FTPP_SUCCESS;

    ThisFmt->next_param = params_begin;

    if (ThisFmt->optional_fmt)
    {
        /* Check against optional */
        iRet = validate_param(p, this_param, params_end,
            ThisFmt->optional_fmt, session);
        if (iRet == FTPP_SUCCESS)
        {
            const char* next_param;
            NextFmt = ThisFmt->optional_fmt;
            next_param = NextFmt->next_param+1;
            iRet = check_ftp_param_validity(p, next_param, params_end,
                NextFmt, session);
            if (iRet == FTPP_SUCCESS)
            {
                this_param = NextFmt->next_param+1;
            }
        }
    }

    if ((iRet != FTPP_SUCCESS) && (ThisFmt->choices))
    {
        /* Check against choices -- one of many */
        int i;
        int valid = 0;
        for (i=0; i<ThisFmt->numChoices && !valid; i++)
        {
            /* Try choice [i] */
            iRet = validate_param(p, this_param, params_end,
                ThisFmt->choices[i], session);
            if (iRet == FTPP_SUCCESS)
            {
                const char* next_param;
                NextFmt = ThisFmt->choices[i];
                next_param = NextFmt->next_param+1;
                iRet = check_ftp_param_validity(p, next_param, params_end,
                    NextFmt, session);
                if (iRet == FTPP_SUCCESS)
                {
                    this_param = NextFmt->next_param+1;
                    break;
                }
            }
        }
    }
    else if ((iRet != FTPP_SUCCESS) && (ThisFmt->next_param_fmt))
    {
        /* Check against next param */
        iRet = validate_param(p, this_param, params_end,
            ThisFmt->next_param_fmt, session);
        if (iRet == FTPP_SUCCESS)
        {
            const char* next_param;
            NextFmt = ThisFmt->next_param_fmt;
            next_param = NextFmt->next_param+1;
            iRet = check_ftp_param_validity(p, next_param, params_end,
                NextFmt, session);
            if (iRet == FTPP_SUCCESS)
            {
                this_param = NextFmt->next_param+1;
            }
        }
    }
    else if ((iRet != FTPP_SUCCESS) && (!ThisFmt->next_param_fmt) &&
        this_param)
    {
        iRet = FTPP_SUCCESS;
    }
    if (iRet == FTPP_SUCCESS)
    {
        ThisFmt->next_param = this_param;
    }
    return iRet;
}

/*
 * Function: initialize_ftp(FTP_SESSION *session, Packet *p, int iMode)
 *
 * Purpose: Initializes the state machine for checking an FTP packet.
 *          Does normalization checks.
 *
 * Arguments: session        => Pointer to session info
 *            p              => pointer to the current packet struct
 *            iMode          => Mode indicating server or client checks
 *
 * Returns: int => return code indicating error or success
 *
 */
int initialize_ftp(FTP_SESSION* session, Packet* p, int iMode)
{
    int iRet;
    const unsigned char* read_ptr = p->data;
    FTP_CLIENT_REQ* req;
    char ignoreTelnetErase = FTPP_APPLY_TNC_ERASE_CMDS;

    /* Normalize this packet ala telnet */
    if (((iMode == FTPP_SI_CLIENT_MODE) &&
        session->client_conf->ignore_telnet_erase_cmds) ||
        ((iMode == FTPP_SI_SERVER_MODE) &&
        session->server_conf->ignore_telnet_erase_cmds) )
        ignoreTelnetErase = FTPP_IGNORE_TNC_ERASE_CMDS;

    iRet = normalize_telnet(nullptr, p, iMode, ignoreTelnetErase);

    if (iRet != FTPP_SUCCESS && iRet != FTPP_NORMALIZED)
    {
        if (iRet == FTPP_ALERT)
            DetectionEngine::queue_event(GID_FTP, FTP_EVASIVE_TELNET_CMD);

        return iRet;
    }

    if ( DecodeBuffer.len )
    {
        /* Normalized data will always be in decode buffer */
        if ( (iMode == FTPP_SI_CLIENT_MODE) ||
            (iMode == FTPP_SI_SERVER_MODE) )
        {
            DetectionEngine::queue_event(GID_FTP, FTP_TELNET_CMD);
            return FTPP_ALERT; /* Nothing else to do since we alerted */
        }

        read_ptr = DecodeBuffer.data;
    }

    if (iMode == FTPP_SI_CLIENT_MODE)
        req = &session->client.request;
    else if (iMode == FTPP_SI_SERVER_MODE)
    {
        FTP_SERVER_RSP* rsp = &session->server.response;
        req = (FTP_CLIENT_REQ*)rsp;
    }
    else
        return FTPP_INVALID_ARG;

    /* Set the beginning of the pipeline to the start of the
     * (normalized) buffer */
    req->pipeline_req = (const char*)read_ptr;

    return FTPP_SUCCESS;
}

/*
 * Function: do_stateful_checks(FTP_SESSION *session, Packet *p,
 *                            FTP_CLIENT_REQ *req, int rsp_code)
 *
 * Purpose: Handle stateful checks and state updates for FTP response
 *          packets.
 *
 * Arguments: session        => Pointer to session info
 *            p              => Pointer to the current packet struct
 *            req            => Pointer to current response from packet
 *                              (this function may be called multiple
 *                              times for pipelined requests).
 *            rsp_code       => Integer response value for server response
 *
 * Returns: int => return code indicating error or success
 *
 */
// FIXIT-M X Expected flow operations are using hardcoded TCP PktType/IpProtocol,
//      which could that bite us on the mythical FTP over UDP or SCTP?
static int do_stateful_checks(FTP_SESSION* session, Packet* p,
    FTP_CLIENT_REQ* req, int rsp_code)
{
    int iRet = FTPP_SUCCESS;

    //if (session->server_conf->data_chan)
    {
        if (rsp_code == 226)
        {
            /* Just ignore this code -- end of transfer...
             * If we saw all the other dat for this channel
             * session->data_chan_state should be NO_STATE. */
        }
        else if (session->data_chan_state & DATA_CHAN_PASV_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == session->data_chan_index)
            {
                if (session->data_xfer_index == -1)
                    ftp_cmd_pipe_index = 0;
                session->data_chan_index = -1;

                if ( rsp_code >= 227 && rsp_code <= 229 )
                {
                    SfIp ipAddr;
                    uint16_t port=0;
                    const char* ip_begin = req->param_begin;
                    ipAddr.clear();
                    session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
                    session->data_chan_state |= DATA_CHAN_PASV_CMD_ACCEPT;
                    session->data_chan_index = -1;
                    /* Interpret response message to identify the
                     * Server IP/Port.  Server response is inside
                     * a pair of ()s.  Find the left (, and use same
                     * means to find IP/Port as is done for the PORT
                     * command. */
                    if (req->param_size != 0)
                    {
                        while ((ip_begin < req->param_end) &&
                            (*ip_begin != '('))
                        {
                            ip_begin++;
                        }
                    }

                    if (ip_begin < req->param_end)
                    {
                        FTP_PARAM_TYPE ftyp =
                            /* e_int is used in lieu of adding a new value to the
                             * enum because this case doesn't correspond to a
                             * validation config option; it could effectively be
                             * replaced with an additional bool arg to getFTPip() that
                             * differentiated between commands and responses, but
                             * this distinction is only required for EPSV rsps. */
                            (rsp_code == 229) ? e_int :
                            (rsp_code == 228 ? e_long_host_port : e_host_port);

                        ip_begin++;
                        iRet = getFTPip(
                            ftyp, &ip_begin, req->param_end, ")", &ipAddr, &port
                            );
                        if (iRet == FTPP_SUCCESS)
                        {
                            if (!ipAddr.is_set())
                                session->serverIP.set(*p->ptrs.ip_api.get_src());
                            else
                            {
                                session->serverIP = ipAddr;
                            }
                            session->serverPort = port;
                            session->clientIP.set(*p->ptrs.ip_api.get_dst());
                            session->clientPort = 0;

                            if ((FileService::get_max_file_depth() > 0) ||
                                !(session->server_conf->data_chan))
                            {
                                FtpDataFlowData* fd = new FtpDataFlowData(p);
                                FTP_DATA_SESSION* ftpdata = &fd->session;

                                int result;
                                /* This is a passive data transfer */
                                ftpdata->mode = FTPP_XFER_PASSIVE;
                                ftpdata->data_chan = session->server_conf->data_chan;
                                if (session->flags & FTP_FLG_MALWARE)
                                    session->datassn = ftpdata;

                                /* Call into Streams to mark data channel as ftp-data */
                                result = Stream::set_snort_protocol_id_expected(
                                    p, PktType::TCP, IpProtocol::TCP,
                                    &session->clientIP, session->clientPort,
                                    &session->serverIP, session->serverPort,
                                    ftp_data_snort_protocol_id, fd);

                                if (result < 0)
                                {
                                    delete fd;
                                    session->datassn = nullptr;
                                }
                            }
                            else if (session->server_conf->data_chan)
                            {
                                /* Call into Streams to mark data channel as something
                                 * to ignore. */
                                Stream::ignore_flow(
                                    p, PktType::TCP, IpProtocol::TCP,
                                    &session->clientIP, session->clientPort,
                                    &session->serverIP, session->serverPort,
                                    SSN_DIR_BOTH, FtpDataFlowData::inspector_id);
                            }
                        }
                    }
                    else
                    {
                        iRet = FTPP_MALFORMED_FTP_RESPONSE;
                    }
                }
                else
                {
                    session->data_chan_index = -1;
                    session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
                }
            }
        }
        else if (session->data_chan_state & DATA_CHAN_PORT_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == session->data_chan_index)
            {
                if (session->data_xfer_index == -1)
                    ftp_cmd_pipe_index = 0;
                session->data_chan_index = -1;
                if (rsp_code == 200)
                {
                    session->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                    session->data_chan_state |= DATA_CHAN_PORT_CMD_ACCEPT;
                    session->data_chan_index = -1;
                    if (session->clientIP.is_set())
                    {
                        /* This means we're not in passive mode. */
                        /* Server is listening/sending from its own IP,
                         * FTP Port -1 */
                        /* Client IP, Port specified via PORT command */
                        session->serverIP.set(*p->ptrs.ip_api.get_src());

                        /* Can't necessarily guarantee this, especially
                         * in the case of a proxy'd connection where the
                         * data channel might not be on port 20 (or server
                         * port-1).  Comment it out for now.
                         */
                        /*
                        session->serverPort = ntohs(p->ptrs.tcph->th_sport) -1;
                        */
                        if ((FileService::get_max_file_depth() > 0) ||
                            !(session->server_conf->data_chan))
                        {
                            FtpDataFlowData* fd = new FtpDataFlowData(p);
                            FTP_DATA_SESSION* ftpdata = &fd->session;

                            int result;
                            /* This is a active data transfer */
                            ftpdata->mode = FTPP_XFER_ACTIVE;
                            ftpdata->data_chan = session->server_conf->data_chan;
                            if (session->flags & FTP_FLG_MALWARE)
                                session->datassn = ftpdata;

                            /* Call into Streams to mark data channel as ftp-data */
                            result = Stream::set_snort_protocol_id_expected(
                                p, PktType::TCP, IpProtocol::TCP,
                                &session->clientIP, session->clientPort,
                                &session->serverIP, session->serverPort,
                                ftp_data_snort_protocol_id, fd);

                            if (result < 0)
                            {
                                delete fd;
                                session->datassn = nullptr;
                            }
                        }
                        else if (session->server_conf->data_chan)
                        {
                            /* Call into Streams to mark data channel as something
                             * to ignore. */
                            Stream::ignore_flow(
                                p, PktType::TCP, IpProtocol::TCP,
                                &session->clientIP, session->clientPort,
                                &session->serverIP, session->serverPort,
                                SSN_DIR_BOTH, FtpDataFlowData::inspector_id);
                        }
                    }
                }
                else if (ftp_cmd_pipe_index == session->data_chan_index)
                {
                    session->data_chan_index = -1;
                    session->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                }
            }
        }
        else if (session->data_chan_state & DATA_CHAN_REST_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == session->data_xfer_index)
            {
                if (session->data_chan_index == 0)
                    ftp_cmd_pipe_index = 1;
                session->data_xfer_index = 0;
                if (rsp_code == 350)
                {
                    FTP_DATA_SESSION *ftpdata = (FTP_DATA_SESSION*)session->datassn;

                    if ((session->flags & FTP_FLG_MALWARE) && ftpdata)
                    {
                        ftpdata->packet_flags |= FTPDATA_FLG_REST;
                        session->datassn = nullptr;
                    }
                }
                session->data_chan_index = 0;
                session->data_chan_state &= ~DATA_CHAN_REST_CMD_ISSUED;
            }
        }
        else if (session->data_chan_state & DATA_CHAN_XFER_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == session->data_xfer_index)
            {
                if (session->data_chan_index == -1)
                    ftp_cmd_pipe_index = 0;

                session->data_xfer_index = -1;

                if ((rsp_code == 150) || (rsp_code == 125))
                    session->data_chan_state = DATA_CHAN_XFER_STARTED;

                /* Clear the session info for next transfer -->
                 * reset host/port */
                session->serverIP.clear();
                session->clientIP.clear();
                session->serverPort = session->clientPort = 0;
                session->datassn = nullptr;

                session->data_chan_state = NO_STATE;
            }
        }
    } /* if (session->server_conf->data_chan) */

    if (session->server_conf->detect_encrypted)
    {
        switch (session->encr_state)
        {
        case AUTH_TLS_CMD_ISSUED:
            if (rsp_code == 234)
            {
                /* Could check that response msg includes "TLS" */
                session->encr_state = AUTH_TLS_ENCRYPTED;
                DetectionEngine::queue_event(GID_FTP, FTP_ENCRYPTED);
            }
            break;
        case AUTH_SSL_CMD_ISSUED:
            if (rsp_code == 234)
            {
                /* Could check that response msg includes "SSL" */
                session->encr_state = AUTH_SSL_ENCRYPTED;
                DetectionEngine::queue_event(GID_FTP, FTP_ENCRYPTED);
            }
            break;
        case AUTH_UNKNOWN_CMD_ISSUED:
            if (rsp_code == 234)
            {
                session->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                DetectionEngine::queue_event(GID_FTP, FTP_ENCRYPTED);
            }
            break;
        }
    }

    return iRet;
}

/*
 * Function: check_ftp(FTP_SESSION *session, Packet *p, int iMode)
 *
 * Purpose: Handle some trivial validation checks of an FTP packet.  Namely,
 *          check argument length and some protocol enforcement.
 *
 *          Wishful: This results in exposing the FTP command (and looking
 *          at the results) to the rules layer.
 *
 * Arguments: session        => Pointer to session info
 *            p              => pointer to the current packet struct
 *            iMode          => Mode indicating server or client checks
 *
 * Returns: int => return code indicating error or success
 *
 */
#define NUL 0x00
#define CR 0x0d
#define LF 0x0a
#define SP 0x20
#define DASH 0x2D

#define FTP_CMD_OK 0
#define FTP_CMD_INV 1
#define FTP_RESPONSE_INV 1
#define FTP_RESPONSE 2
#define FTP_RESPONSE_2BCONT 2
#define FTP_RESPONSE_CONT   3
#define FTP_RESPONSE_ENDCONT 4

int check_ftp(FTP_SESSION* ftpssn, Packet* p, int iMode)
{
    int iRet = FTPP_SUCCESS;
    int encrypted = 0;
    int space = 0;
    int rsp_code = 0;
    FTP_CLIENT_REQ* req;
    FTP_CMD_CONF* CmdConf = nullptr;

    const unsigned char* end = p->data + p->dsize;

    if ( DecodeBuffer.len )
        end = DecodeBuffer.data + DecodeBuffer.len;

    if (iMode == FTPP_SI_CLIENT_MODE)
    {
        req = &ftpssn->client.request;
        ftp_cmd_pipe_index = 0;
    }
    else if (iMode == FTPP_SI_SERVER_MODE)
    {
        FTP_SERVER_RSP* rsp = &ftpssn->server.response;
        req = (FTP_CLIENT_REQ*)rsp;
    }
    else
        return FTPP_INVALID_ARG;

    while (req->pipeline_req)
    {
        long state = FTP_CMD_OK;

        /* Starts at the beginning of the buffer/line, so next up is a command */
        const unsigned char* read_ptr = (const unsigned char*)req->pipeline_req;

        /* but first we ignore leading white space */
        while ( (read_ptr < end) &&
            (iMode == FTPP_SI_CLIENT_MODE) && isspace(*read_ptr) )
            read_ptr++;

        // ignore extra \r\n emitted by some clients
        if ( read_ptr == end )
            break;

        req->cmd_begin = (const char*)read_ptr;

        while ((read_ptr < end) &&
            (*read_ptr != SP) &&
            (*read_ptr != CR) &&
            (*read_ptr != LF) &&    /* Check for LF when there wasn't a CR,
                                     * protocol violation, but accepted by
                                     * some servers. */
            (*read_ptr != DASH))
        {
            /* If the first char is a digit this is a response
             * in server mode. */
            if (iMode == FTPP_SI_SERVER_MODE)
            {
                if (isdigit(*read_ptr))
                {
                    if (state != FTP_RESPONSE_INV)
                    {
                        state = FTP_RESPONSE;
                    }
                }
                else if (!isascii(*read_ptr))
                {
                    /* Non-ascii char here?  Bad response */
                    state = FTP_RESPONSE_INV;
                }
            }
            /* Or, if this is not a char, this is garbage in client mode */
            else if (!isalpha(*read_ptr) && (iMode == FTPP_SI_CLIENT_MODE))
            {
                state = FTP_CMD_INV;
            }

            read_ptr++;
        }
        req->cmd_end = (const char*)read_ptr;
        req->cmd_size = req->cmd_end - req->cmd_begin;

        if (iMode == FTPP_SI_CLIENT_MODE)
        {
            if ( (req->cmd_size > ftpssn->server_conf->max_cmd_len)
                || (req->cmd_size < MIN_CMD)
                || (state == FTP_CMD_INV) )
            {
                /* Uh, something is very wrong...
                 * nonalpha char seen or cmd is bad length.
                 * See if this might be encrypted, ie, non-alpha bytes. */
                const unsigned char* ptr = (const unsigned char*)req->cmd_begin;
                while (ptr < (const unsigned char*)req->cmd_end)
                {
                    if (!isalpha((int)(*ptr)))
                    {
                        if (!isascii((int)(*ptr)) || !isprint((int)(*ptr)))
                        {
                            encrypted = 1;
                        }
                        break;
                    }
                    ptr++;
                }
            }

            if (encrypted)
            {
                /* If the session wasn't already marked as encrypted...
                 * Don't want to double-alert if we've already
                 * determined the session is encrypted and we're
                 * checking encrypted sessions.
                 */
                if (ftpssn->encr_state == 0)
                {
                    ftpssn->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                    DetectionEngine::queue_event(GID_FTP, FTP_ENCRYPTED);

                    if (!ftpssn->server_conf->check_encrypted_data)
                    {
                        /* Mark this session & packet as one to ignore */
                        Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
                    }
                }
                break;
            }
            else
            {
                /*
                 * Check the list of valid FTP commands as
                 * supplied in ftpssn.
                 */
                if ( req->cmd_size > ftpssn->server_conf->max_cmd_len )
                {
                    /* Alert, cmd not found */
                    DetectionEngine::queue_event(GID_FTP, FTP_INVALID_CMD);
                    state = FTP_CMD_INV;
                }
                else
                {
                    CmdConf = ftp_cmd_lookup_find(ftpssn->server_conf->cmd_lookup,
                        req->cmd_begin,
                        req->cmd_size,
                        &iRet);
                    if ((iRet == FTPP_NOT_FOUND) || (CmdConf == nullptr))
                    {
                        /* Alert, cmd not found */
                        DetectionEngine::queue_event(GID_FTP, FTP_INVALID_CMD);
                        state = FTP_CMD_INV;
                    }
                    else
                    {
                        /* In case we were encrypted, but aren't now */
                        ftpssn->encr_state = 0;
                    }
                }
            }
        }
        else if (iMode == FTPP_SI_SERVER_MODE)
        {
            if (state == FTP_CMD_INV)
                state = FTP_RESPONSE_INV;

            if ( (req->cmd_size != 3) || (state == FTP_RESPONSE_INV) )
            {
                /* Uh, something is very wrong...
                 * nondigit char seen or resp code is not 3 chars.
                 * See if this might be encrypted, ie, non-alpha bytes. */
                const char* ptr = req->cmd_begin;
                while (ptr < req->cmd_end)
                {
                    if (!isdigit((int)(*ptr)))
                    {
                        if (!isascii((int)(*ptr)) || !isprint((int)(*ptr)))
                        {
                            encrypted = 1;
                        }
                        break;
                    }
                    ptr++;
                }
            }

            if (encrypted)
            {
                /* If the session wasn't already marked as encrypted...
                 * Don't want to double-alert if we've already
                 * determined the session is encrypted and we're
                 * checking encrypted sessions.
                 */
                if (ftpssn->encr_state == 0)
                {
                    ftpssn->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                    DetectionEngine::queue_event(GID_FTP, FTP_ENCRYPTED);

                    if (!ftpssn->server_conf->check_encrypted_data)
                    {
                        /* Mark this session & packet as one to ignore */
                        Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
                    }
                }
                break;
            }
            else
            {
                /* In case we were encrypted, but aren't now */
                if ((ftpssn->encr_state == AUTH_TLS_ENCRYPTED) ||
                    (ftpssn->encr_state == AUTH_SSL_ENCRYPTED) ||
                    (ftpssn->encr_state == AUTH_UNKNOWN_ENCRYPTED))
                {
                    ftpssn->encr_state = 0;
                }

                /* Otherwise, might have an encryption command pending */
            }

            if (read_ptr < end)
            {
                if (*read_ptr != DASH)
                {
                    const unsigned char* resp_begin = (const unsigned char*)req->cmd_begin;
                    const unsigned char* resp_end = (const unsigned char*)req->cmd_end;
                    if (resp_end - resp_begin >= 3)
                    {
                        if (isdigit(*(resp_begin)) &&
                            isdigit(*(resp_begin+1)) &&
                            isdigit(*(resp_begin+2)) )
                        {
                            rsp_code = ( (*(resp_begin) - '0') * 100 +
                                (*(resp_begin+1) - '0') * 10 +
                                (*(resp_begin+2) - '0') );
                            if (rsp_code == ftpssn->server.response.state)
                            {
                                /* End of continued response */
                                state = FTP_RESPONSE_ENDCONT;
                                ftpssn->server.response.state = 0;
                            }
                            else
                            {
                                /* Single line response */
                                state = FTP_RESPONSE;
                            }
                        }
                    }

                    if (ftpssn->server.response.state != 0)
                    {
                        req->cmd_begin = nullptr;
                        req->cmd_end = nullptr;
                        if (*read_ptr != SP)
                            read_ptr--;
                        state = FTP_RESPONSE_CONT;
                    }
                }
                else if ((state == FTP_RESPONSE) && (*read_ptr == DASH))
                {
                    const unsigned char* resp_begin = (const unsigned char*)req->cmd_begin;
                    if (isdigit(*(resp_begin)) &&
                        isdigit(*(resp_begin+1)) &&
                        isdigit(*(resp_begin+2)) )
                    {
                        int resp_code = ( (*(resp_begin) - '0') * 100 +
                            (*(resp_begin+1) - '0') * 10 +
                            (*(resp_begin+2) - '0') );
                        if (resp_code == ftpssn->server.response.state)
                        {
                            /* Continuation of previous response */
                            state = FTP_RESPONSE_CONT;
                        }
                        else
                        {
                            /* Start of response, state stays as -2 */
                            state = FTP_RESPONSE_2BCONT;
                            ftpssn->server.response.state = resp_code;
                            rsp_code = resp_code;
                        }
                    }
                    else
                    {
                        ftpssn->server.response.state = FTP_RESPONSE_INV;
                    }
                }
            }
        }

        if (read_ptr < end)
        {
            if (*read_ptr == SP)
            {
                space = 1;
            }

            read_ptr++; /* Move past the space, dash, or CR */
        }

        /* If there is anything left... */

        if (read_ptr < end)
        {
            /* Look for an LF --> implies no parameters/message */
            if (*read_ptr == LF)
            {
                read_ptr++;
                req->param_begin = nullptr;
                req->param_end = nullptr;
            }
            else if (space || ftpssn->server.response.state != 0)
            {
                /* Now grab the command parameters/response message
                 * read_ptr < end already checked */
                req->param_begin = (const char*)read_ptr;
                if ((read_ptr = (unsigned char*)memchr(read_ptr, CR, end - read_ptr)) == nullptr)
                    read_ptr = end;
                req->param_end = (const char*)read_ptr;
                read_ptr++;

                if (read_ptr < end)
                {
                    /* Cool, got the end of the parameters, move past
                     * the LF, so we can process the next one in
                     * the pipeline.
                     */
                    if (*read_ptr == LF)
                        read_ptr++;
                }
            }
        }
        else
        {
            /* Nothing left --> no parameters/message.  Not even an LF */
            req->param_begin = nullptr;
            req->param_end = nullptr;
        }

        /* Set the pointer for the next request/response
         * in the pipeline. */
        if (read_ptr < end)
            req->pipeline_req = (const char*)read_ptr;
        else
            req->pipeline_req = nullptr;

        req->param_size = req->param_end - req->param_begin;
        switch (state)
        {
        case FTP_CMD_INV:
            iRet = FTPP_ALERT;
            break;
        case FTP_RESPONSE: /* Response */
            if ((ftpssn->client_conf->max_resp_len > 0) &&
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                DetectionEngine::queue_event(GID_FTP, FTP_RESPONSE_LENGTH_OVERFLOW);
                iRet = FTPP_ALERT;
            }

            {
                int newRet = do_stateful_checks(ftpssn, p, req, rsp_code);
                if (newRet != FTPP_SUCCESS)
                    iRet = newRet;
            }
            break;
        case FTP_RESPONSE_CONT: /* Response continued */
            if ((ftpssn->client_conf->max_resp_len > 0) &&
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                DetectionEngine::queue_event(GID_FTP, FTP_RESPONSE_LENGTH_OVERFLOW);
                iRet = FTPP_ALERT;
            }
            break;
        case FTP_RESPONSE_ENDCONT: /* Continued response end */
            if ((ftpssn->client_conf->max_resp_len > 0) &&
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                DetectionEngine::queue_event(GID_FTP, FTP_RESPONSE_LENGTH_OVERFLOW);
                iRet = FTPP_ALERT;
            }
            break;
        default:
            if (CmdConf)
            {
                unsigned max = CmdConf->max_param_len;
                if ( !max )
                    max = ftpssn->server_conf->def_max_param_len;

                if ( req->param_size > max )
                {
                    /* Alert on param length overrun */
                    DetectionEngine::queue_event(GID_FTP, FTP_PARAMETER_LENGTH_OVERFLOW);
                    iRet = FTPP_ALERT;
                }

                if (CmdConf->data_chan_cmd)
                {
                    ftpssn->data_chan_state |= DATA_CHAN_PASV_CMD_ISSUED;
                    ftpssn->data_chan_index = ftp_cmd_pipe_index;
                    if (ftpssn->data_chan_state & DATA_CHAN_PORT_CMD_ISSUED)
                    {
                        /*
                         * If there was a PORT command previously in
                         * a series of pipelined requests, this
                         * cancels it.
                         */
                        ftpssn->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                    }
                }
                else if ((ftpssn->flags & FTP_FLG_MALWARE) && CmdConf->data_rest_cmd)
                {
                    if ((req->param_begin != nullptr) && (req->param_size > 0))
                    {
                        char *return_ptr = nullptr;
                        errno = 0;
                        unsigned long offset = strtoul(req->param_begin, &return_ptr, 10);
                        if ((errno == ERANGE || errno == EINVAL) || (offset > 0))
                        {
                            ftpssn->data_chan_state |= DATA_CHAN_REST_CMD_ISSUED;
                            ftpssn->data_xfer_index = ftp_cmd_pipe_index;
                        }
                    }
                }
                else if (CmdConf->data_xfer_cmd)
                {
                    /* If we are not ignoring the data channel OR file processing is enabled */
                    if (!ftpssn->server_conf->data_chan || (FileService::get_max_file_depth() > -1))
                    {
                        /* The following  check cleans up filename  for failed data
                         * transfers.  If  the  transfer had  been  successful  the
                         * filename  pointer  would have  been  handed  off to  the
                         * FTP_DATA_SESSION for tracking. */
                        if (ftpssn->filename)
                        {
                            snort_free(ftpssn->filename);
                            ftpssn->filename = nullptr;
                            ftpssn->file_xfer_info = FTPP_FILE_IGNORE;
                        }

                        // Get the file name and set direction of the get/put request.
                        // Request could have been sent without parameters, i.e. filename,
                        // so make sure something is there.
                        if (((req->param_begin != nullptr) && (req->param_size > 0))
                            && (CmdConf->file_get_cmd || CmdConf->file_put_cmd))
                        {
                            ftpssn->filename = (char*)snort_alloc(req->param_size+1);
                            memcpy(ftpssn->filename, req->param_begin, req->param_size);
                            ftpssn->filename[req->param_size] = '\0';
                            ftpssn->file_xfer_info = req->param_size;

                            // 0 for Download, 1 for Upload
                            ftpssn->data_xfer_dir = CmdConf->file_get_cmd ? false : true;
                        }
                        else
                        {
                            ftpssn->file_xfer_info = FTPP_FILE_IGNORE;
                        }
                    }
                    ftpssn->data_chan_state |= DATA_CHAN_XFER_CMD_ISSUED;
                    ftpssn->data_xfer_index = ftp_cmd_pipe_index;
                }
                else if (CmdConf->encr_cmd)
                {
                    if (req->param_begin && (req->param_size > 0) &&
                        ((req->param_begin[0] == 'T') || (req->param_begin[0] == 't')))
                    {
                        ftpssn->encr_state = AUTH_TLS_CMD_ISSUED;
                    }
                    else if (req->param_begin && (req->param_size > 0) &&
                        ((req->param_begin[0] == 'S') || (req->param_begin[0] == 's')))
                    {
                        ftpssn->encr_state = AUTH_SSL_CMD_ISSUED;
                    }
                    else
                    {
                        ftpssn->encr_state = AUTH_UNKNOWN_CMD_ISSUED;
                    }
                }
                if (CmdConf->check_validity)
                {
                    iRet = check_ftp_param_validity(p, req->param_begin,
                        req->param_end, CmdConf->param_format,
                        ftpssn);
                    /* If negative, haven't already alerted on violation */
                    if (iRet < 0)
                    {
                        /* Set Alert on malformatted parameter */
                        DetectionEngine::queue_event(GID_FTP, FTP_MALFORMED_PARAMETER);
                        iRet = FTPP_ALERT;
                        break;
                    }
                    else if (iRet > 0)
                    {
                        /* Already alerted -- ie, string format attack. */
                        break;
                    }
                }
            }
            break;
        }

        if (iMode == FTPP_SI_CLIENT_MODE)
            ftp_cmd_pipe_index++;
        else if ((rsp_code != 226) && (rsp_code != 426))
        {
            /*
             * In terms of counting responses, ignore
             * 226 response saying transfer complete
             * 426 response saying transfer aborted
             * The 226 may or may not be sent by the server.
             * Both are 2nd response to a transfer command.
             */
            ftp_cmd_pipe_index++;
        }
    }

    if (iMode == FTPP_SI_CLIENT_MODE)
    {
        ftp_cmd_pipe_index = 0;
    }

    if (encrypted)
        return FTPP_ALERT;

    return iRet;
}

