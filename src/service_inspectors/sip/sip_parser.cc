//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// sip_parser.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_parser.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "sip_module.h"
#include "sip_utils.h"

using namespace snort;

#define MAX_NUM_32BIT  2147483647

#define SIP_PARSE_NOFOLDING  (-2)
#define SIP_PARSE_ERROR      (-1)
#define SIP_PARSE_SUCCESS    (1)

/* Should at least have SIP/2.0 */
#define SIP_KEYWORD          "SIP/"
#define SIP_KEYWORD_LEN      4
#define SIP_VERSION_NUM_LEN  3  /*2.0 or 1.0 or 1.1*/
#define SIP_VERSION_LEN      (SIP_KEYWORD_LEN + SIP_VERSION_NUM_LEN)
#define SIP_MIN_MSG_LEN      SIP_VERSION_LEN

#define SIP_TAG_KEYWORD      "tag="
#define SIP_TAG_KEYWORD_LEN      4

static int sip_parse_via(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_from(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_to(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_call_id(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_user_agent(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_server(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_cseq(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_contact(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_authorization(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_content_type(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_content_len(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_parse_content_encode(SIPMsg*, const char*, const char*, SIP_PROTO_CONF*);
static int sip_process_headField(SIPMsg*, const char*, const char*, int*, SIP_PROTO_CONF*);
static int sip_process_bodyField(SIPMsg*, const char*, const char*);
static int sip_parse_sdp_o(SIPMsg*, const char*, const char*);
static int sip_parse_sdp_c(SIPMsg*, const char*, const char*);
static int sip_parse_sdp_m(SIPMsg*, const char*, const char*);

/*
 * Header fields and processing functions
 */
typedef struct _SIPheaderField
{
    const char* fname;
    int fnameLen;
    const char* shortName;
    int (* setfield)(SIPMsg*, const char*,const char*, SIP_PROTO_CONF*);
} SIPheaderField;

/*
 * Body fields and processing functions
 */
typedef struct _SIPbodyField
{
    const char* fname;
    int fnameLen;
    int (* setfield)(SIPMsg*, const char*,const char*);
} SIPbodyField;

/*
 * header field name, short form field name, and field processing function
 */

SIPheaderField headerFields[] =
{
    { "Via", 3, "v",  &sip_parse_via },
    { "From", 4,"f",  &sip_parse_from },
    { "To", 2, "t",  &sip_parse_to },
    { "Call-ID", 7, "i", &sip_parse_call_id },
    { "CSeq", 4, nullptr, &sip_parse_cseq },
    { "Contact", 7, "m", &sip_parse_contact },
    { "Authorization", 13, nullptr,  &sip_parse_authorization },
    { "Content-Type", 12, "c",  &sip_parse_content_type },
    { "Content-Length", 14, "l",  &sip_parse_content_len },
    { "Content-Encoding", 16, "e", &sip_parse_content_encode },
    { "User-Agent", 10, nullptr, &sip_parse_user_agent },
    { "Server", 6, nullptr, &sip_parse_server },
    { nullptr, 0, nullptr, nullptr }
};

/*
 * body field name, field processing function
 */

SIPbodyField bodyFields[] =
{
    { "o=", 2, &sip_parse_sdp_o },
    { "c=", 2, &sip_parse_sdp_c },
    { "m=", 2, &sip_parse_sdp_m },
    { nullptr, 0, nullptr }
};

/********************************************************************
 * Function: sip_process_headField()
 *
 * Process the header fields (lines). This also deals with folding.
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start - start of the header line
 *  char* end   - end of the header line
 *  int*        - index of last field processed. Used for folding processing
 *                This value will be updated after current field been processed
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_process_headField(SIPMsg* msg, const char* start, const char* end,
    int* lastFieldIndex, SIP_PROTO_CONF* config)
{
    int findex =0;
    int length = end -start;
    char* colonIndex;
    const char* newStart, * newEnd;
    char newLength;

    // If this is folding
    if ((' ' == start[0]) || ('\t' == start[0]))
    {
        if (SIP_PARSE_NOFOLDING != *lastFieldIndex)
        {
            SIP_TrimSP(start, end, &newStart, &newEnd);
            return(headerFields[*lastFieldIndex].setfield(msg, newStart, newEnd, config));
        }
    }
    // Otherwise, continue normal processing
    colonIndex = (char*)memchr(start, ':', length);

    if (!colonIndex || (colonIndex < start + 1))
        return SIP_PARSE_ERROR;

    if (!SIP_TrimSP(start, colonIndex, &newStart, &newEnd))
        return SIP_PARSE_ERROR;

    newLength =  newEnd - newStart;

    /*Find out whether the field name needs to process*/
    while (nullptr != headerFields[findex].fname)
    {
        //Use the full name to check
        if ((headerFields[findex].fnameLen == newLength)&&
            (0 == strncasecmp(headerFields[findex].fname, newStart, newLength)))
        {
            break;
        }
        //Use short name to check
        else if ((nullptr != headerFields[findex].shortName) &&
            ( 1 == newLength)&&
            (0 == strncasecmp(headerFields[findex].shortName, newStart, newLength)))
        {
            break;
        }
        findex++;
    }

    if (nullptr != headerFields[findex].fname)
    {
        // Found the field name, evaluate the value
        SIP_TrimSP(colonIndex + 1, end, &newStart, &newEnd);
        *lastFieldIndex = findex;
        return (headerFields[findex].setfield(msg, newStart, newEnd, config));
    }
    *lastFieldIndex = SIP_PARSE_NOFOLDING;
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_process_bodyField()
 *
 * Process the body fields.
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start - start of the line
 *  char* end   - end of the line
 *
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_process_bodyField(SIPMsg* msg, const char* start, const char* end)
{
    int findex =0;
    if (start == end)
        return SIP_PARSE_SUCCESS;
    /*Find out whether the field name needs to process*/
    while (nullptr != bodyFields[findex].fname)
    {
        int length = bodyFields[findex].fnameLen;
        if (0 == strncasecmp(bodyFields[findex].fname, start,length))
        {
            return (bodyFields[findex].setfield(msg,start + length, end));
        }

        findex++;
    }
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_find_linebreak()
 *
 * Find the line break \r \n in the current buffer
 *
 * Arguments:
 *  char* start - start of the buffer
 *  char* end   - end of the buffer
 *  char **lineEnd - output, point to the end of the line defined by line breaks
 * Returns:
 *  int - number of line breaks found in the line found.
 ********************************************************************/
static int sip_find_linebreak(const char* start, const char* end, const char** lineEnd)
{
    int numCRLF = 0;
    *lineEnd = nullptr;

    if (start >= end)
        return numCRLF;

    const char* s = start;

    while ((s < end) && !('\r' ==*s || '\n' == *s))
    {
        s++;
    }

    if (s == end)
        return numCRLF;

    s++;
    numCRLF = 1;

    if ((s < end) && ('\r' == s[-1]) && ('\n' == s[0]))
    {
        s++;
        numCRLF = 2;
    }

    *lineEnd= s;
    return numCRLF;
}

/********************************************************************
 * Function: sip_is_valid_version()
 *
 * Check whether the version is a valid version (2.0, 1.1, 1.0)
 *
 * Arguments:
 *  char* start - start of the version
 *
 * Returns:
 *   TRUE
 *   FALSE
 ********************************************************************/
static inline int sip_is_valid_version(const char* start)
{
    if (!strncmp(start, "1.", 2))
    {
        if ((*(start+2) == '1') || (*(start+2) == '0'))
            return true;
    }
    else if (!strncmp(start, "2.0", 3))
        return true;

    return false;
}

/********************************************************************
 * Function: sip_startline_parse()
 *
 * Parse the start line: request and response are different
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* buff  - start of the sip message buffer
 *  char* end   - end of the buffer
 *  char**lineEnd - output, the found end of start line
 * Returns:
 *  false
 *  true
 ********************************************************************/

static bool sip_startline_parse(SIPMsg* msg, const char* buff, const char* end, const char** lineEnd,
    SIP_PROTO_CONF* config)
{
    const char* next;
    const char* start;
    int length;
    int numOfLineBreaks;

    start = buff;

    numOfLineBreaks = sip_find_linebreak(start, end, &next);
    if (numOfLineBreaks < 1)
    {
        /*No CRLF */
        return false;
    }

    /*Exclude CRLF from start line*/
    length =  next - start - numOfLineBreaks;

    /*Should at least have SIP/2.0 */
    if (length < SIP_MIN_MSG_LEN)
    {
        return false;
    }

    *lineEnd = next;
    // This is a response
    if (0 == strncmp((const char*)buff, (const char*)SIP_KEYWORD, SIP_KEYWORD_LEN))
    {
        char* space;
        unsigned long statusCode;

        /*Process response*/
        msg->method = nullptr;
        msg->uri = nullptr;

        /*Check SIP version number, end with SP*/
        if (!(sip_is_valid_version(buff + SIP_KEYWORD_LEN) && (*(buff + SIP_VERSION_LEN) == ' ')))
        {
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_INVALID_VERSION);
        }

        space = (char*)strchr(buff, ' ');
        if (space == nullptr)
            return false;
        statusCode = SnortStrtoul(space + 1, nullptr, 10);
        if (( statusCode > MAX_STAT_CODE) || (statusCode < MIN_STAT_CODE ))
        {
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_STATUS_CODE);
            msg->status_code =  MAX_STAT_CODE + 1;
        }
        else
            msg->status_code =  (uint16_t)statusCode;
    }
    else  /* This might be a request*/
    {
        char* space;
        char* version;
        SIPMethodNode* method;

        /*Process request*/
        msg->status_code = 0;

        // Parse the method
        space = (char*)memchr(buff, ' ', end - buff);
        if (space == nullptr)
            return false;
        msg->method = buff;
        msg->methodLen = space - buff;

        method = SIP_FindMethod (config->methods, msg->method, msg->methodLen);
        if (method)
        {
            msg->methodFlag = method->methodFlag;
        }

        // parse the uri
        if (space + 1 > end)
            return false;
        msg->uri = space + 1;
        space = (char*)memchr(space + 1, ' ', end - msg->uri);
        if (space == nullptr)
            return false;
        msg->uriLen = space - msg->uri;

        if (0 == msg->uriLen)
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_REQUEST_URI);
        else if (config->maxUriLen && (msg->uriLen > config->maxUriLen))
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_URI);

        version = space + 1;
        if (version + SIP_VERSION_LEN > end)
            return false;
        if (0 != strncmp((const char*)version, (const char*)SIP_KEYWORD, SIP_KEYWORD_LEN))
            return false;
        /*Check SIP version number, end with CRLF*/
        if (!sip_is_valid_version(*lineEnd - SIP_VERSION_NUM_LEN - numOfLineBreaks))
        {
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_INVALID_VERSION);
        }

        if (nullptr == method)
        {
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_UNKOWN_METHOD);
            return false;
        }
    }

    return true;
}

/********************************************************************
 * Function: sip_headers_parse()
 *
 * Parse the SIP header: request and response are the same
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* buff  - start of the header
 *  char* end   - end of the buffer
 *  char**lineEnd - output, the found end of header
 * Returns:
 *  false
 *  true
 ********************************************************************/
static bool sip_headers_parse(
    SIPMsg* msg, const char* buff, const char* end, const char** headEnd,
    SIP_PROTO_CONF* config)
{
    const char* next;
    const char* start = buff;
    int lastFieldIndex = SIP_PARSE_NOFOLDING;

    /*
     * The end of header is defined by two CRLFs, or CRCR, or LFLF
     */
    int numOfLineBreaks = sip_find_linebreak(start, end, &next);

    while (numOfLineBreaks > 0)
    {
        /*Processing this line*/
        int length =  next - start - numOfLineBreaks;

        /*Process headers*/
        sip_process_headField(msg, start, start + length, &lastFieldIndex, config);

        /*check the end of header*/
        if ((1 == numOfLineBreaks) &&  ( start[0] == start[-1]))
        {
            /*Either CRCR or LFLF*/
            *headEnd = next;
            return true;
        }
        else if ( (2 == numOfLineBreaks) && ('\r' == start[0])&&('\n' == start[1]))
        {
            *headEnd = next;
            return true;
        }

        start = next;
        numOfLineBreaks = sip_find_linebreak(start, end, &next);
    }
    return true;
}

/********************************************************************
 * Function: sip_body_parse()
 *
 * Parse the SIP body: request and response are the same
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* buff  - start of the body
 *  char* end   - end of the buffer
 *  char**lineEnd - output, the found end of body
 * Returns:
 *  false
 *  true
 ********************************************************************/
static bool sip_body_parse(SIPMsg* msg, const char* buff, const char* end, const char** bodyEnd)
{
    // Initialize it
    *bodyEnd = end;

    if (buff == end)
        return true;

    msg->body_data = (const uint8_t*)buff;
    msg->bodyLen = end - buff;

    // Create a media session
    msg->mediaSession = (SIP_MediaSession*)snort_calloc(sizeof(SIP_MediaSession));
    const char* start = buff;

    /*
     * The end of body is defined by two CRLFs or CRCR or LFLF
     */
    const char* next;
    int numOfLineBreaks = sip_find_linebreak(start, end, &next);

    while (numOfLineBreaks > 0)
    {
        /*Processing this line*/
        int length = next - start - numOfLineBreaks;

        /*Process body fields*/
        sip_process_bodyField(msg, start, start + length);

        start = next;
        numOfLineBreaks = sip_find_linebreak(start, end, &next);
    }
    *bodyEnd = start;
    return true;
}

/********************************************************************
 * Function: sip_check_headers()
 *
 * Check whether the headers are mal-formed.
 * Most checks are here, except some need context information are scattered
 * in the parsing.
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *
 * Returns:
 *  false
 *  true
 ********************************************************************/
static bool sip_check_headers(SIPMsg* msg, SIP_PROTO_CONF* config)
{
    int ret = true;
    if (0 == msg->fromLen)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_FROM);
        ret =  false;
    }
    else if (config->maxFromLen && (msg->fromLen > config->maxFromLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_FROM);
        ret = false;
    }

    if (0 == msg->toLen)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_TO);
        ret = false;
    }
    else if (config->maxToLen && (msg->toLen > config->maxToLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_TO);
        ret = false;
    }

    if (0 == msg->callIdLen)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_CALL_ID);
        ret = false;
    }
    else if ( config->maxCallIdLen && (msg->callIdLen > config->maxCallIdLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CALL_ID);
        ret = false;
    }

    if (msg->cseqnum > MAX_NUM_32BIT)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CSEQ_NUM);
        ret = false;
    }
    if ( config->maxRequestNameLen && (msg->cseqNameLen > config->maxRequestNameLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CSEQ_NAME);
        ret = false;
    }

    /*Alert here after parsing*/
    if (0 == msg->viaLen)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_VIA);
        ret = false;
    }
    else if (config->maxViaLen && (msg->viaLen > config->maxViaLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_VIA);
        ret = false;
    }

    // Contact is required for invite message
    if ((0 == msg->contactLen)&&(msg->methodFlag == SIP_METHOD_INVITE)&&(0 == msg->status_code))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_CONTACT);
        ret = false;
    }
    else if (config->maxContactLen && (msg->contactLen > config->maxContactLen))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CONTACT);
        ret = false;
    }

    if ((0 == msg->contentTypeLen) && (msg->content_len > 0))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_EMPTY_CONTENT_TYPE);
        ret = false;
    }

    return ret;
}

/********************************************************************
 * Function: sip_parse_via()
 *
 * Parse the via field: Via can have multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the via filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_via(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    int length = end -start;
    msg->viaLen = msg->viaLen + length;

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_from()
 *
 * Parse the from field and get from tag
 * Note: From has no multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the from filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_from(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    char* buff;
    char* userEnd;
    char* userStart;

    msg->from = start;
    msg->fromLen = end - start;

    /*Get the from tag*/
    msg->fromTagLen = 0;

    buff = (char*)memchr(start, ';', msg->fromLen);
    while ((nullptr != buff)&& (buff < end))
    {
        if (0 == strncmp(buff + 1, SIP_TAG_KEYWORD, SIP_TAG_KEYWORD_LEN))
        {
            msg->from_tag = buff + SIP_TAG_KEYWORD_LEN + 1;
            msg->fromTagLen = end - msg->from_tag;
            msg->dlgID.fromTagHash = strToHash(msg->from_tag,msg->fromTagLen);
            break;
        }
        buff = (char*)memchr(buff + 1, ';', msg->fromLen);
    }

    userStart = (char*)memchr(msg->from, ':', msg->fromLen);
    userEnd = (char*)memchr(msg->from, '>', msg->fromLen);

    if (userStart && userEnd && (userEnd > userStart))
    {
        msg->userName = userStart+1;
        msg->userNameLen = userEnd - userStart - 1;
    }
    else
    {
        msg->userName = nullptr;
        msg->userNameLen = 0;
    }

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_to()
 *
 * Parse the to field and get to tag information
 * Note: To has no multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the to filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_to(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    char* buff;
    msg->to = start;
    msg->toLen = end - start;

    /*Processing tag information*/
    msg->toTagLen = 0;

    buff = (char*)memchr(start, ';', msg->toLen);
    while ((nullptr != buff)&& (buff < end))
    {
        if (0 == strncmp(buff + 1, SIP_TAG_KEYWORD, SIP_TAG_KEYWORD_LEN))
        {
            msg->to_tag = buff + SIP_TAG_KEYWORD_LEN + 1;
            msg->toTagLen = end - msg->to_tag;
            msg->dlgID.toTagHash = strToHash(msg->to_tag,msg->toTagLen);
            break;
        }
        buff = (char*)memchr(buff + 1, ';', msg->toLen);
    }

    return SIP_PARSE_SUCCESS;
}

static inline bool is_valid_ip(const char* start, int length)
{
    SfIp ip;
    char ipStr[INET6_ADDRSTRLEN];

    /*Get the IP address*/
    if (length > INET6_ADDRSTRLEN - 1)
    {
        length = INET6_ADDRSTRLEN - 1;
    }
    memcpy(ipStr, start, length);
    ipStr[length] = '\0';

    if ( ip.set(ipStr) != SFIP_SUCCESS)
        return false;

    return true;
}

/********************************************************************
 * Function: sip_parse_call_id()
 *
 * Parse the call-id field
 * Note: call-id has no multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_call_id(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    int length = end -start;
    msg->call_id = start;
    /*ignore ip address in call id by adjusting length*/
    char* at = (char*)memchr(start, '@', length);
    if (at && (at < end) && is_valid_ip(at+1, (end-at-1)))
    {
        length = at - start;
    }

    msg->callIdLen = end - start;
    msg->dlgID.callIdHash =  strToHash(msg->call_id, length);

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_user_agent()
 *
 * Parse the user_agent field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the field line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_parse_user_agent(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    msg->userAgent = start;
    msg->userAgentLen = end - start;

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_server()
 *
 * Parse the server field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the field line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_parse_server(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    msg->server = start;
    msg->serverLen = end - start;

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_cseq()
 *
 * Parse the cseq field: get sequence number and request name
 * Note: Cseq has no multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_cseq(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF* config)
{
    char* next = nullptr;
    SIPMethodNode* method = nullptr;

    msg->cseqnum = SnortStrtoul(start, &next, 10);
    if ((nullptr != next )&&(next < end))
    {
        msg->cseqName = next + 1;
        msg->cseqNameLen = end - msg->cseqName;
        method = SIP_FindMethod (config->methods, msg->cseqName, msg->cseqNameLen);
    }

    if (nullptr == method)
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_INVALID_CSEQ_NAME);
        return SIP_PARSE_ERROR;
    }
    else
    {
        /*Use request name only for response message*/
        if ((SIP_METHOD_NULL == msg->methodFlag)&&( msg->status_code > 0))
            msg->methodFlag = method->methodFlag;
        else if ( method->methodFlag != msg->methodFlag)
        {
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_MISMATCH_METHOD);
        }
    }

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_contact()
 *
 * Parse the to contact field
 * Note: Contact has multiple header
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_contact(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    int length = end -start;
    msg->contact = start;
    msg->contactLen = msg->contactLen + length;
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_authorization()
 *
 * Parse the to authorization field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_authorization(
    SIPMsg* msg, const char* start, const char*, SIP_PROTO_CONF*)
{
    msg->authorization = start;
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_content_type()
 *
 * Parse the to content type field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_content_type(SIPMsg* msg, const char* start, const char* end, SIP_PROTO_CONF*)
{
    msg->contentTypeLen = end - start;
    msg->content_type = start;
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_content_len()
 *
 * Parse the to content length field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_content_len(SIPMsg* msg, const char* start, const char*,
    SIP_PROTO_CONF* config)
{
    char* next = nullptr;

    msg->content_len = SnortStrtoul(start, &next, 10);
    if ( config->maxContentLen && (msg->content_len > config->maxContentLen))
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CONTENT_LEN);
    /*Check the length of the value*/
    if (next > start + SIP_CONTENT_LEN) // This check is to prevent overflow
    {
        if (config->maxContentLen)
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_BAD_CONTENT_LEN);
        return SIP_PARSE_ERROR;
    }

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_content_encode()
 *
 * Parse the to content encode field
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/

static int sip_parse_content_encode(
    SIPMsg* msg, const char* start, const char*, SIP_PROTO_CONF*)
{
    msg->content_encode = start;
    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_sdp_o()
 *
 * Parse SDP origination information
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_parse_sdp_o(SIPMsg* msg, const char* start, const char* end)
{
    int length;
    char* spaceIndex = nullptr;
    char* spaceIndex2 = nullptr;

    if (nullptr == msg->mediaSession)
        return SIP_PARSE_ERROR;
    length = end - start;
    // Get username and session ID information (before second space)
    spaceIndex = (char*)memchr(start, ' ', length);  // first space
    if ((nullptr == spaceIndex)||(spaceIndex == end))
        return SIP_PARSE_ERROR;
    spaceIndex = (char*)memchr(spaceIndex + 1, ' ', end - spaceIndex -1);   // second space
    if (nullptr == spaceIndex)
        return SIP_PARSE_ERROR;
    spaceIndex2 = (char*)memchr(spaceIndex + 1, ' ', end - spaceIndex -1);   // third space
    if (nullptr == spaceIndex2)
        return SIP_PARSE_ERROR;

    //sessionId uses all elements from o: line except sessionId version
    msg->mediaSession->sessionID =  strToHash(start, spaceIndex - start);
    msg->mediaSession->sessionID +=  strToHash(spaceIndex2+1, end - (spaceIndex2+1));

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_sdp_c()
 *
 * Parse SDP connection data
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_parse_sdp_c(SIPMsg* msg, const char* start, const char* end)
{
    int length;
    SfIp* ip;
    char ipStr[INET6_ADDRSTRLEN + 5];     /* Enough for IPv4 plus netmask or
                                                       full IPv6 plus prefix */
    char* spaceIndex = nullptr;

    if (nullptr == msg->mediaSession)
        return SIP_PARSE_ERROR;
    length = end - start;

    /*Get the IP address*/
    spaceIndex = (char*)memchr(start, ' ', length);  // first space
    if ((nullptr == spaceIndex)||(spaceIndex == end))
        return SIP_PARSE_ERROR;
    spaceIndex = (char*)memchr(spaceIndex + 1, ' ', end - spaceIndex -1);   // second space
    if (nullptr == spaceIndex)
        return SIP_PARSE_ERROR;
    length = end - spaceIndex;

    memset(ipStr, 0, sizeof(ipStr));
    if (length > INET6_ADDRSTRLEN)
    {
        length = INET6_ADDRSTRLEN;
    }
    strncpy(ipStr, spaceIndex, length);
    ipStr[length] = '\0';

    // If no default session connect information, add it
    if (nullptr == msg->mediaSession->medias)
    {
        ip = &(msg->mediaSession->maddress_default);
    }
    else // otherwise, update the latest media data (header of media list)
    {
        ip = &(msg->mediaSession->medias->maddress);
    }
    if ( ip->set(ipStr) != SFIP_SUCCESS)
    {
        return SIP_PARSE_ERROR;
    }

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse_sdp_c()
 *
 * Parse media type information
 * Note: to make it easier update the media address, media data are added to the header of media list
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* start  - start of the filed line
 *  char* end   - end of the line
 * Returns:
 *  SIP_PARSE_ERROR
 *  SIP_PARSE_SUCCESS
 ********************************************************************/
static int sip_parse_sdp_m(SIPMsg* msg, const char* start, const char* end)
{
    int length;
    char* spaceIndex = nullptr;
    char* next;
    SIP_MediaData* mdata;

    if (nullptr == msg->mediaSession)
        return SIP_PARSE_ERROR;
    length = end - start;

    spaceIndex = (char*)memchr(start, ' ', length);  // first space

    if ((nullptr == spaceIndex)||(spaceIndex == end))
        return SIP_PARSE_ERROR;

    mdata = (SIP_MediaData*)snort_calloc(sizeof(SIP_MediaData));
    mdata->mport = (uint16_t)SnortStrtoul(spaceIndex + 1, &next, 10);

    if ((nullptr != next)&&('/'==next[0]))
        mdata->numPort = (uint8_t)SnortStrtoul(spaceIndex + 1, &next, 10);
    // Put
    mdata->nextM = msg->mediaSession->medias;
    mdata->maddress = msg->mediaSession->maddress_default;
    msg->mediaSession->medias = mdata;

    return SIP_PARSE_SUCCESS;
}

/********************************************************************
 * Function: sip_parse()
 *
 * The main entry for parser: process the sip messages.
 *
 * Arguments:
 *  SIPMsg *    - sip message
 *  char* buff - start of the sip message buffer
 *  char* end   - end of the buffer
 *
 * Returns:
 *  false
 *  true
 ********************************************************************/
bool sip_parse(SIPMsg* msg, const char* buff, const char* end, SIP_PROTO_CONF* config)
{
    const char* nextIndex;
    const char* start;

    /*Initialize key values*/
    msg->methodFlag = SIP_METHOD_NULL;
    msg->status_code = 0;

    /*Parse the start line*/
    start = buff;
    nextIndex = nullptr;

    msg->header = (const uint8_t*)buff;
    if (!sip_startline_parse(msg, start, end, &nextIndex, config))
        return false;

    /*Parse the headers*/
    start = nextIndex;
    sip_headers_parse(msg, start, end, &nextIndex, config);
    msg->headerLen =  nextIndex - buff;

    sip_check_headers(msg, config);

    /*Parse the body*/
    start = nextIndex;
    uint16_t bodyLen = end - start;

    /*Disable this check for TCP. Revisit this again when PAF enabled for SIP*/
    if ((!msg->isTcp)&&(msg->content_len > bodyLen))
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_MISMATCH_CONTENT_LEN);

    bool status = sip_body_parse(msg, start, start + msg->content_len, &nextIndex);

    // Find out whether multiple SIP messages in this packet
    /*Disable this check for TCP. Revisit this again when PAF enabled for SIP*/
    if ((!msg->isTcp) && (msg->content_len < bodyLen))
    {
        if ( sip_startline_parse(msg, start + msg->content_len, end, &nextIndex, config) )
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_MULTI_MSGS);
        else
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_MISMATCH_CONTENT_LEN);
    }
    return status;
}

/********************************************************************
 * Function: sip_freeMsg
 *
 * Frees a sip msg.
 * Media session information will be release if they are not used by dialog.
 *
 * Arguments:
 *  SIPMsg *
 *      The sip message to free.
 *
 * Returns: None
 *
 ********************************************************************/
void sip_freeMsg(SIPMsg* msg)
{
    if (nullptr == msg)
        return;
    if (nullptr != msg->mediaSession)
    {
        if (SIP_SESSION_SAVED != msg->mediaSession->savedFlag)
            sip_freeMediaSession(msg->mediaSession);
    }
}

/********************************************************************
 * Function: sip_freeMediaSession
 *
 * Frees a sip media session
 *
 * Arguments:
 *  SIP_MediaSession *
 *      The media session to free.
 *
 * Returns: None
 *
 ********************************************************************/
void sip_freeMediaSession(SIP_MediaSession* mediaSession)
{
    SIP_MediaData* nextNode;
    SIP_MediaData* curNode = nullptr;

    if (nullptr != mediaSession)
    {
        curNode = mediaSession->medias;
    }

    while (nullptr != curNode)
    {
        nextNode = curNode->nextM;
        snort_free(curNode);
        curNode = nextNode;
    }
    if (nullptr != mediaSession)
        snort_free(mediaSession);
}

/********************************************************************
 * Function: sip_freeMediaList
 *
 * Frees a sip media session list
 *
 * Arguments:
 *  SIP_MediaList
 *      The media session list to free.
 *
 * Returns: None
 *
 ********************************************************************/
void sip_freeMediaList(SIP_MediaList medias)
{
    SIP_MediaSession* nextNode;
    SIP_MediaSession* curNode = medias;

    while (nullptr != curNode)
    {
        nextNode = curNode->nextS;
        sip_freeMediaSession(curNode);
        curNode = nextNode;
    }
}

