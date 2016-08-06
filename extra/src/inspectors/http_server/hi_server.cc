//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/**
**  @file       hi_server.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Handles inspection of HTTP server responses.
**
**  HttpInspect handles server responses in a stateless manner because we
**  are really only interested in the first response packet that contains
**  the HTTP response code, headers, and the payload.
**
**  The first big thing is to incorporate the HTTP protocol flow
**  analyzer.
**
**  NOTES:
**      - Initial development.  DJR
*/
#include <stdio.h>
#include <zlib.h>

#include "hi_stream_splitter.h"
#include "main/thread.h"
#include "utils/safec.h"
#include "utils/util_utf.h"

static THREAD_LOCAL bool headers = false;
static THREAD_LOCAL bool simple_response = false;
static THREAD_LOCAL uint8_t decompression_buffer[65535];
static THREAD_LOCAL uint8_t dechunk_buffer[65535];

#include "hi_server.h"
#include "hi_ui_config.h"
#include "hi_return_codes.h"
#include "hi_si.h"

#include "detection/detection_util.h"
#include "utils/util_unfold.h"
#include "protocols/tcp.h"

#define STAT_END 100
#define HTTPRESP_HEADER_NAME__COOKIE "Set-Cookie"
#define HTTPRESP_HEADER_LENGTH__COOKIE 10
#define HTTPRESP_HEADER_NAME__CONTENT_ENCODING "Content-Encoding"
#define HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING 16
#define HTTPRESP_HEADER_NAME__GZIP "gzip"
#define HTTPRESP_HEADER_NAME__XGZIP "x-gzip"
#define HTTPRESP_HEADER_LENGTH__GZIP 4
#define HTTPRESP_HEADER_LENGTH__XGZIP 6
#define HTTPRESP_HEADER_NAME__DEFLATE "deflate"
#define HTTPRESP_HEADER_LENGTH__DEFLATE 7
#define HTTPRESP_HEADER_NAME__CONTENT_LENGTH "Content-length"
#define HTTPRESP_HEADER_LENGTH__CONTENT_LENGTH 14
#define HTTPRESP_HEADER_NAME__CONTENT_TYPE "Content-Type"
#define HTTPRESP_HEADER_LENGTH__CONTENT_TYPE 12
#define HTTPRESP_HEADER_NAME__TRANSFER_ENCODING "Transfer-Encoding"
#define HTTPRESP_HEADER_LENGTH__TRANSFER_ENCODING 17

#define CLR_SERVER_HEADER(Server) \
    do { \
        Server->response.header_raw = NULL; \
        Server->response.header_raw_size = 0; \
        Server->response.header_norm = NULL; \
        Server->response.header_norm_size = 0; \
        Server->response.cookie.cookie = NULL; \
        Server->response.cookie.cookie_end = NULL; \
        if (Server->response.cookie.next) { \
            COOKIE_PTR* cookie = Server->response.cookie.next; \
            do { \
                Server->response.cookie.next = Server->response.cookie.next->next; \
                snort_free(cookie); \
                cookie = Server->response.cookie.next; \
            } while (cookie); \
        } \
        Server->response.cookie.next = NULL; \
        Server->response.cookie_norm = NULL; \
        Server->response.cookie_norm_size = 0; \
    } while (0);

#define CLR_SERVER_STAT(Server) \
    do { \
        Server->response.status_msg = NULL; \
        Server->response.status_code = NULL; \
        Server->response.status_code_size = 0; \
        Server->response.status_msg_size = 0; \
    } while (0);

#define CLR_SERVER_STAT_MSG(Server) \
    do { \
        Server->response.status_msg = NULL; \
        Server->response.status_msg_size = 0; \
    } while (0);

#define CLR_SERVER_BODY(Server) \
    do { \
        Server->response.body = NULL; \
        Server->response.body_size = 0; \
    } while (0);

static inline void clearHttpRespBuffer(HI_SERVER* Server)
{
    CLR_SERVER_HEADER(Server);
    CLR_SERVER_STAT(Server);
    CLR_SERVER_BODY(Server);
}

static inline const u_char* MovePastDelims(const u_char* start, const u_char* end,const
    u_char* ptr)
{
    while (hi_util_in_bounds(start, end, ptr))
    {
        if (*ptr < 0x21)
        {
            if (*ptr < 0x0E && *ptr > 0x08)
            {
                ptr++;
                continue;
            }
            else
            {
                if (*ptr == 0x20)
                {
                    ptr++;
                    continue;
                }
            }
        }

        break;
    }

    return ptr;
}

/**
**  NAME
**    IsHttpServerData::
*/
/**
**  Inspect an HTTP server response packet to determine the state.
**
**  We inspect this packet and determine whether we are in the beginning
**  of a response header or if we are looking at payload.  We limit the
**  amount of inspection done on responses by only inspecting the HTTP header
**  and some payload.  If the whole packet is a payload, then we just ignore
**  it, since we inspected the previous header and payload.
**
**  We limit the amount of the payload by adjusting the Server structure
**  members, header and header size.
**
**  @param Server      the server structure
**  @param data        pointer to the beginning of payload
**  @param dsize       the size of the payload
**  @param flow_depth  the amount of header and payload to inspect
**
**  @return integer
**
**  @retval HI_INVALID_ARG invalid argument
**  @retval HI_SUCCESS     function success
*/
static int IsHttpServerData(HI_SESSION* session, Packet* p, HttpSessionData* sd)
{
    const u_char* start;
    const u_char* end;
    const u_char* ptr;
    int len;
    uint32_t seq_num = 0;
    HI_SERVER* Server;
    HTTPINSPECT_CONF* ServerConf;

    ServerConf = session->server_conf;
    if (!ServerConf)
        return HI_INVALID_ARG;

    Server = &(session->server);

    clearHttpRespBuffer(Server);
    /*
    ** HTTP:Server-Side-session-Performance-Optimization
    ** This drops Server->Client packets which are not part of the
    ** HTTP Response header. It can miss part of the response header
    ** if the header is sent as multiple packets.
    */
    if (!(p->data))
    {
        return HI_INVALID_ARG;
    }

    seq_num = sd ? sd->resp_state.next_seq : 0;

    /*
    **  Let's set up the data pointers.
    */
    Server->response.header_raw      = p->data;
    Server->response.header_raw_size = p->dsize;

    start = p->data;
    end = p->data + p->dsize;
    ptr = start;

    ptr = MovePastDelims(start,end,ptr);

    len = end - ptr;
    if ( len > 4 )
    {
        if (!IsHttpVersion(&ptr, end))
        {
            p->packet_flags |= PKT_HTTP_DECODE;
            ApplyFlowDepth(ServerConf, p, sd, 0, 0, seq_num);
            return HI_SUCCESS;
        }
        else
        {
            if (ServerConf->server_flow_depth > 0)
            {
                if (sd)
                {
                    sd->resp_state.flow_depth_excd = false;
                    sd->resp_state.max_seq = seq_num + ServerConf->server_flow_depth;
                }
            }
            p->packet_flags |= PKT_HTTP_DECODE;
            ApplyFlowDepth(ServerConf, p, sd, 0, 1, seq_num);
            return HI_SUCCESS;
        }
    }

    return HI_SUCCESS;
}

static inline int hi_server_extract_status_msg(const u_char* start, const u_char* ptr,
    const u_char* end, URI_PTR* result)
{
    int iRet = HI_SUCCESS;
    SkipBlankSpace(start,end,&ptr);

    if (  hi_util_in_bounds(start, end, ptr) )
    {
        const u_char* crlf = (u_char*)SnortStrnStr((const char*)ptr, end - ptr, "\n");
        result->uri = ptr;
        if (crlf)
        {
            if (crlf[-1] == '\r')
                result->uri_end = crlf - 1;
            else
                result->uri_end = crlf;
            ptr = crlf;
        }
        else
        {
            result->uri_end =end;
        }

        if (result->uri < result->uri_end)
            iRet = STAT_END;
        else
            iRet = HI_OUT_OF_BOUNDS;
    }
    else
        iRet = HI_OUT_OF_BOUNDS;

    return iRet;
}

static inline int hi_server_extract_status_code(
    HI_SESSION*, const u_char* start, const u_char* ptr,
    const u_char* end, URI_PTR* result)
{
    int iRet = HI_SUCCESS;
    SkipBlankSpace(start,end,&ptr);

    result->uri = ptr;
    result->uri_end = ptr;

    while (  hi_util_in_bounds(start, end, ptr) )
    {
        if (isdigit((int)*ptr))
        {
            SkipDigits(start, end, &ptr);
            if (  hi_util_in_bounds(start, end, ptr) )
            {
                if (isspace((int)*ptr))
                {
                    result->uri_end = ptr;
                    iRet = STAT_END;
                    return iRet;
                }
                else
                {
                    result->uri_end = ptr;
                    iRet = HI_NONFATAL_ERR;
                    return iRet;
                }
            }
            else
            {
                iRet = HI_OUT_OF_BOUNDS;
                return iRet;
            }
        }
        else
        {
            hi_set_event(GID_HTTP_SERVER, HI_SERVER_INVALID_STATCODE);
            ptr++;
        }
    }

    iRet = HI_OUT_OF_BOUNDS;

    return iRet;
}

/* Grab the argument of "charset=foo" from a Content-Type header */
static inline const u_char* extract_http_content_type_charset(
    HI_SESSION*, HttpSessionData* hsd,
    const u_char* p, const u_char*, const u_char* end)
{
    size_t cmplen;
    uint8_t unfold_buf[DECODE_BLEN];
    uint32_t unfold_size =0;
    const char* ptr, * ptr_end;

    if (hsd == NULL)
        return p;

    /* Don't trim spaces so p is set to end of header */
    sf_unfold_header(p, end-p, unfold_buf, sizeof(unfold_buf), &unfold_size, 0, 0);
    if (!unfold_size)
    {
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_DEFAULT);
        return p;
    }
    p += unfold_size;

    ptr = (const char*)unfold_buf;
    ptr_end = (const char*)(ptr + strlen((const char*)unfold_buf));

    ptr = SnortStrcasestr(ptr, (int)(ptr_end - ptr), "text");
    if (!ptr)
    {
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_DEFAULT);
        return p;
    }

    ptr = SnortStrcasestr(ptr, (int)(ptr_end - ptr), "utf-");
    if (!ptr)
    {
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UNKNOWN);
        return p;
    }
    ptr += 4; /* length of "utf-" */
    cmplen = ptr_end - ptr;

    if ((cmplen > 0) && (*ptr == '8'))
    {
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_DEFAULT);
    }
    else if ((cmplen > 0) && (*ptr == '7'))
    {
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UTF7);
        hi_set_event(GID_HTTP_SERVER, HI_SERVER_UTF7);
    }
    else if (cmplen >= 4)
    {
        if ( !strncasecmp(ptr, "16le", 4) )
            set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UTF16LE);
        else if ( !strncasecmp(ptr, "16be", 4) )
            set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UTF16BE);
        else if ( !strncasecmp(ptr, "32le", 4) )
            set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UTF32LE);
        else if ( !strncasecmp(ptr, "32be", 4) )
            set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UTF32BE);
        else
            set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UNKNOWN);
    }
    else
        set_decode_utf_state_charset(&(hsd->utf_state), CHARSET_UNKNOWN);

    return p;
}

static inline const u_char* extract_http_content_encoding(HTTPINSPECT_CONF* ServerConf,
    const u_char* p, const u_char* start, const u_char* end, HEADER_PTR* header_ptr,
    HEADER_FIELD_PTR* header_field_ptr)
{
    const u_char* crlf;
    int space_present = 0;
    if (header_ptr->content_encoding.cont_encoding_start)
    {
        header_ptr->header.uri_end = p;
        header_ptr->content_encoding.compress_fmt = 0;
        return p;
    }
    else
    {
        header_field_ptr->content_encoding = &header_ptr->content_encoding;
        p = p + HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING;
    }
    SkipBlankSpace(start,end,&p);
    if (hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        if (  hi_util_in_bounds(start, end, p) )
        {
            if ( ServerConf->profile == HI_APACHE || ServerConf->profile == HI_DEFAULT)
            {
                SkipWhiteSpace(start,end,&p);
            }
            else
            {
                SkipBlankAndNewLine(start,end,&p);
            }
            if ( hi_util_in_bounds(start, end, p))
            {
                if ( *p == '\n' )
                {
                    while (hi_util_in_bounds(start, end, p))
                    {
                        if ( *p == '\n')
                        {
                            p++;
                            while ( hi_util_in_bounds(start, end, p) && ( *p == ' ' || *p == '\t'))
                            {
                                space_present = 1;
                                p++;
                            }
                            if ( space_present )
                            {
                                if ( isalpha((int)*p))
                                    break;
                                else if (isspace((int)*p) && (ServerConf->profile == HI_APACHE ||
                                    ServerConf->profile == HI_DEFAULT) )
                                {
                                    SkipWhiteSpace(start,end,&p);
                                }
                                else
                                {
                                    header_field_ptr->content_encoding->cont_encoding_start=
                                        header_field_ptr->content_encoding->cont_encoding_end =
                                            NULL;
                                    header_field_ptr->content_encoding->compress_fmt = 0;
                                    return p;
                                }
                            }
                            else
                            {
                                header_field_ptr->content_encoding->cont_encoding_start=
                                    header_field_ptr->content_encoding->cont_encoding_end = NULL;
                                header_field_ptr->content_encoding->compress_fmt = 0;
                                return p;
                            }
                        }
                        else
                            break;
                    }
                }
                else if (isalpha((int)*p))
                {
                    header_field_ptr->content_encoding->cont_encoding_start = p;
                    while (hi_util_in_bounds(start, end, p) && *p!='\n' )
                    {
                        if (IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__GZIP,
                            HTTPRESP_HEADER_LENGTH__GZIP) ||
                            IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__XGZIP,
                            HTTPRESP_HEADER_LENGTH__XGZIP))
                        {
                            header_field_ptr->content_encoding->compress_fmt |=
                                HTTP_RESP_COMPRESS_TYPE__GZIP;
                            p = p + HTTPRESP_HEADER_LENGTH__GZIP;
                            continue;
                        }
                        else if (IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__DEFLATE,
                            HTTPRESP_HEADER_LENGTH__DEFLATE))
                        {
                            header_field_ptr->content_encoding->compress_fmt |=
                                HTTP_RESP_COMPRESS_TYPE__DEFLATE;
                            p = p + HTTPRESP_HEADER_LENGTH__DEFLATE;
                            continue;
                        }
                        else
                            p++;
                    }

                    /*crlf = (u_char *)SnortStrnStr((const char *)p, end - p, "\n");
                    if(crlf)
                    {
                        p = crlf;
                    }
                    else
                    {
                        header_ptr->header.uri_end = end ;
                        return end;
                    }*/
                }
                else
                {
                    header_field_ptr->content_encoding->cont_encoding_start=
                        header_field_ptr->content_encoding->cont_encoding_end = NULL;
                    header_field_ptr->content_encoding->compress_fmt = 0;
                    return p;
                }
            }
        }
    }
    else
    {
        if (hi_util_in_bounds(start, end, p))
        {
            crlf = (u_char*)SnortStrnStr((const char*)p, end - p, "\n");
            if (crlf)
            {
                p = crlf;
            }
            else
            {
                header_ptr->header.uri_end = end;
                return end;
            }
        }
    }
    if (!p || !hi_util_in_bounds(start, end, p))
        p = end;

    return p;
}

const u_char* extract_http_transfer_encoding(
    HI_SESSION*, HttpSessionData* hsd,
    const u_char* p, const u_char* start, const u_char* end,
    HEADER_PTR* header_ptr, int iInspectMode)
{
    uint8_t unfold_buf[DECODE_BLEN];
    uint32_t unfold_size =0;
    const u_char* start_ptr, * end_ptr, * cur_ptr;

    SkipBlankSpace(start,end,&p);

    if (hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        if (hi_util_in_bounds(start, end, p))
            sf_unfold_header(p, end-p, unfold_buf, sizeof(unfold_buf), &unfold_size, 1, 0);

        if (!unfold_size)
        {
            header_ptr->header.uri_end = end;
            return end;
        }

        p = p + unfold_size;

        start_ptr = unfold_buf;
        cur_ptr = unfold_buf;
        end_ptr = unfold_buf + unfold_size;
        SkipBlankSpace(start_ptr,end_ptr,&cur_ptr);

        start_ptr = cur_ptr;

        start_ptr = (u_char*)SnortStrcasestr((const char*)start_ptr, (end_ptr - start_ptr),
            "chunked");
        if (start_ptr)
        {
            if ((iInspectMode == HI_SI_SERVER_MODE) && hsd)
            {
                hsd->resp_state.last_pkt_chunked = 1;
                hsd->resp_state.last_pkt_contlen = 0;
            }
            header_ptr->content_len.len = 0;
            header_ptr->content_len.cont_len_start = NULL;
            header_ptr->is_chunked = true;
        }
    }
    else
    {
        header_ptr->header.uri_end = end;
        return end;
    }

    return p;
}

static inline const u_char* extractHttpRespHeaderFieldValues(HTTPINSPECT_CONF* ServerConf,
    const u_char* p, const u_char* offset, const u_char* start,
    const u_char* end, HEADER_PTR* header_ptr,
    HEADER_FIELD_PTR* header_field_ptr, int parse_cont_encoding, HttpSessionData* hsd,
    HI_SESSION* session)
{
    if (((p - offset) == 0) && ((*p == 'S') || (*p == 's')))
    {
        /* Search for 'Cookie' at beginning, starting from current *p */
        if ( ServerConf->enable_cookie &&
            IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__COOKIE,
            HTTPRESP_HEADER_LENGTH__COOKIE))
        {
            p = extract_http_cookie((p + HTTPRESP_HEADER_LENGTH__COOKIE), end, header_ptr,
                header_field_ptr);
        }
    }
    else if (((p - offset) == 0) && ((*p == 'C') || (*p == 'c')))
    {
        if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__CONTENT_TYPE,
            HTTPRESP_HEADER_LENGTH__CONTENT_TYPE) && ServerConf->normalize_utf)
        {
            p = extract_http_content_type_charset(session, hsd, p, start, end);
        }
        else if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__CONTENT_ENCODING,
            HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING) && parse_cont_encoding)
        /*&& ServerConf->extract_gzip*/         // FIXIT-L move back to ServerConf?
        {
            p = extract_http_content_encoding(ServerConf, p, start, end, header_ptr,
                header_field_ptr);
        }
        else if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__CONTENT_LENGTH,
            HTTPRESP_HEADER_LENGTH__CONTENT_LENGTH) )
        {
            if (hsd && !hsd->resp_state.last_pkt_chunked)
                p = extract_http_content_length(session, ServerConf, p, start, end, header_ptr,
                    header_field_ptr);
        }
    }
    else if (((p - offset) == 0) && ((*p == 'T') || (*p == 't')))
    {
        if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__TRANSFER_ENCODING,
            HTTPRESP_HEADER_LENGTH__TRANSFER_ENCODING))
        {
            p = p + HTTPRESP_HEADER_LENGTH__TRANSFER_ENCODING;
            p = extract_http_transfer_encoding(session, hsd, p, start, end, header_ptr,
                HI_SI_SERVER_MODE);
        }
    }
    return p;
}

static inline const u_char* hi_server_extract_header(
    HI_SESSION* session, HTTPINSPECT_CONF* ServerConf,
    HEADER_PTR* header_ptr, const u_char* start,
    const u_char* end, int parse_cont_encoding,
    HttpSessionData* hsd)
{
    const u_char* p;
    const u_char* offset;
    HEADER_FIELD_PTR header_field_ptr;

    if (!start || !end)
        return NULL;

    p = start;

    offset = (u_char*)p;

    header_ptr->header.uri = p;
    header_ptr->header.uri_end = end;
    header_ptr->content_encoding.compress_fmt = 0;
    header_ptr->content_len.len = 0;
    header_ptr->is_chunked = false;

    while (hi_util_in_bounds(start, end, p))
    {
        if (*p == '\n')
        {
            p++;

            offset = (u_char*)p;

            if (!hi_util_in_bounds(start, end, p))
            {
                header_ptr->header.uri_end = p;
                return p;
            }

            if (*p < 0x0E)
            {
                if (*p == '\r')
                {
                    p++;

                    if (hi_util_in_bounds(start, end, p) && (*p == '\n'))
                    {
                        p++;
                        header_ptr->header.uri_end = p;
                        return p;
                    }
                }
                else if (*p == '\n')
                {
                    p++;
                    header_ptr->header.uri_end = p;
                    return p;
                }
            }
            else if ( (p = extractHttpRespHeaderFieldValues(ServerConf, p, offset,
                    start, end, header_ptr, &header_field_ptr,
                    parse_cont_encoding, hsd, session)) == end)
            {
                return end;
            }
        }
        else if ( (p == header_ptr->header.uri) &&
            (p = extractHttpRespHeaderFieldValues(ServerConf, p, offset,
                start, end, header_ptr, &header_field_ptr,
                parse_cont_encoding, hsd, session)) == end)
        {
            return end;
        }
        if ( *p == '\n')
            continue;
        p++;
    }

    header_ptr->header.uri_end = p;
    return p;
}

static inline int hi_server_extract_body(
    HI_SESSION* session, HttpSessionData* sd,
    const u_char* ptr, const u_char* end, URI_PTR* result)
{
    HTTPINSPECT_CONF* ServerConf;
    const u_char* start = ptr;
    int iRet = HI_SUCCESS;
    const u_char* post_end = end;
    uint32_t updated_chunk_remainder = 0;
    uint32_t chunk_read = 0;
    int64_t bytes_to_read = 0;
    ServerConf = session->server_conf;

    switch (ServerConf->server_extract_size)
    {
    case -1:
        result->uri = result->uri_end = NULL;
        return iRet;
    case 0:
        break;
    default:
        if (sd->resp_state.data_extracted < ServerConf->server_extract_size)
        {
            bytes_to_read = ServerConf->server_extract_size - sd->resp_state.data_extracted;
            if ((end-ptr) > bytes_to_read )
            {
                end = ptr + bytes_to_read;
            }
            else
                bytes_to_read = (end-ptr);
            sd->resp_state.data_extracted += (int)bytes_to_read;
        }
        else
        {
            result->uri = result->uri_end = NULL;
            return iRet;
        }
    }

/*    if( ServerConf->server_flow_depth && ((end - ptr) > ServerConf->server_flow_depth) )
    {
        end = ptr + ServerConf->server_flow_depth;
    }*/

    if (!(sd->resp_state.last_pkt_contlen))
    {
        if ( ServerConf->chunk_length || ServerConf->small_chunk_length.size )
        {
            if (sd->resp_state.last_pkt_chunked
                && CheckChunkEncoding(session, start, end, &post_end,
                (u_char*)HttpDecodeBuf.data, sizeof(HttpDecodeBuf.data),
                sd->resp_state.chunk_remainder, &updated_chunk_remainder, &chunk_read,
                sd, HI_SI_SERVER_MODE) == 1)
            {
                sd->resp_state.chunk_remainder = updated_chunk_remainder;
                sd->resp_state.last_pkt_chunked = 1;
                result->uri = (u_char*)HttpDecodeBuf.data;
                result->uri_end = result->uri + chunk_read;
                return iRet;
            }
            else
            {
                if (!(sd->resp_state.last_pkt_chunked) && !simple_response)
                {
                    if ( headers )
                        hi_set_event(GID_HTTP_SERVER, HI_SERVER_NO_CONTLEN);
                }
                else
                    sd->resp_state.last_pkt_chunked = 0;
                result->uri = start;
                result->uri_end = end;
            }
        }
        else
        {
            result->uri = start;
            result->uri_end = end;
            return iRet;
        }
    }

    result->uri = start;
    result->uri_end = end;

    return STAT_END;
}

static void LogFileDecomp(void*, int event)
{
    switch ( event )
    {
    case FILE_DECOMP_ERR_SWF_ZLIB_FAILURE:
        event = HI_SERVER_SWF_ZLIB_FAILURE;
        break;
    case FILE_DECOMP_ERR_SWF_LZMA_FAILURE:
        event = HI_SERVER_SWF_LZMA_FAILURE;
        break;
    case FILE_DECOMP_ERR_PDF_DEFL_FAILURE:
        event = HI_SERVER_PDF_DEFL_FAILURE;
        break;
    case FILE_DECOMP_ERR_PDF_UNSUP_COMP_TYPE:
        event = HI_SERVER_PDF_UNSUP_COMP_TYPE;
        break;
    case FILE_DECOMP_ERR_PDF_CASC_COMP:
        event = HI_SERVER_PDF_CASC_COMP;
        break;
    case FILE_DECOMP_ERR_PDF_PARSE_FAILURE:
        event = HI_SERVER_PDF_PARSE_FAILURE;
        break;
    }
    hi_set_event(GID_HTTP_SERVER, event);
}

static void InitFileDecomp(HttpSessionData* hsd, HI_SESSION* session)
{
    fd_session_p_t fd_session;

    if ((hsd == NULL) || (session == NULL) || (session->server_conf == NULL) ||
        (session->global_conf == NULL))
        return;

    if ( (fd_session = File_Decomp_New()) == (fd_session_p_t)NULL )
        return;

    hsd->fd_state = fd_session;
    fd_session->Modes = session->server_conf->file_decomp_modes;

    fd_session->Alert_Callback = LogFileDecomp;
    fd_session->Alert_Context = session;

    if ( (session->server_conf->unlimited_decompress) != 0 )
    {
        fd_session->Compr_Depth = 0;
        fd_session->Decompr_Depth = 0;
    }
    else
    {
        fd_session->Compr_Depth = session->global_conf->compr_depth;
        fd_session->Decompr_Depth = session->global_conf->decompr_depth;
    }

    (void)File_Decomp_Init(fd_session);
}

static void SetGzipBuffers(HttpSessionData* hsd, HI_SESSION* session)
{
    if ((hsd != NULL) && (hsd->decomp_state == NULL)
        && (session != NULL) && (session->server_conf != NULL)
        && (session->global_conf != NULL) && session->server_conf->extract_gzip)
    {
        hsd->decomp_state = (DECOMPRESS_STATE*)snort_calloc(sizeof(*hsd->decomp_state));

        if (session->server_conf->unlimited_decompress)
        {
            hsd->decomp_state->compr_depth = MAX_GZIP_DEPTH;
            hsd->decomp_state->decompr_depth = MAX_GZIP_DEPTH;
        }
        else
        {
            hsd->decomp_state->compr_depth = session->global_conf->compr_depth;
            hsd->decomp_state->decompr_depth = session->global_conf->decompr_depth;
        }
        hsd->decomp_state->inflate_init = 0;
    }
}

static int uncompress_gzip(u_char* dest, int destLen, const u_char* source,
    int sourceLen, HttpSessionData* sd, int* total_bytes_read, int compr_fmt)
{
    z_stream stream;
    int err;
    int iRet = HI_SUCCESS;

    stream = sd->decomp_state->d_stream;

    stream.next_in = (Bytef*)source;
    stream.avail_in = (uInt)sourceLen;
    if ((uLong)stream.avail_in != (uLong)sourceLen)
    {
        sd->decomp_state->d_stream = stream;
        return HI_FATAL_ERR;
    }

    stream.next_out = dest;
    stream.avail_out = (uInt)destLen;
    if ((uLong)stream.avail_out != (uLong)destLen)
    {
        sd->decomp_state->d_stream = stream;
        return HI_FATAL_ERR;
    }

    if (!sd->decomp_state->inflate_init)
    {
        sd->decomp_state->inflate_init = 1;
        stream.zalloc = (alloc_func)0;
        stream.zfree = (free_func)0;
        if (compr_fmt & HTTP_RESP_COMPRESS_TYPE__DEFLATE)
            err = inflateInit(&stream);
        else
            err = inflateInit2(&stream, GZIP_WBITS);
        if (err != Z_OK)
        {
            sd->decomp_state->d_stream = stream;
            return HI_FATAL_ERR;
        }
    }
    else
    {
        stream.total_in = 0;
        stream.total_out =0;
    }

    err = inflate(&stream, Z_SYNC_FLUSH);
    if ((!sd->decomp_state->deflate_initialized)
        && (err == Z_DATA_ERROR)
        && (compr_fmt & HTTP_RESP_COMPRESS_TYPE__DEFLATE))
    {
        /* Might not have zlib header - add one */
        static constexpr char zlib_header[2] = { 0x78, 0x01 };

        inflateReset(&stream);
        stream.next_in = (Bytef*)zlib_header;
        stream.avail_in = sizeof(zlib_header);

        sd->decomp_state->deflate_initialized = true;

        err = inflate(&stream, Z_SYNC_FLUSH);
        if (err == Z_OK)
        {
            stream.next_in = (Bytef*)source;
            stream.avail_in = (uInt)sourceLen;

            err = inflate(&stream, Z_SYNC_FLUSH);
        }
    }

    if ((err != Z_STREAM_END) && (err !=Z_OK))
    {
        /* If some of the compressed data is decompressed we need to provide that for detection */
        if (( stream.total_out > 0) && (err != Z_DATA_ERROR))
        {
            *total_bytes_read = stream.total_out;
            iRet = HI_NONFATAL_ERR;
        }
        else
            iRet = HI_FATAL_ERR;
        inflateEnd(&stream);
        sd->decomp_state->d_stream = stream;
        return iRet;
    }
    *total_bytes_read = stream.total_out;
    sd->decomp_state->d_stream = stream;
    return HI_SUCCESS;
}

static inline int hi_server_decompress(HI_SESSION* session, HttpSessionData* sd, const u_char* ptr,
    const u_char* end, URI_PTR* result)
{
    const u_char* start = ptr;
    int rawbuf_size = end - ptr;
    int iRet = HI_SUCCESS;
    int zRet = HI_FATAL_ERR;
    int compr_depth, decompr_depth;
    int compr_bytes_read, decompr_bytes_read;
    int compr_avail, decompr_avail;
    int total_bytes_read = 0;
    uint32_t updated_chunk_remainder = 0;
    uint32_t chunk_read = 0;
    uint32_t saved_chunk_size = 0;

    compr_depth = sd->decomp_state->compr_depth;
    decompr_depth = sd->decomp_state->decompr_depth;
    compr_bytes_read = sd->decomp_state->compr_bytes_read;
    decompr_bytes_read = sd->decomp_state->decompr_bytes_read;
    saved_chunk_size = sd->resp_state.chunk_remainder;

    if (session->server_conf->unlimited_decompress)
    {
        compr_avail = compr_depth;
        decompr_avail = decompr_depth;
    }
    else
    {
        compr_avail = compr_depth-compr_bytes_read;
        decompr_avail = decompr_depth - decompr_bytes_read;
    }

    /* Apply the server extract size
     * If the server extract size is set then we need to decompress only upto the
     * server flow depth
     */
    switch ( session->server_conf->server_extract_size)
    {
    case -1:
        decompr_avail=0;
        break;
    case 0:
        break;
    default:
        if (sd->resp_state.data_extracted < session->server_conf->server_extract_size)
        {
            if (decompr_avail > (session->server_conf->server_extract_size -
                sd->resp_state.data_extracted))
                decompr_avail = (int)(session->server_conf->server_extract_size -
                    sd->resp_state.data_extracted);
        }
        else
        {
            decompr_avail = 0;
        }
        break;
    }

    if ((compr_avail <= 0) || (decompr_avail <= 0))
    {
        (void)File_Decomp_Reset(sd->fd_state);
        ResetGzipState(sd->decomp_state);
        ResetRespState(&(sd->resp_state));
        return iRet;
    }

    if (rawbuf_size < compr_avail)
    {
        compr_avail = rawbuf_size;
    }

    if (!(sd->resp_state.last_pkt_contlen))
    {
        if (sd->resp_state.last_pkt_chunked
            && CheckChunkEncoding(session, start, end, NULL, dechunk_buffer, compr_avail,
            sd->resp_state.chunk_remainder, &updated_chunk_remainder, &chunk_read,
            sd, HI_SI_SERVER_MODE) == 1)
        {
            sd->resp_state.chunk_remainder = updated_chunk_remainder;
            compr_avail = chunk_read;
            zRet = uncompress_gzip(decompression_buffer, decompr_avail, dechunk_buffer,
                compr_avail, sd, &total_bytes_read, sd->decomp_state->compress_fmt);
        }
        else
        {
            /* No Content-Length or Transfer-Encoding : chunked */
            hi_set_event(GID_HTTP_SERVER, HI_SERVER_NO_CONTLEN);

            zRet = uncompress_gzip(decompression_buffer, decompr_avail, ptr, compr_avail,
                sd, &total_bytes_read, sd->decomp_state->compress_fmt);
        }
    }
    else
    {
        zRet = uncompress_gzip(decompression_buffer, decompr_avail, ptr, compr_avail,
            sd, &total_bytes_read, sd->decomp_state->compress_fmt);
    }

    if ((zRet == HI_SUCCESS) || (zRet == HI_NONFATAL_ERR))
    {
        sd->decomp_state->compr_bytes_read += compr_avail;
        hi_stats.compr_bytes_read += compr_avail;

        result->uri = decompression_buffer;
        if ( total_bytes_read < decompr_avail )
        {
            result->uri_end = decompression_buffer + total_bytes_read;
            sd->decomp_state->decompr_bytes_read += total_bytes_read;
            sd->resp_state.data_extracted += total_bytes_read;
            hi_stats.decompr_bytes_read += total_bytes_read;
        }
        else
        {
            result->uri_end = decompression_buffer + decompr_avail;
            sd->decomp_state->decompr_bytes_read += decompr_avail;
            sd->resp_state.data_extracted += decompr_avail;
            hi_stats.decompr_bytes_read += decompr_avail;
        }
    }
    else
    {
        if (!sd->decomp_state->decompr_bytes_read)
        {
            sd->resp_state.chunk_remainder = saved_chunk_size;
            iRet = HI_NONFATAL_ERR;
        }
        else
            ResetRespState(&(sd->resp_state));
        (void)File_Decomp_Reset(sd->fd_state);
        ResetGzipState(sd->decomp_state);
    }

    if (zRet!=HI_SUCCESS)
    {
        if (sd->decomp_state->decompr_bytes_read)
        {
            hi_set_event(GID_HTTP_SERVER, HI_SERVER_DECOMPR_FAILED);
        }
    }

    return iRet;
}

static inline int hi_server_inspect_body(HI_SESSION* session, HttpSessionData* sd, const
    u_char* ptr,
    const u_char* end, URI_PTR* result)
{
    int iRet = HI_SUCCESS;

    result->uri =ptr;
    result->uri_end = end;
    if (!session || !sd )
    {
        if ((sd != NULL))
        {
            (void)File_Decomp_Reset(sd->fd_state);
            ResetGzipState(sd->decomp_state);
            ResetRespState(&(sd->resp_state));
        }
        return HI_INVALID_ARG;
    }

    if ((sd->decomp_state != NULL) && sd->decomp_state->decompress_data)
    {
        iRet = hi_server_decompress(session, sd, ptr, end, result);
        if (iRet == HI_NONFATAL_ERR)
        {
            sd->resp_state.inspect_body = 1;
            result->uri = ptr;
            result->uri_end = end;
            iRet = hi_server_extract_body(session, sd, ptr, end, result);
        }
    }
    else
    {
        result->uri = ptr;
        result->uri_end = end;
        iRet = hi_server_extract_body(session, sd, ptr, end, result);
    }

    return iRet;
}

void ApplyFlowDepth(
    HTTPINSPECT_CONF* ServerConf, Packet* p,
    HttpSessionData* sd, int resp_header_size, int, uint32_t seq_num)
{
    if (!ServerConf->server_flow_depth)
    {
        SetDetectLimit(p, p->dsize);
    }
    else if (ServerConf->server_flow_depth == -1)
    {
        SetDetectLimit(p, resp_header_size);
    }
    else
    {
        if (sd != NULL)
        {
            if (!(sd->resp_state.flow_depth_excd ))
            {
                if (sd->resp_state.max_seq)
                {
                    if (SEQ_GEQ((sd->resp_state.max_seq), seq_num))
                    {
                        if (((uint32_t)p->dsize) > (sd->resp_state.max_seq- seq_num))
                        {
                            SetDetectLimit(p, (uint16_t)(sd->resp_state.max_seq-seq_num));
                            return;
                        }
                        else
                        {
                            SetDetectLimit(p, p->dsize);
                            return;
                        }
                    }
                    else
                    {
                        sd->resp_state.flow_depth_excd = true;
                        SetDetectLimit(p, resp_header_size);
                        return;
                    }
                }
                else
                {
                    sd->resp_state.flow_depth_excd = false;
                    SetDetectLimit(p, (((ServerConf->server_flow_depth) < p->dsize) ?
                        ServerConf->server_flow_depth : p->dsize));
                }
            }
            else
            {
                SetDetectLimit(p, 0);
                return;
            }
        }
        else
        {
            SetDetectLimit(p, (((ServerConf->server_flow_depth) < p->dsize) ?
                (ServerConf->server_flow_depth) : (p->dsize)));
        }
    }
}

static inline void ResetState(HttpSessionData* sd)
{
    (void)File_Decomp_Reset(sd->fd_state);
    ResetGzipState(sd->decomp_state);
    ResetRespState(&(sd->resp_state));
}

static int HttpResponseInspection(HI_SESSION* session, Packet* p, const unsigned char* data,
    int dsize, HttpSessionData* sd)
{
    HTTPINSPECT_CONF* ServerConf;
    URI_PTR stat_code_ptr;
    URI_PTR stat_msg_ptr;
    HEADER_PTR header_ptr;
    URI_PTR body_ptr;
    HI_SERVER* Server;

    const u_char* start;
    const u_char* end;
    const u_char* ptr;
    int len;
    int iRet = 0;
    int resp_header_size = 0;
    /* Refers to the stream reassembled packets when reassembly is turned on.
     * Refers to all packets when reassembly is turned off.
     */
    int not_stream_insert = 1;
    int parse_cont_encoding = 1;
    int expected_pkt = 0;
    unsigned alt_dsize;
    uint32_t seq_num = 0;

    if (!session || !p || !data || (dsize == 0))
        return HI_INVALID_ARG;

    ServerConf = session->server_conf;
    if (!ServerConf)
        return HI_INVALID_ARG;

    Server = &(session->server);
    headers = false;

    clearHttpRespBuffer(Server);

    seq_num = sd ? sd->resp_state.next_seq : 0;

    {
        expected_pkt = !p->is_pdu_start();
        parse_cont_encoding = !expected_pkt;
        not_stream_insert = p->has_paf_payload();

        if ( !expected_pkt )
        {
            simple_response = false;
            if ( sd )
            {
                ResetState(sd);
            }
        }
        else if ( sd )
        {
            if (hi_paf_simple_request(p->flow))
            {
                simple_response = true;
                if (!(sd->resp_state.next_seq))
                {
                    /*first simple response packet */
                    sd->resp_state.next_seq = seq_num + p->dsize;
                    if (ServerConf->server_flow_depth == -1)
                        sd->resp_state.flow_depth_excd = true;
                    else
                    {
                        sd->resp_state.flow_depth_excd = false;
                        sd->resp_state.max_seq = seq_num + ServerConf->server_flow_depth;
                    }
                }
            }
            else
                simple_response = false;

            if (ServerConf->server_extract_size)
            {
                /*Packet is beyond the extract limit*/
                if ( sd && (sd->resp_state.data_extracted > ServerConf->server_extract_size ))
                {
                    expected_pkt = 0;
                    ResetState(sd);
                }
            }
        }
    }
    // when PAF is hardened, the following can be removed
    if ( (sd != NULL) )
    {
        /* If the previously inspected packet in this session identified as a body
         * and if the packets are stream inserted wait for reassembled */
        if (sd->resp_state.inspect_reassembled)
        {
            if (p->packet_flags & PKT_STREAM_INSERT)
            {
                parse_cont_encoding = 0;
                not_stream_insert = 0;
            }
        }
        /* If this packet is the next expected packet to be inspected and is out of sequence
         * clear out the resp state*/
        if (( sd->decomp_state && sd->decomp_state->decompress_data) && parse_cont_encoding)
        {
            if ( sd->resp_state.next_seq &&
                (seq_num == sd->resp_state.next_seq) )
            {
                sd->resp_state.next_seq = seq_num + p->dsize;
                expected_pkt = 1;
            }
            else
            {
                (void)File_Decomp_Reset(sd->fd_state);
                ResetGzipState(sd->decomp_state);
                ResetRespState(&(sd->resp_state));
            }
        }
        else if (sd->resp_state.inspect_body && not_stream_insert)
        {
            /* If the server extrtact size is 0 then we need to check if the packet
             * is in sequence
             */
            if (!ServerConf->server_extract_size)
            {
                if ( sd->resp_state.next_seq &&
                    (seq_num == sd->resp_state.next_seq) )
                {
                    sd->resp_state.next_seq = seq_num + p->dsize;
                    expected_pkt = 1;
                }
                else
                {
                    (void)File_Decomp_Reset(sd->fd_state);
                    ResetGzipState(sd->decomp_state);
                    ResetRespState(&(sd->resp_state));
                }
            }
            else
            {
                if ( (ServerConf->server_extract_size > 0) &&(sd->resp_state.data_extracted >
                    ServerConf->server_extract_size))
                {
                    expected_pkt = 1;
                }
                else
                {
                    (void)File_Decomp_Reset(sd->fd_state);
                    ResetGzipState(sd->decomp_state);
                    ResetRespState(&(sd->resp_state));
                }
            }
        }
    }

    memset(&stat_code_ptr, 0x00, sizeof(URI_PTR));
    memset(&stat_msg_ptr, 0x00, sizeof(URI_PTR));
    memset(&header_ptr, 0x00, sizeof(HEADER_PTR));
    memset(&body_ptr, 0x00, sizeof(URI_PTR));

    start = data;
    end = data + dsize;
    ptr = start;

    /* moving past the CRLF */

    while (hi_util_in_bounds(start, end, ptr))
    {
        if (*ptr < 0x21)
        {
            if (*ptr < 0x0E && *ptr > 0x08)
            {
                ptr++;
                continue;
            }
            else
            {
                if (*ptr == 0x20)
                {
                    ptr++;
                    continue;
                }
            }
        }

        break;
    }

    /*after doing this we need to basically check for version, status code and status message*/

    len = end - ptr;
    if ( len > 4 )
    {
        if (!IsHttpVersion(&ptr, end))
        {
            if (expected_pkt)
            {
                ptr = start;
                p->packet_flags |= PKT_HTTP_DECODE;
            }
            else
            {
                p->packet_flags |= PKT_HTTP_DECODE;
                ApplyFlowDepth(ServerConf, p, sd, resp_header_size, 0, seq_num);
                if ( not_stream_insert && (sd != NULL))
                {
                    (void)File_Decomp_Reset(sd->fd_state);
                    ResetGzipState(sd->decomp_state);
                    ResetRespState(&(sd->resp_state));
                }
                CLR_SERVER_HEADER(Server);
                return HI_SUCCESS;
            }
        }
        else
        {
            headers = true;
            simple_response = false;
            p->packet_flags |= PKT_HTTP_DECODE;
            /* This is a next expected packet to be decompressed but the packet is a
             * valid HTTP response. So the gzip decompression ends here */
            if (expected_pkt)
            {
                expected_pkt = 0;
                if (sd != NULL)
                {
                    (void)File_Decomp_Reset(sd->fd_state);
                    ResetGzipState(sd->decomp_state);
                    ResetRespState(&(sd->resp_state));
                    sd->resp_state.flow_depth_excd = false;
                }
            }
            while (hi_util_in_bounds(start, end, ptr))
            {
                if (isspace((int)*ptr))
                    break;
                ptr++;
            }
        }
    }
    else if (!expected_pkt)
    {
        return HI_SUCCESS;
    }

    /*If this is the next expected packet to be decompressed, send this packet
     * decompression */

    if (expected_pkt)
    {
        if (hi_util_in_bounds(start, end, ptr))
        {
            hi_server_inspect_body(session, sd, ptr, end, &body_ptr);
        }
    }
    else
    {
        iRet = hi_server_extract_status_code(session, start,ptr,end, &stat_code_ptr);

        if ( iRet != HI_OUT_OF_BOUNDS )
        {
            Server->response.status_code = stat_code_ptr.uri;
            Server->response.status_code_size = stat_code_ptr.uri_end - stat_code_ptr.uri;
            if ( (int)Server->response.status_code_size <= 0)
            {
                CLR_SERVER_STAT(Server);
            }
            else
            {
                hi_server_extract_status_msg(start, stat_code_ptr.uri_end,
                    end, &stat_msg_ptr);

                if ( stat_msg_ptr.uri )
                {
                    Server->response.status_msg = stat_msg_ptr.uri;
                    Server->response.status_msg_size = stat_msg_ptr.uri_end - stat_msg_ptr.uri;
                    if ((int)Server->response.status_msg_size <= 0)
                    {
                        CLR_SERVER_STAT_MSG(Server);
                    }
                    {
                        ptr =  hi_server_extract_header(session, ServerConf, &header_ptr,
                            stat_msg_ptr.uri_end, end, parse_cont_encoding, sd);
                    }
                }
                else
                {
                    CLR_SERVER_STAT(Server);
                }
            }

            if (header_ptr.header.uri)
            {
                Server->response.header_raw = header_ptr.header.uri;
                Server->response.header_raw_size =
                    header_ptr.header.uri_end - header_ptr.header.uri;
                if (!Server->response.header_raw_size)
                {
                    CLR_SERVER_HEADER(Server);
                }
                else
                {
                    resp_header_size = (header_ptr.header.uri_end - p->data);
                    hi_stats.resp_headers++;
                    Server->response.header_norm = header_ptr.header.uri;
                    if (header_ptr.cookie.cookie)
                    {
                        hi_stats.resp_cookies++;
                        Server->response.cookie.cookie = header_ptr.cookie.cookie;
                        Server->response.cookie.cookie_end = header_ptr.cookie.cookie_end;
                        Server->response.cookie.next = header_ptr.cookie.next;
                    }
                    else
                    {
                        Server->response.cookie.cookie = NULL;
                        Server->response.cookie.cookie_end = NULL;
                        Server->response.cookie.next = NULL;
                    }
                    if (sd != NULL)
                    {
                        if ( header_ptr.content_encoding.compress_fmt )
                        {
                            hi_stats.gzip_pkts++;

                            /* We've got gzip data - grab buffer from mempool and attach
                             * to session data if server is configured to do so */
                            if (sd->decomp_state == NULL)
                                SetGzipBuffers(sd, session);

                            if (sd->decomp_state != NULL)
                            {
                                sd->decomp_state->decompress_data = 1;
                                sd->decomp_state->compress_fmt =
                                    header_ptr.content_encoding.compress_fmt;
                            }
                        }
                        else
                        {
                            sd->resp_state.inspect_body = 1;
                        }

                        if ( ServerConf->file_decomp_modes != 0 )
                        {
                            InitFileDecomp(sd, session);
                        }

                        sd->resp_state.last_pkt_contlen = (header_ptr.content_len.len != 0);
                        if (ServerConf->server_flow_depth == -1)
                            sd->resp_state.flow_depth_excd = true;
                        else
                        {
                            sd->resp_state.flow_depth_excd = false;
                            sd->resp_state.max_seq = seq_num +
                                (header_ptr.header.uri_end - start)+ ServerConf->server_flow_depth;
                        }

                        if (p->packet_flags & PKT_STREAM_INSERT)
                        {
                            if ( p->packet_flags & PKT_PDU_TAIL )
                                expected_pkt = 1;
                            else
                                sd->resp_state.inspect_reassembled = 1;
                        }
                        else
                        {
                            if (p->packet_flags & PKT_REBUILT_STREAM)
                                sd->resp_state.inspect_reassembled = 1;

                            expected_pkt = 1;
                        }
                        if (expected_pkt)
                        {
                            sd->resp_state.next_seq = seq_num + p->dsize;

                            if (hi_util_in_bounds(start, end, header_ptr.header.uri_end))
                            {
                                hi_server_inspect_body(session, sd, header_ptr.header.uri_end,
                                    end, &body_ptr);
                            }
                        }
                    }
                }
            }
            else
            {
                CLR_SERVER_HEADER(Server);
            }
        }
        else
        {
            CLR_SERVER_STAT(Server);
        }
    }

    if ( body_ptr.uri )
    {
        Server->response.body = body_ptr.uri;
        Server->response.body_size = body_ptr.uri_end - body_ptr.uri;
        if ( Server->response.body_size > 0)
        {
            if ( Server->response.body_size < sizeof(HttpDecodeBuf.data) )
            {
                alt_dsize = Server->response.body_size;
            }
            else
            {
                alt_dsize = sizeof(HttpDecodeBuf.data);
            }
            /* not checking if sd== NULL as the body_ptr.uri = NULL when sd === NULL in
              hi_server_inspect_body */
            if (sd && sd->decomp_state && sd->decomp_state->decompress_data)
            {
                if (alt_dsize > sizeof(HttpDecodeBuf.data))
                {
                    CLR_SERVER_HEADER(Server);
                    CLR_SERVER_STAT_MSG(Server);
                    CLR_SERVER_STAT(Server);
                    return HI_MEM_ALLOC_FAIL;
                }

                memcpy_s(HttpDecodeBuf.data, sizeof(HttpDecodeBuf.data),
                    Server->response.body, alt_dsize);

                SetHttpDecode((uint16_t)alt_dsize);
                Server->response.body = HttpDecodeBuf.data;
                Server->response.body_size = HttpDecodeBuf.len;
                sd->log_flags |= HTTP_LOG_GZIP_DATA;
            }
            else
            {
                if (sd && sd->resp_state.last_pkt_chunked)
                {
                    SetHttpDecode((uint16_t)alt_dsize);
                    Server->response.body = HttpDecodeBuf.data;
                    Server->response.body_size = HttpDecodeBuf.len;
                }
                else
                {
                    Server->response.body_size = alt_dsize;
                }
            }

            if ((get_decode_utf_state_charset(&(sd->utf_state)) != CHARSET_DEFAULT)
                || (ServerConf->normalize_javascript && Server->response.body_size))
            {
                if ( Server->response.body_size < sizeof(HttpDecodeBuf.data) )
                {
                    alt_dsize = Server->response.body_size;
                }
                else
                {
                    alt_dsize = sizeof(HttpDecodeBuf.data);
                }
                Server->response.body_size = alt_dsize;
                SetHttpDecode((uint16_t)alt_dsize);
            }
        }
    }
    ApplyFlowDepth(ServerConf, p, sd, resp_header_size, 1, seq_num);
    return HI_SUCCESS;
}

static int ServerInspection(HI_SESSION* session, Packet* p, HttpSessionData* hsd)
{
    int iRet;

    if ((p->data == NULL) || (p->dsize == 0))
    {
        return HI_INVALID_ARG;
    }

    if ( session->server_conf->inspect_response )
    {
        iRet = HttpResponseInspection(session, p, p->data, p->dsize, hsd);
    }
    else
    {
        iRet = IsHttpServerData(session, p, hsd);
    }

    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}

int hi_server_inspection(void* S, Packet* p, HttpSessionData* hsd)
{
    HI_SESSION* session;

    int iRet;

    if (!S )
    {
        return HI_INVALID_ARG;
    }

    session = (HI_SESSION*)S;

    /*
    **  Let's inspect the server response.
    */
    iRet = ServerInspection(session, p, hsd);
    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}

