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
**  @file       hi_client.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Main file for all the client functions and inspection
**              flow.
**
**
**  The job of the client module is to analyze and inspect the HTTP
**  protocol, finding where the various fields begin and end.  This must
**  be accomplished in a stateful and stateless manner.
**
**  While the fields are being determined, we also do checks for
**  normalization, so we don't normalize fields that don't need it.
**
**  Currently, the only fields we check for this is the URI and the
**  parameter fields.
**
**  NOTES:
**    - 3.8.03:  Initial development.  DJR
**    - 2.4.05:  Added tab_uri_delimiter config option.  AJM.
*/

#include "hi_client.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>

#include "hi_ui_config.h"
#include "hi_si.h"
#include "hi_mi.h"
#include "hi_util.h"
#include "hi_return_codes.h"
#include "hi_cmd_lookup.h"

#include "utils/util.h"
#include "utils/util_unfold.h"
#include "detection/detection_util.h"
#include "utils/safec.h"

#define HEADER_NAME__COOKIE "Cookie"
#define HEADER_LENGTH__COOKIE 6
#define HEADER_NAME__CONTENT_LENGTH "Content-length"
#define HEADER_LENGTH__CONTENT_LENGTH 14
#define HEADER_NAME__XFF HI_UI_CONFIG_XFF_FIELD_NAME
#define HEADER_LENGTH__XFF (sizeof(HEADER_NAME__XFF)-1)
#define HEADER_NAME__TRUE_IP HI_UI_CONFIG_TCI_FIELD_NAME
#define HEADER_LENGTH__TRUE_IP (sizeof(HEADER_NAME__TRUE_IP)-1)
#define HEADER_NAME__HOSTNAME "Host"
#define HEADER_LENGTH__HOSTNAME 4
#define HEADER_NAME__TRANSFER_ENCODING "Transfer-encoding"
#define HEADER_LENGTH__TRANSFER_ENCODING 17
#define HEADER_NAME__CONTENT_TYPE "Content-Type"
#define HEADER_LENGTH__CONTENT_TYPE 12

const u_char* proxy_start = NULL;
const u_char* proxy_end = NULL;

// FIXIT-H for 2.9.7 code not yet ported in
/*static const char *g_field_names[] =
{
    HEADER_NAME__COOKIE,
    HEADER_NAME__CONTENT_LENGTH,
    HEADER_NAME__XFF,
    HEADER_NAME__TRUE_IP,
    HEADER_NAME__HOSTNAME,
    HEADER_NAME__TRANSFER_ENCODING,
    HEADER_NAME__CONTENT_TYPE,
    NULL
};*/

/**  This makes passing function arguments much more readable and easier
**  to follow.
*/
typedef int (* LOOKUP_FCN)(HI_SESSION*, const u_char*, const u_char*, const u_char**,
    URI_PTR*);

/*
**  The lookup table contains functions for different HTTP delimiters
**  (like whitespace and the HTTP delimiter \r and \n).
*/
LOOKUP_FCN lookup_table[256];
/*
**  NAME
**    CheckChunkEncoding::
*/
/**
**  This routine checks for chunk encoding anomalies in an HTTP client request
**  packet.
**
**  We convert potential chunk lengths and test them against the user-defined
**  max chunk length.  We log events on any chunk lengths that are over this
**  defined chunk lengths.
**
**  Chunks are skipped to save time when the chunk is contained in the packet.
**
**  We assume coming into this function that we are pointed at the beginning
**  of what may be a chunk length.  That's why the iCheckChunk var is set
**  to 1.
**
**  @param session pointer to the session construct
**  @param start   pointer to where to beginning of buffer
**  @param end     pointer to the end of buffer
**
**  @return integer
**
**  @retval HI_SUCCESS      function successful
**  @retval HI_INVALID_ARG  invalid argument
*/
int CheckChunkEncoding(HI_SESSION* session, const u_char* start, const u_char* end,
    const u_char** post_end, u_char* iChunkBuf, uint32_t max_size,
    uint32_t chunk_remainder, uint32_t* updated_chunk_remainder, uint32_t* chunkRead,
    HttpSessionData* hsd,
    int iInspectMode)
{
    uint32_t iChunkLen   = 0;
    uint32_t iChunkChars = 0;
    int chunkPresent = 0;
    uint32_t iCheckChunk = 1;
    const u_char* ptr;
    const u_char* jump_ptr;
    uint32_t iDataLen = 0;
    uint32_t chunkBytesCopied = 0;
    uint8_t stateless_chunk_count = 0;
    bool alerted = false;

    if (!start || !end)
        return HI_INVALID_ARG;

    ptr = start;

    if (chunk_remainder)
    {
        iDataLen = end - ptr;

        if ( iDataLen < max_size)
        {
            if ( chunk_remainder > iDataLen )
            {
                if (updated_chunk_remainder)
                    *updated_chunk_remainder = chunk_remainder - iDataLen;
                chunk_remainder = iDataLen;
            }
        }
        else
        {
            if ( chunk_remainder > max_size )
            {
                if (updated_chunk_remainder)
                    *updated_chunk_remainder = chunk_remainder - max_size;
                chunk_remainder = max_size;
            }
        }

        jump_ptr = ptr + chunk_remainder - 1;

        if (hi_util_in_bounds(start, end, jump_ptr))
        {
            chunkPresent = 1;
            if (iChunkBuf)
            {
                memcpy(iChunkBuf, ptr, chunk_remainder);
                chunkBytesCopied = chunk_remainder;
            }
            ptr = jump_ptr + 1;
        }
    }

    while (hi_util_in_bounds(start, end, ptr))
    {
        if (*ptr == '\n')
        {
            if (iCheckChunk && iChunkLen != 0)
            {
                if ( (session->server_conf->chunk_length != 0)
                    && (iInspectMode == HI_SI_CLIENT_MODE)
                    && (session->server_conf->chunk_length < iChunkLen) )
                {
                    hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LARGE_CHUNK);
                }

                if (session->server_conf->small_chunk_length.size != 0)
                {
                    if (iChunkLen <= session->server_conf->small_chunk_length.size)
                    {
                        uint8_t* chunk_count;
                        unsigned gid, sid;

                        if (iInspectMode == HI_SI_CLIENT_MODE)
                        {
                            if (hsd)
                                chunk_count = &hsd->cli_small_chunk_count;
                            else
                                chunk_count = &stateless_chunk_count;
                            gid = GID_HTTP_CLIENT;
                            sid = HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS;
                        }
                        else
                        {
                            if (hsd)
                                chunk_count = &hsd->srv_small_chunk_count;
                            else
                                chunk_count = &stateless_chunk_count;
                            gid = GID_HTTP_SERVER;
                            sid = HI_SERVER_CONSECUTIVE_SMALL_CHUNKS;
                        }

                        (*chunk_count)++;
                        if ( *chunk_count >= session->server_conf->small_chunk_length.num )
                        {
                            if ( !alerted )
                            {
                                hi_set_event(gid, sid);
                                alerted = true;
                            }
                            *chunk_count = 0;
                        }
                    }
                    else
                    {
                        // Reset for non-consecutive small chunks
                        if (iInspectMode == HI_SI_CLIENT_MODE)
                        {
                            if (hsd)
                                hsd->cli_small_chunk_count = 0;
                            else
                                stateless_chunk_count = 0;
                        }
                        else
                        {
                            if (hsd)
                                hsd->srv_small_chunk_count = 0;
                            else
                                stateless_chunk_count = 0;
                        }
                    }
                }

                SkipBlankAndNewLine(start,end, &ptr);

                if (*ptr == '\n')
                    ptr++;

                if (!hi_util_in_bounds(start, end, ptr))
                {
                    if (updated_chunk_remainder)
                        *updated_chunk_remainder = iChunkLen;
                    break;
                }

                iDataLen = end - ptr;

                if ( iChunkLen > iDataLen)
                {
                    if (updated_chunk_remainder)
                        *updated_chunk_remainder = iChunkLen - iDataLen;
                    iChunkLen = iDataLen;
                }

                jump_ptr = ptr + iChunkLen;

                if (jump_ptr <= ptr)
                {
                    break;
                }

                /* Since we're doing a memcpy end and jump_ptr can be the same
                 * but hi_util_in_bounds ensures last arg is less than so
                 * subtract 1 from jump_ptr */
                if (hi_util_in_bounds(start, end, jump_ptr - 1))
                {
                    chunkPresent = 1;
                    if (iChunkBuf && ((chunkBytesCopied + iChunkLen) <= max_size))
                    {
                        memcpy(iChunkBuf+chunkBytesCopied, ptr, iChunkLen);
                        chunkBytesCopied += iChunkLen;
                    }
                    ptr = jump_ptr;

                    if (!hi_util_in_bounds(start, end, ptr))
                        break;

                    /* Check to see if the chunks ends - LF or CRLF are valid */
                    if (
                        (*ptr != '\n') && (*ptr != '\r')
                        && ((ptr + 1) < end) && (*(ptr + 1) != '\n') )
                    {
                        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_CHUNK_SIZE_MISMATCH);
                    }
                }
                else
                {
                    /*
                    **  Chunk too large for packet, so we bail
                    */
                    break;
                }
            }

            /*
            **  If we've already evaluated the chunk, or we have a valid delimiter
            **  for handling new chunks, we reset and starting evaluating possible
            **  chunk lengths.
            */
            if (iCheckChunk || (hi_util_in_bounds(start, end, ptr) && *ptr == '\n'))
            {
                iCheckChunk = 1;
                iChunkLen   = 0;
                iChunkChars = 0;
            }

            ptr++;
            continue;
        }

        if (iCheckChunk)
        {
            if (valid_lookup[*ptr] != HEX_VAL)
            {
                if (*ptr == '\r')
                {
                    ptr++;

                    if (!hi_util_in_bounds(start, end, ptr))
                        break;

                    if (*ptr == '\n')
                        continue;
                }
                else if (*ptr != '\n')
                {
                    /*
                     **  This is where we skip through the chunk name=value
                     ** field.
                     */
                    ptr = (u_char*)memchr(ptr, '\n', (end-ptr));
                    if (ptr == NULL)
                    {
                        ptr = end;
                        break;
                    }
                    else
                        continue;
                }

                iCheckChunk = 0;
                iChunkLen   = 0;
                iChunkChars = 0;
            }
            else
            {
                if (iChunkChars >= 8)
                {
                    if ( (session->server_conf->chunk_length != 0)
                        && (iInspectMode == HI_SI_CLIENT_MODE)
                        && (session->server_conf->chunk_length < iChunkLen) )
                    {
                        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LARGE_CHUNK);
                    }

                    iCheckChunk = 0;
                    iChunkLen   = 0;
                    iChunkChars = 0;
                }
                else
                {
                    iChunkLen <<= 4;
                    iChunkLen |= (unsigned int)(hex_lookup[*ptr]);
                    iChunkChars++;
                }
            }
        }

        ptr++;
    }
    if (chunkPresent )
    {
        if (post_end)
        {
            *(post_end) = ptr;
        }

        if (chunkRead)
        {
            *chunkRead = chunkBytesCopied;
        }
        return 1;
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    FindPipelineReq::
*/
/**
**  Catch multiple requests per packet, by returning pointer to after the
**  end of the request header if there is another request.
**
**  There are 4 types of "valid" delimiters that we look for.  They are:
**  "\r\n\r\n"
**  "\r\n\n"
**  "\n\r\n"
**  "\n\n"
**  The only patterns that we really only need to look for are:
**  "\n\r\n"
**  "\n\n"
**  The reason being that these two patterns are suffixes of the other
**  patterns.  So once we find those, we are all good.
**
**  @param session pointer to the session
**  @param start pointer to the start of text
**  @param end   pointer to the end of text
**
**  @return pointer
**
**  @retval NULL  Did not find pipeline request
**  @retval !NULL Found another possible request.
*/
static inline const u_char* FindPipelineReq(HI_SESSION* session,
    const u_char* start, const u_char* end)
{
    const u_char* p;
    u_char* offset;

    if (!start || !end)
        return NULL;

    p = start;

    offset = (u_char*)p;

    /*
    **  We say end - 6 because we need at least six bytes to verify that
    **  there is an end to the URI and still a request afterwards.  To be
    **  exact, we should only subtract 1, but we are not interested in a
    **  1 byte method, uri, etc.
    **
    **  a.k.a there needs to be data after the initial request to inspect
    **  to make it worth our while.
    */
    while (p < (end - 6))
    {
        if (*p == '\n')
        {
            if ( session->server_conf->max_hdr_len &&
                (p - offset) >= session->server_conf->max_hdr_len )
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HDR);
            }

            p++;

            offset = (u_char*)p;

            if (*p < 0x0E)
            {
                if (*p == '\r')
                {
                    p++;

                    if (*p == '\n')
                    {
                        return ++p;
                    }
                }
                else if (*p == '\n')
                {
                    return ++p;
                }
            }
        }

        p++;
    }

    /* Never observed an end-of-field.  Maybe it's not there, but the header is long anyway: */
    if ( session->server_conf->max_hdr_len &&
        (p - start) >= session->server_conf->max_hdr_len )
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HDR);
    }

    return NULL;
}

/*
**  NAME
**    NextNonWhiteSpace::
*/
/**
**  Update the URI_PTR fields spaces, find the next non-white space char,
**  and validate the HTTP version identifier after the spaces.
**
**  This is the main part of the URI algorithm.  This verifies that there
**  isn't too many spaces in the data to be a URI, it checks that after the
**  second space that there is an HTTP identifier or otherwise it's no good.
**  Also, if we've found an identifier after the first whitespace, and
**  find another whitespace, there is no URI.
**
**  The uri and uri_end pointers are updated in this function depending
**  on what space we are at, and if the space was followed by the HTTP
**  identifier.  (NOTE:  the HTTP delimiter is no longer "HTTP/", but
**  can also be "\r\n", "\n", or "\r".  This is the defunct method, and
**  we deal with it in the IsHttpVersion and delimiter functions.)
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       found the next non-whitespace
**  @retval HI_OUT_OF_BOUNDS whitespace to the end of the buffer
**  @retval URI_END          delimiter found, end of URI
**  @retval NO_URI
*/
static int NextNonWhiteSpace(HI_SESSION* session, const u_char* start,
    const u_char* end, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;
    const u_char** start_sp;
    const u_char** end_sp;

    /*
    **  Horizontal tab is only accepted by apache web servers, not IIS.
    **  Some IIS exploits contain a tab (0x09) in the URI, so we don't want
    **  to treat it as a URI delimiter and cut off the URI.
    */
    if ( **ptr == '\t' && !ServerConf->tab_uri_delimiter )
    {
        (*ptr)++;
        return HI_SUCCESS;
    }

    /*
    **  Reset the identifier, because we've just seen another space.  We
    **  should only see the identifier immediately after a space followed
    **  by a delimiter.
    */
    if (uri_ptr->ident)
    {
        if (ServerConf->non_strict)
        {
            /*
            **  In non-strict mode it is ok to see spaces after the
            **  "identifier", so we just increment the ptr and return.
            */
            (*ptr)++;
            return HI_SUCCESS;
        }
        else
        {
            /*
            **  This means that we've already seen a space and a version
            **  identifier, and now that we've seen another space, we know
            **  that this can't be the URI so we just bail out with no
            **  URI.
            */
            return NO_URI;
        }
    }

    uri_ptr->ident = NULL;

    /*
    **  We only check for one here, because both should be set if one
    **  is.
    */
    if (uri_ptr->first_sp_end)
    {
        /*
        **  If the second space has been set, then this means that we have
        **  seen a third space, which we shouldn't see in the URI so we
        **  are now done and know there is no URI in this packet.
        */
        if (uri_ptr->second_sp_end)
        {
            return NO_URI;
        }

        /*
        **  Treat whitespace differently at the end of the URI than we did
        **  at the beginning.  Ignore and return if special characters are
        **  not defined as whitespace after the URI.
        */
        if (ServerConf->whitespace[**ptr]
            && !(ServerConf->whitespace[**ptr] & HI_UI_CONFIG_WS_AFTER_URI))
        {
            (*ptr)++;
            return HI_SUCCESS;
        }

        /*
        **  Since we've seen the second space, we need to update the uri ptr
        **  to the end of the first space, since the URI cannot be before the
        **  first space.
        */
        uri_ptr->uri = uri_ptr->first_sp_end;

        uri_ptr->second_sp_start = *ptr;
        uri_ptr->second_sp_end = NULL;

        start_sp = &uri_ptr->second_sp_start;
        end_sp = &uri_ptr->second_sp_end;
    }
    else
    {
        /*
        **  This means that there is whitespace at the beginning of the line
        **  and we unset the URI so we can set it later if need be.
        **
        **  This is mainly so we handle data that is all spaces correctly.
        **
        **  In the normal case where we've seen text and then the first space,
        **  we leave the uri ptr pointing at the beginning of the data, and
        **  set the uri end after we've determined where to put it.
        */
        if (start == *ptr)
            uri_ptr->uri = NULL;

        uri_ptr->first_sp_start = *ptr;
        uri_ptr->first_sp_end = NULL;

        start_sp = &uri_ptr->first_sp_start;
        end_sp = &uri_ptr->first_sp_end;
    }

    while (hi_util_in_bounds(start, end, *ptr))
    {
        /*
        **  Check for whitespace
        */
        if (**ptr == ' ')
        {
            (*ptr)++;
            continue;
        }
        else if (ServerConf->whitespace[**ptr])
        {
            if (ServerConf->apache_whitespace.on)
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_APACHE_WS);
            }
            (*ptr)++;
            continue;
        }
        else
        {
            /*
            **  This sets the sp_end for whatever space delimiter we are on,
            **  whether that is the first space or the second space.
            */
            *end_sp = *ptr;

            if (!IsHttpVersion(ptr, end))
            {
                /*
                **  This is the default method and what we've been doing
                **  since the start of development.
                */
                if (uri_ptr->second_sp_start)
                {
                    /*
                    **  There is no HTTP version indentifier at the beginning
                    **  of the second space, and this means that there is no
                    **  URI.
                    */
                    if (ServerConf->non_strict)
                    {
                        /*
                        **  In non-strict mode, we must assume the URI is
                        **  between the first and second space, so now
                        **  that we've seen the second space that's the
                        **  identifier.
                        */
                        uri_ptr->ident  = *end_sp;
                        uri_ptr->uri_end = *start_sp;

                        return HI_SUCCESS;
                    }
                    else
                    {
                        /*
                        **  Since we are in strict mode here, it means that
                        **  we haven't seen a valid identifier, so there was
                        **  no URI.
                        */

                        return NO_URI;
                    }
                }

                /*
                **  RESET NECESSARY URI_PTRs HERE.  This is the place where
                **  the uri is updated.  It can only happen once, so do it
                **  right here.
                **
                **  When we get here it means that we have found the end of
                **  the FIRST whitespace, and that there was no delimiter,
                **  so we reset the uri pointers and other related
                **  pointers.
                */
                uri_ptr->uri      = *end_sp;
                uri_ptr->uri_end  = end;
                uri_ptr->norm     = NULL;
                uri_ptr->last_dir = NULL;
                uri_ptr->param    = NULL;
                uri_ptr->proxy    = NULL;
            }
            else
            {
                /*
                **  Means we found the HTTP version identifier and we reset
                **  the uri_end pointer to point to the beginning of the
                **  whitespace detected.
                **
                **  This works for both "uri_is_here HTTP/1.0" and
                **  "METHOD uri_is_here HTTP/1.0", so it works when the
                **  identifier is after either the first or the second
                **  whitespace.
                */
                uri_ptr->ident   = *end_sp;
                uri_ptr->uri_end = *start_sp;
            }

            /*
            **  We found a non-whitespace char
            */
            return HI_SUCCESS;
        }
    }

    /*
    **  This is the case where we've seen text and found a whitespace until
    **  the end of the buffer.  In that case, we set the uri_end to the
    **  beginning of the whitespace.
    */
    uri_ptr->uri_end = *start_sp;

    return HI_OUT_OF_BOUNDS;
}

/*
**  NAME
**    IsHttpVersion::
*/
/**
**  This checks that there is a version following a space with in an HTTP
**  packet.
**
**  This function gets called when a whitespace area has ended, and we want
**  to know if a version identifier is followed directly after.  So we look
**  for the rfc standard "HTTP/" and report appropriately.  We also need
**  to make sure that the function succeeds given an end of buffer, so for
**  instance if the buffer ends like "  HTT", we still assume that this is
**  a valid version identifier because of TCP segmentation.
**
**  We also check for the 0.9 standard of GET URI\r\n.  When we see a \r or
**  a \n, then we just return with the pointer still pointing to that char.
**  The reason is because on the next loop, we'll do the evaluation that
**  we normally do and finish up processing there.
**
**  @param start pointer to the start of the version identifier
**  @param end   pointer to the end of the buffer (could be the end of the
**               data section, or just to the beginning of the delimiter.
**
**  @return integer
**
**  @retval 1 this is an HTTP version identifier
**  @retval 0 this is not an HTTP identifier, or bad parameters
*/
int IsHttpVersion(const u_char** ptr, const u_char* end)
{
    static const u_char s_acHttpDelimiter[] = "HTTP/";
    static const int s_iHttpDelimiterLen = 5;
    int len;
    int iCtr;

    if (*ptr >= end)
    {
        return 0;
    }

    len = end - *ptr;
    if (len > s_iHttpDelimiterLen)
    {
        len = s_iHttpDelimiterLen;
    }

    /*
    **  This is where we check for the defunct method again.  This method
    **  allows a request of "GET   /index.html    \r[\n]".  So we need to
    **  check validate this as a legal identifier.
    */
    if (**ptr == '\n' || **ptr == '\r')
    {
        /*
        **  We don't increment the pointer because we check for a legal
        **  identifier in the delimiter checking.  Read the comments for
        **  setting the defunct variable in these functions.
        */
        return 1;
    }

    for (iCtr = 0; iCtr < len; iCtr++)
    {
        if (s_acHttpDelimiter[iCtr] != (u_char)toupper((int)**ptr))
        {
            return 0;
        }

        (*ptr)++;
    }

    /*
    **  This means that we match all the chars that we could given the
    **  remaining length so we should increment the pointer by that much
    **  since we don't need to inspect this again.
    */

    /* This pointer is not used again.   When 1 is returned it causes
     * NextNonWhiteSpace to return also.  */
#if 0
    (*ptr)++;
#endif

    return 1;
}

/*
**  NAME
**    find_rfc_delimiter::
*/
/**
**  Check for standard RFC HTTP delimiter.
**
**  If we find the delimiter, we return that URI_PTR structures should
**  be checked, which bails us out of the loop.  If there isn't a RFC
**  delimiter, then we bail with a no URI.  Otherwise, we check for out
**  of bounds.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_OUT_OF_BOUNDS
**  @retval URI_END end of the URI is found, check URI_PTR.
**  @retval NO_URI  malformed delimiter, no URI.
*/
static int find_rfc_delimiter(HI_SESSION* session, const u_char* start,
    const u_char* end, const u_char** ptr, URI_PTR* uri_ptr)
{
    if (*ptr == start || !uri_ptr->uri)
        return NO_URI;

    /*
    **  This is important to catch the defunct way of getting URIs without
    **  specifying "HTTP/major.minor\r\n\r\n".  This is a quick way for
    **  us to tell if we are in that state.
    **
    **  We check for a legal identifier to deal with the case of
    **  "some_of_the_uri_in segmented packet \r\n" in the defunct case.
    **  Since we find a "valid" (still defunct) delimiter, we account for
    **  it here, so that we don't set the uri_end to the delimiter.
    **
    **  NOTE:
    **  We now assume that the defunct method is in effect and if there is
    **  a valid identifier, then we don't update the uri_end because it's
    **  already been set when the identifier was validated.
    */

    (*ptr)++;
    if (!hi_util_in_bounds(start, end, *ptr))
    {
        return HI_OUT_OF_BOUNDS;
    }

    if (**ptr == '\n')
    {
        uri_ptr->delimiter = (*ptr)-1;

        if (!uri_ptr->ident)
            uri_ptr->uri_end = uri_ptr->delimiter;

        return URI_END;
    }

    return NextNonWhiteSpace(session, start, end, ptr, uri_ptr);
}

/*
**  NAME
**    find_non_rfc_delimiter::
*/
/**
**  Check for non standard delimiter '\n'.
**
**  It now appears that apache and iis both take this non-standard
**  delimiter.  So, we most likely will always look for it, but maybe
**  give off a special alert or something.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval URI_END delimiter found, end of URI
**  @retval NO_URI
*/
static int find_non_rfc_delimiter(
    HI_SESSION* session, const u_char* start,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;

    if (*ptr == start || !uri_ptr->uri)
        return NO_URI;

    /*
    **  This is important to catch the defunct way of getting URIs without
    **  specifying "HTTP/major.minor\r\n\r\n".  This is a quick way for
    **  us to tell if we are in that state.
    **
    **  We check for a legal identifier to deal with the case of
    **  "some_of_the_uri_in segmented packet \r\n" in the defunct case.
    **  Since we find a "valid" (still defunct) delimiter, we account for
    **  it here, so that we don't set the uri_end to the delimiter.
    **
    **  NOTE:
    **  We now assume that the defunct method is in effect and if there is
    **  a valid identifier, then we don't update the uri_end because it's
    **  already been set when the identifier was validated.
    */
    if (ServerConf->iis_delimiter.on)
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_IIS_DELIMITER);

        uri_ptr->delimiter = *ptr;

        if (!uri_ptr->ident)
            uri_ptr->uri_end = uri_ptr->delimiter;

        return URI_END;
    }

    /*
    **  This allows us to do something if the delimiter check is not turned
    **  on.  Most likely this is worthy of an alert, IF it's not normal to
    **  see these requests.
    **
    **  But for now, we always return true.
    */
    uri_ptr->delimiter = *ptr;

    if (!uri_ptr->ident)
        uri_ptr->uri_end = uri_ptr->delimiter;

    return URI_END;
}

/*
**  NAME
**    SetPercentNorm::
*/
/**
**  Check for percent normalization in the URI buffer.
**
**  We don't do much here besides check the configuration, set the pointer,
**  and continue processing.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
*/
static int SetPercentNorm(
    HI_SESSION* session, const u_char*,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;

    if (!uri_ptr->norm && !uri_ptr->ident)
    {
        if (ServerConf->ascii.on)
        {
            uri_ptr->norm = *ptr;
        }
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    CheckLongDir::
*/
/**
**  We check the directory length against the global config.
**
**  @param session pointer to the current session
**  @param uri_ptr pointer to the URI state
**  @param ptr     pointer to the current index in buffer
**
**  @return integer
**
**  @retval HI_SUCCESS
*/
static inline int CheckLongDir(HI_SESSION* session, URI_PTR* uri_ptr,
    const u_char* ptr)
{
    int iDirLen;

    /*
    **  Check for oversize directory
    */
    if (session->server_conf->long_dir &&
        uri_ptr->last_dir && !uri_ptr->param)
    {
        iDirLen = ptr - uri_ptr->last_dir;

        if ( iDirLen > session->server_conf->long_dir )
        {
            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_OVERSIZE_DIR);
        }
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    SetSlashNorm::
*/
/**
**  Check for any directory traversal or multi-slash normalization.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       function successful
**  @retval HI_OUT_OF_BOUNDS reached the end of the buffer
*/
static int SetSlashNorm(HI_SESSION* session, const u_char* start,
    const u_char* end, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;

    CheckLongDir(session, uri_ptr, *ptr);
    if ( proxy_start)
    {
        // This is the first dir after http://
        if (!uri_ptr->ident && !uri_ptr->last_dir)
            proxy_end = *ptr;
    }
    uri_ptr->last_dir = *ptr;

    if (!uri_ptr->norm && !uri_ptr->ident)
    {
        uri_ptr->norm = *ptr;

        (*ptr)++;

        if (!hi_util_in_bounds(start,end, *ptr))
        {
            /*
            **  This is the case where there is a slash as the last char
            **  and we don't want to normalize that since there really
            **  is nothing to normalize.
            */
            uri_ptr->norm = NULL;
            return HI_OUT_OF_BOUNDS;
        }

        /*
        **  Check for directory traversals
        */
        if (ServerConf->directory.on)
        {
            if (**ptr == '.')
            {
                (*ptr)++;
                if (!hi_util_in_bounds(start, end, *ptr))
                {
                    uri_ptr->norm = NULL;
                    return HI_OUT_OF_BOUNDS;
                }

                if (**ptr == '.' || **ptr == '/')
                {
                    return HI_SUCCESS;
                }
            }
        }

        /*
        **  Check for multiple slash normalization
        */
        if (ServerConf->multiple_slash.on)
        {
            if (**ptr == '/')
            {
                return HI_SUCCESS;
            }
        }

        uri_ptr->norm = NULL;
        return HI_SUCCESS;
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    SetBackSlashNorm::
*/
/**
**  Check for backslashes and if we need to normalize.
**
**  This really just checks the configuration option, and sets the norm
**  variable if applicable.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       function successful
*/
static int SetBackSlashNorm(
    HI_SESSION* session, const u_char*,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;

    if (!uri_ptr->norm && !uri_ptr->ident)
    {
        if (ServerConf->iis_backslash.on)
        {
            uri_ptr->norm = *ptr;
        }
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
 * **  NAME
 * **    SetPlusNorm::
 * */
/**
 * **  Check for "+" and if we need to normalize.
 * **
 * **
 * **  @param ServerConf pointer to the server configuration
 * **  @param start      pointer to the start of payload
 * **  @param end        pointer to the end of the payload
 * **  @param ptr        pointer to the pointer of the current index
 * **  @param uri_ptr    pointer to the URI_PTR construct
 * **
 * **  @return integer
 * **
 * **  @retval HI_SUCCESS       function successful
 * */

static int SetPlusNorm(
    HI_SESSION*, const u_char*,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    if (!uri_ptr->norm && !uri_ptr->ident)
    {
        uri_ptr->norm = *ptr;
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    SetBinaryNorm::
*/
/**
**  Look for non-ASCII chars in the URI.
**
**  We look for these chars in the URI and set the normalization variable
**  if it's not already set.  I think we really only need this for IIS
**  servers, but we may want to know if it's in the URI too.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       function successful
*/
static int SetBinaryNorm(
    HI_SESSION*, const u_char*,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    if (!uri_ptr->norm && !uri_ptr->ident)
    {
        uri_ptr->norm = *ptr;
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    SetParamField::
*/
/**
**  This function sets the parameter field as the first '?'.  The big thing
**  is that we set the param value, so we don't false positive long dir
**  events when it's really just a long parameter field.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       function successful
*/
static int SetParamField(
    HI_SESSION*, const u_char*,
    const u_char*, const u_char** ptr, URI_PTR* uri_ptr)
{
    if (!uri_ptr->ident)
    {
        uri_ptr->param = *ptr;
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    SetProxy::
*/
/**
**  This function checks for an absolute URI in the URI.
**
**  @param ServerConf pointer to the server configuration
**  @param start      pointer to the start of payload
**  @param end        pointer to the end of the payload
**  @param ptr        pointer to the pointer of the current index
**  @param uri_ptr    pointer to the URI_PTR construct
**
**  @return integer
**
**  @retval HI_SUCCESS       function successful
*/
static int SetProxy(HI_SESSION* session, const u_char* start,
    const u_char* end, const u_char** ptr, URI_PTR* uri_ptr)
{
    HTTPINSPECT_CONF* ServerConf = session->server_conf;

    if (!uri_ptr->ident && !uri_ptr->last_dir)
    {
        if (hi_util_in_bounds(start, end, ((*ptr)+2)))
        {
            if (*((*ptr)+1) == '/' && *((*ptr)+2) == '/')
            {
                if (session->global_conf->proxy_alert && !ServerConf->allow_proxy)
                    uri_ptr->proxy = *ptr;
                // If we found :// check to see if it is preceeded by http. If so, this is a proxy
                proxy_start = (u_char*)SnortStrcasestr((const char*)uri_ptr->uri, (*ptr -
                    uri_ptr->uri), "http");
                proxy_end = end;
                (*ptr) = (*ptr) + 3;
                return HI_SUCCESS;
            }
        }
    }

    (*ptr)++;

    return HI_SUCCESS;
}

/*
**  NAME
**    SetClientVars::
*/
/**
**  This is where we set the HI_CLIENT values that we found during URI
**  discovery.  This also covers checking these values for errors.
**
**  @param Client   pointer to HI_CLIENT structure
**  @param uri_ptr  pointer to the uri data
**
**  @return integer
**
**  @retval HI_NONFATAL_ERR problem with the uri values.
**  @retval HI_SUCCESS      values set successfully
*/
static int SetClientVars(HI_CLIENT* Client, URI_PTR* uri_ptr, u_int dsize)
{
    /*
    **  We got here either because we found the delimiter or we are
    **  out of bounds.
    */

    /*
    if(uri_ptr->first_sp_start)
        printf("** first_start  = %c\n", *uri_ptr->first_sp_start);
    if(uri_ptr->first_sp_end)
        printf("** first_end    = %c\n", *uri_ptr->first_sp_end);
    if(uri_ptr->second_sp_start)
        printf("** second_start = %c\n", *uri_ptr->second_sp_start);
    if(uri_ptr->second_sp_end)
        printf("** second_end   = %c\n", *uri_ptr->second_sp_end);
    if(uri_ptr->delimiter)
        printf("** delimiter    = %c\n", *uri_ptr->delimiter);
    if(uri_ptr->uri)
        printf("** uri          = %c\n", *uri_ptr->uri);
    if(uri_ptr->norm)
        printf("** norm         = %.2x\n", *uri_ptr->norm);
    */

    /*
    **  This means that there was only spaces or delimiters within the
    **  complete URI.  In this case, there is no valid URI so we just
    **  return such.
    */
    if (uri_ptr->uri == NULL)
    {
        return HI_NONFATAL_ERR;
    }

    /*
    **  This is where we set the session variables before moving into more
    **  HttpInspect processing.  If we don't get to this point, then we don't
    **  need to set these variables since we would have aborted with a
    **  NONFATAL_ERR.
    */
    Client->request.uri      = uri_ptr->uri;
    Client->request.uri_size = uri_ptr->uri_end - uri_ptr->uri;
    Client->request.uri_norm = uri_ptr->norm;

    /*
    **  LAST RESORT:
    **
    **  This is one of the last checks we do to make sure that we didn't
    **  mess up or anything.
    */
    if (Client->request.uri_size > dsize)
    {
        return HI_NONFATAL_ERR;
    }

    /*
    printf("** Norm = %s\n", Client->request.uri_norm ? "YES" : "NO");
    printf("** URI: |%.*s| size = %u\n", Client->request.uri_size,
           Client->request.uri, Client->request.uri_size);
    */

    return HI_SUCCESS;
}

static inline int hi_client_extract_post(
    HI_SESSION* session, HTTPINSPECT_CONF* ServerConf,
    const u_char* ptr, const u_char* end, URI_PTR* result,
    int content_length, bool is_chunked, HttpSessionData* hsd)
{
    const u_char* start = ptr;
    const u_char* post_end = end;

    session->norm_flags &= HI_BODY;

    /* Limit search depth */
    if (is_chunked)
    {
        if ( (ServerConf->chunk_length || ServerConf->small_chunk_length.size)
            && (CheckChunkEncoding(session, start, end, &post_end, NULL, 0,
            0, NULL, NULL, hsd, HI_SI_CLIENT_MODE) == 1) )
        {
            result->uri = start;
            result->uri_end = post_end;
            return POST_END;
        }
        else
        {
            return HI_NONFATAL_ERR;
        }
    }
    else if (content_length > 0)
    {
        if ((post_end - ptr ) > content_length)
        {
            post_end = ptr + content_length;
        }
    }
    else
    {
        return HI_NONFATAL_ERR;
    }

    result->uri = start;
    result->uri_end = post_end;

    return POST_END;
}

static inline int HTTP_CopyExtraDataTosession(const uint8_t* start, int length, int command_type,
    HTTP_LOG_STATE* log_state)
{
    uint8_t* alt_buf;
    uint32_t alt_size;
    uint32_t* alt_len;

    if (length <= 0)
        return -1;

    switch (command_type)
    {
    case COPY_URI:
        alt_buf = log_state->uri_extracted;
        alt_size = MAX_URI_EXTRACTED;
        alt_len = &(log_state->uri_bytes);
        break;

    case COPY_HOSTNAME:
        alt_buf = log_state->hostname_extracted;
        alt_size = MAX_HOSTNAME;
        alt_len = &(log_state->hostname_bytes);
        break;

    default:
        return -1;
    }

    if (length > (int)alt_size)
        length = alt_size;

    *alt_len = 0;

    memcpy_s(alt_buf, alt_size, start, length);

    *alt_len += length;

    return 0;
}

static inline void HTTP_CopyUri(
    HTTPINSPECT_CONF* /*ServerConf*/, const u_char* start, const u_char* end,
    HttpSessionData* hsd, int stream_ins)
{
    int iRet = 0;
    const u_char* cur_ptr;

    cur_ptr = start;

    if (/*ServerConf->log_uri &&*/ !stream_ins && hsd)  // FIXIT-L move back to ServerConf?
    {
        SkipBlankSpace(start,end,&cur_ptr);

        start = cur_ptr;
        if (!SetLogBuffers(hsd))
        {
            iRet = HTTP_CopyExtraDataTosession((uint8_t*)start, (end - start), COPY_URI,
                hsd->log_state);
            if (!iRet)
                hsd->log_flags |= HTTP_LOG_URI;
        }
    }
}

static inline int unfold_http_uri(HTTPINSPECT_CONF* ServerConf, const u_char* end,
    URI_PTR* uri_ptr, HttpSessionData* hsd, int stream_ins)
{
    uint8_t unfold_buf[DECODE_BLEN];
    uint32_t unfold_size =0;
    const u_char* p;
    int folded = 0;
    const char* tmp = NULL;
    int iRet = -1;

    p =  uri_ptr->uri;

    sf_unfold_header(p, (end - p), unfold_buf, sizeof(unfold_buf), &unfold_size, 0, &folded);

    if ( !folded)
    {
        HTTP_CopyUri(ServerConf, uri_ptr->uri, uri_ptr->uri_end, hsd, stream_ins);
        return iRet;
    }

    tmp = SnortStrnPbrk((const char*)unfold_buf, unfold_size, " \t");

    if (tmp != NULL)
    {
        unfold_size = ((uint8_t*)tmp - unfold_buf);
        iRet = 0;
    }

    p = p + unfold_size;
    uri_ptr->uri_end = p;

    HTTP_CopyUri(ServerConf, unfold_buf, unfold_buf + unfold_size, hsd, stream_ins);

    return iRet;
}

static inline int hi_client_extract_uri(
    HI_SESSION* session, HTTPINSPECT_CONF* ServerConf,
    HI_CLIENT* Client, const u_char* start, const u_char* end,
    const u_char* ptr, URI_PTR* uri_ptr, HttpSessionData* hsd, int stream_ins)
{
    int iRet = HI_SUCCESS;
    const u_char* tmp;
    int uri_copied = 0;

    session->norm_flags &= ~HI_BODY;

    /*
    **  This loop compares each char to an array of functions
    **  (one for each char) and calling that function if there is one.
    **
    **  If there is no function, then we just increment the char ptr and
    **  continue processing.
    **
    **  If there is a function, we call that function and process.  It's
    **  important to note that the function that is called is responsible
    **  for incrementing the ptr to the next char to be inspected.  The
    **  loop does not increment the pointer when a function is called to
    **  allow the maximum flexibility to the functions.
    */

    while (hi_util_in_bounds(start, end, ptr))
    {
        if (!ServerConf->extended_ascii_uri)
        {
            /* isascii returns non-zero if it is ascii */
            if (isascii((int)*ptr) == 0)
            {
                /* Possible post data or something else strange... */
                iRet = URI_END;
                /* Find the end of the URI in this case*/
                tmp = (const u_char*)SnortStrnPbrk((const char*)ptr, (uri_ptr->uri_end - ptr),
                    " \r\n\t");
                if (tmp != NULL)
                    uri_ptr->uri_end = tmp;

                if (!uri_copied)
                {
                    HTTP_CopyUri(ServerConf, uri_ptr->uri, uri_ptr->uri_end, hsd, stream_ins);
                }
                break;
            }
        }

        if (lookup_table[*ptr] || ServerConf->whitespace[*ptr])
        {
            if (lookup_table[*ptr])
            {
                iRet = (lookup_table[*ptr])(session, start, end,
                    &ptr, uri_ptr);
            }
            else
            {
                iRet = NextNonWhiteSpace(session, start, end, &ptr, uri_ptr);
            }

            if (iRet)
            {
                if (iRet == URI_END)
                {
                    if ((*(uri_ptr->uri_end) == '\n') || (*(uri_ptr->uri_end) == '\r') )
                    {
                        uri_copied = 1;
                        if (!unfold_http_uri(ServerConf, end, uri_ptr, hsd, stream_ins))
                        {
                            SkipCRLF(start,end, &ptr);
                            continue;
                        }
                    }
                    else if (!uri_copied)
                    {
                        HTTP_CopyUri(ServerConf, uri_ptr->uri, uri_ptr->uri_end, hsd, stream_ins);
                    }
                    /*
                    **  You found a URI, let's break and check it out.
                    */
                    break;
                }
                else if (iRet == HI_OUT_OF_BOUNDS)
                {
                    /*
                    **  Means you've reached the end of the buffer.  THIS
                    **  DOESN'T MEAN YOU HAVEN'T FOUND A URI.
                    */
                    break;
                }
                else /* NO_URI */
                {
                    /*
                    **  Check for chunk encoding, because the delimiter can
                    **  also be a space, which would look like a pipeline request
                    **  to us if we don't do this first.
                    */
                    if (session->server_conf->chunk_length ||
                        session->server_conf->small_chunk_length.size)
                    {
                        (void)CheckChunkEncoding(session, start, end, NULL, NULL, 0,
                            0, NULL, NULL, hsd, HI_SI_CLIENT_MODE);
                    }

                    /*
                    **  We only inspect the packet for another pipeline
                    **  request if there wasn't a previous pipeline request.
                    **  The reason that we do this is because
                    */
                    if (!Client->request.pipeline_req)
                    {
                        /*
                        **  Just because there was no URI in the first part
                        **  the packet, doesn't mean that this isn't a
                        **  pipelined request that has been segmented.
                        */
                        if (!ServerConf->no_pipeline)
                        {
                            Client->request.pipeline_req = FindPipelineReq(session, ptr, end);
                            if (Client->request.pipeline_req)
                            {
                                return HI_SUCCESS;
                            }
                        }
                    }

                    return HI_NONFATAL_ERR;
                }
            }
            else
            {
                /*
                **  This means that we found the next non-whitespace char
                **  and since we are already pointed there, so we just
                **  continue.
                */
                continue;
            }
        }

        ptr++;
    }
    /* No uri in this request. We shouldn't process this request */
    if (uri_ptr->uri == uri_ptr->uri_end)
        return HI_NONFATAL_ERR;
    return iRet;
}

const u_char* extract_http_cookie(
    const u_char* p, const u_char* end, HEADER_PTR* header_ptr,
    HEADER_FIELD_PTR* header_field_ptr)
{
    const u_char* crlf;
    const u_char* start;
    if (header_ptr->cookie.cookie)
    {
        /* unusal, multiple cookies... alloc new cookie pointer */
        COOKIE_PTR* extra_cookie = (COOKIE_PTR*)snort_calloc(sizeof(*extra_cookie));
        extra_cookie->next = header_ptr->cookie.next;
        header_ptr->cookie.next = extra_cookie;
        header_field_ptr->cookie = extra_cookie;
    }
    else
    {
        header_field_ptr->cookie = &header_ptr->cookie;
    }

    start = p;
    /* skip spaces before : */
    SkipBlankSpace(start,end,&p);
    if (hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        SkipBlankSpace(start,end,&p);
    }

    header_field_ptr->cookie->cookie = p;

    {
        crlf = (u_char*)SnortStrnStr((const char*)p, end - p, "\n");

        /* find a \n  */
        if (crlf) /* && hi_util_in_bounds(start, end, crlf+1)) bounds is checked in SnortStrnStr */
        {
            if (*(crlf -1) == '\r')
                header_field_ptr->cookie->cookie_end = crlf - 1;
            else
                header_field_ptr->cookie->cookie_end = crlf;

            p = crlf;
        }
        else
        {
            header_ptr->header.uri_end = header_field_ptr->cookie->cookie_end = end;
            return end;
        }
    }
    return p;
}

static const u_char* extract_http_xff(HI_SESSION* session, const u_char* p, const u_char* start,
    const u_char* end, HI_CLIENT_HDR_ARGS* hdrs_args)
{
    int num_spaces = 0;
    SFIP_RET status;
    sfip_t* tmp;
    char* ipAddr = NULL;
    uint8_t unfold_buf[DECODE_BLEN];
    uint32_t unfold_size =0;
    const u_char* start_ptr, * end_ptr, * cur_ptr;
    const u_char* port;
    HEADER_PTR* header_ptr;
    sfip_t** true_ip;

    header_ptr = hdrs_args->hdr_ptr;
    true_ip = &(hdrs_args->sd->true_ip);

    if (!true_ip)
        return p;

    if ( (hdrs_args->true_clnt_xff & (HDRS_BOTH | XFF_HEADERS)) == HDRS_BOTH)
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_BOTH_TRUEIP_XFF_HDRS);
    }

    SkipBlankSpace(start,end,&p);

    if (hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        if (hi_util_in_bounds(start, end, p))
            sf_unfold_header(p, end-p, unfold_buf, sizeof(unfold_buf), &unfold_size, 0,
                &num_spaces);

        if (!unfold_size)
        {
            header_ptr->header.uri_end = end;
            return end;
        }

        if ( session->server_conf->max_spaces &&
            num_spaces >= session->server_conf->max_spaces )
        {
            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_EXCEEDS_SPACES);
        }

        p = p + unfold_size;

        start_ptr = unfold_buf;
        cur_ptr = unfold_buf;
        end_ptr = unfold_buf + unfold_size;
        SkipBlankSpace(start_ptr,end_ptr,&cur_ptr);

        start_ptr = cur_ptr;
        while ( cur_ptr < end_ptr )
        {
            if ( *cur_ptr == ' ' || *cur_ptr == '\t' ||
                *cur_ptr == ',' )
                break;
            cur_ptr++;
        }

        if (cur_ptr - start_ptr)
        {
            ipAddr = SnortStrndup((const char*)start_ptr, cur_ptr - start_ptr);
        }
        if (ipAddr)
        {
            if ( (tmp = sfip_alloc(ipAddr, &status)) == NULL )
            {
                port = (u_char*)SnortStrnStr((const char*)start_ptr, (cur_ptr - start_ptr), ":");
                if (port)
                {
                    snort_free(ipAddr);
                    ipAddr = SnortStrndup((const char*)start_ptr, port - start_ptr);
                    if ( !ipAddr)
                    {
                        return p;
                    }
                    if ( (tmp = sfip_alloc(ipAddr, &status)) == NULL )
                    {
                        if ((status != SFIP_ARG_ERR) && (status !=SFIP_ALLOC_ERR))
                        {
                            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_INVALID_TRUEIP);
                            return p;
                        }
                    }
                }
                else if ((status != SFIP_ARG_ERR) && (status !=SFIP_ALLOC_ERR))
                {
                    hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_INVALID_TRUEIP);
                    snort_free(ipAddr);
                    return p;
                }
            }
            /* At this point we have a new/valid IP from the header being processed.
               If we are using custom xff headers, check the precedence ranking. */
            if ( (hdrs_args->true_clnt_xff & XFF_HEADERS) != 0 )
            {
                /* Have we located any others? */
                if ( (hdrs_args->top_precedence > 0) &&
                    (hdrs_args->new_precedence >= hdrs_args->top_precedence) )
                {
                    sfip_free(tmp);
                    snort_free(ipAddr);
                    return( p );
                }

                hdrs_args->top_precedence = hdrs_args->new_precedence;

                /* if we find the top precedence, no need to continue
                   looking so clear the XFF_HEADERS_ACTIVE flag. */
                if ( hdrs_args->top_precedence == XFF_TOP_PRECEDENCE )
                    hdrs_args->true_clnt_xff &= (~XFF_HEADERS_ACTIVE);
            }

            /* If we have already set a 'true_ip' for the session, look to see if the
               new IP differs from the current IP. If so, replace it and post an alert. */
            if (*true_ip)
            {
                if (!sfip_equals(*true_ip, tmp))
                {
                    sfip_free(*true_ip);
                    *true_ip = tmp;

                    if ((hdrs_args->true_clnt_xff & XFF_HEADERS) == 0)
                        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION);
                }
                else
                    sfip_free(tmp);
            }
            else
                *true_ip = tmp;
            snort_free(ipAddr);
        }
    }
    else
    {
        header_ptr->header.uri_end = end;
        return end;
    }

    return p;
}

static const u_char* extract_http_hostname(HI_SESSION* session, const u_char* p, const u_char* start,
    const u_char* end, HEADER_PTR* header_ptr, HttpSessionData* hsd)
{
    int num_spaces = 0;
    uint8_t unfold_buf[DECODE_BLEN];
    uint32_t unfold_size =0;
    const u_char* start_ptr, * end_ptr, * cur_ptr;
    int iRet=0;

    SkipBlankSpace(start,end,&p);

    if (hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        if (hi_util_in_bounds(start, end, p))
            sf_unfold_header(p, end-p, unfold_buf, sizeof(unfold_buf), &unfold_size, 0,
                &num_spaces);

        if (!unfold_size)
        {
            header_ptr->header.uri_end = end;
            return end;
        }

        if ( session->server_conf->max_spaces &&
            num_spaces >= session->server_conf->max_spaces )
        {
            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_EXCEEDS_SPACES);
        }
        p = p + unfold_size;

        start_ptr = unfold_buf;
        cur_ptr = unfold_buf;
        end_ptr = unfold_buf + unfold_size;
        SkipBlankSpace(start_ptr,end_ptr,&cur_ptr);

        start_ptr = cur_ptr;

        if ((end_ptr - start_ptr) >= MAX_HOSTNAME)
        {
            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HOSTNAME);
        }

        iRet = HTTP_CopyExtraDataTosession((uint8_t*)start_ptr, (end_ptr - start_ptr),
            COPY_HOSTNAME, hsd->log_state);
        if (!iRet)
        {
            hsd->log_flags |= HTTP_LOG_HOSTNAME;
        }
    }
    else
    {
        header_ptr->header.uri_end = end;
        return end;
    }

    return p;
}

const u_char* extract_http_content_length(HI_SESSION* session,
    HTTPINSPECT_CONF* ServerConf, const u_char* p, const u_char* start,
    const u_char* end, HEADER_PTR* header_ptr, HEADER_FIELD_PTR* header_field_ptr)
{
    int num_spaces = 0;
    const u_char* crlf;
    int space_present = 0;
    if (header_ptr->content_len.cont_len_start)
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_MULTIPLE_CONTLEN);
        header_ptr->header.uri_end = p;
        header_ptr->content_len.len = 0;
        return p;
    }
    else
    {
        header_field_ptr->content_len = &header_ptr->content_len;
        p = p + 14;
    }
    /* Move past all the blank spaces. Only tabs and spaces are allowed here */
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
                                num_spaces++;
                            }
                            if ( space_present )
                            {
                                if ( session->server_conf->max_spaces &&
                                    num_spaces >= session->server_conf->max_spaces )
                                {
                                    hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_EXCEEDS_SPACES);
                                }
                                if ( isdigit((int)*p))
                                    break;
                                else if (isspace((int)*p) &&
                                    (ServerConf->profile == HI_APACHE || ServerConf->profile ==
                                    HI_DEFAULT) )
                                {
                                    SkipWhiteSpace(start,end,&p);
                                }
                                else
                                {
                                    header_field_ptr->content_len->cont_len_start =
                                        header_field_ptr->content_len->cont_len_end = NULL;
                                    header_field_ptr->content_len->len = 0;
                                    return p;
                                }
                            }
                            else
                            {
                                header_field_ptr->content_len->cont_len_start =
                                    header_field_ptr->content_len->cont_len_end = NULL;
                                header_field_ptr->content_len->len = 0;
                                return p;
                            }
                        }
                        else
                            break;
                    }
                }
                else if (!isdigit((int)*p))
                {
                    header_field_ptr->content_len->cont_len_start =
                        header_field_ptr->content_len->cont_len_end = NULL;
                    header_field_ptr->content_len->len = 0;
                    return p;
                }
                if (isdigit((int)*p))
                {
                    header_field_ptr->content_len->cont_len_start = p;
                    p++;
                    while (hi_util_in_bounds(start, end, p))
                    {
                        if (isdigit((int)*p))
                        {
                            p++;
                            continue;
                        }
                        else if ((*p == '\n')) /* digit followed by \n */
                        {
                            header_field_ptr->content_len->cont_len_end = p;
                            break;
                        }
                        else if ( (!isdigit((int)*p)) && (!isspace((int)*p))) /* alphabet after
                                                                                digit*/
                        {
                            header_field_ptr->content_len->cont_len_start =
                                header_field_ptr->content_len->cont_len_end = NULL;
                            header_field_ptr->content_len->len = 0;

                            crlf = (u_char*)SnortStrnStr((const char*)p, end - p, "\n");
                            if (crlf)
                            {
                                return p;
                            }
                            else
                            {
                                header_ptr->header.uri_end = end;
                                return end;
                            }
                        }
                        else
                        {
                            if (ServerConf->profile == HI_APACHE || ServerConf->profile ==
                                HI_DEFAULT)
                            {
                                SkipWhiteSpace(start,end,&p);
                            }
                            else
                            {
                                SkipBlankAndNewLine(start,end,&p);
                            }
                            if ( *p == '\n' )
                            {
                                header_field_ptr->content_len->cont_len_end = p;
                                break;
                            }
                            else /*either a "digit digit" or "digit other character" */
                            {
                                header_field_ptr->content_len->cont_len_start =
                                    header_field_ptr->content_len->cont_len_end = NULL;
                                header_field_ptr->content_len->len = 0;
                                crlf = (u_char*)SnortStrnStr((const char*)p, end - p, "\n");
                                if (crlf)
                                {
                                    p = crlf;
                                    return p;
                                }
                                else
                                {
                                    header_ptr->header.uri_end = end;
                                    return end;
                                }
                            }
                        }
                    }
                }
                else
                {
                    header_field_ptr->content_len->cont_len_start =
                        header_field_ptr->content_len->cont_len_end = NULL;
                    header_field_ptr->content_len->len = 0;
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
    if ( header_field_ptr->content_len->cont_len_start &&
        header_field_ptr->content_len->cont_len_end )
    {
        char* pcEnd;
        uint64_t len;
        len = (uint64_t)SnortStrtol((char*)header_field_ptr->content_len->cont_len_start, &pcEnd,
            10);

        if ( (errno == ERANGE)
            || ((char*)header_field_ptr->content_len->cont_len_start == pcEnd)
            || (len > 0xFFFFFFFF) )
        {
            header_field_ptr->content_len->len = 0;
        }
        else
            header_field_ptr->content_len->len = (uint32_t)len;
    }
    if (!p || !hi_util_in_bounds(start, end, p))
        p = end;

    return p;
}

static inline bool IsXFFFieldName(HI_CLIENT_HDR_ARGS* hdrs_args,
    u_char** pp, const u_char* end,
    uint8_t** Field_Names, uint8_t* Field_Length)
{
    int i;
    int len;
    uint8_t* header_ptr;
    uint8_t* field_ptr;

    i = 0;        // index into the list of XFF field names
    field_ptr = NULL; // pointer into the active Field_Name entry
    header_ptr = *pp;  // pointer into the header, will not step past 'end'
    len = 0;      // len of the matched name entry

    while ( true )
    {
        /* If we run off the end of the active table, or table is truncated then
           we can stop.  We didn't locate a match. */
        if ( (i >= (HI_UI_CONFIG_MAX_XFF_FIELD_NAMES)) || (Field_Names[i] == NULL) )
            break;

        if ( field_ptr == NULL )  // didn't start to match any entry
        {
            /* If the length doesn't permit a match, move on.  */
            if ( (end - *pp) < Field_Length[i] )
            {
                i += 1;
                continue;
            }

            if ( toupper(*header_ptr) == *Field_Names[i] )  // does the first char match?
            {
                /* set our working pointer to the field name */
                field_ptr = (Field_Names[i] + 1);
                header_ptr += 1;
                len = 1;   // We matched one character
                continue;
            }
            i += 1;
        }
        else
        {
            /* If we are still matching and we get to the end
               of the field name, then we've located a name match */
            if ( *field_ptr == 0 )  // End of the field name
            {
                *pp += len;  // Step input pointer over what we found
                hdrs_args->new_precedence = (i+1);  // Precedence started with one
                return( true );
            }
            else
            {
                /* check for another matching character */
                if ( toupper(*header_ptr) == *field_ptr )
                {
                    header_ptr += 1;
                    field_ptr += 1;
                    len += 1;
                }
                else
                {
                    header_ptr = *pp;  // Back to the start for the name
                    field_ptr = NULL;  // No longer a match
                    len = 0;
                    i += 1;
                }
            }
        }
    }

    return( false );
}

static inline const u_char* extractHeaderFieldValues(HI_SESSION* session,
    HTTPINSPECT_CONF* ServerConf, const u_char* p, const u_char* offset,
    const u_char* start, const u_char* end, HI_CLIENT_HDR_ARGS* hdrs_args)
{
    HttpSessionData* hsd;

    hsd = hdrs_args->sd;
    if (((p - offset) == 0) && (ServerConf->enable_xff != 0) &&
        ((hdrs_args->true_clnt_xff & XFF_HEADERS_ACTIVE) != 0) && (hsd) &&
        IsXFFFieldName(hdrs_args, (u_char**)&p, (const u_char*)end,
        ServerConf->xff_headers, ServerConf->xff_header_lengths))
    {
        p = extract_http_xff(session, p, start, end, hdrs_args);
    }
    else if (((p - offset) == 0) && ((*p == 'C') || (*p == 'c')))
    {
        /* Search for 'Cookie' at beginning, starting from current *p */
        if ( ServerConf->enable_cookie &&
            IsHeaderFieldName(p, end, HEADER_NAME__COOKIE, HEADER_LENGTH__COOKIE))
        {
            p = extract_http_cookie((p+ HEADER_LENGTH__COOKIE), end, hdrs_args->hdr_ptr,
                hdrs_args->hdr_field_ptr);
        }
        else if ( IsHeaderFieldName(p, end, HEADER_NAME__CONTENT_LENGTH,
            HEADER_LENGTH__CONTENT_LENGTH) )
        {
            p = extract_http_content_length(session, ServerConf, p, start,
                end, hdrs_args->hdr_ptr, hdrs_args->hdr_field_ptr);
        }
        else if ( IsHeaderFieldName(p, end, HEADER_NAME__CONTENT_TYPE,
            HEADER_LENGTH__CONTENT_TYPE) )
        {
            session->client.request.content_type = p;
        }
    }
    else if (((p - offset) == 0) && ((*p == 'x') || (*p == 'X') || (*p == 't') || (*p == 'T')))
    {
        // The default/legacy behavior with two builtin XFF field names
        if ( (ServerConf->enable_xff) && hsd && ((hdrs_args->true_clnt_xff & XFF_HEADERS) == 0) )
        {
            if (IsHeaderFieldName(p, end, HEADER_NAME__XFF, HEADER_LENGTH__XFF))
            {
                hdrs_args->true_clnt_xff |= XFF_HDR;
                p = p + HEADER_LENGTH__XFF;
                p = extract_http_xff(session, p, start, end, hdrs_args);
            }
            else if (IsHeaderFieldName(p, end, HEADER_NAME__TRUE_IP, HEADER_LENGTH__TRUE_IP))
            {
                hdrs_args->true_clnt_xff |= TRUE_CLIENT_IP_HDR;
                p = p + HEADER_LENGTH__TRUE_IP;
                p = extract_http_xff(session, p, start, end, hdrs_args);
            }
        }
        else if ( IsHeaderFieldName(p, end, HEADER_NAME__TRANSFER_ENCODING,
            HEADER_LENGTH__TRANSFER_ENCODING) && hsd)
        {
            p = p + HEADER_LENGTH__TRANSFER_ENCODING;
            p = extract_http_transfer_encoding(session, hsd, p, start, end, hdrs_args->hdr_ptr,
                HI_SI_CLIENT_MODE);
        }
    }
    else if (((p - offset) == 0) && ((*p == 'H') || (*p == 'h')))
    {
        if (IsHeaderFieldName(p, end, HEADER_NAME__HOSTNAME, HEADER_LENGTH__HOSTNAME))
        {
            /* Alert when there are multiple host headers in one request */
            if (hdrs_args->hst_name_hdr)
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_MULTIPLE_HOST_HDRS);
                return p;
            }
            else
            {
                hdrs_args->hst_name_hdr = 1;
                // FIXIT-L move back to ServerConf?
                if ( hsd && !(hdrs_args->strm_ins) /*&& (ServerConf->log_hostname)*/)
                {
                    if (!SetLogBuffers(hsd))
                    {
                        p = p + HEADER_LENGTH__HOSTNAME;
                        p = extract_http_hostname(session, p, start, end, hdrs_args->hdr_ptr, hsd);
                    }
                }
            }
        }
    }
    return p;
}

/*
**  NAME
**    hi_client_extract_header::
*/
/**
**  Catch multiple requests per packet, by returning pointer to after the
**  end of the request header if there is another request.
**
**  There are 4 types of "valid" delimiters that we look for.  They are:
**  "\r\n\r\n"
**  "\r\n\n"
**  "\n\r\n"
**  "\n\n"
**  The only patterns that we really only need to look for are:
**  "\n\r\n"
**  "\n\n"
**  The reason being that these two patterns are suffixes of the other
**  patterns.  So once we find those, we are all good.
**
**  @param session pointer to the session
**  @param start pointer to the start of text
**  @param end   pointer to the end of text
**
**  @return pointer
**
**  @retval NULL  Did not find pipeline request
**  @retval !NULL Found another possible request.
*/
static inline const u_char* hi_client_extract_header(
    HI_SESSION* session, HTTPINSPECT_CONF* ServerConf,
    HEADER_PTR* header_ptr, const u_char* start,
    const u_char* end, HttpSessionData* hsd, int stream_ins)
{
    int iRet = HI_SUCCESS;
    const u_char* p;
    const u_char* offset;
    const u_char* crlf;
    URI_PTR version_string;
    HEADER_FIELD_PTR header_field_ptr;
    HI_CLIENT_HDR_ARGS hdrs_args;
    int header_count = 0;
    int num_spaces = 0;

    if (!start || !end)
        return NULL;

    p = start;

    /*
    **  We say end - 6 because we need at least six bytes to verify that
    **  there is an end to the URI and still a request afterwards.  To be
    **  exact, we should only subtract 1, but we are not interested in a
    **  1 byte method, uri, etc.
    **
    **  a.k.a there needs to be data after the initial request to inspect
    **  to make it worth our while.
    */
    if (p > (end - 6 ))
    {
        header_ptr->header.uri = NULL;
        return p;
    }
    header_ptr->content_len.len = 0;
    header_ptr->is_chunked = false;

    header_ptr->header.uri = start;
    header_ptr->header.uri_end = end;
    hdrs_args.hdr_ptr = header_ptr;
    hdrs_args.hdr_field_ptr = &header_field_ptr;
    hdrs_args.sd = hsd;
    hdrs_args.strm_ins = stream_ins;
    hdrs_args.hst_name_hdr = 0;
    hdrs_args.true_clnt_xff = (ServerConf->xff_headers[0] != NULL) ? XFF_INIT : 0;

    SkipBlankSpace(start,end,&p);

    /* This is to skip past the HTTP/1.0 (or 1.1) version string */
    if (IsHttpVersion(&p, end))
    {
        memset(&version_string, 0, sizeof(URI_PTR));
        version_string.uri = p;

        while (hi_util_in_bounds(start, end, p))
        {
            if (lookup_table[*p] || ServerConf->whitespace[*p])
            {
                if (lookup_table[*p])
                {
                    iRet = (lookup_table[*p])(session, start, end, &p, &version_string);
                }
                else
                {
                    iRet = NextNonWhiteSpace(session, start, end, &p, &version_string);
                }

                if (iRet == URI_END)
                {
                    if (*p == '\n')
                    {
                        p++;
                        if (hi_util_in_bounds(start, end, p))
                        {
                            version_string.uri_end = p;
                        }
                        else
                        {
                            return p;
                        }

                        num_spaces =  SkipBlankSpace(start,end,&p);

                        if ( session->server_conf->max_spaces &&
                            num_spaces >= session->server_conf->max_spaces )
                        {
                            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_EXCEEDS_SPACES);
                        }
                    }
                    break;
                }
                else if (iRet == HI_OUT_OF_BOUNDS)
                {
                    return p;
                }
            }
            p++;
        }
        if (iRet == URI_END)
        {
            header_ptr->header.uri = version_string.uri_end + 1;
        }
        else
        {
            return p;
        }
    }
    else
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_UNESCAPED_SPACE_URI);
        if (p < end)
        {
            crlf = (u_char*)SnortStrnStr((const char*)p, end - p, "\n");
            if (crlf)
            {
                p = crlf;
            }
            else
                return p;
        }
        else
        {
            return p;
        }
    }

    offset = (u_char*)p;

    header_ptr->header.uri = p;

    while (hi_util_in_bounds(start, end, p))
    {
        if (*p == '\n')
        {
            header_count++;

            if ( session->server_conf->max_hdr_len &&
                (p - offset) >= session->server_conf->max_hdr_len )
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HDR);
            }

            if (session->server_conf->max_headers &&
                (header_count > session->server_conf->max_headers))
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_MAX_HEADERS);
            }

            p++;

            num_spaces =  SkipBlankSpace(start,end,&p);

            if ( session->server_conf->max_spaces &&
                num_spaces >= session->server_conf->max_spaces )
            {
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_EXCEEDS_SPACES);
            }

            offset = (u_char*)p;

            if (!hi_util_in_bounds(start, end, p))
            {
                header_ptr->header.uri_end = p;
                return p;
            }

            hdrs_args.hdr_ptr = header_ptr;
            hdrs_args.hdr_field_ptr = &header_field_ptr;

            /* As performance ugly as this may be, need to bounds check p in each of the
             * if blocks below to prevent read beyond end of buffer */
            if (*p < 0x0E)
            {
                if (*p == '\r')
                {
                    p++;

                    if (!hi_util_in_bounds(start, end, p))
                    {
                        header_ptr->header.uri_end = p;
                        return p;
                    }
                    else if (*p == '\n')
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
            else if ( (p = extractHeaderFieldValues(session, ServerConf, p, offset, start, end,
                    &hdrs_args)) == end)
            {
                return end;
            }
        }
        else if ( (p == header_ptr->header.uri) &&
            (p = extractHeaderFieldValues(session, ServerConf, p, offset, start, end,
                &hdrs_args)) == end)
        {
            return end;
        }
        if ( *p == '\n')
            continue;
        p++;
    }

    /* Never observed an end-of-field.  Maybe it's not there, but the header is long anyway: */
    if ( session->server_conf->max_hdr_len &&
        (p - start) >= session->server_conf->max_hdr_len )
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HDR);
    }

    header_ptr->header.uri_end = p;
    return p;
}

#define CLR_POST(Client) \
    do { \
        Client->request.post_raw = NULL; \
        Client->request.post_raw_size = 0; \
        Client->request.post_norm = NULL; \
    } while (0);

#define CLR_HEADER(Client) \
    do { \
        Client->request.header_raw = NULL; \
        Client->request.header_raw_size = 0; \
        Client->request.header_norm = NULL; \
        Client->request.header_norm_size = 0; \
        Client->request.cookie.cookie = NULL; \
        Client->request.cookie.cookie_end = NULL; \
        if (Client->request.cookie.next) { \
            COOKIE_PTR* cookie = Client->request.cookie.next; \
            do { \
                Client->request.cookie.next = Client->request.cookie.next->next; \
                snort_free(cookie); \
                cookie = Client->request.cookie.next; \
            } while (cookie); \
        } \
        Client->request.cookie.next = NULL; \
        Client->request.cookie_norm = NULL; \
        Client->request.cookie_norm_size = 0; \
    } while (0);

#define CLR_METHOD(Client) \
    do { \
        Client->request.method_raw = NULL; \
        Client->request.method_size = 0; \
        Client->request.method = 0; \
    } while (0);

/*
**  NAME
**    StatelessInspection::
*/
/**
**  Find the URI and determine whether the URI needs to be normalized.
**
**  This is a big step in stateless inspection, because we need to reliably
**  find the URI and when possible filter out non-URIs.  We do this using a
**  simple state machine that is based on characters found in the data
**  buffer.
**
**  Another important aspect of the stateless inspection is the ability to
**  track and inspect pipelined requests.  It is VERY IMPORTANT to reset the
**  pipeline_req pointer, since we don't memset the whole structure.  This
**  pointer is reset in the hi_si_session_inspection() function.  Check there
**  for more details.
**
**  Normalization is detected when we are looking at the packet for the URI.
**  We look for the following issues:
**      - ////
**      - /../
**      - /./
**      - non-ascii charss
**      - %
**      - \
**  When these things are seen we point to the first occurence in the URI, or
**  where we have to start normalizing.  If the URI is updated to a new
**  pointer, then the normalization pointer is reset and we start over.
**  Using this method should cut down the memcpy()s per URI, since most
**  URIs are not normalized.
**
**  If this function returns HI_NONFATAL_ERR, we return out of mode_inspection
**  with an error and abort HttpInspect processing, and continue on with
**  any other processing we do.  The session parameters that we use here are
**  reset in the next time that we do session_inspection, so we don't do
**  any initialization here.
**
**  @param session pointer to the HTTP session
**  @param data    pointer to the start of the packet payload
**  @param dsize   size of the payload
**
**  @return integer
**
**  @retval HI_INVALID_ARG  invalid argument
**  @retval HI_NONFATAL_ERR no URI detected
**  @retval HI_SUCCESS      URI detected and session pointers updated
*/

static int StatelessInspection(Packet* p, HI_SESSION* session, HttpSessionData* hsd, int stream_ins)
{
    HTTPINSPECT_CONF* ServerConf;
    HTTPINSPECT_CONF* ClientConf;
    HI_CLIENT* Client;
    URI_PTR method_ptr;
    URI_PTR uri_ptr;
    URI_PTR post_ptr;
    HEADER_PTR header_ptr;
    HTTP_CMD_CONF* CmdConf = NULL;
    const u_char* start;
    const u_char* end;
    const u_char* ptr, * mthd;
    const u_char* method_end = NULL;
    int method_len;
    int iRet=0;
    bool sans_uri = false;
    const unsigned char* data = p->data;
    int dsize = p->dsize;

    if ( stream_ins && (p->packet_flags & PKT_STREAM_INSERT) )
        return HI_INVALID_ARG;

    ServerConf = session->server_conf;
    if (!ServerConf)
    {
        return HI_INVALID_ARG;
    }

    ClientConf = session->client_conf;
    if (!ClientConf)
    {
        return HI_INVALID_ARG;
    }

    Client = &session->client;
    CLR_HEADER(Client);

    memset(&uri_ptr, 0x00, sizeof(URI_PTR));
    memset(&post_ptr, 0x00, sizeof(URI_PTR));
    memset(&header_ptr, 0x00, sizeof(HEADER_PTR));
    memset(&method_ptr, 0x00, sizeof(URI_PTR));

    /*
    **  We set the starting boundary depending on whether this request is
    **  a normal request or a pipeline request.  The end boundary is always
    **  the same whether it is a pipeline request or other.
    */
    if (Client->request.pipeline_req)
    {
        start = Client->request.pipeline_req;
        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    }
    else
    {
        start = data;
    }

    Client->request.pipeline_req = NULL;

    end = data + dsize;
    ptr = start;

    /*
    **  Apache and IIS strike again . . . Thanks Kanatoko
    **    - Ignore CRLFs at the beginning of the request.
    */
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

    mthd = method_ptr.uri = ptr;

    while (hi_util_in_bounds(start, end, mthd))
    {
        if (ServerConf->whitespace[*mthd] || (lookup_table[*mthd] == NextNonWhiteSpace))
        {
            method_end = mthd++;
            break;
        }
        mthd++;
    }
    if (method_end)
    {
        method_ptr.uri_end = method_end;
    }
    else
    {
        method_ptr.uri_end = end;
    }
    method_len = method_ptr.uri_end - method_ptr.uri;

    /* Need slightly special handling for POST requests
     * Since we don't normalize on the request method itself,
     * just do a strcmp here and skip the characters below. */
    if (method_len == 4 && !strncasecmp("POST", (const char*)method_ptr.uri, 4))
    {
        hi_stats.post++;
        Client->request.method = HI_POST_METHOD;
    }
    else if (method_len == 3 && !strncasecmp("GET", (const char*)method_ptr.uri, 3))
    {
        hi_stats.get++;
        Client->request.method = HI_GET_METHOD;
    }
    else if (method_len > 0 && method_len <= MAX_METHOD_LEN )
    {
        CmdConf = http_cmd_lookup_find(ServerConf->cmd_lookup, (const char*)method_ptr.uri,
            method_len, &iRet);

        if (iRet == -1 || (CmdConf == NULL))
        {
            hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_UNKNOWN_METHOD);
            Client->request.method = HI_UNKNOWN_METHOD;
        }
    }
    else
    {
        {
            /* Might have gotten non-ascii characters, hence no method, but if
             * PAF is in use, checking "!stream_ins" equates to is_pdu_start()
             * so we know we're looking for a method and not guessing that we're in
             * the body or somewhere else because we found a non-ascii character */
            if ( !stream_ins )
                hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_UNKNOWN_METHOD);
            Client->request.method = HI_UNKNOWN_METHOD;
            sans_uri = true;
        }
    }

    if (!sans_uri )
    {
        uri_ptr.uri = method_ptr.uri_end;
        uri_ptr.uri_end = end;

        /* This will set up the URI pointers - effectively extracting
         * the URI. */
        iRet = hi_client_extract_uri(
            session, ServerConf, Client, start, end, uri_ptr.uri, &uri_ptr, hsd, stream_ins);
    }

    /* Check if the URI exceeds the max header field length */
    /* Only check if we succesfully observed a GET or POST method, otherwise,
     * this may very well be a POST body */
    if ( iRet == URI_END && ServerConf->max_hdr_len &&
        ((uri_ptr.uri_end - uri_ptr.uri) >= ServerConf->max_hdr_len) )
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_LONG_HDR);
    }

    if (iRet == URI_END &&
        !(ServerConf->uri_only))
    {
        Client->request.method_raw = method_ptr.uri;
        Client->request.method_size = method_ptr.uri_end - method_ptr.uri;
        // XXX
        // Copy out the header into its own buffer...,
        //  set ptr to end of header.
        //
        // uri_ptr.end points to end of URI & HTTP version identifier.
        if (hi_util_in_bounds(start, end, uri_ptr.uri_end + 1))
            hi_client_extract_header(session, ServerConf, &header_ptr, uri_ptr.uri_end+1, end, hsd,
                stream_ins);

        if (header_ptr.header.uri)
        {
            Client->request.header_raw = header_ptr.header.uri;
            Client->request.header_raw_size = header_ptr.header.uri_end - header_ptr.header.uri;
            if (!Client->request.header_raw_size)
            {
                CLR_HEADER(Client);
            }
            else
            {
                hi_stats.req_headers++;
                Client->request.header_norm = header_ptr.header.uri;
                if (header_ptr.cookie.cookie)
                {
                    hi_stats.req_cookies++;
                    Client->request.cookie.cookie = header_ptr.cookie.cookie;
                    Client->request.cookie.cookie_end = header_ptr.cookie.cookie_end;
                    Client->request.cookie.next = header_ptr.cookie.next;
                    Client->request.cookie_norm = header_ptr.cookie.cookie;
                }
                else
                {
                    Client->request.cookie.cookie = NULL;
                    Client->request.cookie.cookie_end = NULL;
                    Client->request.cookie.next = NULL;
                    Client->request.cookie_norm = NULL;
                }
            }
        }
        else
        {
            CLR_HEADER(Client);
        }

        /* Got a Content-Length or it's a POST request which may be chunked */
        if (header_ptr.content_len.cont_len_start || header_ptr.is_chunked)
        {
            /* Need to skip over header and get to the body.
             * The unaptly named FindPipelineReq will do that. */
            ptr = FindPipelineReq(session, uri_ptr.delimiter, end);
            //ptr = FindPipelineReq(session, ptr, end);
            if (ptr)
            {
                post_ptr.uri = ptr;
                post_ptr.uri_end = end;
                if ((POST_END == hi_client_extract_post(
                    session, ServerConf, ptr, end, &post_ptr,
                    header_ptr.content_len.len, header_ptr.is_chunked, hsd)))
                {
                    hi_stats.post_params++;
                    Client->request.post_raw = post_ptr.uri;
                    Client->request.post_raw_size = post_ptr.uri_end - post_ptr.uri;
                    Client->request.post_norm = post_ptr.norm;
                    ptr = post_ptr.uri_end;
                }
                else
                {
                    CLR_POST(Client);
                }

                if ( ptr < end )
                    Client->request.pipeline_req = ptr;

                if (Client->request.post_raw && (ServerConf->post_extract_size > -1))
                {
                    if (ServerConf->post_extract_size && ((int)Client->request.post_raw_size >
                        ServerConf->post_extract_size))
                    {
                        Client->request.post_raw_size = (unsigned
                            int)ServerConf->post_extract_size;
                    }
                }
                else
                {
                    CLR_POST(Client);
                }
            }
            else
            {
                CLR_POST(Client);
                ptr = uri_ptr.delimiter;
            }
        }
        else
        {
            ptr = uri_ptr.delimiter;
        }
    }
    else
    {
        CLR_HEADER(Client);
        CLR_POST(Client);
        if (!(Client->request.method & HI_UNKNOWN_METHOD) && method_ptr.uri)
        {
            Client->request.method_raw = method_ptr.uri;
            Client->request.method_size = method_ptr.uri_end - method_ptr.uri;
        }
        else
        {
            CLR_METHOD(Client);
            return HI_NONFATAL_ERR;
        }
        ptr = uri_ptr.delimiter;
    }

    /*
     **  Find the next pipeline request, if one is there.  If we don't find
     **  a pipeline request, then we return NULL here, so this is always
     **  set to the correct value.
     */
    if (!ServerConf->no_pipeline)
    {
        if (post_ptr.uri)
        {
            Client->request.pipeline_req =
                FindPipelineReq(session, post_ptr.delimiter, end);
        }
        else if (!Client->request.pipeline_req && uri_ptr.uri)
        {
            Client->request.pipeline_req =
                FindPipelineReq(session, ptr, end);
        }
    }
    else
    {
        Client->request.pipeline_req = NULL;
    }

    /*
    **  We set the HI_CLIENT variables from the URI_PTR structure.  We also
    **  do error checking for the values in this routine as well.
    */
    iRet = SetClientVars(Client, &uri_ptr, dsize);
    if (iRet)
    {
        CLR_HEADER(Client);
        CLR_POST(Client);
        CLR_METHOD(Client);
        return iRet;
    }
    /*
    **  One last check for an oversize directory.  This gets the long
    **  directory when there is a beginning slash and no other slashes
    **  until the end of the packet.
    **
    **  We do this check after we set the variables, just in case there
    **  was some errors while setting the variables.  This could save some
    **  false positives on a bad URI setting.
    */
    if (uri_ptr.uri_end)
        CheckLongDir(session, &uri_ptr, uri_ptr.uri_end);

    /*
    **  Check for absolute URI and alert for proxy comm if necessary
    **
    **  NOTE:
    **    Also check ClientConf for proxy configuration so we don't
    **    alert on outbound requests from legitimate proxies.
    */
    if (uri_ptr.proxy && session->global_conf->proxy_alert &&
        (!ServerConf->allow_proxy && !ClientConf->allow_proxy))
    {
        hi_set_event(GID_HTTP_CLIENT, HI_CLIENT_PROXY_USE);
    }

    return HI_SUCCESS;
}

int hi_client_inspection(Packet* p, void* S, HttpSessionData* hsd, int stream_ins)
{
    if (!S || !(p->data) || (p->dsize < 1))
    {
        return HI_INVALID_ARG;
    }

    HI_SESSION* session = (HI_SESSION*)S;

    if (!session->global_conf)
    {
        return HI_INVALID_ARG;
    }

    return StatelessInspection(p, session, hsd, stream_ins);
}

/*
**  NAME
**    hi_client_init::
*/
/**
**  Initializes arrays and search algorithms depending on the type of
**  inspection that we are doing.
**
**  @retval HI_SUCCESS function successful.
*/
int hi_client_init()
{
    int iCtr;

    memset(lookup_table, 0x00, sizeof(lookup_table));

    // Set up the non-ASCII register for processing.
    for (iCtr = 0x80; iCtr <= 0xff; iCtr++)
    {
        lookup_table[iCtr] = SetBinaryNorm;
    }
    lookup_table[0x00] = SetBinaryNorm;

    lookup_table[(uint8_t)' ']  = NextNonWhiteSpace;
    lookup_table[(uint8_t)'\r'] = find_rfc_delimiter;
    lookup_table[(uint8_t)'\n'] = find_non_rfc_delimiter;

    // ASCII encoding
    lookup_table[(uint8_t)'%']  = SetPercentNorm;

    // Looking for multiple slashes
    lookup_table[(uint8_t)'/']  = SetSlashNorm;

    // Looking for backslashs
    lookup_table[(uint8_t)'\\'] = SetBackSlashNorm;

    lookup_table[(uint8_t)'+'] = SetPlusNorm;

    //  Look up parameter field, so we don't alert on long directory
    //  strings, when the next slash in the parameter field.
    lookup_table[(uint8_t)'?'] = SetParamField;

    //  Look for absolute URI and proxy communication.
    lookup_table[(uint8_t)':'] = SetProxy;

    return HI_SUCCESS;
}

/**
**  This was just an initial testing program for these functions.
*/
#ifdef TEST_ME

int main(int argc, char** argv)
{
    HTTPINSPECT_GLOBAL_CONF GlobalConf;
    HI_SESSION* session;
    HI_SI_INPUT SiInput;
    int iInspectMode = 0;
    int iRet;
    char data[] = "Hdslkfjaslfkj    HTTP/00000.111111";

    if ((iRet = hi_ui_config_init_global_conf(&GlobalConf)))
    {
        printf("** error during global init.\n");
        return iRet;
    }

    if ((iRet = hi_ui_config_default(&GlobalConf)))
    {
        printf("** error config default.\n");
        return iRet;
    }

    hi_ui_config_print_config(&GlobalConf);

    if ((iRet = hi_client_init()))
    {
        printf("** error client init\n");
        return iRet;
    }

    SiInput.sip = inet_addr("1.1.1.1");
    SiInput.sip = inet_addr("1.1.1.2");
    SiInput.dport = 80;
    SiInput.sport = 7880;

    if ((iRet = hi_si_session_inspection(&GlobalConf, &session, &SiInput,
            &iInspectMode)))
    {
        printf("** error session inspection\n");
        return iRet;
    }

    printf("** iInspectMode = %d\n", iInspectMode);
    if ((iRet = hi_mi_mode_inspection(session, iInspectMode, data,
            strlen(data))))
    {
        printf("** error mode_inspection\n");
        return iRet;
    }

    return 0;
}

#endif

