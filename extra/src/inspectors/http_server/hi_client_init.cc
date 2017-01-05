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

// hi_client_init.cc author Russ Combs <rucombs@cisco.com>
// 
// this file was split from hi_client.cc; look there for the real
// culprits ;)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hi_events.h"
#include "hi_return_codes.h"
#include "hi_si.h"
#include "hi_util.h"

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

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

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

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
int NextNonWhiteSpace(HI_SESSION* session, const u_char* start,
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
int CheckLongDir(HI_SESSION* session, URI_PTR* uri_ptr, const u_char* ptr)
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

