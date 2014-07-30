/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2012-2013 Sourcefire, Inc.
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
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  9.25.2012 - Initial Source Code. Hcao
 */

#include "file_mime_process.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "file_api.h"
#include "snort_bounds.h"
#include "util.h"
#include "search_engines/str_search.h"
#include "protocols/packet.h"
#include "detection_util.h"

MimePcre mime_boundary_pcre;

typedef struct _MimeToken
{
    const char *name;
    int   name_len;
    int   search_id;

} MimeToken;

typedef enum _MimeHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_CONT_DISP,
    HDR_LAST

} MimeHdrEnum;

const MimeToken mime_hdrs[] =
{
        {"Content-type:", 13, HDR_CONTENT_TYPE},
        {"Content-Transfer-Encoding:", 26, HDR_CONT_TRANS_ENC},
        {"Content-Disposition:", 20, HDR_CONT_DISP},
        {NULL,             0, 0}
};

typedef struct _MIMESearch
{
    const char *name;
    int   name_len;

} MIMESearch;

typedef struct _MIMESearchInfo
{
    int id;
    int index;
    int length;

} MIMESearchInfo;

MIMESearchInfo mime_search_info;

void *mime_hdr_search_mpse = NULL;
MIMESearch mime_hdr_search[HDR_LAST];
MIMESearch *mime_current_search = NULL;

/* Extract the filename from the header */
static inline int extract_file_name(const char **start, int length, bool *disp_cont)
{
    const char *tmp = NULL;
    const char *end = *start+length;

    if (length <= 0)
        return -1;


    if (!(*disp_cont))
    {
        tmp = SnortStrcasestr(*start, length, "filename");

        if( tmp == NULL )
            return -1;

        tmp = tmp + 8;
        while( (tmp < end) && ((isspace(*tmp)) || (*tmp == '=') ))
        {
            tmp++;
        }
    }
    else
        tmp = *start;

    if(tmp < end)
    {
        if(*tmp == '"' || (*disp_cont))
        {
            if(*tmp == '"')
            {
                if(*disp_cont)
                {
                    *disp_cont = false;
                    return (tmp - *start);
                }
                tmp++;

            }
            *start = tmp;
            tmp = SnortStrnPbrk(*start ,(end - tmp),"\"");
            if(tmp == NULL )
            {
                if ((end - tmp) > 0 )
                {
                    tmp = end;
                    *disp_cont = true;
                }
                else
                    return -1;
            }
            else
                *disp_cont = false;
            end = tmp;
        }
        else
        {
            *start = tmp;
        }
        return (end - *start);
    }
    else
    {
        return -1;
    }

}

/* accumulate MIME attachment filenames. The filenames are appended by commas */
int log_file_name(const uint8_t *start, int length, FILE_LogState *log_state, bool *disp_cont)
{
    uint8_t *alt_buf;
    int alt_size;
    uint16_t *alt_len;
    int ret=0;
    int cont =0;
    int log_avail = 0;


    if(!start || (length <= 0))
    {
        *disp_cont = false;
        return -1;
    }

    if(*disp_cont)
        cont = 1;

    ret = extract_file_name((const char **)(&start), length, disp_cont);

    if (ret == -1)
        return ret;

    length = ret;

    alt_buf = log_state->filenames;
    alt_size =  MAX_FILE;
    alt_len = &(log_state->file_logged);
    log_avail = alt_size - *alt_len;

    if(!alt_buf || (log_avail <= 0))
        return -1;


    if ( *alt_len > 0 && ((*alt_len + 1) < alt_size))
    {
        if(!cont)
        {
            alt_buf[*alt_len] = ',';
            *alt_len = *alt_len + 1;
        }
    }

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        if(*alt_len != 0)
            *alt_len = *alt_len - 1;
        return -1;
    }

    log_state->file_current = *alt_len;
    *alt_len += length;

    return 0;
}
/*
 * Return: 0: success
 *         -1: fail
 *
 */
int set_log_buffers(MAIL_LogState **log_state, MAIL_LogConfig *conf)
{
    if((*log_state == NULL)
            && (conf->log_email_hdrs || conf->log_filename
                    || conf->log_mailfrom || conf->log_rcptto))
    {
        uint32_t bufsz = (2* MAX_EMAIL) + MAX_FILE + conf->email_hdrs_log_depth;
        *log_state = (MAIL_LogState *)calloc(1, sizeof(*log_state) + bufsz);

        if((*log_state) != NULL)
        {
            uint8_t* buf = ((uint8_t*)(*log_state)) + sizeof(*log_state);
            (*log_state)->log_depth = conf->email_hdrs_log_depth;
            (*log_state)->recipients = buf;
            (*log_state)->rcpts_logged = 0;
            (*log_state)->senders = buf + MAX_EMAIL;
            (*log_state)->snds_logged = 0;
            (*log_state)->file_log.filenames = buf + (2*MAX_EMAIL);
            (*log_state)->file_log.file_logged = 0;
            (*log_state)->file_log.file_current = 0;
            (*log_state)->emailHdrs = buf + (2*MAX_EMAIL) + MAX_FILE;
            (*log_state)->hdrs_logged = 0;
        }
        else
        {
            return -1;
        }

    }
    return 0;
}

static void set_mime_buffers(MimeState *ssn)
{
    if ((ssn != NULL) && (ssn->decode_state == NULL))
    {
        DecodeConfig* conf = ssn->decode_conf;

        ssn->decode_state = NewEmailDecodeState(
            conf->max_depth, conf->b64_depth, conf->qp_depth,
            conf->uu_depth, conf->bitenc_depth,
                        conf->file_depth);
    }
}

/*
 * Initialize run-time boundary search, this should be called for every transaction
 */
static int init_boundary_search(MimeBoundary *mime_boundary )
{
    if (mime_boundary->boundary_search != NULL)
        search_api->search_instance_free(mime_boundary->boundary_search);

    mime_boundary->boundary_search = search_api->search_instance_new();

    if (mime_boundary->boundary_search == NULL)
        return -1;

    search_api->search_instance_add(mime_boundary->boundary_search,
            mime_boundary->boundary,
            mime_boundary->boundary_len, BOUNDARY);

    search_api->search_instance_prep(mime_boundary->boundary_search);

    return 0;
}

/*
 * Update boundary search string when found
 */
static int get_boundary(const char *data, int data_len, MimeBoundary *mime_boundary)
{
    int result;
    int ovector[9];
    int ovecsize = 9;
    const char *boundary;
    int boundary_len;
    int ret;
    char *mime_boundary_str;
    int  *mime_boundary_len;


    mime_boundary_str = &mime_boundary->boundary[0];
    mime_boundary_len = &mime_boundary->boundary_len;

    /* result will be the number of matches (including submatches) */
    result = pcre_exec(mime_boundary_pcre.re, mime_boundary_pcre.pe,
            data, data_len, 0, 0, ovector, ovecsize);
    if (result < 0)
        return -1;

    result = pcre_get_substring(data, ovector, result, 1, &boundary);
    if (result < 0)
        return -1;

    boundary_len = strlen(boundary);
    if (boundary_len > MAX_MIME_BOUNDARY_LEN)
    {
        /* XXX should we alert? breaking the law of RFC */
        boundary_len = MAX_MIME_BOUNDARY_LEN;
    }

    mime_boundary_str[0] = '-';
    mime_boundary_str[1] = '-';
    ret = SafeMemcpy(mime_boundary_str + 2, boundary, boundary_len,
            mime_boundary_str + 2, mime_boundary_str + 2 + MAX_MIME_BOUNDARY_LEN);

    pcre_free_substring(boundary);

    if (ret != SAFEMEM_SUCCESS)
    {
        return -1;
    }

    *mime_boundary_len = 2 + boundary_len;
    mime_boundary_str[*mime_boundary_len] = '\0';

    return 0;
}

void get_mime_eol(const uint8_t *ptr, const uint8_t *end,
        const uint8_t **eol, const uint8_t **eolm)
{
    const uint8_t *tmp_eol;
    const uint8_t *tmp_eolm;

    /* XXX maybe should fatal error here since none of these
     * pointers should be NULL */
    if (ptr == NULL || end == NULL || eol == NULL || eolm == NULL)
        return;

    tmp_eol = (uint8_t *)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == NULL)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and
         * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from mime_config.cmds
 * @param   index   index in array of search strings from mime_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int search_str_found(void *id, void*, int index, void*, void*)
{
    int search_id = (int)(uintptr_t)id;

    mime_search_info.id = search_id;
    mime_search_info.index = index;
    mime_search_info.length = mime_current_search[search_id].name_len;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

/*
 * Callback function for boundary search
 *
 * @param   id      id in array of search strings
 * @param   index   index in array of search strings
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int boundary_str_found(void *id, void*, int index, void*, void*)
{
    int boundary_id = (int)(uintptr_t)id;

    mime_search_info.id = boundary_id;
    mime_search_info.index = index;
    //mime_search_info.length = mime_ssn->mime_boundary.boundary_len;

    return 1;
}

static inline int is_decoding_enabled(DecodeConfig *pPolicyConfig)
{
    if( (pPolicyConfig->b64_depth > -1) || (pPolicyConfig->qp_depth > -1)
            || (pPolicyConfig->uu_depth > -1) || (pPolicyConfig->bitenc_depth > -1)
            || (pPolicyConfig->file_depth > -1))
    {
        return 0;
    }
    else
        return -1;

}

static inline void process_decode_type(const char *start, int length, bool cnt_xf, MimeState *mime_ssn)
{
    const char *tmp = NULL;
    Email_DecodeState *decode_state = (Email_DecodeState *)(mime_ssn->decode_state);

    if(cnt_xf)
    {
        if(decode_state->b64_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "base64");
            if( tmp != NULL )
            {
                decode_state->decode_type = DECODE_B64;
                return;
            }
        }

        if(decode_state->qp_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "quoted-printable");
            if( tmp != NULL )
            {
                decode_state->decode_type = DECODE_QP;
                return;
            }
        }

        if(decode_state->uu_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "uuencode");
            if( tmp != NULL )
            {
                decode_state->decode_type = DECODE_UU;
                return;
            }
        }
    }

    if(decode_state->bitenc_state.depth > -1)
    {
        decode_state->decode_type = DECODE_BITENC;
        return;
    }

    return;
}

static inline void setup_decode(const char *data, int size, bool cnt_xf, MimeState *mime_ssn)
{
    /* Check for Encoding Type */
    if( !is_decoding_enabled(mime_ssn->decode_conf))
    {
        set_mime_buffers(mime_ssn);
        if(mime_ssn->decode_state != NULL)
        {
            ResetBytesRead((Email_DecodeState *)(mime_ssn->decode_state));
            process_decode_type(data, size, cnt_xf, mime_ssn );
            mime_ssn->state_flags |= MIME_FLAG_EMAIL_ATTACH;
            /* check to see if there are other attachments in this packet */
            if( ((Email_DecodeState *)(mime_ssn->decode_state))->decoded_bytes )
                mime_ssn->state_flags |= MIME_FLAG_MULTIPLE_EMAIL_ATTACH;
        }
    }
}
/*
 * Handle Headers - Data or Mime
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static const uint8_t * process_mime_header(
    Packet*, const uint8_t *ptr,
    const uint8_t *data_end_marker, MimeState *mime_ssn)
{
    const uint8_t *eol = data_end_marker;
    const uint8_t *eolm = eol;
    const uint8_t *colon;
    const uint8_t *content_type_ptr = NULL;
    const uint8_t *cont_trans_enc = NULL;
    const uint8_t *cont_disp = NULL;
    int header_found;
    int ret;
    const uint8_t *start_hdr;

    start_hdr = ptr;

    /* if we got a content-type in a previous packet and are
     * folding, the boundary still needs to be checked for */
    if (mime_ssn->state_flags & MIME_FLAG_IN_CONTENT_TYPE)
        content_type_ptr = ptr;

    if (mime_ssn->state_flags & MIME_FLAG_IN_CONT_TRANS_ENC)
        cont_trans_enc = ptr;

    if (mime_ssn->state_flags & MIME_FLAG_IN_CONT_DISP)
        cont_disp = ptr;

    while (ptr < data_end_marker)
    {
        get_mime_eol(ptr, data_end_marker, &eol, &eolm);

        /* got a line with only end of line marker should signify end of header */
        if (eolm == ptr)
        {
            /* reset global header state values */
            mime_ssn->state_flags &=
                    ~(MIME_FLAG_FOLDING | MIME_FLAG_IN_CONTENT_TYPE | MIME_FLAG_DATA_HEADER_CONT
                            | MIME_FLAG_IN_CONT_TRANS_ENC );

            mime_ssn->data_state = STATE_DATA_BODY;

            /* if no headers, treat as data */
            if (ptr == start_hdr)
                return eolm;
            else
                return eol;
        }

        /* if we're not folding, see if we should interpret line as a data line
         * instead of a header line */
        if (!(mime_ssn->state_flags & (MIME_FLAG_FOLDING | MIME_FLAG_DATA_HEADER_CONT)))
        {
            char got_non_printable_in_header_name = 0;

            /* if we're not folding and the first char is a space or
             * colon, it's not a header */
            if (isspace((int)*ptr) || *ptr == ':')
            {
                mime_ssn->data_state = STATE_DATA_BODY;
                return ptr;
            }

            /* look for header field colon - if we're not folding then we need
             * to find a header which will be all printables (except colon)
             * followed by a colon */
            colon = ptr;
            while ((colon < eolm) && (*colon != ':'))
            {
                if (((int)*colon < 33) || ((int)*colon > 126))
                    got_non_printable_in_header_name = 1;

                colon++;
            }

            /* If the end on line marker and end of line are the same, assume
             * header was truncated, so stay in data header state */
            if ((eolm != eol) &&
                    ((colon == eolm) || got_non_printable_in_header_name))
            {
                /* no colon or got spaces in header name (won't be interpreted as a header)
                 * assume we're in the body */
                mime_ssn->state_flags &=
                        ~(MIME_FLAG_FOLDING | MIME_FLAG_IN_CONTENT_TYPE | MIME_FLAG_DATA_HEADER_CONT
                                |MIME_FLAG_IN_CONT_TRANS_ENC);

                mime_ssn->data_state = STATE_DATA_BODY;

                return ptr;
            }

            if(tolower((int)*ptr) == 'c')
            {
                mime_current_search = &mime_hdr_search[0];
                header_found =search_api->search_instance_find
                        (mime_hdr_search_mpse, (const char *)ptr,
                                eolm - ptr, 1, search_str_found);

                /* Headers must start at beginning of line */
                if ((header_found > 0) && (mime_search_info.index == 0))
                {
                    switch (mime_search_info.id)
                    {
                    case HDR_CONTENT_TYPE:
                        content_type_ptr = ptr + mime_search_info.length;
                        mime_ssn->state_flags |= MIME_FLAG_IN_CONTENT_TYPE;
                        break;
                    case HDR_CONT_TRANS_ENC:
                        cont_trans_enc = ptr + mime_search_info.length;
                        mime_ssn->state_flags |= MIME_FLAG_IN_CONT_TRANS_ENC;
                        break;
                    case HDR_CONT_DISP:
                        cont_disp = ptr + mime_search_info.length;
                        mime_ssn->state_flags |= MIME_FLAG_IN_CONT_DISP;
                        break;
                    default:
                        break;
                    }
                }
            }
            else if(tolower((int)*ptr) == 'e')
            {
                if((eolm - ptr) >= 9)
                {
                    if(strncasecmp((const char *)ptr, "Encoding:", 9) == 0)
                    {
                        cont_trans_enc = ptr + 9;
                        mime_ssn->state_flags |= MIME_FLAG_IN_CONT_TRANS_ENC;
                    }
                }
            }
        }
        else
        {
            mime_ssn->state_flags &= ~MIME_FLAG_DATA_HEADER_CONT;
        }


        /* check for folding
         * if char on next line is a space and not \n or \r\n, we are folding */
        if ((eol < data_end_marker) && isspace((int)eol[0]) && (eol[0] != '\n'))
        {
            if ((eol < (data_end_marker - 1)) && (eol[0] != '\r') && (eol[1] != '\n'))
            {
                mime_ssn->state_flags |= MIME_FLAG_FOLDING;
            }
            else
            {
                mime_ssn->state_flags &= ~MIME_FLAG_FOLDING;
            }
        }
        else if (eol != eolm)
        {
            mime_ssn->state_flags &= ~MIME_FLAG_FOLDING;
        }

        /* check if we're in a content-type header and not folding. if so we have the whole
         * header line/lines for content-type - see if we got a multipart with boundary
         * we don't check each folded line, but wait until we have the complete header
         * because boundary=BOUNDARY can be split across mulitple folded lines before
         * or after the '=' */
        if ((mime_ssn->state_flags &
                (MIME_FLAG_IN_CONTENT_TYPE | MIME_FLAG_FOLDING)) == MIME_FLAG_IN_CONTENT_TYPE)
        {
            if (mime_ssn->data_state != STATE_MIME_HEADER)
            {
                /* we got the full content-type header - look for boundary string */
                ret = get_boundary((const char *)content_type_ptr, eolm - content_type_ptr,
                        &(mime_ssn->mime_boundary));
                if (ret != -1)
                {
                    ret = init_boundary_search(&(mime_ssn->mime_boundary));
                    if (ret != -1)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Got mime boundary: %s\n",
                                mime_ssn->mime_boundary.boundary););

                        mime_ssn->state_flags |= MIME_FLAG_GOT_BOUNDARY;
                    }
                }
            }
            else if (!(mime_ssn->state_flags & MIME_FLAG_EMAIL_ATTACH))
            {
                setup_decode((const char *)content_type_ptr, (eolm - content_type_ptr), false, mime_ssn );
            }

            mime_ssn->state_flags &= ~MIME_FLAG_IN_CONTENT_TYPE;
            content_type_ptr = NULL;
        }
        else if ((mime_ssn->state_flags &
                (MIME_FLAG_IN_CONT_TRANS_ENC | MIME_FLAG_FOLDING)) == MIME_FLAG_IN_CONT_TRANS_ENC)
        {
            setup_decode((const char *)cont_trans_enc, (eolm - cont_trans_enc), true, mime_ssn );

            mime_ssn->state_flags &= ~MIME_FLAG_IN_CONT_TRANS_ENC;

            cont_trans_enc = NULL;
        }
        else if (((mime_ssn->state_flags &
                (MIME_FLAG_IN_CONT_DISP | MIME_FLAG_FOLDING)) == MIME_FLAG_IN_CONT_DISP) && cont_disp)
        {
            bool disp_cont = (mime_ssn->state_flags & MIME_FLAG_IN_CONT_DISP_CONT)? true: false;
            if(mime_ssn->log_config->log_filename && mime_ssn->log_state )
            {
                if(!log_file_name(cont_disp, eolm - cont_disp,
                        &(mime_ssn->log_state->file_log), &disp_cont) )
                    mime_ssn->log_flags |= MIME_FLAG_FILENAME_PRESENT;
            }
            if (disp_cont)
            {
                mime_ssn->state_flags |= MIME_FLAG_IN_CONT_DISP_CONT;
            }
            else
            {
                mime_ssn->state_flags &= ~MIME_FLAG_IN_CONT_DISP;
                mime_ssn->state_flags &= ~MIME_FLAG_IN_CONT_DISP_CONT;
            }

            cont_disp = NULL;
        }

        /* if state was unknown, at this point assume we know */
        if (mime_ssn->data_state == STATE_DATA_UNKNOWN)
            mime_ssn->data_state = STATE_DATA_HEADER;

        ptr = eol;

        if (ptr == data_end_marker)
            mime_ssn->state_flags |= MIME_FLAG_DATA_HEADER_CONT;
    }

    return ptr;
}

/*
 * Handle DATA_BODY state
 * @param   packet standard Packet structure
 * @param   i index into p->payload buffer to start looking at data
 * @return  i index into p->payload where we stopped looking at data
 */
static const uint8_t * process_mime_body(
    Packet*, const uint8_t *ptr,
    const uint8_t *data_end_marker, MimeState *mime_ssn)
{
    int boundary_found = 0;
    const uint8_t *boundary_ptr = NULL;
    const uint8_t *attach_start = NULL;
    const uint8_t *attach_end = NULL;
    Email_DecodeState *decode_state = (Email_DecodeState *)(mime_ssn->decode_state);

    if ( mime_ssn->state_flags & MIME_FLAG_EMAIL_ATTACH )
        attach_start = ptr;
    /* look for boundary */
    if (mime_ssn->state_flags & MIME_FLAG_GOT_BOUNDARY)
    {
        boundary_found = search_api->search_instance_find
                (mime_ssn->mime_boundary.boundary_search, (const char *)ptr,
                        data_end_marker - ptr, 0, boundary_str_found);

        mime_search_info.length = mime_ssn->mime_boundary.boundary_len;

        if (boundary_found > 0)
        {
            boundary_ptr = ptr + mime_search_info.index;

            /* should start at beginning of line */
            if ((boundary_ptr == ptr) || (*(boundary_ptr - 1) == '\n'))
            {
                const uint8_t *eol;
                const uint8_t *eolm;
                const uint8_t *tmp;

                if (mime_ssn->state_flags & MIME_FLAG_EMAIL_ATTACH )
                {
                    attach_end = boundary_ptr-1;
                    mime_ssn->state_flags &= ~MIME_FLAG_EMAIL_ATTACH;
                    if(attach_start < attach_end)
                    {
                        if(EmailDecode( attach_start, attach_end, decode_state) < DECODE_SUCCESS )
                        {
                            // MIME_DecodeAlert();
                        }
                    }
                }


                /* Check for end boundary */
                tmp = boundary_ptr + mime_search_info.length;
                if (((tmp + 1) < data_end_marker) && (tmp[0] == '-') && (tmp[1] == '-'))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Mime boundary end found: %s--\n",
                            (char *)mime_ssn->mime_boundary.boundary););

                    /* no more MIME */
                    mime_ssn->state_flags &= ~MIME_FLAG_GOT_BOUNDARY;
                    mime_ssn->state_flags |= MIME_FLAG_MIME_END;

                    /* free boundary search */
                    search_api->search_instance_free(mime_ssn->mime_boundary.boundary_search);
                    mime_ssn->mime_boundary.boundary_search = NULL;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Mime boundary found: %s\n",
                            (char *)mime_ssn->mime_boundary.boundary););

                    mime_ssn->data_state = STATE_MIME_HEADER;
                }

                /* get end of line - there could be spaces after boundary before eol */
                get_mime_eol(boundary_ptr + mime_search_info.length, data_end_marker, &eol, &eolm);

                return eol;
            }
        }
    }

    if ( mime_ssn->state_flags & MIME_FLAG_EMAIL_ATTACH )
    {
        attach_end = data_end_marker;
        if(attach_start < attach_end)
        {
            if(EmailDecode( attach_start, attach_end, decode_state) < DECODE_SUCCESS )
            {
                //  MIME_DecodeAlert();
            }
        }
    }

    return data_end_marker;
}

/*
 * Reset MIME session state
 */
static void reset_mime_state(MimeState *mime_ssn)
{
    Email_DecodeState *decode_state = (Email_DecodeState *)(mime_ssn->decode_state);

    if (mime_ssn->mime_boundary.boundary_search != NULL)
    {
        search_api->search_instance_free(mime_ssn->mime_boundary.boundary_search);
        mime_ssn->mime_boundary.boundary_search = NULL;
    }

    mime_ssn->data_state = STATE_DATA_INIT;
    mime_ssn->state_flags = 0;
    ClearEmailDecodeState(decode_state);
    memset(&mime_ssn->mime_boundary, 0, sizeof(MimeBoundary));
}

#if 0
static inline FilePosition getFilePoistion(Packet *p)
{
    FilePosition position = SNORT_FILE_POSITION_UNKNOWN;

    if (PacketHasFullPDU(p))
        position = SNORT_FILE_FULL;
    else if (PacketHasStartOfPDU(p))
        position = SNORT_FILE_START;
    else if (p->packet_flags & PKT_PDU_TAIL)
        position = SNORT_FILE_END;
    else if (file_api->get_file_processed_size(p->flow))
        position = SNORT_FILE_MIDDLE;

    return position;
}
#endif

/*
 * Main function for mime processing
 *
 * This should be called when mime data is available
 */
const uint8_t * process_mime_data(void *packet, const uint8_t *start, const uint8_t *end,
        const uint8_t *data_end_marker, uint8_t *data_end, MimeState *mime_ssn, bool upload)
{
    Packet *p = (Packet *)packet;
    FilePosition position = SNORT_FILE_START;

    /* if we've just entered the data state, check for a dot + end of line
     * if found, no data */
    if ((mime_ssn->data_state == STATE_DATA_INIT) ||
            (mime_ssn->data_state == STATE_DATA_UNKNOWN))
    {
        if ((start < end) && (*start == '.'))
        {
            const uint8_t *eol = NULL;
            const uint8_t *eolm = NULL;

            get_mime_eol(start, end, &eol, &eolm);

            /* this means we got a real end of line and not just end of payload
             * and that the dot is only char on line */
            if ((eolm != end) && (eolm == (start + 1)))
            {
                /* if we're normalizing and not ignoring data copy data end marker
                 * and dot to alt buffer */

                reset_mime_state(mime_ssn);

                return eol;
            }
        }

        if (mime_ssn->data_state == STATE_DATA_INIT)
            mime_ssn->data_state = STATE_DATA_HEADER;

        /* XXX A line starting with a '.' that isn't followed by a '.' is
         * deleted (RFC 821 - 4.5.2.  TRANSPARENCY).  If data starts with
         * '. text', i.e a dot followed by white space then text, some
         * servers consider it data header and some data body.
         * Postfix and Qmail will consider the start of data:
         * . text\r\n
         * .  text\r\n
         * to be part of the header and the effect will be that of a
         * folded line with the '.' deleted.  Exchange will put the same
         * in the body which seems more reasonable. */
    }

    /* get end of data body
     * TODO check last bytes of previous packet to see if we had a partial
     * end of data */
    /* mime_current_search = &mime_data_end_search[0];
    data_end_found = search_api->search_instance_find
        (mime_data_search_mpse, (const char *)start, end - start,
         0, search_str_found);

    if (data_end_found > 0)
    {
        data_end_marker = start + mime_search_info.index;
        data_end = data_end_marker + mime_search_info.length;
    }
    else
    {
        data_end_marker = data_end = end;
    }
     */

    set_file_data((uint8_t*)start, (data_end - start));

    if ((mime_ssn->data_state == STATE_DATA_HEADER) ||
            (mime_ssn->data_state == STATE_DATA_UNKNOWN))
    {
#ifdef DEBUG_MSGS
        if (mime_ssn->data_state == STATE_DATA_HEADER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "DATA HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "DATA UNKNOWN STATE ~~~~~~~~~~~~~~~~~~~~~\n"););
        }
#endif

        start = process_mime_header(p, start, data_end_marker, mime_ssn);
        if (start == NULL)
            return NULL;

    }

    /* now we shouldn't have to worry about copying any data to the alt buffer
     * only mime headers if we find them and only if we're ignoring data */
    initFilePosition(&position, file_api->get_file_processed_size(p->flow));

    while ((start != NULL) && (start < data_end_marker))
    {
        /* multiple MIME attachments in one single packet.
         * Pipeline the MIME decoded data.*/
        if ( mime_ssn->state_flags & MIME_FLAG_MULTIPLE_EMAIL_ATTACH)
        {
            DecodeConfig *conf= mime_ssn->decode_conf;
            int detection_size = getDetectionSize(conf->b64_depth, conf->qp_depth,
                    conf->uu_depth, conf->bitenc_depth, (Email_DecodeState *)(mime_ssn->decode_state) );

            set_file_data(((Email_DecodeState *)(mime_ssn->decode_state))->decodePtr, detection_size);
            /*Process file type/file signature*/
            if (file_api->file_process(p,(uint8_t *)((Email_DecodeState *)(mime_ssn->decode_state))->decodePtr,
                    (uint16_t)((Email_DecodeState *)(mime_ssn->decode_state))->decoded_bytes, position, upload, false)
                    && (isFileStart(position)) && mime_ssn->log_state)
            {
                file_api->set_file_name_from_log(&(mime_ssn->log_state->file_log), p->flow);
            }
            updateFilePosition(&position, file_api->get_file_processed_size(p->flow));
            Detect(p);
            mime_ssn->state_flags &= ~MIME_FLAG_MULTIPLE_EMAIL_ATTACH;
            ResetEmailDecodeState((Email_DecodeState *)(mime_ssn->decode_state));
            p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
            /* Reset the log count when a packet goes through detection multiple times */
            DetectReset();
        }
        switch (mime_ssn->data_state)
        {
        case STATE_MIME_HEADER:
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "MIME HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
            start = process_mime_header(p, start, data_end_marker, mime_ssn);
            file_api->finalize_mime_position(p->flow, mime_ssn->decode_state, &position);
            break;
        case STATE_DATA_BODY:
            DEBUG_WRAP(DebugMessage(DEBUG_FILE, "DATA BODY STATE ~~~~~~~~~~~~~~~~~~~~~~~~\n"););
            start = process_mime_body(p, start, data_end_marker, mime_ssn);
            break;
        }
    }

    /* We have either reached the end of MIME header or end of MIME encoded data*/

    if((mime_ssn->decode_state) != NULL)
    {
        if ((position == SNORT_FILE_START) || (position == SNORT_FILE_FULL))
        {
            DecodeConfig *conf= mime_ssn->decode_conf;
            int detection_size = getDetectionSize(conf->b64_depth, conf->qp_depth,
                    conf->uu_depth, conf->bitenc_depth, (Email_DecodeState *)(mime_ssn->decode_state) );
            set_file_data(((Email_DecodeState *)(mime_ssn->decode_state))->decodePtr, detection_size);
        }
        else
        {
            set_file_data(((Email_DecodeState *)(mime_ssn->decode_state))->decodePtr, 0);
        }
        if ((data_end_marker != end)||(mime_ssn->state_flags & MIME_FLAG_MIME_END))
        {
            finalFilePosition(&position);
        }
        /*Process file type/file signature*/
        if (file_api->file_process(p,(uint8_t *)((Email_DecodeState *)(mime_ssn->decode_state))->decodePtr,
                (uint16_t)((Email_DecodeState *)(mime_ssn->decode_state))->decoded_bytes, position, upload, false)
                && (isFileStart(position))&& mime_ssn->log_state)
        {
            file_api->set_file_name_from_log(&(mime_ssn->log_state->file_log), p->flow);
        }
        ResetDecodedBytes((Email_DecodeState *)(mime_ssn->decode_state));
    }

    /* if we got the data end reset state, otherwise we're probably still in the data
     * to expect more data in next packet */
    if (data_end_marker != end)
    {
        reset_mime_state(mime_ssn);
    }

    return data_end;
}

/*
 * This is the initialization funcation for mime processing.
 * This should be called when snort initializes
 */
void init_mime(void)
{
    const char *error;
    int erroffset;
    const MimeToken *tmp;

    /* Header search */
    mime_hdr_search_mpse = search_api->search_instance_new();
    if (mime_hdr_search_mpse == NULL)
    {
        FatalError("Could not allocate MIME "
                "header search.\n");
    }

    for (tmp = &mime_hdrs[0]; tmp->name != NULL; tmp++)
    {
        mime_hdr_search[tmp->search_id].name = tmp->name;
        mime_hdr_search[tmp->search_id].name_len = tmp->name_len;

        search_api->search_instance_add(mime_hdr_search_mpse, tmp->name,
                tmp->name_len, tmp->search_id);
    }

    search_api->search_instance_prep(mime_hdr_search_mpse);

    /* create regex for finding boundary string - since it can be cut across multiple
     * lines, a straight search won't do. Shouldn't be too slow since it will most
     * likely only be acting on a small portion of data */
    mime_boundary_pcre.re = pcre_compile("boundary\\s*=\\s*\"?([^\\s\"]+)\"?",
            PCRE_CASELESS | PCRE_DOTALL,
            &error, &erroffset, NULL);
    if (mime_boundary_pcre.re == NULL)
    {
        FatalError("Failed to compile pcre regex for getting boundary "
                "in a multipart message: %s\n", error);
    }

    mime_boundary_pcre.pe = pcre_study(mime_boundary_pcre.re, 0, &error);

    if (error != NULL)
    {
        FatalError("Failed to study pcre regex for getting boundary "
                "in a multipart message: %s\n", error);
    }
}

/*
 * Free anything that needs it before shutting down preprocessor
 *
 * @param   none
 *
 * @return  none
 */
void free_mime(void)
{

    if (mime_hdr_search_mpse != NULL)
        search_api->search_instance_free(mime_hdr_search_mpse);

    if (mime_boundary_pcre.re )
        pcre_free(mime_boundary_pcre.re);

    if (mime_boundary_pcre.pe )
        pcre_free(mime_boundary_pcre.pe);
}

void free_mime_session(MimeState *mime_ssn)
{
    if (!mime_ssn)
        return;

    if (mime_ssn->mime_boundary.boundary_search != NULL)
    {
        search_api->search_instance_free(mime_ssn->mime_boundary.boundary_search);
        mime_ssn->mime_boundary.boundary_search = NULL;
    }

    if(mime_ssn->decode_state != NULL)
    {
        free(mime_ssn->decode_state);
    }
    if(mime_ssn->log_state != NULL)
    {
        free(mime_ssn->log_state);
    }

    free(mime_ssn);

}

/*
 * When the file ends (a MIME boundary detected), position are updated
 */
void finalize_mime_position(Flow *flow, void *decode_state, FilePosition *position)
{
    /* check to see if there are file data in the session or
     * new decoding data waiting for processing */
    if( file_api->get_file_processed_size(flow) ||
            (decode_state && ((Email_DecodeState *)decode_state)->decoded_bytes) )
        finalFilePosition(position);
}
