//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_process.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_process.h"

#include "detection/detection_engine.h"
#include "file_api/file_flows.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "search_engines/search_tool.h"
#include "utils/util_cstring.h"

using namespace snort;

struct MimeToken
{
    const char* name;
    int name_len;
    int search_id;
};

enum MimeHdrEnum
{
    HDR_CONTENT_TYPE = 0,
    HDR_CONT_TRANS_ENC,
    HDR_CONT_DISP,
    HDR_LAST
};

const MimeToken mime_hdrs[] =
{
    { "Content-type:", 13, HDR_CONTENT_TYPE },
    { "Content-Transfer-Encoding:", 26, HDR_CONT_TRANS_ENC },
    { "Content-Disposition:", 20, HDR_CONT_DISP },
    { nullptr,             0, 0 }
};

struct MIMESearch
{
    const char* name;
    int name_len;
};

struct MIMESearchInfo
{
    int id;
    int index;
    int length;
};

static THREAD_LOCAL MIMESearchInfo mime_search_info;
static THREAD_LOCAL MIMESearch* mime_current_search = nullptr;

SearchTool* mime_hdr_search_mpse = nullptr;
MIMESearch mime_hdr_search[HDR_LAST];

static bool get_mime_eol(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    assert(eol and eolm);

    if ( !ptr or !end )
    {
        *eol = *eolm = end;
        return false;
    }

    tmp_eol = (const uint8_t*)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == nullptr)
    {
        *eol = *eolm = end;
        return false;
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
    return true;
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
static int search_str_found(void* id, void*, int index, void*, void*)
{
    int search_id = (int)(uintptr_t)id;

    mime_search_info.id = search_id;
    mime_search_info.length = mime_current_search[search_id].name_len;
    mime_search_info.index = index - mime_search_info.length;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

void MimeSession::setup_attachment_processing()
{
    /* Check for Encoding Type */
    if ( decode_conf && decode_conf->is_decoding_enabled())
    {
        if (decode_state == nullptr)
        {
            decode_state = new MimeDecode(decode_conf);
        }
        if (decode_state != nullptr)
            state_flags |= MIME_FLAG_FILE_ATTACH;
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
const uint8_t* MimeSession::process_mime_header(Packet* p, const uint8_t* ptr,
    const uint8_t* data_end_marker)
{
    const uint8_t* eol = data_end_marker;
    const uint8_t* eolm = eol;
    const uint8_t* start_hdr;

    start_hdr = ptr;
    bool cont = true;
    while (cont and ptr < data_end_marker)
    {
        bool found_end_marker = get_mime_eol(ptr, data_end_marker, &eol, &eolm);
        // Save partial header lines until we have the full line
        if (!found_end_marker)
        {
            if (partial_header)
            {
                // Single header line split into >2 sections, accumulate
                // FIXIT-P: could allocate reasonable-size buf and only reallocate if needed
                const uint32_t new_len = data_end_marker - ptr;
                const uint32_t cum_len = partial_header_len + new_len;
                uint8_t* tmp = new uint8_t[cum_len];
                memcpy(tmp, partial_header, partial_header_len);
                memcpy(tmp + partial_header_len, ptr, new_len);
                delete[] partial_header;
                partial_header_len = cum_len;
                partial_header = tmp;
            }
            else
            {
                partial_header_len = data_end_marker - ptr;
                partial_header = new uint8_t[partial_header_len];
                memcpy(partial_header, ptr, partial_header_len);
            }
            return data_end_marker;
        }
        if (partial_header)
        {
            const uint32_t remainder_header_len = eol - ptr;
            const uint32_t full_header_len = partial_header_len + remainder_header_len;
            const uint8_t* full_header = new uint8_t[full_header_len];
            const uint8_t* head_ptr = full_header;
            memcpy((void*)full_header, partial_header, partial_header_len);
            memcpy((void*)(full_header + partial_header_len), ptr, remainder_header_len);
            ptr = eol;
            // Update eol and eolm to point to full_header buffer. eol points to byte after end
            // marker and eolm points to start of the end marker - either \n or \r if CR precedes LF
            eol = full_header + full_header_len;
            if ((full_header_len > 1) && (*(eol - 2) == '\r'))
                eolm = eol - 2;
            else
                eolm = eol - 1;

            cont = process_header_line(head_ptr, eol, eolm, start_hdr, p);

            delete[] partial_header;
            partial_header = nullptr;
            partial_header_len = 0;
            delete[] full_header;
        }
        else
        {
            cont = process_header_line(ptr, eol, eolm, start_hdr, p);
        }
        state_flags |= MIME_FLAG_SEEN_HEADERS;
    }
    if (!cont)
    {
        data_state = STATE_DATA_BODY;
        delete[] partial_data;
        partial_data = nullptr;
        partial_data_len = 0;
    }
    return ptr;
}

static bool is_wsp(const uint8_t* c)
{
    return (*c == ' ' or *c == '\t');
}

bool MimeSession::process_header_line(const uint8_t*& ptr, const uint8_t* eol, const uint8_t* eolm,
    const uint8_t* start_hdr, Packet* p)
{
    const uint8_t* colon;
    const uint8_t* header_value_ptr = nullptr;
    int max_header_name_len = 0;

    /* got a line with only end of line marker should signify end of header */
    if (eolm == ptr)
    {
        /* if no headers, treat as data */
        if ((ptr == start_hdr) and !(state_flags & MIME_FLAG_SEEN_HEADERS))
            ptr = eolm;
        else
            ptr = eol;
        return false;
    }

    // If we're not folding, process the header field name
    if (!is_wsp(ptr))
    {
        // Clear flags from last header line
        state_flags &= ~(MIME_FLAG_IN_CONTENT_TYPE | MIME_FLAG_IN_CONT_TRANS_ENC);

        bool got_non_printable_in_header_name = false;

        // If we're not folding and the first char is a whitespace (other than space (0x20) or htab
        // (0x09) that means folding), it's not a header
        if (isspace((int)*ptr) || *ptr == ':')
        {
            return false;
        }

        /* look for header field colon - if we're not folding then we need
         * to find a header which will be all printables (except colon)
         * followed by a colon */
        colon = ptr;
        while ((colon < eolm) && (*colon != ':'))
        {
            if (((int)*colon < 33) || ((int)*colon > 126))
                got_non_printable_in_header_name = true;

            colon++;
        }

        if (colon + 1 < eolm)
            header_value_ptr = colon + 1;

        /* Check for Exim 4.32 exploit where number of chars before colon is greater than 64 */
        int header_name_len = colon - ptr;

        if ((colon < eolm) && (header_name_len > MAX_HEADER_NAME_LEN))
        {
            max_header_name_len = header_name_len;
        }

        /* If the end on line marker and end of line are the same, assume
         * header was truncated, so stay in data header state */
        if ((eolm != eol) &&
            ((colon == eolm) || got_non_printable_in_header_name))
        {
            /* no colon or got spaces in header name (won't be interpreted as a header)
             * assume we're in the body */
            return false;
        }

        if (tolower((int)*ptr) == 'c')
        {
            mime_current_search = &mime_hdr_search[0];
            int header_found = mime_hdr_search_mpse->find(
                (const char*)ptr, eolm - ptr, search_str_found, true);

            /* Headers must start at beginning of line */
            if ((header_found > 0) && (mime_search_info.index == 0))
            {
                switch (mime_search_info.id)
                {
                    case HDR_CONTENT_TYPE:
                        state_flags |= MIME_FLAG_IN_CONTENT_TYPE;
                        break;
                    case HDR_CONT_TRANS_ENC:
                        state_flags |= MIME_FLAG_IN_CONT_TRANS_ENC;
                        break;
                    case HDR_CONT_DISP:
                        state_flags |= MIME_FLAG_IN_CONT_DISP;
                        break;
                    default:
                        assert(false);
                        break;
                }
            }
        }
        else if (tolower((int)*ptr) == 'e')
        {
            if ((eolm - ptr) >= 9)
            {
                if (strncasecmp((const char*)ptr, "Encoding:", 9) == 0)
                {
                    state_flags |= MIME_FLAG_IN_CONT_TRANS_ENC;
                }
            }
        }
    }
    else if (!(state_flags & MIME_FLAG_SEEN_HEADERS))
    {
        // If the line starts with folding whitespace but we haven't seen any headers yet, we can't
        // be folding. Treat as body.
        return false;
    }
    else
    {
        // If we are folding, we've already processed the header field and are somewhere in the
        // header value
        header_value_ptr = ptr;
    }

    int ret = handle_header_line(ptr, eol, max_header_name_len, p);
    if (ret != 0)
        return false;

    // Now handle the header value
    const uint32_t header_value_len = eolm - header_value_ptr;

    if (state_flags & MIME_FLAG_IN_CONTENT_TYPE)
    {
        if (data_state == STATE_MIME_HEADER)
        {
            setup_attachment_processing();
        }
        // We don't need the value, so it doesn't matter if we're folding
        state_flags &= ~MIME_FLAG_IN_CONTENT_TYPE;
    }
    else if (state_flags & MIME_FLAG_IN_CONT_TRANS_ENC)
    {
        setup_attachment_processing();
        if (decode_state != nullptr and header_value_len > 0)
        {
            decode_state->process_decode_type((const char*)header_value_ptr, header_value_len);
        }
        // Don't clear the MIME_FLAG_IN_CONT_TRANS_ENC flag in case of folding
    }
    else if (state_flags & MIME_FLAG_IN_CONT_DISP)
    {
        int len = extract_file_name((const char*&)header_value_ptr, header_value_len);

        if (len > 0)
        {
            filename.assign((const char*)header_value_ptr, len);

            if (log_config->log_filename && log_state)
            {
                log_state->log_file_name(header_value_ptr, len);
            }
            state_flags &= ~MIME_FLAG_IN_CONT_DISP;
        }
    }

    ptr = eol;
    return true;
}

/* Get the end of data body (excluding boundary)*/
static const uint8_t* GetDataEnd(const uint8_t* data_start,
    const uint8_t* data_end_marker)
{
    // '\r\n' + '--' + MIME boundary string
    const int Max_Search = 4 + MAX_MIME_BOUNDARY_LEN;
    const uint8_t* start;
    // Exclude 2 bytes because either \r\n or '--'  at the end
    const uint8_t* end = data_end_marker - 2;

    // Search for the start of boundary, should be less than boundary length
    if (end > data_start + Max_Search)
        start = end - Max_Search;
    else
        start = data_start;

    while (end > start)
    {
        if (*(--end) != '\n')
            continue;

        if ((*(end+1) == '-') && (*(end+2) == '-'))
        {
            if ((end > start) && (*(end-1) == '\r'))
                return (end - 1);
            else
                return end;
        }
        break;
    }
    return data_end_marker;
}

const uint8_t* MimeSession::process_mime_body(const uint8_t* ptr,
    const uint8_t* data_end, FilePosition position)
{
    auto data_size = data_end - ptr;

    if (partial_data && mime_boundary.boundary_search_len < data_size)
    {
        delete[] rebuilt_data;
        rebuilt_data = new uint8_t[partial_data_len + data_size];
        memcpy(rebuilt_data, partial_data, partial_data_len);
        memcpy(rebuilt_data + partial_data_len, ptr, data_size);

        ptr = rebuilt_data;
        data_size = partial_data_len + data_size;

        delete[] partial_data;
        partial_data = nullptr;
        partial_data_len = 0;
    }

    const uint8_t* attach_end = isFileEnd(position) && mime_boundary.boundary_search_len < data_size
        ? GetDataEnd(ptr, ptr + data_size) : ptr + data_size - mime_boundary.boundary_search_len;

    if (!isFileEnd(position)
        && mime_boundary.boundary_search_len && mime_boundary.boundary_state != MIME_PAF_BOUNDARY_UNKNOWN)
    {
        delete[] partial_data;
        partial_data_len = mime_boundary.boundary_search_len;
        partial_data = new uint8_t[partial_data_len];
        memcpy(partial_data, attach_end, partial_data_len);
    }

    if (ptr < attach_end && decode_state)
    {
        decode_state->finalize_decoder(mime_stats);
        if (decode_state->decode_data(ptr, attach_end) == DECODE_FAIL)
            decode_alert();
    }

    return data_end;
}

/*
 * Reset MIME session state
 */
void MimeSession::reset_mime_state()
{
    data_state = STATE_DATA_INIT;
    state_flags = 0;
    if (decode_state)
        decode_state->clear_decode_state();
}

const uint8_t* MimeSession::process_mime_data_paf(
    Packet* p, const uint8_t* start, const uint8_t* end, bool upload, FilePosition position)
{
    Flow* flow = p->flow;
    bool done_data = is_end_of_data(flow);

    /* if we've just entered the data state, check for a dot + end of line
     * if found, no data */
    if ( data_state == STATE_DATA_INIT )
    {
        if ((start < end) && (*start == '.'))
        {
            const uint8_t* eol = nullptr;
            const uint8_t* eolm = nullptr;

            get_mime_eol(start, end, &eol, &eolm);

            /* this means we got a real end of line and not just end of payload
             * and that the dot is only char on line */
            if ((eolm != end) && (eolm == (start + 1)))
            {
                /* if we're normalizing and not ignoring data copy data end marker
                 * and dot to alt buffer */
                if (normalize_data(start, end, p) < 0)
                    return nullptr;

                reset_mime_state();

                return eol;
            }
        }

        if (data_state == STATE_DATA_INIT)
            data_state = STATE_DATA_HEADER;

        /* A line starting with a '.' that isn't followed by a '.' is
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

    if (data_state == STATE_DATA_HEADER)
    {
        start = process_mime_header(p, start, end);
        if (start == nullptr)
            return nullptr;
    }

    if (normalize_data(start, end, p) < 0)
        return nullptr;

    // now we shouldn't have to worry about copying any data to the alt buffer
    // only mime headers if we find them and only if we're ignoring data

    while ((start != nullptr) && (start < end))
    {
        switch (data_state)
        {
        case STATE_MIME_HEADER:
            start = process_mime_header(p, start, end);
            break;

        case STATE_DATA_BODY:
            if (isFileEnd(position))
                data_state = STATE_MIME_HEADER;

            if (!(state_flags & MIME_FLAG_FILE_ATTACH))
                start = end;
            else
            {
                start = process_mime_body(start, end, position);

                const DecodeConfig* conf = decode_conf;
                const uint8_t* buffer = nullptr;
                uint32_t buf_size = 0;

                decode_state->get_decoded_data(&buffer, &buf_size);

                if (conf and buf_size > 0)
                {
                    const uint8_t* decomp_buffer = nullptr;
                    uint32_t detection_size, decomp_buf_size = 0;

                    detection_size = (uint32_t)decode_state->get_detection_depth();

                    DecodeResult result =
                        decode_state->decompress_data(buffer, detection_size, decomp_buffer, decomp_buf_size);

                    if (result != DECODE_SUCCESS)
                        decompress_alert();

                    if (session_base_file_id)
                        set_file_data(decomp_buffer, decomp_buf_size, get_multiprocessing_file_id());
                    else
                        set_file_data(decomp_buffer, decomp_buf_size, file_counter);

                    attachment.data = decomp_buffer;
                    attachment.length = decomp_buf_size;
                    attachment.finished = isFileEnd(position);
                }

                // Process file type/file signature
                mime_file_process(p, buffer, buf_size, position, upload);

                if (mime_stats)
                {
                    switch (decode_state->get_decode_type())
                    {
                        case DECODE_B64:
                            mime_stats->b64_bytes += buf_size;
                            break;
                        case DECODE_QP:
                            mime_stats->qp_bytes += buf_size;
                            break;
                        case DECODE_UU:
                            mime_stats->uu_bytes += buf_size;
                            break;
                        case DECODE_BITENC:
                            mime_stats->bitenc_bytes += buf_size;
                            break;
                        default:
                            break;
                    }
                }

                decode_state->reset_decoded_bytes();
            }
            break;
        }
    }

    if (isFileEnd(position))
        reset_part_state();

    /* if we got the data end reset state, otherwise we're probably still in the data
     *      * to expect more data in next packet */
    if (done_data)
    {
        reset_mime_state();
        reset_state(flow);
    }

    return end;
}

void MimeSession::reset_part_state()
{
    state_flags = 0;
    filename_state = CONT_DISP_FILENAME_PARAM_NAME;

    delete[] partial_header;
    partial_header = nullptr;
    partial_header_len = 0;

    delete[] partial_data;
    partial_data = nullptr;
    partial_data_len = 0;

    if (decode_state)
    {
        decode_state->clear_decode_state();
        decode_state->file_decomp_reset();
    }

    // Clear MIME's file data to prepare for next file
    filename.clear();
    file_counter++;
    file_offset = 0;
    current_file_cache_file_id = 0;
    current_multiprocessing_file_id = 0;
    continue_inspecting_file = true;
}

// Main function for mime processing
// This should be called when mime data is available
const uint8_t* MimeSession::process_mime_data(Packet* p, const uint8_t* start,
    int data_size, bool upload, FilePosition position)
{
    const uint8_t* attach_start = start;
    const uint8_t* attach_end;

    const uint8_t* data_end_marker = start + data_size;

    attachment.data = nullptr;
    attachment.length = 0;
    attachment.finished = true;

    if (position != SNORT_FILE_POSITION_UNKNOWN)
    {
        process_mime_data_paf(p, attach_start, data_end_marker,
            upload, position);
        return data_end_marker;
    }

    initFilePosition(&position, file_offset);
    // look for boundary
    while (start < data_end_marker)
    {
        // Found the boundary, start processing data
        if (process_mime_paf_data(&(mime_boundary),  *start))
        {
            attach_end = start;
            finalFilePosition(&position);
            process_mime_data_paf(p, attach_start, attach_end,
                upload, position);
            data_state = STATE_MIME_HEADER;
            return attach_end;
        }

        start++;
    }

    if ((start == data_end_marker) && (attach_start < data_end_marker))
    {
        updateFilePosition(&position, file_offset);
        process_mime_data_paf(p, attach_start, data_end_marker,
            upload, position);
    }

    return data_end_marker;
}

int MimeSession::get_data_state()
{
    return data_state;
}

void MimeSession::set_data_state(int state)
{
    data_state = state;
}

void MimeSession::set_mime_stats(MimeStats* stats)
{
    mime_stats = stats;
}

const BufferData& MimeSession::get_ole_buf()
{
    if (!decode_state)
        return BufferData::buffer_null;

    return decode_state->_get_ole_buf();
}

const BufferData& MimeSession::get_vba_inspect_buf()
{
    if (!decode_state)
        return BufferData::buffer_null;

    return decode_state->get_decomp_vba_data();
}

MailLogState* MimeSession::get_log_state()
{
    return log_state;
}

int MimeSession::extract_file_name(const char*& start, int length)
{
    const char* tmp = start;
    const char* end = start+length;

    if (length <= 0)
        return -1;

    while (tmp < end)
    {
        switch (filename_state)
        {
            case CONT_DISP_FILENAME_PARAM_NAME:
            {
                tmp = SnortStrcasestr(start, length, "filename");
                if ( tmp == nullptr )
                    return -1;
                tmp = tmp + 8;
                filename_state = CONT_DISP_FILENAME_PARAM_EQUALS;
                break;
            }
            case CONT_DISP_FILENAME_PARAM_EQUALS:
            {
                //skip past whitespace and '='
                if (isspace(*tmp) or (*tmp == '='))
                    tmp++;
                else if (*tmp == '"')
                {
                    // Skip past the quote
                    tmp++;
                    filename_state = CONT_DISP_FILENAME_PARAM_VALUE_QUOTE;
                }
                else
                {
                    filename_state = CONT_DISP_FILENAME_PARAM_VALUE;
                    start = tmp;
                }
                break;
            }
            case CONT_DISP_FILENAME_PARAM_VALUE_QUOTE:
                start = tmp;
                tmp = SnortStrnPbrk(start,(end - tmp),"\"");
                if (tmp)
                {
                    end = tmp;
                    return (end - start);
                }
                // Since we have the full header line and there can't be wrapping within a quoted
                // string, getting here means the line is malformed. Treat like unquoted string
                filename_state = CONT_DISP_FILENAME_PARAM_VALUE;
                tmp = start;
                break;
            case CONT_DISP_FILENAME_PARAM_VALUE:
                // Go until we get a ';' or whitespace
                if ((*tmp == ';') or isspace(*tmp))
                {
                    end = tmp;
                    return (end - start);
                }
                tmp++;
                break;
        }
    }
    if (filename_state == CONT_DISP_FILENAME_PARAM_VALUE)
    {
        // The filename is ended by the eol marker
        return (end - start);
    }
    return -1;
}

/*
 * This is the initialization function for mime processing.
 * This should be called when snort initializes
 */
void MimeSession::init()
{
    MimeDecode::init();

    mime_hdr_search_mpse = new SearchTool;
    for (const MimeToken* tmp = &mime_hdrs[0]; tmp->name != nullptr; tmp++)
    {
        mime_hdr_search[tmp->search_id].name = tmp->name;
        mime_hdr_search[tmp->search_id].name_len = tmp->name_len;
        mime_hdr_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }

    mime_hdr_search_mpse->prep();
}

void MimeSession::exit()
{
    if (mime_hdr_search_mpse != nullptr)
        delete mime_hdr_search_mpse;
}

MimeSession::MimeSession(Packet* p, const DecodeConfig* dconf, MailLogConfig* lconf, uint64_t base_file_id,
    const uint8_t* uri, const int32_t uri_length):
    decode_conf(dconf),
    log_config(lconf),
    log_state(new MailLogState(log_config)),
    session_base_file_id(base_file_id),
    uri(uri),
    uri_length(uri_length)
{
    p->flow->stash->store(STASH_EXTRADATA_MIME, log_state);
    reset_mime_paf_state(&mime_boundary);
}

MimeSession::~MimeSession()
{
    delete decode_state;
    delete[] partial_header;
    delete[] partial_data;
    delete[] rebuilt_data;
}

// File verdicts get cached with key (file_id, sip, dip). File_id is hash of filename if available.
// Otherwise file_id is 0 and verdict will not be cached.
uint64_t MimeSession::get_file_cache_file_id()
{
    if (!current_file_cache_file_id and filename.length() > 0)
        current_file_cache_file_id = str_to_hash((const uint8_t*)filename.c_str(), filename.length());
    return current_file_cache_file_id;
}

// This file id is used to store file contexts on the flow during processing. Each file processed
// per flow needs a unique (per flow) id, so use hash of the URL (passed from http_inspect) with a
// file counter
uint64_t MimeSession::get_multiprocessing_file_id()
{
    if (!current_multiprocessing_file_id and session_base_file_id)
    {
        const int data_len = sizeof(session_base_file_id) + sizeof(file_counter);
        uint8_t data[data_len];
        memcpy(data, (void*)&session_base_file_id, sizeof(session_base_file_id));
        memcpy(data + sizeof(session_base_file_id), (void*)&file_counter, sizeof(file_counter));
        current_multiprocessing_file_id = str_to_hash(data, data_len);
    }
    return current_multiprocessing_file_id;
}

void MimeSession::mime_file_process(Packet* p, const uint8_t* data, int data_size,
    FilePosition position, bool upload)
{
    Flow* flow = p->flow;
    FileFlows* file_flows = FileFlows::get_file_flows(flow);

    if (!file_flows)
        return;

    if (continue_inspecting_file)
    {
        if (session_base_file_id)
        {
            const FileDirection dir = upload ? FILE_UPLOAD : FILE_DOWNLOAD;
            continue_inspecting_file = file_flows->file_process(p, get_file_cache_file_id(), data,
                data_size, file_offset, dir, get_multiprocessing_file_id(), position, (const uint8_t*)filename.c_str(),
                filename.length());
        }
        else
        {
            continue_inspecting_file = file_flows->file_process(p, data, data_size, position,
                upload, 0, (const uint8_t*)filename.c_str(),
                filename.length());
        }
        file_offset += data_size;
        if (continue_inspecting_file and (isFileStart(position)) && log_state)
        {
            continue_inspecting_file = file_flows->set_file_name((const uint8_t*)filename.c_str(),
                filename.length(), 0, get_multiprocessing_file_id(), uri, uri_length);
            filename.clear();
        }
    }
}
