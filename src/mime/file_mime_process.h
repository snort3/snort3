//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// file_mime_process.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_PROCESS_H
#define FILE_MIME_PROCESS_H

// Provides list of MIME processing functions. Encoded file data will be decoded
// and file name will be extracted from MIME header
#include <string>
#include "file_api/file_api.h"
#include "mime/file_mime_config.h"
#include "mime/file_mime_decode.h"
#include "mime/file_mime_log.h"
#include "mime/file_mime_paf.h"

namespace snort
{
/* state flags */
#define MIME_FLAG_IN_CONTENT_TYPE            0x00000002
#define MIME_FLAG_GOT_BOUNDARY               0x00000004
#define MIME_FLAG_SEEN_HEADERS               0x00000008
#define MIME_FLAG_IN_CONT_TRANS_ENC          0x00000010
#define MIME_FLAG_FILE_ATTACH                0x00000020
#define MIME_FLAG_MULTIPLE_EMAIL_ATTACH      0x00000040
#define MIME_FLAG_MIME_END                   0x00000080
#define MIME_FLAG_IN_CONT_DISP               0x00000200
#define MIME_FLAG_IN_CONT_DISP_CONT          0x00000400

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    /* Data header section of data state */
#define STATE_DATA_BODY    2    /* Data body section of data state */
#define STATE_MIME_HEADER  3    /* MIME header section within data section */

enum FilenameState
{
    CONT_DISP_FILENAME_PARAM_NAME,
    CONT_DISP_FILENAME_PARAM_EQUALS,
    CONT_DISP_FILENAME_PARAM_VALUE_QUOTE,
    CONT_DISP_FILENAME_PARAM_VALUE
};

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64

class SO_PUBLIC MimeSession
{
public:
    MimeSession(Packet*, const DecodeConfig*, MailLogConfig*, uint64_t base_file_id=0,
        const uint8_t* uri=nullptr, const int32_t uri_length=0);
    virtual ~MimeSession();

    MimeSession(const MimeSession&) = delete;
    MimeSession& operator=(const MimeSession&) = delete;

    static void init();
    static void exit();

    const uint8_t* process_mime_data(Packet*, const uint8_t *data, int data_size,
        bool upload, FilePosition);

    int get_data_state();
    void set_data_state(int);
    MailLogState* get_log_state();
    void set_mime_stats(MimeStats*);

    const BufferData& get_ole_buf();
    const BufferData& get_vba_inspect_buf();

    struct AttachmentBuffer
    {
        const uint8_t* data = nullptr;
        uint32_t length = 0;
        bool finished = true;
    };

    const AttachmentBuffer get_attachment() { return attachment; }

protected:
    MimeDecode* decode_state = nullptr;

private:
    int data_state = STATE_DATA_INIT;
    int state_flags = 0;
    MimeDataPafInfo mime_boundary;
    const DecodeConfig* decode_conf = nullptr;
    MailLogConfig* log_config = nullptr;
    MailLogState* log_state = nullptr;
    MimeStats* mime_stats = nullptr;
    FilenameState filename_state = CONT_DISP_FILENAME_PARAM_NAME;
    std::string filename;
    bool continue_inspecting_file = true;
    // This counter is not an accurate count of files; used only for creating a unique mime_file_id
    uint32_t file_counter = 0;
    uint32_t file_offset = 0;
    uint64_t session_base_file_id = 0;
    uint64_t current_file_cache_file_id = 0;
    uint64_t current_multiprocessing_file_id = 0;
    const uint8_t* uri;
    const int32_t uri_length;
    uint64_t get_file_cache_file_id();
    uint64_t get_multiprocessing_file_id();
    void mime_file_process(Packet* p, const uint8_t* data, int data_size,
        FilePosition position, bool upload);
    void reset_part_state();

    // Individual service inspectors may have different implementations for these
    virtual int handle_header_line(const uint8_t*, const uint8_t*, int, Packet*) { return 0; }
    virtual int normalize_data(const uint8_t*, const uint8_t*, Packet*) { return 0; }
    virtual void decode_alert() { }
    virtual void decompress_alert() { }
    virtual void reset_state(Flow*) { }
    virtual bool is_end_of_data(Flow*) { return false; }

    void reset_mime_state();
    void setup_attachment_processing();
    const uint8_t* process_mime_header(Packet*, const uint8_t* ptr, const uint8_t* data_end_marker);
    bool process_header_line(const uint8_t*& ptr, const uint8_t* eol, const uint8_t* eolm, const
        uint8_t* start_hdr, Packet* p);
    const uint8_t* process_mime_body(const uint8_t* ptr, const uint8_t* data_end, FilePosition);
    const uint8_t* process_mime_data_paf(Packet*, const uint8_t* start, const uint8_t* end,
        bool upload, FilePosition);
    int extract_file_name(const char*& start, int length);

    uint8_t* partial_header = nullptr;      // single header line split into multiple sections
    uint32_t partial_header_len = 0;
    uint8_t* partial_data = nullptr;        // attachment's trailing bytes (suspected boundary)
    uint32_t partial_data_len = 0;
    uint8_t* rebuilt_data = nullptr;        // prepended attachment data for detection module

    AttachmentBuffer attachment;            // decoded and uncompressed file body
};
}
#endif

