//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// file_mime_decode.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_decode.h"

#include "decompress/file_olefile.h"
#include "utils/util_cstring.h"

#include "decode_b64.h"
#include "decode_bit.h"
#include "decode_qp.h"
#include "decode_uu.h"
#include "file_mime_context_data.h"

using namespace snort;

const BufferData BufferData::buffer_null;

void MimeDecode::init()
{ MimeDecodeContextData::init(); }

void MimeDecode::reset_decoded_bytes()
{
    if (decoder)
        decoder->reset_decoded_bytes();
}

void MimeDecode::clear_decode_state()
{
    decode_type = DECODE_NONE;
    if (decoder)
        decoder->reset_decode_state();
}

void MimeDecode::process_decode_type(const char* start, int length, bool cnt_xf,
    MimeStats* mime_stats)
{
    if (decoder)
        delete decoder;

    decoder = nullptr;

    if (cnt_xf)
    {
        if (config->get_b64_depth() > -1)
        {
            const char* tmp = SnortStrcasestr(start, length, "base64");

            if ( tmp )
            {
                decode_type = DECODE_B64;
                if (mime_stats)
                    mime_stats->b64_attachments++;
                decoder = new B64Decode(config->get_max_depth(config->get_b64_depth()),
                        config->get_b64_depth());
                file_decomp_reset();
                return;
            }
        }

        if (config->get_qp_depth() > -1)
        {
            const char* tmp = SnortStrcasestr(start, length, "quoted-printable");

            if ( tmp )
            {
                decode_type = DECODE_QP;
                if (mime_stats)
                    mime_stats->qp_attachments++;
                decoder = new QPDecode(config->get_max_depth(config->get_qp_depth()),
                        config->get_qp_depth());
                file_decomp_reset();
                return;
            }
        }

        if (config->get_uu_depth() > -1)
        {
            const char* tmp = SnortStrcasestr(start, length, "uuencode");

            if ( tmp )
            {
                decode_type = DECODE_UU;
                if (mime_stats)
                    mime_stats->uu_attachments++;
                decoder = new UUDecode(config->get_max_depth(config->get_uu_depth()),
                        config->get_uu_depth());
                file_decomp_reset();
                return;
            }
        }
    }

    if (config->get_bitenc_depth() > -1)
    {
        decode_type = DECODE_BITENC;
        if (mime_stats)
            mime_stats->bitenc_attachments++;
        decoder = new BitDecode(config->get_max_depth(config->get_bitenc_depth()),
            config->get_bitenc_depth());
        file_decomp_reset();
        return;
    }
}

DecodeResult MimeDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint8_t* decode_buf = MimeDecodeContextData::get_decode_buf();
    return (decoder ? decoder->decode_data(start,end, decode_buf) : DECODE_SUCCESS);
}

int MimeDecode::get_detection_depth()
{
    return (decoder ? decoder->get_detection_depth() : 0);
}

int MimeDecode::get_decoded_data(const uint8_t** buf,  uint32_t* size)
{
    return (decoder ? decoder->get_decoded_data(buf, size) : 0);
}

DecodeType MimeDecode::get_decode_type()
{
    return decode_type;
}

DecodeResult MimeDecode::decompress_data(const uint8_t* buf_in, uint32_t size_in,
                                         const uint8_t*& buf_out, uint32_t& size_out)
{
    DecodeResult result = DECODE_SUCCESS;
    buf_out = buf_in;
    size_out = size_in;

    if ( (fd_state == nullptr) || (size_in == 0) )
        return result;

    clear_decomp_vba_data();

    if ( fd_state->State == STATE_COMPLETE )
        return result;

    uint8_t* decompress_buf = MimeDecodeContextData::get_decompress_buf();
    uint32_t decompress_buf_size = MimeDecodeContextData::get_decompress_buf_size();
    fd_state->Next_In = buf_in;
    fd_state->Avail_In = size_in;
    fd_state->Next_Out = decompress_buf;
    fd_state->Avail_Out = decompress_buf_size;

    const fd_status_t status = File_Decomp(fd_state);

    switch ( status )
    {
    case File_Decomp_DecompError:
        result = DECODE_FAIL;
        // fallthrough
    case File_Decomp_NoSig:
    case File_Decomp_Error:
        break;
    default:
        buf_out = decompress_buf;
        size_out = fd_state->Next_Out - decompress_buf;
        get_ole_data();
        break;
    }

    return result;
}

void MimeDecode::get_ole_data()
{
    uint8_t* ole_data_ptr;
    uint32_t ole_len;

    fd_state->get_ole_data(ole_data_ptr, ole_len);

    if (ole_data_ptr)
    {
        ole_data.set(ole_len, ole_data_ptr, false);

        //Reset the ole data ptr once it is stored in msg body
        fd_state->ole_data_reset();
    }
}

const BufferData& MimeDecode::get_decomp_vba_data()
{
    if (decompressed_vba_data.length() > 0)
        return decompressed_vba_data;

    if (ole_data.length() <= 0)
        return BufferData::buffer_null;

    uint8_t* buf = nullptr;
    uint32_t buf_len = 0;
    
    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
               "Found OLE file. Sending %d bytes for the processing.\n",
                ole_data.length());

    oleprocess(ole_data.data_ptr(), ole_data.length(), buf, buf_len);

    if (buf && buf_len)
        decompressed_vba_data.set(buf_len, buf, true);

    return decompressed_vba_data;
}

void MimeDecode::clear_decomp_vba_data()
{
    ole_data.reset();
    decompressed_vba_data.reset();
}

const BufferData& MimeDecode::_get_ole_buf()
{
    if (ole_data.length() <= 0)
        return BufferData::buffer_null;
    return ole_data;
}

void MimeDecode::file_decomp_reset()
{
    if ( fd_state == nullptr )
        return;

    if ( fd_state->State == STATE_READY )
        return;

    File_Decomp_StopFree(fd_state);
    fd_state = nullptr;

    file_decomp_init();
}

void MimeDecode::file_decomp_init()
{
    bool decompress_pdf = config->is_decompress_pdf();
    bool decompress_swf = config->is_decompress_swf();
    bool decompress_zip = config->is_decompress_zip();
    bool decompress_vba = config->is_decompress_vba();

    if ( !decompress_pdf && !decompress_swf && !decompress_zip )
        return;

    fd_state = File_Decomp_New();
    fd_state->Modes =
        (decompress_pdf ? FILE_PDF_DEFL_BIT : 0) |
        (decompress_swf ? (FILE_SWF_ZLIB_BIT | FILE_SWF_LZMA_BIT) : 0) |
        (decompress_zip ? FILE_ZIP_DEFL_BIT : 0) |
        (decompress_vba ? FILE_VBA_EXTR_BIT : 0);
    fd_state->Alert_Callback = nullptr;
    fd_state->Alert_Context = nullptr;
    fd_state->Compr_Depth = 0;
    fd_state->Decompr_Depth = 0;

    (void)File_Decomp_Init(fd_state);
}

MimeDecode::MimeDecode(const DecodeConfig* conf)
{
    config = conf;
    file_decomp_init();
}

MimeDecode::~MimeDecode()
{
    if (fd_state)
        File_Decomp_StopFree(fd_state);

    if (decoder)
        delete decoder;
}

