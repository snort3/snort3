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
// http_stream_splitter_reassemble.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_stream_splitter.h"

#include "protocols/packet.h"

#include "http_inspect.h"
#include "http_module.h"
#include "http_test_input.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

void HttpStreamSplitter::chunk_spray(HttpFlowData* session_data, uint8_t* buffer,
    const uint8_t* data, unsigned length) const
{
    ChunkState& curr_state = session_data->chunk_state[source_id];
    uint32_t& expected = session_data->chunk_expected_length[source_id];
    const bool& is_broken_chunk = session_data->is_broken_chunk[source_id];
    uint32_t& num_good_chunks = session_data->num_good_chunks[source_id];

    if (is_broken_chunk && (num_good_chunks == 0))
        curr_state = CHUNK_BAD;

    for (int32_t k=0; k < static_cast<int32_t>(length); k++)
    {
        switch (curr_state)
        {
        case CHUNK_NEWLINES:
        case CHUNK_LEADING_WS:
            // Cases are combined in reassemble(). CHUNK_LEADING_WS here to avoid compiler warning.
            if (!is_sp_tab_cr_lf[data[k]])
            {
                curr_state = CHUNK_NUMBER;
                k--;
            }
            break;
        case CHUNK_ZEROS:
        case CHUNK_NUMBER:
            // CHUNK_ZEROS is not a distinct state in reassemble(). Here to avoid compiler warning.
            if (data[k] == '\r')
                curr_state = CHUNK_HCRLF;
            else if (data[k] == '\n')
            {
                curr_state = CHUNK_HCRLF;
                k--;
            }
            else if (data[k] == ';')
                curr_state = CHUNK_OPTIONS;
            else if (is_sp_tab[data[k]])
                curr_state = CHUNK_TRAILING_WS;
            else
                expected = expected * 16 + as_hex[data[k]];
            break;
        case CHUNK_TRAILING_WS:
        case CHUNK_OPTIONS:
            // No practical difference between trailing white space and options in reassemble()
            if (data[k] == '\r')
                curr_state = CHUNK_HCRLF;
            else if (data[k] == '\n')
            {
                curr_state = CHUNK_HCRLF;
                k--;
            }
            break;
        case CHUNK_HCRLF:
            if (expected > 0)
                curr_state = CHUNK_DATA;
            else
            {
                // Terminating zero-length chunk
                assert(k+1 == static_cast<int32_t>(length));
                curr_state = CHUNK_NEWLINES;
            }
            break;
        case CHUNK_DATA:
          {
            const uint32_t skip_amount = (length-k <= expected) ? length-k : expected;
            const bool at_start = (session_data->body_octets[source_id] == 0) &&
                (session_data->section_offset[source_id] == 0);
            decompress_copy(buffer, session_data->section_offset[source_id], data+k, skip_amount,
                session_data->compression[source_id], session_data->compress_stream[source_id],
                at_start, session_data->get_infractions(source_id),
                session_data->events[source_id], session_data);
            if ((expected -= skip_amount) == 0)
                curr_state = CHUNK_DCRLF1;
            k += skip_amount-1;
            break;
          }
        case CHUNK_DCRLF1:
            curr_state = CHUNK_DCRLF2;
            if (data[k] == '\n')
                k--;
            break;
        case CHUNK_DCRLF2:
            if (is_broken_chunk && (--num_good_chunks == 0))
                curr_state = CHUNK_BAD;
            else
            {
                curr_state = CHUNK_NEWLINES;
                expected = 0;
            }
            if (!is_cr_lf[data[k]])
                k--;
            break;
        case CHUNK_BAD:
          {
            const uint32_t skip_amount = length-k;
            const bool at_start = (session_data->body_octets[source_id] == 0) &&
                (session_data->section_offset[source_id] == 0);
            decompress_copy(buffer, session_data->section_offset[source_id], data+k, skip_amount,
                session_data->compression[source_id], session_data->compress_stream[source_id],
                at_start, session_data->get_infractions(source_id),
                session_data->events[source_id], session_data);
            k += skip_amount-1;
            break;
          }
        }
    }
}

void HttpStreamSplitter::process_gzip_header(const uint8_t* data,
    uint32_t length, HttpFlowData* session_data) const
{
    uint32_t& header_bytes_processed = session_data->gzip_header_bytes_processed[source_id];
    uint32_t input_bytes_processed = 0;
    if (session_data->gzip_state[source_id] == GZIP_TBD)
    {
        static const uint8_t gzip_magic[] = {0x1f, 0x8b, 0x08};
        static const uint8_t magic_length = 3;
        const uint32_t magic_cmp_len = (magic_length - header_bytes_processed) < length ?
            (magic_length - header_bytes_processed) : length;

        if (memcmp(data, gzip_magic + header_bytes_processed, magic_cmp_len))
            session_data->gzip_state[source_id] = GZIP_MAGIC_BAD;
        else if (header_bytes_processed + length >= magic_length)
            session_data->gzip_state[source_id] = GZIP_MAGIC_GOOD;
        header_bytes_processed += magic_cmp_len;
        input_bytes_processed += magic_cmp_len;
    }
    if (session_data->gzip_state[source_id] == GZIP_MAGIC_GOOD and length > input_bytes_processed)
    {
        const uint8_t gzip_flags = data[input_bytes_processed];
        if (gzip_flags & GZIP_FLAG_FEXTRA)
        {
            *session_data->get_infractions(source_id) += INF_GZIP_FEXTRA;
            session_data->events[source_id]->create_event(EVENT_GZIP_FEXTRA);
        }
        header_bytes_processed++;
        session_data->gzip_state[source_id] = GZIP_FLAGS_PROCESSED;
    }
}

bool HttpStreamSplitter::gzip_header_check_done(HttpFlowData* session_data) const
{
    return session_data->gzip_state[source_id] == HttpEnums::GZIP_MAGIC_BAD or
        session_data->gzip_state[source_id] == HttpEnums::GZIP_FLAGS_PROCESSED;
}

void HttpStreamSplitter::decompress_copy(uint8_t* buffer, uint32_t& offset, const uint8_t* data,
    uint32_t length, HttpEnums::CompressId& compression, z_stream*& compress_stream,
    bool at_start, HttpInfractions* infractions, HttpEventGen* events, HttpFlowData* session_data) const
{
    if ((compression == CMP_GZIP) || (compression == CMP_DEFLATE))
    {
        if (compression == CMP_GZIP and !gzip_header_check_done(session_data))
            process_gzip_header(data, length, session_data);

        compress_stream->next_in = const_cast<Bytef*>(data);
        compress_stream->avail_in = length;
        compress_stream->next_out = buffer + offset;
        compress_stream->avail_out = MAX_OCTETS - offset;
        int ret_val = inflate(compress_stream, Z_SYNC_FLUSH);

        if ((ret_val == Z_OK) || (ret_val == Z_STREAM_END))
        {
            offset = MAX_OCTETS - compress_stream->avail_out;
            if (compress_stream->avail_in > 0)
            {
                // There are two ways not to consume all the input
                if (ret_val == Z_STREAM_END)
                {
                    // The zipped data stream ended but there is more input data
                    *infractions += INF_GZIP_EARLY_END;
                    events->create_event(EVENT_GZIP_EARLY_END);
                    const uInt num_copy =
                        (compress_stream->avail_in <= compress_stream->avail_out) ?
                        compress_stream->avail_in : compress_stream->avail_out;
                    memcpy(buffer + offset, data + (length - compress_stream->avail_in), num_copy);
                    offset += num_copy;
                }
                else
                {
                    assert(compress_stream->avail_out == 0);
                    // The data expanded too much
                    *infractions += INF_GZIP_OVERRUN;
                    events->create_event(EVENT_GZIP_OVERRUN);
                }
                compression = CMP_NONE;
                inflateEnd(compress_stream);
                delete compress_stream;
                compress_stream = nullptr;
                // FIXIT-E - Will need to clear gzip header processing state here when we implement
                // processing multiple gzip members in a message section
            }
            return;
        }
        else if ((compression == CMP_DEFLATE) && at_start && (ret_val == Z_DATA_ERROR))
        {
            // Some incorrect implementations of deflate don't use the expected header. Feed a
            // dummy header to zlib and retry the inflate.
            static constexpr uint8_t zlib_header[2] = { 0x78, 0x01 };

            inflateReset(compress_stream);
            compress_stream->next_in = const_cast<Bytef*>(zlib_header);
            compress_stream->avail_in = sizeof(zlib_header);
            inflate(compress_stream, Z_SYNC_FLUSH);

            // Start over at the beginning
            decompress_copy(buffer, offset, data, length, compression, compress_stream, false,
                infractions, events, session_data);
            return;
        }
        else
        {
            *infractions += INF_GZIP_FAILURE;
            events->create_event(EVENT_GZIP_FAILURE);
            compression = CMP_NONE;
            inflateEnd(compress_stream);
            delete compress_stream;
            compress_stream = nullptr;
            // Since we failed to uncompress the data, fall through
        }
    }

    // The following precaution is necessary because mixed compressed and uncompressed data can
    // cause the buffer to overrun even though we are not decompressing right now
    if (length > MAX_OCTETS - offset)
    {
        length = MAX_OCTETS - offset;
        *infractions += INF_GZIP_OVERRUN;
        events->create_event(EVENT_GZIP_OVERRUN);
    }
    memcpy(buffer + offset, data, length);
    offset += length;
}

const StreamBuffer HttpStreamSplitter::reassemble(Flow* flow, unsigned total,
    unsigned, const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    Profile profile(HttpModule::get_profile_stats());

    copied = len;

    HttpFlowData* session_data = HttpInspect::http_get_flow_data(flow);
    if (session_data == nullptr)
    {
        assert(false);
        return { nullptr, 0 };
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
    {
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
        {
            if (!(flags & PKT_PDU_TAIL))
            {
                return { nullptr, 0 };
            }
            bool tcp_close;
            uint8_t* test_buffer;
            unsigned unused;
            HttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, total, unused,
                flags, source_id, tcp_close);
            if (tcp_close)
            {
                finish(flow);
            }
            if (test_buffer == nullptr)
            {
                // Source ID does not match test data, no test data was flushed, preparing for a
                // TCP connection close, or there is no more test data
                return { nullptr, 0 };
            }
            data = test_buffer;
        }
        else
        {
            fprintf(HttpTestManager::get_output_file(), "Reassemble from flow data %" PRIu64
                " direction %d total %u length %u partial %d\n", session_data->seq_num, source_id,
                total, len, session_data->partial_flush[source_id]);
            fflush(HttpTestManager::get_output_file());
        }
    }
#endif

    if ((session_data->type_expected[source_id] == SEC_ABORT) ||
        (session_data->section_type[source_id] == SEC__NOT_COMPUTE))
    {
        assert(session_data->type_expected[source_id] != SEC_ABORT);
        assert(session_data->section_type[source_id] != SEC__NOT_COMPUTE);
        session_data->type_expected[source_id] = SEC_ABORT;
        return { nullptr, 0 };
    }

    // Sometimes it is necessary to reassemble zero bytes when a connection is closing to trigger
    // proper clean up. But even a zero-length buffer cannot be processed with a nullptr lest we
    // get in trouble with memcpy() (undefined behavior) or some library.
    if (data == nullptr)
    {
        if (len != 0)
        {
            assert(false);
            session_data->type_expected[source_id] = SEC_ABORT;
            return { nullptr, 0 };
        }
        data = (const uint8_t*)"";
    }

    uint8_t*& partial_buffer = session_data->partial_buffer[source_id];
    uint32_t& partial_buffer_length = session_data->partial_buffer_length[source_id];
    uint32_t& partial_raw_bytes = session_data->partial_raw_bytes[source_id];
    assert(partial_raw_bytes + total <= MAX_OCTETS);

    if ((session_data->section_offset[source_id] == 0) &&
        (session_data->octets_expected[source_id] != partial_raw_bytes + total))
    {
        assert(!session_data->for_httpx);
        assert(total == 0); // FIXIT-L this special exception for total of zero is needed for now
        session_data->type_expected[source_id] = SEC_ABORT;
        return { nullptr, 0 };
    }

    session_data->running_total[source_id] += len;
    if (session_data->running_total[source_id] > total)
    {
        assert(false);
        session_data->type_expected[source_id] = SEC_ABORT;
        return { nullptr, 0 };
    }

    // FIXIT-P stream should be enhanced to do discarding for us. For now flush-then-discard here
    // is how scan() handles things we don't need to examine.
    if (session_data->section_type[source_id] == SEC_DISCARD)
    {
#ifdef REG_TEST
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
        {
            fprintf(HttpTestManager::get_output_file(), "Discarded %u octets\n\n", len);
            fflush(HttpTestManager::get_output_file());
        }
#endif
        assert(partial_buffer == nullptr);
        if (flags & PKT_PDU_TAIL)
        {
            assert(session_data->running_total[source_id] == total);
            session_data->running_total[source_id] = 0;
            session_data->section_type[source_id] = SEC__NOT_COMPUTE;

            // When we are skipping through a message body beyond flow depth this is the end of
            // the line. Here we do the message section's normal job of updating the flow for the
            // next stage.
            if (session_data->cutter[source_id] == nullptr)
            {
                if (session_data->type_expected[source_id] == SEC_BODY_CL)
                {
                    session_data->half_reset(source_id);
                }
                else if (session_data->type_expected[source_id] == SEC_BODY_CHUNK ||
                        (session_data->type_expected[source_id] == SEC_BODY_HX &&
                        session_data->hx_body_state[source_id] == HX_BODY_COMPLETE_EXPECT_TRAILERS))
                {
                    session_data->trailer_prep(source_id);
                }
            }
        }
        return { nullptr, 0 };
    }

    HttpModule::increment_peg_counts(PEG_REASSEMBLE);

    const bool is_body =
        (session_data->section_type[source_id] == SEC_BODY_CHUNK) ||
        (session_data->section_type[source_id] == SEC_BODY_CL) ||
        (session_data->section_type[source_id] == SEC_BODY_OLD) ||
        (session_data->section_type[source_id] == SEC_BODY_HX);

    uint8_t*& buffer = session_data->section_buffer[source_id];
    if (buffer == nullptr)
    {
        // Body sections need extra space to accommodate unzipping
        if (is_body)
            buffer = new uint8_t[MAX_OCTETS];
        else
        {
            const uint32_t buffer_size = (total > 0) ? total : 1;
            buffer = new uint8_t[buffer_size];
        }
    }

    if (partial_buffer_length > 0)
    {
        assert(session_data->section_offset[source_id] == 0);
        memcpy(buffer, partial_buffer, partial_buffer_length);
        session_data->section_offset[source_id] = partial_buffer_length;
        delete[] partial_buffer;
        partial_buffer_length = 0;
        partial_buffer = nullptr;
    }

    if (session_data->section_type[source_id] != SEC_BODY_CHUNK)
    {
        const bool at_start = (session_data->body_octets[source_id] == 0) &&
             (session_data->section_offset[source_id] == 0);
        decompress_copy(buffer, session_data->section_offset[source_id], data, len,
            session_data->compression[source_id], session_data->compress_stream[source_id],
            at_start, session_data->get_infractions(source_id),
            session_data->events[source_id], session_data);
    }
    else
    {
        chunk_spray(session_data, buffer, data, len);
    }

    StreamBuffer http_buf { nullptr, 0 };

    if (flags & PKT_PDU_TAIL)
    {
        uint32_t& running_total = session_data->running_total[source_id];
        if (running_total != total)
        {
            assert(false);
            session_data->type_expected[source_id] = SEC_ABORT;
            return { nullptr, 0 };
        }
        running_total = 0;
        const uint32_t buf_size =
            session_data->section_offset[source_id] - session_data->num_excess[source_id];

        if (session_data->partial_flush[source_id])
        {
            // It's possible we're doing a partial flush but there is no actual data to flush after
            // decompression.
            if (buf_size > 0)
            {
                // Store the data from a partial flush for reuse
                partial_buffer = new uint8_t[buf_size];
                memcpy(partial_buffer, buffer, buf_size);
                partial_buffer_length = buf_size;
            }
            partial_raw_bytes += total;
        }
        else
            partial_raw_bytes = 0;

        http_buf.data = buffer;
        http_buf.length = buf_size;
        session_data->octets_reassembled[source_id] = buf_size;

        buffer = nullptr;
        session_data->section_offset[source_id] = 0;
    }
    return http_buf;
}

