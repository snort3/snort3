//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "http_compress_stream.h"
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
            decompress_copy(data+k, skip_amount, buffer,
                session_data->section_offset[source_id], session_data);
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
            decompress_copy(data+k, skip_amount, buffer,
                session_data->section_offset[source_id], session_data);
            k += skip_amount-1;
            break;
          }
        }
    }
}

void HttpStreamSplitter::decompress_copy(const uint8_t* src, uint32_t src_size,
    uint8_t* dst, uint32_t& dst_size, HttpFlowData* const session_data) const
{
    if ( session_data->compress[source_id] != nullptr and
        is_body(session_data->section_type[source_id]) )
        return;

    HttpCompressStream::copy_raw(src, src_size, dst, dst_size);
}

const StreamBuffer HttpStreamSplitter::reassemble(Flow* flow, unsigned total,
    unsigned, const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    // cppcheck-suppress unreadVariable
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

    uint8_t*& buffer = session_data->section_buffer[source_id];
    if ( buffer == nullptr )
    {
        // Body sections need extra space to accommodate unzipping
        if ( is_body(session_data->section_type[source_id]) )
            if ( session_data->compress[source_id] != nullptr and partial_buffer_length > 0 )
            {
                assert(partial_buffer != nullptr);

                buffer = partial_buffer;
                session_data->section_offset[source_id] = partial_buffer_length;

                partial_buffer = nullptr;
                partial_buffer_length = 0;
            }
            else
                buffer = new uint8_t[MAX_OCTETS];
        else
        {
            uint32_t buffer_size = (total > 0) ? total : 1;
            buffer_size += partial_buffer_length;
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
        decompress_copy(data, len, buffer, session_data->section_offset[source_id], session_data);
    else
        chunk_spray(session_data, buffer, data, len);

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
            if (session_data->section_offset[source_id] > 0)
            {
                // Store the data from a partial flush for reuse
                if ( is_body(session_data->section_type[source_id]) )
                    partial_buffer = new uint8_t[MAX_OCTETS];
                else
                    partial_buffer = new uint8_t[session_data->section_offset[source_id]];

                memcpy(partial_buffer, buffer, session_data->section_offset[source_id]);
                partial_buffer_length = session_data->section_offset[source_id];
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

