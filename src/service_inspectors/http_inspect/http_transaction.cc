//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_transaction.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_transaction.h"

#include "pub_sub/http_transaction_end_event.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_event.h"
#include "http_inspect.h"
#include "http_msg_body.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

const uint16_t HttpTransaction::transaction_memory_usage_estimate = sizeof(HttpTransaction) +
    sizeof(HttpMsgRequest) + sizeof(HttpMsgStatus) + (2 * sizeof(HttpMsgHeader)) + sizeof(HttpUri)
    + (2 * sizeof(HttpInfractions)) + small_things;

static void delete_section_list(HttpMsgSection* section_list)
{
    while (section_list != nullptr)
    {
        HttpMsgSection* tmp = section_list;
        section_list = section_list->next;
        delete tmp;
    }
}

HttpTransaction::HttpTransaction(HttpFlowData* session_data_, snort::Flow* const f)
    : session_data(session_data_), flow(f)
{
    infractions[0] = nullptr;
    infractions[1] = nullptr;
    HttpInspect* const hi = (session_data->is_for_httpx()) ?
        (HttpInspect*)(flow->assistant_gadget) : (HttpInspect*)(flow->gadget);
    pub_id = hi->get_pub_id();
}

void HttpTransaction::publish_end_of_transaction()
{
    HttpTransactionEndEvent http_event(this);
    DataBus::publish(pub_id, HttpEventIds::END_OF_TRANSACTION, http_event, flow);
}

HttpTransaction::~HttpTransaction()
{
    publish_end_of_transaction();
    delete request;
    delete status;
    for (int k = 0; k <= 1; k++)
    {
        delete header[k];
        delete trailer[k];
        delete infractions[k];
    }
    delete_section_list(body_list);
    delete_section_list(archive_hdr_list);
    delete_section_list(archive_status_list);
}

HttpTransaction* HttpTransaction::attach_my_transaction(HttpFlowData* session_data, SourceId
    source_id, Flow* const f)
{
    // This factory method:
    // 1. creates new transactions for all request messages and orphaned response messages
    // 2. associates requests and responses and supports pipelining
    // 3. garbage collects unneeded transactions
    // 4. returns the current transaction

    // Request section: replace the old request transaction with a new transaction.
    if (session_data->section_type[source_id] == SEC_REQUEST)
    {
        // If the HTTP request and response messages are alternating (usual situation) the old
        // request transaction will have been moved to the server side when the last response
        // message was received. This will be nullptr and we don't need to deal with the old
        // request transaction here.
        if (session_data->transaction[SRC_CLIENT] != nullptr)
        {
            // The old request transaction is still here. Typically that is because the
            // the current request has arrived before the previous response (pipelining). We need
            // to add this transaction to our pipeline where it will wait for the matching
            // response. But there are some special cases to check first.
            if (session_data->transaction[SRC_CLIENT]->response_seen)
            {
                // The response started before the request finished. When the response took the
                // old request transaction it did not leave the usual nullptr because we still
                // needed it. Instead the two sides have been sharing the transaction. This is a
                // soft delete that eliminates our interest in this transaction without disturbing
                // the possibly ongoing response processing.
                delete_transaction(session_data->transaction[SRC_CLIENT], session_data);
            }
            else if ((session_data->pipeline_overflow) || (session_data->pipeline_underflow))
            {
                // Pipelining previously broke down and both sides are processed separately from
                // now on. We just throw things away when we are done with them.
                delete_transaction(session_data->transaction[SRC_CLIENT], session_data);
            }
            else
            {
                if (!session_data->add_to_pipeline(session_data->transaction[SRC_CLIENT]))
                {
                    // The pipeline is full and just overflowed.
                    *session_data->infractions[source_id] += INF_PIPELINE_OVERFLOW;
                    delete_transaction(session_data->transaction[SRC_CLIENT], session_data);
                    // When overflow occurs the length of the pipeline is unchanged
                    // next code ensures that the alert is still raised
                    *session_data->infractions[source_id] += INF_PIPELINE_MAX;
                    session_data->events[source_id]->create_event(EVENT_PIPELINE_MAX);
                }
                if (session_data->pipeline_length() > session_data->params->maximum_pipelined_requests)
                {
                    *session_data->infractions[source_id] += INF_PIPELINE_MAX;
                    session_data->events[source_id]->create_event(EVENT_PIPELINE_MAX);
                }
            }
        }
        session_data->transaction[SRC_CLIENT] = new HttpTransaction(session_data, f);

        // The StreamSplitter generates infractions related to this transaction while splitting the
        // request line and keeps them in temporary storage in the FlowData. Now we move them here.
        session_data->transaction[SRC_CLIENT]->infractions[SRC_CLIENT] =
            session_data->infractions[SRC_CLIENT];
        session_data->infractions[SRC_CLIENT] = nullptr;
    }
    // This transaction has more than one response. This is a new response which is replacing the
    // interim response. The two responses cannot coexist so we must clean up the interim response.
    else if ((session_data->section_type[source_id] == SEC_STATUS) &&
             (session_data->transaction[SRC_SERVER] != nullptr) &&
              session_data->transaction[SRC_SERVER]->second_response_expected)
    {
        session_data->transaction[SRC_SERVER]->second_response_expected = false;
        session_data->transaction[SRC_SERVER]->archive_status(
            session_data->transaction[SRC_SERVER]->status);
        session_data->transaction[SRC_SERVER]->status = nullptr;
        session_data->transaction[SRC_SERVER]->archive_header(
            session_data->transaction[SRC_SERVER]->header[SRC_SERVER]);
        session_data->transaction[SRC_SERVER]->header[SRC_SERVER] = nullptr;
    }
    // Status section: delete the current transaction and get a new one from the pipeline. If the
    // pipeline is empty check for a request transaction and take it. If there is no transaction
    // available then declare an underflow and create a new transaction specifically for the
    // response side.
    else if (session_data->section_type[source_id] == SEC_STATUS ||
	     (session_data->section_type[source_id] == SEC_HEADER &&
	     session_data->version_id[source_id] == VERS_0_9))
    {
        delete_transaction(session_data->transaction[SRC_SERVER], session_data);
        if (session_data->pipeline_underflow)
        {
            // A previous underflow separated the two sides forever
            session_data->transaction[SRC_SERVER] = new HttpTransaction(session_data, f);
        }
        else if ((session_data->transaction[SRC_SERVER] = session_data->take_from_pipeline()) ==
            nullptr)
        {
            if ((session_data->transaction[SRC_CLIENT] == nullptr) ||
                (session_data->transaction[SRC_CLIENT]->response_seen))
            {
                // Either there is no request at all or there is a request but a previous response
                // already took it. Either way we have more responses than requests.
                session_data->pipeline_underflow = true;
                session_data->transaction[SRC_SERVER] = new HttpTransaction(session_data, f);
            }

            else if (session_data->type_expected[SRC_CLIENT] == SEC_REQUEST)
            {
                // This is the normal case where the requests and responses are alternating (no
                // pipelining). Processing of the response is complete so the request just takes
                // it.
                session_data->transaction[SRC_SERVER] = session_data->transaction[SRC_CLIENT];
                session_data->transaction[SRC_CLIENT] = nullptr;
            }
            else
            {
                // Response message is starting before the request message has finished. Request
                // side is not finished with this transaction so two sides share it
                session_data->transaction[SRC_CLIENT]->shared_ownership = true;
                session_data->transaction[SRC_SERVER] = session_data->transaction[SRC_CLIENT];
            }
        }
        session_data->transaction[SRC_SERVER]->response_seen = true;

        // Move in server infractions now that the response is attached here
        session_data->transaction[SRC_SERVER]->infractions[SRC_SERVER] =
            session_data->infractions[SRC_SERVER];
        session_data->infractions[SRC_SERVER] = nullptr;
    }

    assert(session_data->transaction[source_id] != nullptr);
    session_data->transaction[source_id]->active_sections++;
    return session_data->transaction[source_id];
}

void HttpTransaction::archive_section(HttpMsgSection* section, HttpMsgSection** archive_list)
{
    if (section != nullptr)
    {
        section->next = *archive_list;
        *archive_list = section;
    }
}

void HttpTransaction::archive_status(HttpMsgStatus* status)
{
    archive_section(status, &archive_status_list); 
}

void HttpTransaction::archive_header(HttpMsgHeader* hdr)
{
    archive_section(hdr, &archive_hdr_list); 
}

void HttpTransaction::clear_section()
{
    assert(active_sections > 0);
    active_sections--;
}

void HttpTransaction::garbage_collect()
{
    HttpMsgSection** current = (HttpMsgSection**)&body_list;
    while (*current != nullptr)
    {
        if ((*current)->is_clear())
        {
            HttpMsgSection* tmp = *current;
            *current = (*current)->next;
            delete tmp;
        }
        else
            current = &(*current)->next;
    }
}

void HttpTransaction::delete_transaction(HttpTransaction* transaction, HttpFlowData* session_data)
{
    if (transaction != nullptr)
    {
        if (!transaction->shared_ownership)
        {
            if ((transaction->active_sections > 0) && (session_data != nullptr))
            {
                transaction->next = session_data->discard_list;
                session_data->discard_list = transaction;
            }
            else
                delete transaction;
        }
        else
            transaction->shared_ownership = false;
    }
}

void HttpTransaction::set_body(HttpMsgBody* latest_body)
{
    latest_body->next = body_list;
    body_list = latest_body;
}

HttpInfractions* HttpTransaction::get_infractions(SourceId source_id)
{
    return infractions[source_id];
}

void HttpTransaction::set_one_hundred_response()
{
    assert(response_seen);
    if (one_hundred_response)
    {
        *infractions[SRC_SERVER] += INF_MULTIPLE_100_RESPONSES;
        session_data->events[SRC_SERVER]->create_event(EVENT_MULTIPLE_100_RESPONSES);
    }
    one_hundred_response = true;
    second_response_expected = true;
}

inline bool is_info_code(int32_t code) 
{
    return ((99 < code) and (code < 200));
}

uint8_t HttpTransaction::get_info_code() const
{     
     if (status)
     {
         const int32_t code = status->get_status_code_num();
         if (is_info_code(code))
             return code;
     }

     const HttpMsgStatus* arch_status = (HttpMsgStatus*) archive_status_list;
     while (arch_status)
     {
         const int32_t code = arch_status->get_status_code_num();
         if (is_info_code(code))
             return code;
         arch_status = (HttpMsgStatus*)(arch_status->next);
     }

     return 0;
}

const Field& HttpTransaction::get_info_msg() const
{     
     if (status)
     {
         const int32_t code = status->get_status_code_num();
         if (is_info_code(code))
             return status->get_reason_phrase();
     }

     const HttpMsgStatus* arch_status = (HttpMsgStatus*) archive_status_list;
     while (arch_status)
     {
         const int32_t code = arch_status->get_status_code_num();
         if (is_info_code(code))
             return arch_status->get_reason_phrase();
         arch_status = (HttpMsgStatus*)(arch_status->next);
     }

     return Field::FIELD_NULL;
}

void HttpTransaction::append_separator_if_needed(HttpCommon::SourceId source_id)
{
    static const std::string separator = " ";

    if (!filename[source_id].empty())
    {
        filename[source_id].append(separator);
        content_type[source_id].append(separator);
    }
}

void HttpTransaction::add_filename(HttpCommon::SourceId source_id, const char* fname, uint32_t len,
    const char* ftype, uint32_t tlen)
{
    append_separator_if_needed(source_id);
    if (len)
        filename[source_id].append(fname, len);
    if (tlen)
        content_type[source_id].append(ftype, tlen);
}

void HttpTransaction::add_filename(HttpCommon::SourceId source_id, const std::string& fname,
    const std::string& ftype)
{
    append_separator_if_needed(source_id);
    filename[source_id].append(fname);
    content_type[source_id].append(ftype);
}
