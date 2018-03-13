//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// modbus_decode.cc author Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modbus_decode.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "protocols/packet.h"

#include "modbus.h"
#include "modbus_module.h"

using namespace snort;

// FIXIT-L convert this stuff to a table and make configurable

/* Modbus Function Codes */
#define MODBUS_FUNC_READ_COILS                          0x01
#define MODBUS_FUNC_READ_DISCRETE_INPUTS                0x02
#define MODBUS_FUNC_READ_HOLDING_REGISTERS              0x03
#define MODBUS_FUNC_READ_INPUT_REGISTERS                0x04
#define MODBUS_FUNC_WRITE_SINGLE_COIL                   0x05
#define MODBUS_FUNC_WRITE_SINGLE_REGISTER               0x06
#define MODBUS_FUNC_READ_EXCEPTION_STATUS               0x07
#define MODBUS_FUNC_DIAGNOSTICS                         0x08
#define MODBUS_FUNC_GET_COMM_EVENT_COUNTER              0x0B
#define MODBUS_FUNC_GET_COMM_EVENT_LOG                  0x0C
#define MODBUS_FUNC_WRITE_MULTIPLE_COILS                0x0F
#define MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS            0x10
#define MODBUS_FUNC_REPORT_SLAVE_ID                     0x11
#define MODBUS_FUNC_READ_FILE_RECORD                    0x14
#define MODBUS_FUNC_WRITE_FILE_RECORD                   0x15
#define MODBUS_FUNC_MASK_WRITE_REGISTER                 0x16
#define MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS       0x17
#define MODBUS_FUNC_READ_FIFO_QUEUE                     0x18
#define MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT    0x2B
#define MODBUS_SUB_FUNC_CANOPEN                         0x0D
#define MODBUS_SUB_FUNC_READ_DEVICE_ID                  0x0E

/* Various Modbus lengths */
#define MODBUS_BYTE_COUNT_SIZE                          1
#define MODBUS_DOUBLE_BYTE_COUNT_SIZE                   2
#define MODBUS_FILE_RECORD_SUB_REQUEST_SIZE             7
#define MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET       5
#define MODBUS_READ_DEVICE_ID_HEADER_LEN                6
#define MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET            5

#define MODBUS_EMPTY_DATA_LEN                           0
#define MODBUS_FOUR_DATA_BYTES                          4
#define MODBUS_BYTE_COUNT_SIZE                          1
#define MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET         4
#define MODBUS_WRITE_MULTIPLE_MIN_SIZE                  5
#define MODBUS_MASK_WRITE_REGISTER_SIZE                 6
#define MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET    8
#define MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE             9
#define MODBUS_READ_FIFO_SIZE                           2
#define MODBUS_MEI_MIN_SIZE                             1
#define MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE            1
#define MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE             3
#define MODBUS_SUB_FUNC_READ_DEVICE_START_LEN           2
#define MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET       1

/* Other defines */
#define MODBUS_PROTOCOL_ID                              0

/* Modbus data structures */
struct modbus_header_t
{
    /* MBAP Header */
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t unit_id;

    /* PDU Start */
    uint8_t function_code;
};

static void ModbusCheckRequestLengths(modbus_session_data_t* session, Packet* p)
{
    uint16_t modbus_payload_len = p->dsize - MODBUS_MIN_LEN;
    uint8_t tmp_count;
    bool check_passed = false;

    switch (session->func)
    {
    case MODBUS_FUNC_READ_COILS:
    case MODBUS_FUNC_READ_DISCRETE_INPUTS:
    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
    case MODBUS_FUNC_READ_INPUT_REGISTERS:
    case MODBUS_FUNC_WRITE_SINGLE_COIL:
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
    case MODBUS_FUNC_DIAGNOSTICS:
        if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
            check_passed = true;
        break;

    case MODBUS_FUNC_READ_EXCEPTION_STATUS:
    case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
    case MODBUS_FUNC_GET_COMM_EVENT_LOG:
    case MODBUS_FUNC_REPORT_SLAVE_ID:
        if (modbus_payload_len == MODBUS_EMPTY_DATA_LEN)
            check_passed = true;
        break;

    case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
        if (modbus_payload_len >= MODBUS_WRITE_MULTIPLE_MIN_SIZE)
        {
            tmp_count = *(p->data + MODBUS_MIN_LEN +
                MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
            if (modbus_payload_len == tmp_count + MODBUS_WRITE_MULTIPLE_MIN_SIZE)
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_MASK_WRITE_REGISTER:
        if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
            check_passed = true;
        break;

    case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
        if (modbus_payload_len >= MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE)
        {
            tmp_count = *(p->data + MODBUS_MIN_LEN +
                MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
            if (modbus_payload_len == MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE + tmp_count)
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_READ_FIFO_QUEUE:
        if (modbus_payload_len == MODBUS_READ_FIFO_SIZE)
            check_passed = true;
        break;

    case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
        if (modbus_payload_len >= MODBUS_MEI_MIN_SIZE)
        {
            uint8_t mei_type = *(p->data + MODBUS_MIN_LEN);

            /* MEI Type 0x0E is covered under the Modbus spec as
               "Read Device Identification". Type 0x0D is defined in
               the spec as "CANopen General Reference Request and Response PDU"
               and falls outside the scope of the Modbus preprocessor.

               Other values are reserved.
            */
            if ((mei_type == MODBUS_SUB_FUNC_READ_DEVICE_ID) &&
                (modbus_payload_len == MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE))
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_READ_FILE_RECORD:
        /* Modbus read file record request contains a byte count, followed
           by a set of 7-byte sub-requests. */
        if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
        {
            tmp_count = *(p->data + MODBUS_MIN_LEN);
            if ((tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE) &&
                (tmp_count % MODBUS_FILE_RECORD_SUB_REQUEST_SIZE == 0))
            {
                check_passed = true;
            }
        }
        break;

    case MODBUS_FUNC_WRITE_FILE_RECORD:
        /* Modbus write file record request contains a byte count, followed
           by a set of sub-requests that contain a 7-byte header and a
           variable amount of data. */

        if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
        {
            tmp_count = *(p->data + MODBUS_MIN_LEN);
            if (tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE)
            {
                uint16_t bytes_processed = 0;

                while (bytes_processed < (uint16_t)tmp_count)
                {
                    uint16_t record_length = 0;

                    /* Check space for sub-request header info */
                    if ((modbus_payload_len - bytes_processed) <
                        MODBUS_FILE_RECORD_SUB_REQUEST_SIZE)
                        break;

                    /* Extract record length. */
                    record_length = *(p->data + MODBUS_MIN_LEN +
                        MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                        MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET);

                    record_length = record_length << 8;

                    record_length |= *(p->data + MODBUS_MIN_LEN +
                        MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                        MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET + 1);

                    /* Jump over record data. */
                    bytes_processed += MODBUS_FILE_RECORD_SUB_REQUEST_SIZE +
                        2*record_length;

                    if (bytes_processed == (uint16_t)tmp_count)
                        check_passed = true;
                }
            }
        }
        break;

    default:     /* Don't alert if we couldn't check the length. */
        check_passed = true;
        break;
    }

    if (!check_passed)
        DetectionEngine::queue_event(GID_MODBUS, MODBUS_BAD_LENGTH);
}

static void ModbusCheckResponseLengths(modbus_session_data_t* session, Packet* p)
{
    uint16_t modbus_payload_len = p->dsize - MODBUS_MIN_LEN;
    uint8_t tmp_count;
    bool check_passed = false;

    switch (session->func)
    {
    case MODBUS_FUNC_READ_COILS:
    case MODBUS_FUNC_READ_DISCRETE_INPUTS:
    case MODBUS_FUNC_GET_COMM_EVENT_LOG:
    case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
        if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
        {
            tmp_count = *(p->data + MODBUS_MIN_LEN);     /* byte count */
            if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
    case MODBUS_FUNC_READ_INPUT_REGISTERS:
        if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
        {
            /* count of 2-byte registers*/
            tmp_count = *(p->data + MODBUS_MIN_LEN);
            if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_WRITE_SINGLE_COIL:
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
    case MODBUS_FUNC_DIAGNOSTICS:
    case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
        if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
            check_passed = true;
        break;

    case MODBUS_FUNC_READ_EXCEPTION_STATUS:
        if (modbus_payload_len == MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE)
            check_passed = true;
        break;

    case MODBUS_FUNC_MASK_WRITE_REGISTER:
        if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
            check_passed = true;
        break;

    case MODBUS_FUNC_READ_FIFO_QUEUE:
        if (modbus_payload_len >= MODBUS_DOUBLE_BYTE_COUNT_SIZE)
        {
            uint16_t tmp_count_16;

            /* This function uses a 2-byte byte count!! */
            tmp_count_16 = *(const uint16_t*)(p->data + MODBUS_MIN_LEN);
            tmp_count_16 = ntohs(tmp_count_16);
            if (modbus_payload_len == MODBUS_DOUBLE_BYTE_COUNT_SIZE + tmp_count_16)
                check_passed = true;
        }
        break;

    case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
        if (modbus_payload_len >= MODBUS_READ_DEVICE_ID_HEADER_LEN)
        {
            uint8_t mei_type = *(p->data + MODBUS_MIN_LEN);
            uint8_t num_objects = *(p->data + MODBUS_MIN_LEN +
                MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET);

            /* MEI Type 0x0E is covered under the Modbus spec as
               "Read Device Identification". Type 0x0D is defined in
               the spec as "CANopen General Reference Request and Response PDU"
               and falls outside the scope of the Modbus preprocessor.

               Other values are reserved.
            */

            if (mei_type == MODBUS_SUB_FUNC_CANOPEN)
                check_passed = true;

            if (mei_type != MODBUS_SUB_FUNC_READ_DEVICE_ID)
                break;

            /* Loop through sub-requests, make sure that the lengths inside
               don't violate our total Modbus PDU size. */
            uint16_t offset = MODBUS_READ_DEVICE_ID_HEADER_LEN;
            uint8_t i;

            for ( i = 0; i < num_objects; i++)
            {
                uint8_t sub_request_data_len;

                /* Sub request starts with 2 bytes, type + len */
                if (offset + MODBUS_SUB_FUNC_READ_DEVICE_START_LEN > modbus_payload_len)
                    break;

                /* Length is second byte in sub-request */
                sub_request_data_len = *(p->data + MODBUS_MIN_LEN +
                    offset + MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET);

                /* Set offset to byte after sub-request */
                offset += (MODBUS_SUB_FUNC_READ_DEVICE_START_LEN + sub_request_data_len);
            }

            if ((i == num_objects) && (offset == modbus_payload_len))
                check_passed = true;
        }
        break;

    /* Cannot check this response, as it is device specific. */
    case MODBUS_FUNC_REPORT_SLAVE_ID:

    /* Cannot check these responses, as their sizes depend on the corresponding
       requests. Can re-visit if we bother with request/response tracking. */
    case MODBUS_FUNC_READ_FILE_RECORD:
    case MODBUS_FUNC_WRITE_FILE_RECORD:

    default:     /* Don't alert if we couldn't check the lengths. */
        check_passed = true;
        break;
    }

    if (!check_passed)
        DetectionEngine::queue_event(GID_MODBUS, MODBUS_BAD_LENGTH);
}

static void ModbusCheckReservedFuncs(const modbus_header_t* header, Packet* p)
{
    switch (header->function_code)
    {
    /* Only some sub-functions are reserved here. */
    case MODBUS_FUNC_DIAGNOSTICS:
    {
        uint16_t sub_func;

        if (p->dsize < MODBUS_MIN_LEN+2)
            break;

        sub_func = *((const uint16_t*)(p->data + MODBUS_MIN_LEN));
        sub_func = ntohs(sub_func);

        if ((sub_func == 19) || (sub_func >= 21))
            DetectionEngine::queue_event(GID_MODBUS, MODBUS_RESERVED_FUNCTION);
    }
    break;

    /* Reserved function codes */
    case 0x09:
    case 0x0A:
    case 0x0D:
    case 0x0E:
    case 0x29:
    case 0x2A:
    case 0x5A:
    case 0x5B:
    case 0x7D:
    case 0x7E:
    case 0x7F:
        DetectionEngine::queue_event(GID_MODBUS, MODBUS_RESERVED_FUNCTION);
        break;
    }
}

bool ModbusDecode(Packet* p)
{
    const modbus_header_t* header;

    if (p->dsize < MODBUS_MIN_LEN)
        return false;

    ModbusFlowData* mfd =
        (ModbusFlowData*)p->flow->get_flow_data(ModbusFlowData::inspector_id);

    /* Lay the header struct over the payload */
    header = (const modbus_header_t*)p->data;

    /* The protocol ID field should read 0x0000 for Modbus. It allows for
       multiplexing with some other protocols over serial line. */
    if (header->protocol_id != MODBUS_PROTOCOL_ID)
    {
        DetectionEngine::queue_event(GID_MODBUS, MODBUS_BAD_PROTO_ID);
        return false;
    }

    /* Set the session data.
       Normally we'd need to swap byte order, but these are 8-bit fields. */
    mfd->ssn_data.unit = header->unit_id;
    mfd->ssn_data.func = header->function_code;

    /* Check for reserved function codes */
    ModbusCheckReservedFuncs(header, p);

    /* Read the Modbus payload and check lengths against the expected length for
       each function. */
    if (p->is_from_client())
        ModbusCheckRequestLengths(&mfd->ssn_data, p);
    else
        ModbusCheckResponseLengths(&mfd->ssn_data, p);

    return true;
}

