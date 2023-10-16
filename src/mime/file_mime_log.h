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

// author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_LOG_H
#define FILE_MIME_LOG_H

// File name will be extracted from MIME header
// Email headers and emails are also stored in the log buffer

#include <cstdint>
#include "main/snort_types.h"
#include "flow/flow_stash.h"
#define STASH_EXTRADATA_MIME "mime_data"

namespace snort
{
enum EmailUserType
{
    EMAIL_SENDER,
    EMAIL_RECIPIENT
};

struct MailLogConfig
{
    bool log_mailfrom = false;
    bool log_rcptto = false;
    bool log_filename = false;
    bool log_email_hdrs = false;
    uint32_t email_hdrs_log_depth = 0;
};

class Flow;

class SO_PUBLIC MailLogState : public snort::StashGenericObject
{
public:
    MailLogState(MailLogConfig* conf);
    ~MailLogState() override;

    /* accumulate MIME attachment filenames. The filenames are appended by commas */
    int log_file_name(const uint8_t* start, int length);

    int log_email_hdrs(const uint8_t* start, int length);
    int log_email_id(const uint8_t* start, int length, EmailUserType);

    void get_file_name(uint8_t** buf, uint32_t* len);
    void get_email_hdrs(uint8_t** buf, uint32_t* len);
    void get_email_id(uint8_t** buf, uint32_t* len, EmailUserType);

    bool is_file_name_present() const;
    bool is_email_hdrs_present() const;
    bool is_email_from_present() const;
    bool is_email_to_present() const;

private:
    int log_flags = 0;
    uint8_t* buf = nullptr;
    unsigned char* emailHdrs = nullptr;
    uint32_t log_depth = 0;
    uint32_t hdrs_logged;
    uint8_t* recipients = nullptr;
    uint16_t rcpts_logged;
    uint8_t* senders = nullptr;
    uint16_t snds_logged;
    uint8_t* filenames = nullptr;
    uint16_t file_logged;
    uint16_t file_current;
};
}

#endif

