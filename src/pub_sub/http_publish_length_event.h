//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_publish_length_event.h author Steve Chew <stechew@cisco.com>

#ifndef HTTP_PUBLISH_LENGTH_EVENT_H
#define HTTP_PUBLISH_LENGTH_EVENT_H

// An event to dynamically update the publish length used by http_inspect
// Subscribers MUST retain the given publish length if it's larger than
// the one they desire. That way all subscribers can work together to
// set the publish length.

namespace snort
{

class SO_PUBLIC HttpPublishLengthEvent : public snort::DataEvent
{
public:
    HttpPublishLengthEvent(bool is_data_originates_from_client, int32_t publish_length) :
        is_data_originates_from_client(is_data_originates_from_client), publish_length(publish_length)
    {
    }

    bool is_data_from_client() const
    { return is_data_originates_from_client; }

    int32_t get_publish_length()
    { return publish_length; }

    void set_publish_length(int32_t new_length)
    {
        if (new_length > 0)
        {
            publish_length = new_length;
            publish_body = true;
        }
    }

    bool should_publish_body() const
    { return publish_body; }

private:
    bool is_data_originates_from_client;
    int32_t publish_length;
    bool publish_body = false;
};

}

#endif
