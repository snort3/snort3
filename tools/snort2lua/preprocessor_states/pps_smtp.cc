/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// smtp.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace {

class Smtp : public ConversionState
{
public:
    Smtp(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Smtp() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool Smtp::convert(std::istringstream& data_stream)
{

#if 0
    std::string keyword;
    if(data_stream >> keyword)
    {
        const ConvertMap* map = util::find_map(output_api, keyword);
        if (map)
        {
            cv->set_state(map->ctor(converter));
            return true;
        }
    }

ports
inspection_type stateful|stateless
normalize all|none|cmds *
ignore_data
ignore_tls_data
max_command_line_len <int> 
max_header_line_len <int> *
max_response_line_len <int>
alt_max_command_line_len <int> { <cmd> [<cmd>] }
no_alerts
invalid_cmds { <Space-delimited list of commands> } 
valid_cmds { <Space-delimited list of commands> } 
data_cmds { <Space-delimited list of commands> } 
binary_data_cmds { <Space-delimited list of commands> }
auth_cmds { <Space-delimited list of commands> } 
alert_unknown_cmds
normalize_cmds { <Space-delimited list of commands> } 
xlink2state { enable/disable [drop] }
print_cmds
disabled
b64_decode_depth
qp_decode_depth
bitenc_decode_depth
uu_decode_depth
enable_mime_decoding
max_mime_depth <int> 
max_mime_mem <int> 
log_mailfrom
log_rcptto
log_filename
log_email_hdrs
email_hdrs_log_depth <int> 
memcap <int>
#endif

    return false;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Smtp(cv, ld);
}

static const ConvertMap preprocessor_smtp = 
{
    "smtp",
    ctor,
};

const ConvertMap* smtp_map = &preprocessor_smtp;
