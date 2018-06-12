//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// file_mime_config.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_config.h"

#include "log/messages.h"
#include "file_api/file_service.h"

using namespace snort;

void DecodeConfig::set_ignore_data(bool ignored)
{
    ignore_data = ignored;
}

bool DecodeConfig::is_ignore_data()
{
    return ignore_data;
}

void DecodeConfig::set_b64_depth(int depth)
{
    b64_depth = depth;
}

int DecodeConfig::get_b64_depth()
{
    return b64_depth;
}

void DecodeConfig::set_qp_depth(int depth)
{
    qp_depth = depth;
}

int DecodeConfig::get_qp_depth()
{
    return qp_depth;
}

void DecodeConfig::set_bitenc_depth(int depth)
{
    bitenc_depth = depth;
}

int DecodeConfig::get_bitenc_depth()
{
    return bitenc_depth;
}

void DecodeConfig::set_uu_depth(int depth)
{
    uu_depth = depth;
}

int DecodeConfig::get_uu_depth()
{
    return uu_depth;
}

int64_t DecodeConfig::get_file_depth()
{
    return file_depth;
}

bool DecodeConfig::is_decoding_enabled()
{
    return decode_enabled;
}

// update file depth and max_depth etc
void DecodeConfig::sync_all_depths()
{
    file_depth = snort::FileService::get_max_file_depth();
    if ((file_depth >= 0)or (b64_depth >= 0) or (qp_depth >= 0)
        or (bitenc_depth >= 0) or (uu_depth >= 0))
        decode_enabled = true;
    else
        decode_enabled = false;
}

int DecodeConfig::get_max_depth(int decode_depth)
{
    sync_all_depths();

    if (!file_depth or !decode_depth)
        return 0;
    else if (file_depth > decode_depth)
        return file_depth;
    else
        return decode_depth;
}

void DecodeConfig::print_decode_conf()
{
    if (b64_depth > -1)
    {
        LogMessage("    Base64 Decoding: %s\n", "Enabled");
        switch (b64_depth)
        {
        case 0:
            LogMessage("    Base64 Decoding Depth: %s\n", "Unlimited");
            break;
        default:
            LogMessage("    Base64 Decoding Depth: %d\n", b64_depth);
            break;
        }
    }
    else
        LogMessage("    Base64 Decoding: %s\n", "Disabled");

    if (qp_depth > -1)
    {
        LogMessage("    Quoted-Printable Decoding: %s\n","Enabled");
        switch (qp_depth)
        {
        case 0:
            LogMessage("    Quoted-Printable Decoding Depth: %s\n", "Unlimited");
            break;
        default:
            LogMessage("    Quoted-Printable Decoding Depth: %d\n", qp_depth);
            break;
        }
    }
    else
        LogMessage("    Quoted-Printable Decoding: %s\n", "Disabled");

    if (uu_depth > -1)
    {
        LogMessage("    Unix-to-Unix Decoding: %s\n","Enabled");
        switch (uu_depth)
        {
        case 0:
            LogMessage("    Unix-to-Unix Decoding Depth: %s\n", "Unlimited");
            break;
        default:
            LogMessage("    Unix-to-Unix Decoding Depth: %d\n", uu_depth);
            break;
        }
    }
    else
        LogMessage("    Unix-to-Unix Decoding: %s\n", "Disabled");

    if (bitenc_depth > -1)
    {
        LogMessage("    Non-Encoded MIME attachment Extraction: %s\n","Enabled");
        switch (bitenc_depth)
        {
        case 0:
            LogMessage("    Non-Encoded MIME attachment Extraction Depth: %s\n", "Unlimited");
            break;
        default:
            LogMessage("    Non-Encoded MIME attachment Extraction Depth: %d\n",
                bitenc_depth);
            break;
        }
    }
    else
        LogMessage("    Non-Encoded MIME attachment Extraction/text: %s\n", "Disabled");
}

