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
// ftp_splitter.cc author Shailendra Manghate <smanghat@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "telnet_splitter.h"

#include <cstring>

#include "ftpp_si.h"
#include "protocols/ssl.h"
#include "protocols/packet.h"
#include "utils/util.h"


using namespace snort;

TelnetSplitter::TelnetSplitter(bool c2s) : StreamSplitter(c2s) { }

// flush at last CR or LF in data
// preproc will deal with any pipelined commands
StreamSplitter::Status TelnetSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    if (p->flow)
    {
        FTP_TELNET_SESSION* ft_ssn = nullptr;
        
        FtpFlowData* fd = (FtpFlowData*)p->flow->get_flow_data(FtpFlowData::inspector_id);
        ft_ssn = fd ? &fd->session.ft_ssn : nullptr;

        if (ft_ssn && ft_ssn->fallback)
            return ABORT;
    }
    
    if ( IsSSL(data, len, p->packet_flags) )
    {
        *fp = len;
        return FLUSH;
    }

    const uint8_t* read_ptr = data;
    const uint8_t* end = data + len;
    const uint8_t* fp_ptr = nullptr;

    while ( read_ptr < end )
    {
        switch ( state )
        {
            case TELNET_NONE:
            {
                const uint8_t* ptr = nullptr;      // last CR or LF found
                const uint8_t* iac_ptr = nullptr;  // first IAC found

                for ( const uint8_t* scan = read_ptr; scan < end; ++scan )
                {
                    uint8_t c = *scan;
                    if ( c == '\r' || c == '\n' )
                        ptr = scan;

                    else if ( c == TNC_IAC )
                    {
                        iac_ptr = scan;
                        break;
                    }
                }

                if ( (ptr && iac_ptr && ptr < iac_ptr) || (ptr && !iac_ptr) )
                    fp_ptr = ptr;

                if ( iac_ptr )
                {
                    state = TELNET_IAC;
                    read_ptr = iac_ptr;
                }
                else if ( ptr )
                    read_ptr = ptr;
                else
                    read_ptr = end;
                break;
            }
            case TELNET_IAC:
            {
                if ( *read_ptr == (unsigned char)TNC_SB )
                    state = TELNET_IAC_SB;
                else if ( *read_ptr == (unsigned char)TNC_AYT )
                {
                    state = TELNET_NONE;
                    fp_ptr = read_ptr;
                }
                else if ( *read_ptr != (unsigned char)TNC_IAC )
                    state = TELNET_NONE;
                break;
            }
            case TELNET_IAC_SB:
            {
                const uint8_t* iac_se_ptr = static_cast<const uint8_t*>(memchr(read_ptr, TNC_IAC, end - read_ptr));
                if ( iac_se_ptr )
                {
                    state = TELNET_IAC_SB_IAC;
                    read_ptr = iac_se_ptr;
                }
                else
                    read_ptr = end;
                break;
            }
            case TELNET_IAC_SB_IAC:
            {
                if ( *read_ptr == (unsigned char)TNC_SE )
                {
                    fp_ptr = read_ptr;
                    state = TELNET_NONE;
                }
                else
                    state = TELNET_IAC_SB;
                break;
            }
        }

        if ( read_ptr < end )
            read_ptr++;
    }

    if ( fp_ptr )
    {
        *fp = fp_ptr - data + 1;
        return FLUSH;
    }
    return SEARCH;
}

