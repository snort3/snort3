//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// rna_fp_reader.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FP_READER_H
#define RNA_FP_READER_H

#include <vector>

#include "main/snort_types.h"

#include "rna_fingerprint_tcp.h"

namespace snort
{

class RnaFingerprintReader
{
public:
    RnaFingerprintReader() { }
    virtual ~RnaFingerprintReader() { }
    virtual bool init(const char*) { return true; }

    const std::vector<FpTcpFingerprint>& get_tcp_server_fps() const { return tcp_server_fps; }
    const std::vector<FpTcpFingerprint>& get_tcp_client_fps() const { return tcp_client_fps; }

protected:
    std::vector<FpTcpFingerprint> tcp_server_fps;
    std::vector<FpTcpFingerprint> tcp_client_fps;
};

SO_PUBLIC const RnaFingerprintReader* get_rna_fp_reader();
SO_PUBLIC void set_rna_fp_reader(RnaFingerprintReader*);

}

#endif
