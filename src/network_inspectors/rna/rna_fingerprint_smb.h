//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint_smb.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FINGERPRINT_SMB_H
#define RNA_FINGERPRINT_SMB_H

#include <mutex>
#include <unordered_map>
#include <vector>

#include "main/snort_types.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "sfip/sf_ip.h"

#include "rna_fingerprint.h"

class RNAFlow;

namespace snort
{

class SO_PUBLIC SmbFingerprint : public FpFingerprint
{
public:

    SmbFingerprint(unsigned maj = 0, unsigned min = 0, uint32_t f = 0);
    SmbFingerprint(const RawFingerprint& rfp);

    unsigned smb_major;
    unsigned smb_minor;
    uint32_t flags;

    bool operator==(const SmbFingerprint& y) const;
};

class SO_PUBLIC SmbFpProcessor
{
public:

    struct SmbFpHash
    {
        size_t operator()(const SmbFingerprint & key) const noexcept
        {
            std::hash<decltype(SmbFingerprint::smb_major)> hm;
            std::hash<decltype(SmbFingerprint::flags)> hf;
            auto const h = hm(key.smb_major) ^ (hm(key.smb_minor) << 1) ^ (hf(key.flags) << 2);
            return h;
        }
    };

    struct SmbEqTo
    {
        bool operator() (const SmbFingerprint& x, const SmbFingerprint& y) const
        {
            return x.smb_major == y.smb_major && x.smb_minor == y.smb_minor && x.flags == y.flags;
        }
    };

    typedef std::unordered_set<SmbFingerprint, SmbFpHash, SmbEqTo> SmbFpContainer;
    typedef SmbFpContainer::const_iterator SmbFpIter;

    bool push(const SmbFingerprint&);
    const SmbFingerprint* find(const SmbFingerprint& ) const;

private:

    SmbFpContainer smb_fps;
};

}

snort::SmbFpProcessor* get_smb_fp_processor();
SO_PUBLIC void set_smb_fp_processor(snort::SmbFpProcessor*);

#endif
