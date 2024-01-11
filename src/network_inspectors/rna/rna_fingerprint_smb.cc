//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint_smb.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint_smb.h"

#include <sstream>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "log/messages.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL SmbFpProcessor* smb_fp_processor = nullptr;

SmbFpProcessor* get_smb_fp_processor()
{
    return smb_fp_processor;
}

void set_smb_fp_processor(SmbFpProcessor* processor)
{
    smb_fp_processor = processor;
}

namespace snort
{

SmbFingerprint::SmbFingerprint(unsigned maj, unsigned min, uint32_t f)
    : smb_major(maj), smb_minor(min), flags(f) { }

SmbFingerprint::SmbFingerprint(const RawFingerprint& rfp)
{
    fpid = rfp.fpid;
    fp_type = rfp.fp_type;
    fpuuid = rfp.fpuuid;
    ttl = rfp.ttl;

    smb_major = rfp.smb_major;
    smb_minor = rfp.smb_minor;
    flags = rfp.smb_flags;
}

bool SmbFingerprint::operator==(const SmbFingerprint& y) const
{
    return ((fpid == y.fpid) &&
        (fp_type == y.fp_type) &&
        (fpuuid == y.fpuuid) &&
        (ttl == y.ttl) &&
        (smb_major == y.smb_major) &&
        (smb_minor == y.smb_minor) &&
        (flags == y.flags) );
}

bool SmbFpProcessor::push(const SmbFingerprint& sfp)
{
    auto result = smb_fps.emplace(sfp);
    if (!result.second)
        WarningMessage("SmbFpProcessor: ignoring previously seen fingerprint id: %d\n", sfp.fpid);
    return result.second;
}

const SmbFingerprint* SmbFpProcessor::find(const SmbFingerprint& key) const
{
    const auto& it = smb_fps.find(key);
    return it != smb_fps.end() ? &(*it) : nullptr;
}

}

#ifdef UNIT_TEST

TEST_CASE("get_smb_fp_processor", "[rna_fingerprint_smb]")
{
    SmbFpProcessor smb_processor;
    set_smb_fp_processor(&smb_processor);

    SmbFpProcessor* processor = get_smb_fp_processor();
    CHECK(processor == &smb_processor);

    unsigned smb_major = 6;
    unsigned smb_minor = 4;
    uint32_t flags = 4096;
    SmbFingerprint fp(smb_major, smb_minor, flags);
    processor->push(fp);

    // positive test:
    const SmbFingerprint* fpptr = processor->find({smb_major, smb_minor, flags});
    CHECK(fpptr != nullptr);
    CHECK(*fpptr == fp);

    // negative test:
    fpptr = processor->find({0, 0, 0});
    CHECK(fpptr == nullptr);

    set_smb_fp_processor(nullptr);
    CHECK(smb_fp_processor == nullptr);
}

#endif
