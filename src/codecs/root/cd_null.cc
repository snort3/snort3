//--------------------------------------------------------------------------
// DLT_NULL / BSD loopback codec
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>
#include <cstring>

#include <daq_dlt.h>

#include "framework/codec.h"

using namespace snort;

#define CD_NULL_NAME "null"
#define CD_NULL_HELP_STR "support for BSD/Npcap loopback"
#define CD_NULL_HELP ADD_DLT(CD_NULL_HELP_STR, DLT_NULL)

namespace
{
class NullCodec : public Codec
{
public:
    NullCodec() : Codec(CD_NULL_NAME) { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};
} // namespace

bool NullCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    // DLT_NULL contains a 4-byte address-family header.
    if (raw.len < 4)
        return false;

    uint32_t family = 0;

    // BSD DLT_NULL stores the address family in the first 4 bytes.
    memcpy(&family, raw.data, sizeof(family));

    codec.lyr_len = 4;

    // AF_INET = IPv4 (2)
    // AF_INET6 = IPv6 (24)
    if (family == 2)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    else if (family == 24)
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
    else
        return false;

    return true;
}

void NullCodec::get_data_link_type(std::vector<int>& v)
{
    v.emplace_back(DLT_NULL);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new NullCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi null_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        CD_NULL_NAME,
        CD_NULL_HELP,
        nullptr,
        nullptr,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_null[] =
#endif
{
    &null_api.base,
    nullptr
};
