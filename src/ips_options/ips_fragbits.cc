//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// ips_fragbits.cc author Al Lewis <allewi>@cisco.com
// based on work by Martin Roesch <roesch@sourcefire.com>

/* ips_fragbits.cc
 *
 * Purpose:
 *
 * Check the fragmentation bits of the IP header for set values.  Possible
 * bits are don't fragment (DF), more fragments (MF), and reserved (RB).
 *
 * Arguments:
 *
 * The keyword to reference this plugin is "fragbits".  Possible arguments are
 * D, M and R for DF, MF and RB, respectively.
 *
 * Possible modes are '+', '!', and '*' for plus, not and any modes.
 *
 * Effect:
 *
 * Indicates whether any of the specified bits have been set.
 *
 * Comments:
 *
 * Ofir Arkin should be a little happier now. :)
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

static THREAD_LOCAL ProfileStats fragBitsPerfStats;

// this class holds the logic for setting up the fragment test
// data and testing for the data match (is_match function).
class FragBitsData
{
public:
    FragBitsData()
    { reset(); }

    void reset()
    {
        mode = 0;
        frag_bits = 0;
    }

    uint8_t get_mode() const;
    uint16_t get_frag_bits() const;
    void set_more_fragment_bit();
    void set_dont_fragment_bit();
    void set_reserved_bit();

    //no mode for normal since it is set as the default
    void set_not_mode();
    void set_any_mode();
    void set_plus_mode();

    void parse_fragbits(const char* data);

    bool is_match(Packet *);

private:
    //numeric mode values
    enum MODE { NORMAL, PLUS, ANY, NOT};

    static const uint16_t BITMASK = 0xE000;
    static const uint16_t RESERVED_BIT = 0x8000;
    static const uint16_t DONT_FRAG_BIT = 0x4000;
    static const uint16_t MORE_FRAG_BIT = 0x2000;

    //flags used to indicate mode
    static const char PLUS_FLAG = '+';
    static const char ANY_FLAG = '*';
    static const char NOT_FLAG = '!';

    bool check_normal(const uint16_t);
    bool check_any(const uint16_t);
    bool check_not(const uint16_t);
    bool check_plus(const uint16_t);

    uint8_t mode;
    uint16_t frag_bits;
};

//setter and getters
uint8_t FragBitsData::get_mode() const
{ return mode; }

uint16_t FragBitsData::get_frag_bits() const
{ return (frag_bits); }

void FragBitsData::set_dont_fragment_bit()
{ frag_bits |= DONT_FRAG_BIT; }

void FragBitsData::set_more_fragment_bit()
{ frag_bits |= MORE_FRAG_BIT; }

void FragBitsData::set_reserved_bit()
{ frag_bits |= RESERVED_BIT; }

void FragBitsData::set_any_mode()
{ mode = ANY; }

void FragBitsData::set_plus_mode()
{ mode = PLUS; }

void FragBitsData::set_not_mode()
{ mode = NOT; }

// this is the function that checks for a match
bool FragBitsData::is_match(Packet* p)
{
    uint16_t packet_fragbits = p->ptrs.ip_api.off_w_flags();

    // strip the offset value and leave only the fragment bits
    packet_fragbits &= BITMASK;

    bool match = false;

    // get the mode we have .. then check for match
    switch( get_mode() )
    {
        case NORMAL:
            match = check_normal(packet_fragbits);
            break;
        case ANY:
            match = check_any(packet_fragbits);
            break;
        case PLUS:
            match = check_plus(packet_fragbits);
            break;
        case NOT:
            match = check_not(packet_fragbits);
            break;
    }

    return match;
}

// check if all of flags are present
bool FragBitsData::check_normal(const uint16_t packet_fragbits)
{
    if (get_frag_bits() == packet_fragbits)
    {
        return true;
    }
    return false;
}

// check for these flags being set PLUS additional '+'
bool FragBitsData::check_plus(const uint16_t packet_fragbits)
{
    if ( (get_frag_bits() &  packet_fragbits ) != 0)
    {
        return true;
    }
     return false;
}

// check for any flags that match the ones set '*'
// logic is same as the check_plus
bool FragBitsData::check_any(const uint16_t packet_fragbits)
{
    if ( (get_frag_bits() & packet_fragbits ) != 0)
    {
        return true;
    }
    return false;
}

//check for packets that do NOT have matching flags set '!'
bool FragBitsData::check_not(const uint16_t packet_fragbits)
{
    if ( (get_frag_bits() & packet_fragbits ) == 0)
    {
        return true;
    }
    return false;
}

// parse fragbits and populate the information into this class
void FragBitsData::parse_fragbits(const char* data)
{
    assert(data);
    std::string bit_string = data;

    unsigned long len = bit_string.length();

    for(unsigned long a = 0; a <  len; a++)
    {
        //if we hit a space skip/continue
        if( isspace( bit_string.at(a) ) )
            continue;

        switch ( bit_string.at( a ) )
        {
        case 'd': // don't fragment
        case 'D':
            set_dont_fragment_bit();
            break;

        case 'm': // more fragment
        case 'M':
            set_more_fragment_bit();
            break;

        case 'r': // reserved bit
        case 'R':
            set_reserved_bit();
            break;

        case NOT_FLAG:// NOT flag, fire if flags are NOT set
            set_not_mode();
            break;

        case ANY_FLAG: // '*' ANY flag, fire on ANY of these bits
            set_any_mode();
            break;

        case PLUS_FLAG: // PLUS flag, fire on these bits PLUS any others
            set_plus_mode();
            break;

        default:
            ParseError("Bad fragbit = '%c'. Valid options are: RDM+!*",
                    bit_string.at(a) );
            return;
        }
    }
}

#define s_name "fragbits"

// IpsOptions class
class FragBitsOption : public IpsOption
{
public:
    FragBitsOption(const FragBitsData& fragBitsData) :
        IpsOption(s_name)
    { this->fragBitsData = fragBitsData; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    FragBitsData fragBitsData;
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

uint32_t FragBitsOption::hash() const
{
    uint32_t a,b,c;
    const FragBitsData* data = &fragBitsData;

    a = data->get_mode();
    b = data->get_frag_bits();
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool FragBitsOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const FragBitsOption& rhs = (const FragBitsOption&)ips;
    const FragBitsData* left = &fragBitsData;
    const FragBitsData* right = &rhs.fragBitsData;

    if ((left->get_mode() == right->get_mode()) &&
        (left->get_frag_bits() == right->get_frag_bits()))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus FragBitsOption::eval(Cursor&, Packet* p)
{
    Profile profile(fragBitsPerfStats);

    if ( !p->has_ip() )
        return NO_MATCH;

    bool is_match = fragBitsData.is_match(p);

    if(is_match)
        return MATCH;

    // if the test isn't successful, this function *must* return 0
    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~flags", Parameter::PT_STRING, nullptr, nullptr,
      "these flags are tested" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to test IP frag flags"

class FragBitsModule : public Module
{
public:
    FragBitsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &fragBitsPerfStats; }

    FragBitsData get_fragBits_data();

    Usage get_usage() const override
    { return DETECT; }

private:
    FragBitsData fragBitsData;
};

//provide access to the data object within the module
FragBitsData FragBitsModule::get_fragBits_data()
{
    return fragBitsData;
}

bool FragBitsModule::begin(const char*, int, SnortConfig*)
{
    fragBitsData.reset();
    return true;
}

// the fragbitsData object is set here from the value string
// which is the string of command line arguments
bool FragBitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~flags") )
        fragBitsData.parse_fragbits(v.get_string());
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FragBitsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* fragbits_ctor(Module* p, OptTreeNode*)
{
    FragBitsModule* fragBitsModule = (FragBitsModule*)p;
    return new FragBitsOption( fragBitsModule->get_fragBits_data() );
}

static void fragbits_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi fragbits_api =
{
    //BaseApi struct
    {
        PT_IPS_OPTION,  //PlugType type
        sizeof(IpsApi), //uint32_t size
        IPSAPI_VERSION, //uint32_t api_version
        0,              //uint32_t version
        API_RESERVED,   //uint32_t reserved
        API_OPTIONS,    //const char* options
        s_name,         //const char* name
        s_help,         //const char* help
        mod_ctor,       //ModNewFunc constructor
        mod_dtor        //ModDelFunc destructor
    },

    //IpsApi struct
    OPT_TYPE_DETECTION, //RuleOptType
    1,                  //max per rule
    0,                  //IpsOptFunc protos
    nullptr,            //IpsOptFunc pinit
    nullptr,            //IpsOptFunc pterm
    nullptr,            //IpsOptFunc tinit
    nullptr,            //IpsOptFunc tterm
    fragbits_ctor,      //IpsNewFunc ctor
    fragbits_dtor,      //IpsNewFunc dtor
    nullptr             //IpsOptFunc verify
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_fragbits[] =
#endif
{
    &fragbits_api.base,
    nullptr
};

