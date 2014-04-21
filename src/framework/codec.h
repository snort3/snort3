/*
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef CODEC_H
#define CODEC_H

#include <vector>

#include "snort_types.h"
#include "framework/base_api.h"


struct Packet;

// this is the current version of the api
#define CDAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define CDAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// FIXIT just starting points for Codec and CodecApi





class Codec {
public:
    virtual ~Codec() { };

    virtual bool decode(const uint8_t* raw_packet, const uint32_t raw_len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id) = 0;

    // do nothing unless methods overridden.
    // ONE OF THESE METHODS MUST BE IMPLEMENTED!!
    virtual void get_protocol_ids(std::vector<uint16_t>&){};
    virtual void get_data_link_type(std::vector<int>&){};

    virtual inline bool is_ipv4(){ return false; };
    virtual inline bool is_ipv6(){ return false; };
    virtual inline const char* get_name(){return name; };


protected:
    Codec(const char* s) { name = s; };



private:
    const char* name;
};

struct _daq_pkthdr;

typedef int (*cd_eval_f)(void*, Packet*);
//typedef cd_eval_f (*cd_new_f)(const char* key, void**);
typedef Codec* (*cd_new_f)();

typedef void (*cd_del_f)(Codec *);
typedef void (*cd_aux_f)();
typedef void (*cd_get_protos)(std::vector<uint16_t>&);
typedef void (*cd_get_dlt)(std::vector<int>&);
typedef bool (*decode_f)(const uint8_t *, const uint32_t, Packet *, uint16_t &, uint16_t &);


    // add every protocol id, included IP protocols and 
    // ethertypes, to the passed in vector
//    cd_get_protos get_protos; 
//    cd_get_dlt get_dlt;  // as defined by the daq/libpcap.


struct CodecApi
{
    BaseApi base;


    // these may be nullptr
    cd_aux_f ginit;  // initialize global plugin data
    cd_aux_f gterm;  // clean-up pinit()

    cd_aux_f tinit;  // initialize thread-local plugin data
    cd_aux_f tterm;  // clean-up tinit()

    // these must be set
    cd_new_f ctor;   // get eval optional instance data
    cd_del_f dtor;   // clean up instance data

    cd_aux_f sum;
    cd_aux_f stats;
};

#endif

