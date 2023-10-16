//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// ips_context_data.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_CONTEXT_DATA_H
#define IPS_CONTEXT_DATA_H

#include "main/snort_types.h"

#include "detection/detection_engine.h"

namespace snort
{
class SO_PUBLIC IpsContextData
{
public:
    virtual ~IpsContextData() = default;

    static unsigned get_ips_id();
    // Only unit tests can call this function to clear the id
    static void clear_ips_id();

    template<typename T>
    static T* get(unsigned ips_id)
    {
        T* data = (T*)DetectionEngine::get_data(ips_id);
        if ( ! data )
        {
            data = new T;
            DetectionEngine::set_data(ips_id, data);
        }
        return data;
    }
    virtual void clear() {}

protected:
    IpsContextData() = default;

private:
    static unsigned ips_id;
};
}
#endif

