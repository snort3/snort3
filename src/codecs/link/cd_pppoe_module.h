/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// cd_pppoepkt_module.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CD_PPPOEPKT_MODULE_H
#define CD_PPPOEPKT_MODULE_H

#include "codecs/decode_module.h"


/*
 * NOTE:  This name reflect the file...NOT the Codec!
 *
 * Additionally, this module is used for generator a rule stub ONLY!
 * If you want to create a module for configuration, you must change the
 * names of the correct PPPoEpkt codec
 */


#define CD_PPPOE_NAME "cd_pppoe"

class PPPoEModule : public DecodeModule
{
public:
    PPPoEModule();

    const RuleMap* get_rules() const;
};

#endif
