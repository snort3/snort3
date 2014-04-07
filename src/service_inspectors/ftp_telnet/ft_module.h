/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// ft_module.h author Russ Combs <rucombs@cisco.com>

#ifndef FT_MODULE_H
#define FT_MODULE_H

#include "framework/module.h"

#define GID_FTP     125
#define GID_TELNET  126

#define FTP_TELNET_CMD                   1
#define FTP_INVALID_CMD                  2
#define FTP_PARAMETER_LENGTH_OVERFLOW    3
#define FTP_MALFORMED_PARAMETER          4
#define FTP_PARAMETER_STR_FORMAT         5
#define FTP_RESPONSE_LENGTH_OVERFLOW     6
#define FTP_ENCRYPTED                    7
#define FTP_BOUNCE                       8
#define FTP_EVASIVE_TELNET_CMD           9

#define TELNET_AYT_OVERFLOW              1
#define TELNET_ENCRYPTED                 2
#define TELNET_SB_NO_SE                  3

class SnortConfig;

class FtGlobalModule : public Module
{
public:
    FtGlobalModule();
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);
};

class TelnetModule : public Module
{
public:
    TelnetModule();
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    unsigned get_gid() const
    { return GID_TELNET; };
};

class FtpServerModule : public Module
{
public:
    FtpServerModule();
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    unsigned get_gid() const
    { return GID_FTP; };
};

class FtpClientModule : public Module
{
public:
    FtpClientModule();
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);
};

#endif

