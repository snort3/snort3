//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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
// control.cc author Bhagya Tholpady <bbantwal@cisco.com>
//            author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "control.h"

#include "log/messages.h"
#include "main.h"
#include "main/shell.h"
#include "managers/module_manager.h"
#include "utils/util.h"

#include "control_mgmt.h"

using namespace snort;


ControlConn* ControlConn::query_from_lua(const lua_State* L)
{
#ifdef SHELL
    return ( L ? ControlMgmt::find_control(L) : nullptr );
#else
    UNUSED(L);
    return nullptr;
#endif
}

//------------------------------------------------------------------------
// control channel class
// -----------------------------------------------------------------------

ControlConn::ControlConn(int fd, bool local) : fd(fd), local(local)
{
    touch();
    shell = new Shell;
    configure();
    show_prompt();
}

ControlConn::~ControlConn()
{
    shutdown();
    delete shell;
}

void ControlConn::shutdown()
{
    if (is_closed())
        return;
    if (!local)
        close(fd);
    fd = -1;
}

void ControlConn::configure() const
{
    ModuleManager::load_commands(shell);
}

int ControlConn::read_commands()
{
    char buf[STD_BUF];
    int commands_found = 0;
    ssize_t n = 0;

    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0)
    {
        buf[n] = '\0';
        char* p = buf;
        char* nl;
        while ((nl = strchr(p, '\n')) != nullptr)
        {
            std::string command = next_command;
            next_command.append(buf, nl - p);
            LogMessage("Control: received command, %s\n", next_command.c_str());
            pending_commands.push(std::move(next_command));
            next_command.clear();
            p = nl + 1;
            commands_found++;
        }
        if (*p != '\0')
            next_command.append(p);
        else if (local)
        {
            // For stdin, we are only guaranteed to have some amount of input ending in a
            // newline and future read() calls will block.  To avoid blocking, assume that
            // we're done reading if the input ended with a newline.
            break;
        }
    }

    if (n < 0 && errno != EAGAIN && errno != EINTR)
    {
        ErrorMessage("Error reading from control descriptor: %s\n", get_error(errno));
        return -1;
    }
    if (n == 0 && commands_found == 0)
        return -1;
    touch();
    return commands_found;
}

void ControlConn::set_user_network_policy()
{ shell->set_user_network_policy(); }

int ControlConn::execute_commands()
{
    int executed = 0;
    while (!is_closed() && !blocked && !pending_commands.empty())
    {
        const std::string& command = pending_commands.front();
        std::string rsp;
        shell->execute(command.c_str(), rsp);
        if (!rsp.empty())
            respond("%s", rsp.c_str());
        if (!blocked)
            show_prompt();
        pending_commands.pop();
        executed++;
    }

    return executed;
}

void ControlConn::block()
{
    blocked = true;
}

void ControlConn::remove()
{
    removed = true;
}

void ControlConn::touch()
{
    touched = time(nullptr);
}

time_t ControlConn::get_touched() const
{
    return touched;
}

void ControlConn::unblock()
{
    if (blocked)
    {
        blocked = false;
        execute_commands();
        if (!blocked && !show_prompt())
            shutdown();
    }
}

// FIXIT-L would like to flush prompt w/o \n
bool ControlConn::show_prompt()
{
    return respond("%s\n", get_prompt());
}

bool ControlConn::respond(const char* format, va_list& ap)
{
    char buf[STD_BUF];
    int response_len = vsnprintf(buf, sizeof(buf), format, ap);
    if (response_len < 0 || response_len == sizeof(buf))
        return false;
    buf[response_len] = '\0';

    int bytes_written = 0;
    while (bytes_written < response_len)
    {
        ssize_t n = write(fd, buf + bytes_written, response_len - bytes_written);
        if (n < 0)
        {
            if (errno != EAGAIN && errno != EINTR)
            {
                shutdown();
                return false;
            }
        }
        else
            bytes_written += n;
    }
    touch();
    return true;
}

bool ControlConn::respond(const char* format, ...)
{
    if (is_closed() or is_removed())
        return false;

    va_list ap;
    va_start(ap, format);
    bool ret = respond(format, ap);
    va_end(ap);

    return ret;
}
