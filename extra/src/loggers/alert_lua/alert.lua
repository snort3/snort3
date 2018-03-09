-- ----------------------------------------------------------
-- logger example:
--
--     define keyword lualert
--
-- configure snort with
--
--     ./configure_cmake.sh --prefix=my/prefix
--
-- then set up the path as follows:
--
--     export LUA_PATH=my/prefix/include/snort/lua/?.lua\;\;
--
-- You can use with -A lualert by adding lualert to your 
-- snort.lua:
--
--     lualert =
--     {
--         args = "num = 1, str = 'bar', cond = true"
--     }
--
-- the arg string is (in general) optional
-- if present, it will be put in a table named args, eg:
--
--     args = { num = 1, str = 'bar', cond = true }
--
-- this table is defined before init is called
-- the args string, if present, must be valid lua code like
-- above.
-- ----------------------------------------------------------

-- this pulls in snort bindings with ffi
require("snort_plugin")

-- init() is optional
-- if present, called once when script is loaded
-- here we return bool indicating args ok
function init ()
    return true
end

-- alert() is required
function alert ()
    -- get luajit structs
    local evt = ffi.C.get_event()
    local pkt = ffi.C.get_packet()

    -- str is a luajit string
    local str = ffi.string(evt.msg)

    -- FIXIT - this gets:
    -- bad argument #2 to 'format' (number expected, got cdata)
    --print(string.format('%ld %d:%d:%d %s',
    --    pkt.num, evt.gid, evt.sid, evt.rev, str))

    print(string.format('%d:%d:%d %s',
        evt.gid, evt.sid, evt.rev, str))
end

-- plugin table is required
plugin =
{
    type = "logger", 
    name = "lualert", -- eg -A lualert
    version = 0       -- optional version of this file
}

