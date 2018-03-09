-- ----------------------------------------------------------
-- ips_option example:
--
--     define keyword find
--
-- configure snort with
--
--     ./configure_cmake.sh --prefix=my/prefix
--
-- then set up the path as follows:
--
--     export LUA_PATH=my/prefix/include/snort/lua/?.lua\;\;
--
-- write a rule as follows:
--
--     alert tcp any any -> any 80 ( \
--         msg:"luajit example"; sid:1; \
--         content:"GET"; \
--         find:"pat='HTTP/1%.%d'"; )
--
-- the arg string is (in general) optional
-- if present, it will be put in a table named args, eg:
--
--     args { pat='GET .+ HTTP/1.1' }
--
-- this table is defined before init is called
-- the args string, if present, must be valid lua code like
-- name1 = value1, name2 = 'value2'.
-- ----------------------------------------------------------

-- this pulls in snort bindings with ffi
require("snort_plugin")

-- init() is optional
-- if present, called once when script is loaded
-- here we return bool indicating args ok
function init ()
    if ( args.pat == nil ) then
        return 'missing pat'
    end

    if ( type(args.pat) ~= 'string' ) then
        return 'pat must be string'
    end

    return true
end

-- eval() is required
-- eval must return a bool (match == true)
function eval ()
    -- buf is a luajit cdata
    local buf = ffi.C.get_buffer()

    -- str is a lua string
    local str = ffi.string(buf.data, buf.len)

    local i,j = string.find(str, args.pat)

    return (i and (i > 0))
end

-- plugin table is required
plugin =
{
    type = "ips_option",  -- only available type currently
    name = "find",        -- rule option keyword
    version = 0           -- optional, defaults to zero
}

