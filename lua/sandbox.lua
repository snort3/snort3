---------------------------------------------------------------------------
-- Lua sandbox configurations
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- This file defines a restricted Lua environment.
-- For control channel commands to prevent unauthorized system access.
-- use with --control-socket snort.sock --lua-sandbox lua/sandbox.lua
---------------------------------------------------------------------------

-- Environment with safe functions
sandbox_env =
{
    -- Basic Lua functions
    assert = assert,
    error = error,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = pcall,
    select = select,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    unpack = unpack,
    xpcall = xpcall,
    _VERSION = _VERSION,

    -- String library
    string =
    {
        byte = string.byte,
        char = string.char,
        find = string.find,
        format = string.format,
        gmatch = string.gmatch,
        gsub = string.gsub,
        len = string.len,
        lower = string.lower,
        match = string.match,
        rep = string.rep,
        reverse = string.reverse,
        sub = string.sub,
        upper = string.upper,
    },

    -- Table library
    table =
    {
        concat = table.concat,
        insert = table.insert,
        maxn = table.maxn,      -- Lua 5.1
        remove = table.remove,
        sort = table.sort,
    },

    -- Math library
    math =
    {
        abs = math.abs,
        acos = math.acos,
        asin = math.asin,
        atan = math.atan,
        atan2 = math.atan2,
        ceil = math.ceil,
        cos = math.cos,
        cosh = math.cosh,
        deg = math.deg,
        exp = math.exp,
        floor = math.floor,
        fmod = math.fmod,
        frexp = math.frexp,
        huge = math.huge,
        ldexp = math.ldexp,
        log = math.log,
        log10 = math.log10,
        max = math.max,
        min = math.min,
        modf = math.modf,
        pi = math.pi,
        pow = math.pow,
        rad = math.rad,
        random = math.random,
        randomseed = math.randomseed,
        sin = math.sin,
        sinh = math.sinh,
        sqrt = math.sqrt,
        tan = math.tan,
        tanh = math.tanh,
    },

    -- EXPLICITLY EXCLUDED for security:
    -- os = nil,              -- No shell command execution
    -- io = nil,              -- No file I/O operations
    -- ffi = nil,             -- No raw memory access (LuaJIT FFI)
    -- package = nil,         -- No module loading system
    -- require = nil,         -- No module require
    -- module = nil,          -- No module creation
    -- loadfile = nil,        -- No arbitrary file loading
    -- dofile = nil,          -- No arbitrary file execution
    -- loadstring = nil,      -- No runtime code compilation (sandbox escape)
    -- load = nil,            -- No code loading (Lua 5.2+)
    -- debug = nil,           -- No debug library (can escape sandbox)
    -- getfenv = nil,         -- No environment inspection (Lua 5.1)
    -- setfenv = nil,         -- No environment modification (Lua 5.1)
    -- rawget = nil,          -- No metatable bypass
    -- rawset = nil,          -- No metatable bypass
    -- rawequal = nil,        -- No metatable bypass
    -- getmetatable = nil,    -- No metatable inspection
    -- setmetatable = nil,    -- No metatable modification
    -- coroutine = nil,       -- No coroutines (could be used for DoS)
    -- collectgarbage = nil,  -- No GC control (could cause DoS)

    -- NOTE: The following will be added by Snort's bootstrap.lua
    -- via create_sandbox_env() when the sandbox is initialized:
    --   include()                    - Safe include (checks bytecode, applies sandbox)
    --   snort_whitelist_append()     - Whitelist config keywords
    --   snort_whitelist_add_prefix() - Whitelist config prefixes
    --   SNORT_VERSION                - Version string
    --   SNORT_BUILD                  - Build info
    --   SNORT_MAJOR_VERSION          - Major version number
    --   SNORT_MINOR_VERSION          - Minor version number
    --   SNORT_PATCH_VERSION          - Patch version number
    --   SNORT_SUBLEVEL_VERSION       - Sublevel version
    --   get_module_version()         - Query module versions
    --   tweaks                       - Performance tweaks table
    --   SNORT_DEP_VERSIONS           - Dependency versions
    --
    -- And these will be added by Shell::install() after module loading:
    --   help(), quit(), pause(), resume(), dump_stats(), reload_config(), etc.
    --   (All Snort runtime control commands)
}

-- Optional: Define create_sandbox_env() to customize Snort's additions
--[[
function create_sandbox_env()
    -- At this point, bootstrap.lua has already added:
    --   sandbox_env.include, sandbox_env.SNORT_VERSION, etc.

    -- You can add custom validation or additional restrictions here
    -- Example: Add custom helper functions
    -- sandbox_env.my_custom_helper = function() ... end
end
--]]

-- Example advanced pattern: Logging wrapper
-- Uncomment to log all function calls in the sandbox
--[[
function create_sandbox_env()
    -- Wrap functions to log their usage
    local original_print = sandbox_env.print
    sandbox_env.print = function(...)
        -- Could log to syslog here
        return original_print(...)
    end
end
--]]

-- Example advanced pattern: Talos tweaks compatibility
-- Uncomment to allow '--tweaks talos' with sandboxing
-- (talos.lua uses io.open/io.close to check for local.rules)
--[[
sandbox_env.io =
{
    open = io.open,
    close = io.close,
}
--]]
