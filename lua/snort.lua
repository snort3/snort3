---------------------------------------------------------------------------
-- Snort++ prototype configuration
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- setup environment
---------------------------------------------------------------------------
-- given:
-- export DIR=/install/path
-- configure --prefix=$DIR
-- make install
--
-- then:
-- export LUA_PATH=$DIR/include/snort/lua/?.lua\;\;
-- export SNORT_LUA_PATH=$DIR/conf/
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- setup the basics
---------------------------------------------------------------------------

require('snort_config')  -- for loading

-- Setup the network addresses you are protecting
HOME_NET = 'any'

-- Set up the external network addresses.
-- (leave as "any" in most situations)
EXTERNAL_NET = 'any'

dir = os.getenv('SNORT_LUA_PATH')

if ( not dir ) then
    dir = ''
end

dofile(dir .. 'snort_defaults.lua')
dofile(dir .. 'classification.lua')
dofile(dir .. 'reference.lua')

---------------------------------------------------------------------------
-- configure modules
---------------------------------------------------------------------------
--
-- mod = { } uses internal defaults
-- you can see them with snort --help-module mod
-- comment or delete to disable mod functionality
--
-- you can also use default_ftp_server and default_wizard
---------------------------------------------------------------------------

ppm = { }
profile = { }
perf_monitor = { }

normalize = { }

arp_spoof = { }
back_orifice = { }
rpc_decode = { }

port_scan_global = { }
port_scan = { }

http_inspect = { }
http_server = { }
--nhttp_inspect = { }

telnet = { }

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }

react = { }
reject = { }
--rewrite = { }

wizard = default_wizard

---------------------------------------------------------------------------
-- define / load rules and filters
---------------------------------------------------------------------------

local_rules =
[[
# snort-classic comments, includes, and rules with $VARIABLES

alert tcp any any -> any [80 81] ( sid:1; msg:"test"; http_method; content:"GE", offset 0, depth 2; content:"T", distance 0, within 1; )

#alert tcp any any -> any [80 81] ( sid:1; msg:"test"; http_method; find:"pat = 'GET'"; )
]]

ips =
{
    --include = '../test.rules',
    --include = '../rules/active.rules',
    --rules = local_rules,
    --enable_builtin_rules = true
}

---------------------------------------------------------------------------
-- set up any custom loggers
---------------------------------------------------------------------------

alert_test = { file = false }

