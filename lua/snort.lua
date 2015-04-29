---------------------------------------------------------------------------
-- Snort++ configuration
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

conf_dir = os.getenv('SNORT_LUA_PATH')

if ( not conf_dir ) then
    conf_dir = '.'
end

dofile(conf_dir .. '/snort_defaults.lua')

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

-- uncomment ppm if you built with --enable-ppm
--ppm = { }

-- uncomment profile if you built with --enable-perfprofile
--profile = { }

-- uncomment normalizer if you are inline or not --pedantic
--normalizer = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }

arp_spoof = { }
back_orifice = { }
dns = { }
imap = { }
perf_monitor = { }
pop = { }
port_scan = { }
rpc_decode = { }
ssh = { }
telnet = { }

-- use http_inspect or new_http_inspect (incomplete)
http_inspect = { }
--new_http_inspect = { }

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

wizard = default_wizard

