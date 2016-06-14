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



require("snort_config")

dir = os.getenv('SNORT_LUA_PATH')

if ( not dir ) then
    dir = '.'
end

dofile(dir .. '/snort_defaults.lua')


appid =
{
    conf = 'rna.conf',
    memcap = 15856401,
    app_detector_dir = '/var/sf/appid',
    thirdparty_appid_dir = '/var/sf/appid/thirdparty_appid',
    app_stats_filename = '/var/sf/appid/appid_stats.log',
    app_stats_period = 3600,
    app_stats_rollover_size = 100000000,
    app_stats_rollover_time = 12,
    instance_id = 222,
    debug = true,
    dump_ports = true,
}



