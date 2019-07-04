---------------------------------------------------------------------------
-- talos test tweaks
-- use with --talos or --tweaks talos
---------------------------------------------------------------------------

function file_exists(name)
    local f=io.open(name,'r')
    if f~=nil then
        io.close(f)
        return true
    else
        return false
    end
end

daq =
{
    modules =
    {
        {
            name = 'pcap',
            mode = 'read-file'
        },
        {
            name = 'dump',
            variables = { 'output=none' }
        },
    },
    snaplen = 65535
}

normalizer = { tcp = { ips = true } }

snort = { }
snort['-Q'] = true

if file_exists('local.rules') then
    snort['-R'] = 'local.rules'
end

alert_talos = { }
alerts = { alert_with_interface_name = true }

profiler =
{
    modules = { show = false },
    memory = { show = false },
    rules = { show = true }
}

