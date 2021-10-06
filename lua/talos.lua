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

snort =
{
    ['-Q'] = true,
    ['-s'] = 65535,
    ['--daq'] = 'dump',
    ['--daq-var'] = 'output=none'
}

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

